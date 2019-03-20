from collections import OrderedDict
from math import log2
from datatypes import DoubleDict
import traceback
import re


TTL = 86400
packet_id = 0x1010

SRV_FAIL = 0x0002
SRV_REFSD = 0x0005
ACC_NON_AUTH = 0x0010
CAN_RECURSION = 0x0080
RECURSIVE = 0x0100
AUTH_RESP = 0x0400
IS_RESPONSE = 0x8000


def btoi(b):
    return int.from_bytes(b, 'big')


def itob(num, b=0):
    return num.to_bytes(b if b else int(log2(num) // 8 + 1), 'big')


def ipv6_decoder(bin_addr):
    res = ['']
    for i in range(len(bin_addr)):
        res[-1] += '{:02x}'.format(bin_addr[i])
        if i % 2:
            res[-1] = hex(int(res[-1], 16))[2:]
            res.append('')
    return re.sub(r'(0+:)+', ':', ':'.join(res[:-1]))


def ipv6_encoder(addr):
    addr = addr.split(':')
    emptiness = addr.index('')
    if emptiness >= 0:
        for _ in range(8 - len(addr)):
            addr.insert(emptiness, '')
    return b''.join(itob(int(a.rjust(4, '0'), 16), 2) for a in addr)


allFields = OrderedDict({
    'Queries': ('Name', 'Type', 'Class'),
    'Answers': ('Name', 'Type', 'Class', 'TTL', 'Data length', 'Address'),
    'Authoritative NS': ('Name', 'Type', 'Class', 'TTL', 'Data length', 'Name Server'),
    'Additional records': ('Name', 'Type', 'Class', 'TTL', 'Data length', 'Address', 'CNAME')
})

fieldSections = list(allFields.keys())


class DNSPacket(dict):

    def __init__(self, rawdata=None, tcp=False, *args, **kwargs):
        dict.__init__(self, *args, **kwargs)
        self.store()
        self.update({g: [] for g in fieldSections})
        if rawdata and type(rawdata) != bytes:
            raise Exception('DNSPacket needs bytes or None argument')
        self.__binarydata = rawdata
        self.classes = {b'\x00\x01': 'IN'}
        self.types = DoubleDict({
            b'\x00\x01': 'A',
            b'\x00\x02': 'NS',
            b'\x00\x05': 'CNAME',
            b'\x00\x06': 'SOA',
            b'\x00\x0f': 'MX',
            b'\x00\x10': 'TXT',
            b'\x00\x1c': 'AAAA'})

        self.readOffs = 0
        self.zone_offsets = {}
        self.tcp = tcp

        if not self.__binarydata:
            self.__configure_packet()
        self.__parse()

    def __tcp_prepare(self):
        self.__binarydata = itob(len(self.__binarydata), 2) + self.__binarydata

    @staticmethod
    def domain_encode(bStr) -> bytes:
        '''serialize string into zone1_len+zone1+(zone2_len)+zone2...\0'''
        if type(bStr) == str:
            bStr = bStr.split('.')
        return b''.join(b'%s%s' % (itob(len(i)), bytes(i, 'ascii')) for i in bStr) + b'\x00'

    def __configure_packet(self):
        global packet_id
        self.__binarydata = b''.join([
            itob(packet_id, 2),
            itob(ACC_NON_AUTH | RECURSIVE, 2)
        ])
        packet_id += 0x0A

    def removeField(self, k):
        self[k].clear()

    def addField(self, section, params):
        if section not in fieldSections:
            raise KeyError('Unknown DNS-section', section,
                           'must be one of', fieldSections)
        if set(params.keys()) != set(allFields[section]):
            raise KeyError('Wrong section parameters "%s", must be: %s' %
                           (params.keys(), ', '.join(allFields[section])))
        self[section].append(params)

    def flags(self, flags):
        self['Flags'] &= (flags & 0xFFFF)

    def __setPointers(self, bstr) -> str:
        for i in range(len(bstr)):
            partial_domain = self.domain_encode(bstr[i:])
            if partial_domain in self.zone_offsets.keys() and partial_domain in self.tmp_bindata:
                return self.domain_encode(bstr[:i])[:-1] + self.zone_offsets[partial_domain]
            self.doffs = self.tmp_bindata.find(partial_domain)
            if ~self.doffs:
                self.zone_offsets[partial_domain] = itob(
                    0xc000 | self.doffs, 2)
                return self.domain_encode(bstr[:i])[:-1] + self.zone_offsets[partial_domain]
        return self.domain_encode(bstr)

    def __serialize(self):
        self.lens = list(map(lambda x: len(self[x]), fieldSections))
        self.tmp_bindata = bytearray(b''.join([
            self['ID'],
            itob(self['Flags'], 2)
        ]))
        self.tmp_bindata.extend(b''.join(itob(i, 2) for i in self.lens))
        self.lens = self.lens.__iter__()
        for fieldsection in fieldSections:
            for counter in range(self.lens.__next__()):
                for field in allFields[fieldsection]:
                    try:
                        self.itm = self[fieldsection][counter][field]
                    except:
                        continue
                    if field == 'Type':
                        self.itm = self.types[self.itm]
                    elif field == 'Class':
                        self.itm = b'\x00\x01'
                    elif field == 'TTL':
                        self.itm = itob(self.itm, 4)
                    elif field == 'Data length':
                        self.itm = itob(self.itm, 2)
                    elif field == 'Address':
                        if '.' in self.itm:
                            self.itm = b''.join(
                                map(lambda a: itob(int(a), 1), self.itm.split('.')))
                        elif ':' in self.itm:
                            self.itm = ipv6_encoder(self.itm)
                    elif field == 'Name' or field == 'Name server' or field == 'CNAME':
                        self.itm = self.__setPointers(self.itm.split('.'))
                    self.tmp_bindata.extend(self.itm)
        self.__binarydata = bytes(self.tmp_bindata)
        self.store()
        if self.tcp:
            self.__tcp_prepare()

    def __parse(self):
        self.hdrs = [None]*6
        try:
            if self.tcp:
                self.__binarydata = self.__binarydata[2:]
            for i in range(len(self.hdrs)):
                self.hdrs[i] = self.__substr(2)
                if i >= 2:
                    self.hdrs[i] = btoi(self.hdrs[i])
            self['ID'] = self.hdrs[0]
            self['Flags'] = btoi(self.hdrs[1])
            self.hdrs = self.hdrs[2:].__iter__()
            for fgroup in fieldSections:
                for _ in range(self.hdrs.__next__()):
                    self.fields = {}
                    self.fields['Name'] = self.strDecode(
                        self.__binarydata[self.readOffs:])
                    self.fields['Type'] = self.types[self.__substr(2)]
                    self.fields['Class'] = self.classes[self.__substr(2)]
                    if fgroup != 'Queries':
                        self.fields['TTL'] = btoi(self.__substr(4))
                        self.fields['Data length'] = btoi(self.__substr(2))
                        if fgroup == 'Authoritative NS' or (fgroup == 'Answers' and self.fields['Type'] == 'NS'):
                            self.fields['Name server'] = self.strDecode(
                                self.__substr(self.fields['Data length']), move_carriage=False)
                        else:
                            if self.fields['Type'] == 'CNAME':
                                self.fields['CNAME'] = self.strDecode(self.__substr(
                                    self.fields['Data length']), move_carriage=False)
                            elif self.fields['Type'] == 'AAAA':
                                self.fields['Address'] = ipv6_decoder(
                                    self.__substr(16))
                            elif self.fields['Type'] == 'A':
                                self.fields['Address'] = '.'.join(
                                    map(lambda x: str(x), self.__substr(4)))
                            elif self.fields['Type'] == 'MX':
                                self.__substr(2)  # skip preference
                                self.fields['Address'] = self.strDecode(self.__substr(
                                    self.fields['Data length'] - 2), move_carriage=False)
                            elif self.fields['Type'] == 'TXT':
                                txtlen = btoi(self.__substr(1))
                                self.fields['Address'] = self.__substr(
                                    txtlen).decode('ascii')
                    self[fgroup].append(self.fields)
        except ArithmeticError:
            traceback.print_exc()
            print('Error was in', self.readOffs)

    def __substr(self, sublen) -> str:
        self.sub = self.__binarydata[self.readOffs:self.readOffs+sublen]
        self.readOffs += sublen
        return self.sub

    def getItemByOffset(self, bStr) -> str:
        if bStr not in self.zone_offsets.keys():
            self.zone_offsets[bStr] = self.strDecode(
                self.__binarydata[btoi(bStr) & 0x3fff:], move_carriage=False).encode('ascii')
        return self.zone_offsets[bStr]

    def strDecode(self, bStr, move_carriage=True) -> bytes:
        '''Parse binary string from packet into readable'''
        result = []
        ptr = None
        strlen = 0
        while ptr != 0:
            ptr = bStr[0]
            if ptr & 0xc0 == 0xc0:
                result.append(self.getItemByOffset(bStr[:2]))
                strlen += 2
                break
            strlen += ptr + 1
            if ptr == 0:
                break
            result.append(bStr[1:ptr+1])
            bStr = bStr[ptr+1:]
        if move_carriage:
            self.readOffs += strlen
        return (b'.'.join(result)).decode('ascii')

    def getRawData(self):
        if self.has_changed():
            self.__serialize()
        return self.__binarydata

    def has_changed(self):
        return list(self.values()) != self.__old_vals

    def store(self):
        self.__old_vals = list(self.values())
