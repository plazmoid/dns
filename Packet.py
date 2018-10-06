import traceback
from collections import OrderedDict
from math import log2
from datatypes import FlaggedDict, DoubleDict


TTL = 86400
packet_id = 0x1010


def btoi(b):
    return int.from_bytes(b, 'big')


def itob(num, s=0):
    return num.to_bytes(s if s else int(log2(num) // 8 + 1), 'big')


allFields = OrderedDict({
    'Queries': ('Name', 'Type', 'Class'),
    'Answers': ('Name', 'Type', 'Class', 'TTL', 'Data length', 'Address'),
    'Authoritative NS': ('Name', 'Type', 'Class', 'TTL', 'Data length', 'Name Server'),
    'Additional records': ('Name', 'Type', 'Class', 'TTL', 'Data length', 'Address', 'CNAME')
})

fieldSections = list(allFields.keys())

class DNSPacket:

    def __init__(self, rawdata=None):
        self.__binarydata = rawdata
        self.classes = {b'\x00\x01': 'IN'}
        self.types = DoubleDict({b'\x00\x01': 'A',
                      b'\x00\x02': 'NS',
                      b'\x00\x05': 'CNAME',
                      b'\x00\x06': 'SOA',
                      b'\x00\x0c': 'PTR',
                      b'\x00\x0f': 'MX',
                      b'\x00\x1c': 'AAAA',
                      b'\x00\xfc': 'AXFR'})
        
        self.__records = FlaggedDict({g:[] for g in fieldSections})
        self.readOffs = 0
        self.offsets = {}
        
        if type(self.__binarydata) != bytes:
            self.__createPacket()
        self.__parse()
            
    @staticmethod
    def strEncode(bStr) -> bytes:
        '''serialize string into zone1_len+zone1+(zone2_len)+zone2...\0'''
        if type(bStr) == str:
            bStr = bStr.split('.')
        return b''.join(itob(len(i))+i.encode('ascii') for i in bStr) + b'\x00'
    
    def __createPacket(self):        
        global packet_id
        self.__binarydata = b''.join([
            itob(packet_id, 2), #transaction ID
            b'\x00\x10', #no flags
        ])
        packet_id += 0x0A

    def removeField(self, dkey):
        self.__records[dkey].clear()

    def addField(self, section, argdict):
        if section not in fieldSections:
            raise KeyError('Unknown DNS-section', section, 'must be one of', fieldSections)
        if set(argdict.keys()) != set(allFields[section]):
            raise KeyError('Wrong section parameters, must be: ' + ', '.join(allFields[section]))
        self.__records[section].append(argdict)

    def __setPointers(self, bstr) -> str:
        '''расстановка указателей на строки в бинарном представлении пакета, ищет в дополнительном буфере (не в основном!)'''
        self.pbdata = bytes(self.bindata)
        for i in range(len(bstr)):
            self.text = self.strEncode(bstr[i:])
            if self.text in self.offsets.keys() and self.text in self.pbdata:
                return self.strEncode(bstr[:i])[:-1] + self.offsets[self.text]
            self.doffs = self.pbdata.find(self.text)
            if self.doffs != -1:
                #print('bstr:', self.itob(0xc000 | self.doffs, 2), i, bstr[:i])
                self.offsets[self.text] = itob(0xc000 | self.doffs, 2)
                return self.strEncode(bstr[:i])[:-1] + self.offsets[self.text]
        return self.strEncode(bstr)
        
    def __serialize(self):
        self.lens = [len(self.__records[i]) for i in fieldSections]
        self.bindata = bytearray(b''.join([
            self.__records['ID'],
            self.__records['Flags']
        ]))
        self.bindata.extend(b''.join(itob(i, 2) for i in self.lens))
        self.lens = self.lens.__iter__()
        for fieldsection in fieldSections:
            for counter in range(self.lens.__next__()):
                for field in allFields[fieldsection]:
                    try:
                        self.itm = self.__records[fieldsection][counter][field]
                        #print(fieldsection, counter, field)
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
                            self.itm = b''.join(map(lambda a: itob(int(a), 1), self.itm.split('.')))
                        elif ':' in self.itm:
                            self.itm = b''.join(map(lambda a: itob(int(a, 16), 1), self.itm.split(':')))  
                    elif field == 'Name' or field == 'Name server' or field == 'CNAME':
                        #print(self.itm, self.bindata)
                        self.itm = self.__setPointers(self.itm.split('.'))
                    self.bindata.extend(self.itm)
        self.__binarydata = bytes(self.bindata)
        self.__records.store()

    def __parse(self):
        self.hdrs = [None]*6
        try:
            for i in range(len(self.hdrs)):
                self.hdrs[i] = self.__substr(2)
                if i>=2:
                    self.hdrs[i] = btoi(self.hdrs[i])
            self.__records['ID'] = self.hdrs[0]
            self.__records['Flags'] = self.hdrs[1]
            self.hdrs = self.hdrs[2:].__iter__()
            for fgroup in fieldSections:
                for _ in range(self.hdrs.__next__()):
                    self.fields = {}
                    self.fields['Name'] = self.strDecode(self.__binarydata[self.readOffs:]).decode('ascii')
                    self.fields['Type'] = self.types[self.__substr(2)]
                    self.fields['Class'] = self.classes[self.__substr(2)]
                    if fgroup != 'Queries':
                        self.fields['TTL'] = btoi(self.__substr(4))
                        self.fields['Data length'] = btoi(self.__substr(2))
                        if fgroup == 'Authoritative NS' or (fgroup == 'Answers' and self.fields['Type'] == 'NS'):
                            self.fields['Name server'] = self.strDecode(self.__substr(self.fields['Data length']), move_carriage=False).decode('ascii')
                        else:
                            if self.fields['Type'] == 'CNAME':
                                self.fields['CNAME'] = self.strDecode(self.__substr(self.fields['Data length']), move_carriage=False).decode('ascii')
                            else:
                                if self.fields['Data length'] == 16:
                                    self.fields['Address'] = ':'.join(hex(i)[2:] for i in self.__substr(16))
                                else:
                                    self.fields['Address'] = '.'.join(str(i) for i in self.__substr(4))
                    self.__records[fgroup].append(self.fields)
                #print('FINALLY:', self.__binarydata[self.readOffs:])
        except ArithmeticError:
            traceback.print_exc()
            print('Error was in', self.readOffs)
            
    def __substr(self, sublen) -> str:
        '''как головка, читающая ленту: возвращается sublen следующих элементов строки'''
        self.sub = self.__binarydata[self.readOffs:self.readOffs+sublen]
        self.readOffs += sublen
        return self.sub
    
    def getItemByOffset(self, bStr) -> str:
        if bStr not in self.offsets.keys():
            self.offsets[bStr] = self.strDecode(self.__binarydata[btoi(bStr) & 0x3fff:], move_carriage=False)
        return self.offsets[bStr]

    def strDecode(self, bStr, move_carriage=True) -> bytes:
        '''парсит бинарную строку из пакета (с длинами до точек и указателями) в читабельную'''
        result = []
        ptr = None
        strlen = 0
        while ptr != 0:
            ptr = bStr[0]
            if ptr & 0xc0 == 0xc0:
                result.append(self.getItemByOffset(bStr[:2]))
                strlen += 2
                #print('PTR_SOLVE:', result)
                break
            strlen += ptr+1
            if ptr == 0:
                break
            result.append(bStr[1:ptr+1])
            bStr = bStr[ptr+1:]
        if move_carriage:
            self.readOffs += strlen
        return b'.'.join(result)

    def getParsedData(self, arrs=None, nkey=None, *cond): #TODO: што
        try:
            if nkey == None:
                if arrs == None:
                    return self.__records
                else:
                    return self.__records[arrs]['data']
            if len(cond) == 0:
                return [i[nkey] for i in self.__records[arrs]]
            else:
                return [i[nkey] for i in self.__records[arrs] if i[cond[0]] == cond[1]]
        except Exception as e:
            print(e)
            return []
    
    def getRawData(self):
        if self.__records.has_changed():
            self.__serialize()
        return self.__binarydata
    
