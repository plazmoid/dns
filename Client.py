import Packet
import socket as s
import re
import sys


def beautifulpacket(data):
    hdrs = ['Name', 'Type', 'Class', 'TTL', 'Data length', 'Data']
    try:
        print(' '.join(i for i in data['Queries'][0].values()))
    except:
        print(data)
        return
    if data['Flags'] & Packet.SRV_FAIL:
        print('Server failure!')
        return
    if len(data['Answers']) > 0:
        if data['Flags'] & ~Packet.AUTH_RESP:
            print('Non-authoritative response')
        print('\t%s' % ' | '.join(hdrs))
        for answer in data['Answers']:
            print('\t'+' \t| '.join(str(i) for i in answer.values()))
        print()

def dnsing(url, types, addr, allowtcp=False, recursive=True):
    params = {'Name': url,
              'Class': 'IN'}
    
    if allowtcp:
        def cli_ask(data):
            with s.socket(s.AF_INET, s.SOCK_STREAM, s.IPPROTO_TCP) as sock:
                sock.connect((addr, 53))
                sock.settimeout(3)
                sock.send(data)
                return sock.recv(2048)
    else:
        def cli_ask(data):
            with s.socket(s.AF_INET, s.SOCK_DGRAM, s.IPPROTO_UDP) as sock:
                sock.settimeout(3)
                sock.sendto(data, (addr, 53))
                return sock.recv(2048)
        
    for wtype in types:
        packet = Packet.DNSPacket()
        params['Type'] = wtype
        packet.addField('Queries', params)
        if not recursive:
            packet.flags(~Packet.RECURSIVE)
        answer = cli_ask(packet.getRawData())
        beautifulpacket(Packet.DNSPacket(answer).getParsedData())


def usage():
    print('''Usage: %s host -t type1 type2 ... [-R] [-tcp] [-s dnsserver]
    -R\t\t disable recursion
    -s\t\t use user-defined server
    -t\t\t record types splitted with space
    -tcp\t encapsulate in TCP''' % (__file__))
    sys.exit(1)


def main():
    '''Client.py ya.ru -t A NS AAAA -s'''
    try:
        src = sys.argv[1]
        if src.startswith('-s') or src.startswith('-t'):
            raise IndexError
        args = ' '.join(sys.argv)
        types = re.findall(r'-t ([^-]*)', args)[0].strip().split(' ')
    except IndexError:
        usage()
    try:
        servaddr = re.findall(r'-s (\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})?', args)[0].strip()
    except IndexError:
        servaddr = '8.8.8.8'
        print('Using default DNS-server:', servaddr, '\n')
    dnsing(src, types, servaddr, allowtcp=('-tcp' in args), recursive=('-R' not in args))
    
main()