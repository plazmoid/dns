import Packet
import socket as s
import re
import sys


def beautifulpacket(data):
    try:
        print(' '.join(i for i in data['Queries'][0].values()), end=' ')
    except:
        print(data)
        return
    print('Server failure!' if Packet.btoi(data['Flags']) & 0b0010 == 2 else '')
    if len(data['Answers']) > 0:
        print('\tName | Type | Class | TTL | Data length | Address\n')
        for answer in data['Answers']:
            print('\t'+' | '.join(str(i) for i in answer.values()))
        print()

def dnsing(url, types, addr, allowtcp=False, recursive=True):
    params = {'Name': url,
              'Class': 'IN'}
    
    sock = None
    try:
        if allowtcp:
            def cli_ask(data):
                sock = s.socket(s.AF_INET, s.SOCK_STREAM, s.IPPROTO_TCP)
                sock.connect((addr, 53))
                sock.settimeout(3)
                sock.send(data)
                return sock.recv(2048)
        else:
            def cli_ask(data):
                sock = s.socket(s.AF_INET, s.SOCK_DGRAM, s.IPPROTO_UDP)
                sock.settimeout(3)
                sock.sendto(data, (addr, 53))
                return sock.recv(2048)
            
        
        for wtype in types:
            params['Type'] = wtype
            packet = Packet.DNSPacket()
            packet.addField('Queries', params)
            #print(packet.getParsedData())
            #print(packet.getRawData())
            with s.socket(s.AF_INET, s.SOCK_DGRAM) as sock:
                answer = cli_ask(packet.getRawData())
                #print('ANSWER:', data)
                beautifulpacket(Packet.DNSPacket(answer).getParsedData())
    finally:
        sock.close()

def usage():
    print('Usage: %s URL -t type1 type2 ... [-s dnsserv IP]' % (__file__))
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
    dnsing(src, types, servaddr, allowtcp=('-tcp' in args))
    
main()