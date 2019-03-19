#!/usr/bin/python
import Packet
import argparse
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
    if data['Flags'] & Packet.SRV_REFSD:
        print('Refused')
        return
    if len(data['Answers']) > 0:
        if data['Flags'] & ~Packet.AUTH_RESP:
            print('Non-authoritative response')
        print('%s' % ' | '.join(hdrs))
        for answer in data['Answers']:
            print('\t| '.join(str(i) for i in answer.values()))
        print()


def dnsing(host, types, addr, allowtcp=False, recursive=True):
    params = {'Name': host,
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
        packet = Packet.DNSPacket(tcp=allowtcp)
        params['Type'] = wtype.upper()
        packet.addField('Queries', params)
        if not recursive:
            packet.flags(~Packet.RECURSIVE)
        #print(packet.getRawData())
        answer = cli_ask(packet.getRawData())
        beautifulpacket(Packet.DNSPacket(answer, tcp=allowtcp).getParsedData())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-R', action='store_false', dest='recur', help='Disable recursion')
    parser.add_argument('-T', action='store_true', dest='tcp', help='Use TCP')
    parser.add_argument('-s', action='store', dest='dnsserv', help='DNS server', default='8.8.8.8')
    parser.add_argument('-t', action='store', dest='types', help='Type(s) of DNS record', \
        choices=['A',  'AAAA', 'NS', 'TXT', 'MX', 'CNAME'], nargs='+', default=['A'])
    parser.add_argument('host', action='store', help='Host name')
    args = parser.parse_args()
    #print(vars(args))
    dnsing(args.host, args.types, args.dnsserv, allowtcp=args.tcp, recursive=args.recur)


if __name__ == '__main__':
    main()