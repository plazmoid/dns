#!/usr/bin/python
from pprint import PrettyPrinter
import Packet
import argparse
import socket as s

DEBUG = False
printer = PrettyPrinter(indent=4)

def beautifulpacket(data):
    print()
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


def dns_request(data, server, tcp=False):
    if tcp:
        ptype = s.SOCK_STREAM
        proto = s.IPPROTO_TCP
    else:
        ptype = s.SOCK_DGRAM
        proto = s.IPPROTO_UDP
        
    with s.socket(s.AF_INET, ptype, proto) as sock:
        sock.settimeout(3)
        if tcp:
            sock.connect(server)
            sock.send(data)
            datalen = sock.recv(2)
            return datalen + sock.recv(int.from_bytes(datalen, 'big'))
        else:
            sock.sendto(data, server)            
            return sock.recv(2048)
        
        
# l.rootservers.net
def DNSQuery(data, server='199.7.83.42', port='53', tcp=False):
    global DEBUG, printer
    raw_answer = dns_request(data, server=(server, port), tcp=tcp)
    if not raw_answer:
        return -2
    response = Packet.DNSPacket(raw_answer, tcp=tcp)
    if DEBUG:
        print('\n>>>', server)
        printer.pprint(Packet.DNSPacket(data, tcp=tcp))
        print('\n<<<', server)
        printer.pprint(response)
    if len(response['Answers']) > 0:
        return response
    additional = filter(lambda x: x['Type'] == 'A', response['Additional records']) 
    for srv in additional:
        add_resp = DNSQuery(data, server=srv['Address'], port=port, tcp=tcp)
        if add_resp and len(add_resp['Answers']) > 0:
            return add_resp
    authoritative = filter(lambda x: x['Type'] == 'NS', response['Authoritative NS']) 
    for srv in authoritative:
        auth_resp = DNSQuery(data, server=srv['Name server'], port=port, tcp=tcp)
        if auth_resp and len(auth_resp['Answers']) > 0:
            return auth_resp
    raise Exception('Something very bad happened during the query')


def dnsing(host, types, dnsserv, port='53', tcp=False, recursive=False):
    global DEBUG, printer
    for wtype in types:
        params = {'Name': host,
                  'Class': 'IN'}
        packet = Packet.DNSPacket(tcp=tcp)
        params['Type'] = wtype.upper()
        packet.addField('Queries', params)
        rawdata = packet.getRawData()
        if recursive:
            if dnsserv == '8.8.8.8':
                ans_dict = DNSQuery(rawdata, port=port, tcp=tcp)
            else:
                ans_dict = DNSQuery(rawdata, server=dnsserv, port=port, tcp=tcp)
        else:
            raw_answer = dns_request(rawdata, (dnsserv, port), tcp=tcp)
            ans_dict = Packet.DNSPacket(raw_answer, tcp=tcp)
            if DEBUG:
                print('\n>>>', dnsserv)
                printer.pprint(packet)
                print('\n<<<', dnsserv)
                printer.pprint(ans_dict)
        return ans_dict


def main():
    global DEBUG
    parser = argparse.ArgumentParser()
    parser.add_argument('-r', '--recursive', action='store_true',
                        dest='recur', help='Recursive query')
    parser.add_argument('-T', action='store_true', dest='tcp', help='Use TCP')
    parser.add_argument('-p', action='store', dest='port', help='Port', type=int, 
                        default=53)
    parser.add_argument('-d', '--debug', action='store_true', dest='debug', help='Debug-mode')
    parser.add_argument('-s', action='store', dest='dnsserv',
                        help='DNS server', default='8.8.8.8')
    parser.add_argument('-t', action='store', dest='types', help='Type(s) of DNS record',
                        choices=['A',  'AAAA', 'NS', 'TXT', 'MX', 'CNAME'], nargs='+', default=['A'])
    parser.add_argument('host', action='store', help='Host name')
    args = parser.parse_args()
    
    DEBUG = args.debug
    beautifulpacket(dnsing(args.host, args.types, args.dnsserv,
           port=args.port, tcp=args.tcp, recursive=args.recur))


if __name__ == '__main__':
    main()
