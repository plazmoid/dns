#!/usr/bin/env python
from pprint import pformat
from functools import partial
import Packet
import argparse
import socket as s
import logging

pformat = partial(pformat, indent=1)
logger = logging.getLogger(__name__)


def beautifulpacket(data):
    print()
    hdrs = ['Name', 'Type', 'Class', 'TTL', 'Length', 'Data']
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
        print('%s' % '\t| '.join(hdrs))
        for answer in data['Answers']:
            print('\t| '.join(str(i) for i in answer.values()))
        print()


def dns_request(data, server, timeout, tcp=False):
    if tcp:
        ptype = s.SOCK_STREAM
        proto = s.IPPROTO_TCP

        def recv_at_any_cost(sock, l):
            res = b''
            while len(res) < l:
                res += sock.recv(l - len(res))
            return res
    else:
        ptype = s.SOCK_DGRAM
        proto = s.IPPROTO_UDP

    with s.socket(s.AF_INET, ptype, proto) as sock:
        sock.settimeout(timeout)
        if tcp:
            sock.connect(server)
            sock.send(data)
            datalen = recv_at_any_cost(sock, 2)
            return datalen + recv_at_any_cost(sock, int.from_bytes(datalen, 'big'))
        else:
            sock.sendto(data, server)
            return sock.recv(2048)


def DNSQuery(data, server, port, timeout, tcp=False):
    raw_answer = dns_request(data, (server, port), timeout, tcp=tcp)
    if not raw_answer:
        return
    response = Packet.DNSPacket(raw_answer, tcp=tcp)
    logger.debug('\n>>> {0} \n{1} \n<<< {0} \n{2}'.format(
        server,
        pformat(Packet.DNSPacket(data, tcp=tcp)),
        pformat(response)
    ))
    if len(response['Answers']) > 0:
        return response
    additional = filter(lambda x: x['Type'] == 'A',
                        response['Additional records'])
    for srv in additional:
        add_resp = DNSQuery(data, srv['Address'], port, tcp=tcp)
        if add_resp and len(add_resp['Answers']) > 0:
            return add_resp
    authoritative = filter(
        lambda x: x['Type'] == 'NS', response['Authoritative NS'])
    for srv in authoritative:
        auth_resp = DNSQuery(data, srv['Name server'], port, tcp=tcp)
        if auth_resp and len(auth_resp['Answers']) > 0:
            return auth_resp
    raise Exception('Something very bad happened during the query')


def dnsing(host, types, dnsserv, port=53, timeout=3, tcp=False, recursive=False):
    result = []
    for wtype in types:
        params = {'Name': host,
                  'Class': 'IN'}
        packet = Packet.DNSPacket(tcp=tcp)
        params['Type'] = wtype.upper()
        packet.addField('Queries', params)
        rawdata = packet.getRawData()
        if recursive:
            ans_dict = DNSQuery(rawdata, dnsserv, port, timeout, tcp=tcp)
        else:
            raw_answer = dns_request(
                rawdata, (dnsserv, port), timeout, tcp=tcp)
            ans_dict = Packet.DNSPacket(raw_answer, tcp=tcp)
            logger.debug('\n>>> {0} \n{1} \n\n<<< {0} \n{2}'.format(
                dnsserv,
                pformat(packet),
                pformat(ans_dict)
            ))
        result.append(ans_dict)
        beautifulpacket(ans_dict)
    return result


def main():
    global DEBUG
    parser = argparse.ArgumentParser()
    parser.add_argument('-r', '--recursive', action='store_true',
                        dest='recur', help='Recursive query')
    parser.add_argument('-T', action='store_true', dest='tcp', help='Use TCP')
    parser.add_argument('-o', '--timeout', action='store', dest='timeout',
                        help='Timeout', type=float, default=3)
    parser.add_argument('-p', action='store', dest='port', help='Port', type=int,
                        default=53)
    parser.add_argument('-d', '--debug', action='store_true',
                        dest='debug', help='Debug-mode')
    parser.add_argument('-s', action='store', dest='dnsserv',
                        help='DNS server', default='8.8.8.8')  # l.rootservers.net: '199.7.83.42'
    parser.add_argument('-t', action='store', dest='types', help='Type(s) of DNS record',
                        choices=['A',  'AAAA', 'NS', 'TXT', 'MX', 'CNAME'], nargs='+', default=['A'])
    parser.add_argument('host', action='store', help='Host name')
    args = parser.parse_args()

    log_lvl = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(level=log_lvl)
    dnsing(args.host, args.types, args.dnsserv,
           args.port, args.timeout, tcp=args.tcp, recursive=args.recur)


if __name__ == '__main__':
    main()
