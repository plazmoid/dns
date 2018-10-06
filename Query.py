#coding:utf-8
import socket as s
import traceback
from enum import Enum
from Packet import DNSPacket

ROOT_DNS = '199.7.83.42' #l.rootservers.net

class Response(Enum):
    FULL = 0
    PART = 1
    EMPTY = 2

class DNSQuery():
    #рекурсия
    def __init__(self, data, dnsserv=None):
        self.data = data
        if dnsserv == None: 
            self.dnsserv = ROOT_DNS
        else:
            self.dnsserv = dnsserv
        self.status = 0
        self.finalAddrs = []
        self.addrs_to_next_qry = []
        self.answer = None
        self.main()
        
    def main(self):
        self.answer = self.resolve(self.data)
        #self.printStartInf()
        self.status = self.ansParser()
        #print('Status:', self.status)
        if self.status == Response.EMPTY:
            return
        elif self.status == Response.PART:
            for newserv in self.addrs_to_next_qry:
                try:
                    self.new_res = DNSQuery(self.data, newserv)
                    self.new_ans = self.new_res.getAnswer().getParsedData('Answers')
                    if len(self.new_ans) > 0:
                        self.finalAddrs.extend(self.new_ans)
                        break
                except:
                    print('Got an error in main loop:')
                    traceback.print_exc()
                    continue
        self.answer.removeField('Additional records')
        self.answer.removeField('Authoritative NS')
        self.cnames = []
        for i in self.finalAddrs:
            if i['Type'] == 'CNAME':
                self.answer.addField('Answers', self.answer.getParsedData('Queries')[0]['Name'], i['Type'], i['CNAME'], i['TTL'])
                self.cnames.append(i['CNAME'])
            else:
                self.answer.addField('Answers', self.answer.getParsedData('Queries')[0]['Name'], i['Type'], i['Address'], i['TTL'])
        self.names = self.answer.getParsedData('Answers', 'Name')
        for cname in self.cnames:
            if cname not in self.names:
                self.answer.addField('Answers', cname, 'A', self.extraResolving(DNSPacket((cname, 'A')).getRawData(), ['Answers'], 'A')[0], 21600)
                break
        self.answer.serializedata()

    def resolve(self, query):
        with s.socket(s.AF_INET, s.SOCK_DGRAM, s.IPPROTO_UDP) as nextsrv:
            nextsrv.connect((self.dnsserv, 53))
            nextsrv.send(query)
            #nextsrv.settimeout(0.2)
            self.ans, _ = nextsrv.recvfrom(1024)
            return DNSPacket(self.ans)
            
    def ansParser(self):
        if self.answer == None:
            return Response.EMPTY
        self.parsed = self.answer.getParsedData()
        if len(self.parsed['Answers']) > 0:
            return Response.FULL
        self.addrs_to_next_qry.extend(self.answer.getParsedData('Additional records', 'Address', 'Type', 'A'))
        if len(self.addrs_to_next_qry) == 0:
            for i in self.answer.getParsedData('Authoritative NS', 'Name server', 'Type', 'NS'):
                try:
                    self.addrs_to_next_qry.extend(self.extraResolving(DNSPacket((i, 'A')).getRawData(), ['Answers', 'Additional records'], 'A'))
                    if len(self.addrs_to_next_qry) > 0:
                        break
                except Exception as e:
                    print('Got error in parser:', e)
                    continue
            else:
                return Response.EMPTY
        return Response.PART
    
    def extraResolving(self, bPacket, fields, qtype):
        #print('EXTRA-RESOLVING:', )
        self.nsres = DNSQuery(bPacket).getAnswer()
        for field in fields:
            self.temp = self.nsres.getParsedData(field, 'Address', 'Type', qtype)
            if len(self.temp) > 0:
                return self.temp
        return []
    
    def printStartInf(self):
        print('******New******:',  self.dnsserv)
        for k,v in self.answer.getParsedData().items():
            if k != 'ID' and k != 'Flags':
                print(k+':', end='\n ')
                print('\n '.join(str(i) for i in v))
            print()
    
    def getAnswer(self):
        return self.answer