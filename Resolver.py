import socket as s
import threading
import traceback
import time
from Cache import DNSCache
from Packet import DNSPacket
from Query import DNSQuery

RECV_BUFF = 1024
CACHE = DNSCache()

class CacheChecker(threading.Thread):
    
    def __init__(self):
        threading.Thread.__init__(self)
        self.end = False
        self.start()
        
    def run(self):
        while not self.end:
            CACHE.controls('TTL')
            time.sleep(5)
    
    def die(self):
        self.end = True
        CACHE.controls('close')

class Resolver(threading.Thread):
    
    def __init__(self, data, sender=None, addr=None):
        threading.Thread.__init__(self)
        self.data = data
        self.sender = sender
        self.addr = addr
        self.start()
        
    def run(self):
        try:
            print('------>Start\n', self.data)
            self.resolved = self.cacheOrQuery(self.data)
            self.printResolved()
            self.sender.sendto(self.resolved.getRawData(), self.addr)
        except:
            traceback.print_exc()
            
    def cacheOrQuery(self, data): #TODO: CNAME неверно сериализуются
        self.cacheqry = None #self.searchInCache(data)
        if self.cacheqry != [] and self.cacheqry != None:
            print('FROMCACHE')
            self.ret = DNSPacket(data[:2]+b'\x80\x00'+self.cacheqry[0])
            print('\t', self.ret.getRawData(), '\n\t', self.ret.getParsedData())
            return self.ret
        print('FROMDNS')
        self.ret = DNSQuery(data).getAnswer()
        #CACHE.controls('store', self.ret.getRawData()[4:], self.ret.getParsedData('Answers', 'TTL')[0])
        return self.ret
            
    def searchInCache(self, q):
        return CACHE.controls('find', (q[12:]))

    def printResolved(self):
        print('RESOLVED:')#, self.data[:2], self.resolved.getParsedData())
        print(self.resolved.getRawData())
        for recs in self.resolved.getParsedData('Answers'):
            print('\t', recs['Name'], recs['Type'], end=' ')
            if recs['Type'] == 'CNAME':
                print(recs['CNAME'])
            elif recs['Type'] == 'A' or recs['Type'] == 'AAAA':
                print(recs['Address'])
            elif recs['Type'] == 'SOA':
                print(recs['Name server'])
        print('***********\n')

class Main(threading.Thread):
    
    def __init__(self):
        threading.Thread.__init__(self)
        try:
            CACHE.start()
            self.checker = CacheChecker()
        except:
            traceback.print_exc()
        self.end = False
        
    def run(self):
        with s.socket(s.AF_INET, s.SOCK_DGRAM, s.IPPROTO_UDP) as serv:
            serv.bind(('127.0.0.1', 53))
            #serv.settimeout(1)
            while not self.end:
                try:
                    data, addr = serv.recvfrom(RECV_BUFF)
                except s.error:
                    continue
                rthr = Resolver(data[:2]+b'\x00'+data[3:], serv, addr)
                rthr.join()

    def die(self):
        self.checker.die()
        self.end = True

def main():
    mprg = Main()
    mprg.start()
    while True:
        inp = str(input())
        if inp == 'exit':
            mprg.die()
            break
        elif inp == 'dump':
            CACHE.controls('rewrite')
        else:
            print('Usage: exit, dump')

if __name__ == '__main__':
    main()