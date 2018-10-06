import threading
import traceback
import time
from Packet import DNSPacket

CACHEFILE = r'D:\Programs\eclipse\projects\internets\DNS\cache.bin'
TIME_HEAD = b'\x1e\xad\x1d\xd1'
PCKT_SEPARATOR = b'\xff\xff'

class DNSCache(threading.Thread):

    def __init__(self):
        threading.Thread.__init__(self)
        self.__cache = []
        self.locker = threading.Lock()
        
    def run(self):
        try:
            with open(CACHEFILE, 'rb') as fi:
                self.__cache = fi.read().split(PCKT_SEPARATOR)
        except FileNotFoundError:
            open(CACHEFILE, 'xb').close()
        except Exception as e:
            print('Cache reading error:', e)
        
    def controls(self, fnc, *args):
        self.locker.acquire()
        try:
            if fnc == 'TTL':
                self.__clearOnTTL()
            elif fnc == 'close':
                self.__onclose()
            elif fnc == 'store':
                self.__store(args)
            elif fnc == 'find':
                return self.__cfind(args[0])
            elif fnc == 'rewrite':
                self.__rewrite()
            else:
                raise Exception('Unknown cache command: '+fnc)
        except:
            traceback.print_exc()
        finally:
            self.locker.release()
        
    def prnt(self):
        for i in self.__cache:
            print(i)
    
    def __store(self, data):
        self.temp = data[0] + TIME_HEAD + DNSPacket.itob(int(time.time()), 4) + DNSPacket.itob(data[1])
        self.dupl = self.__cfind(data[0][8:data[0].find(b'\x00', 8)])
        if self.dupl != []:
            for j in self.dupl:
                self.__cache.remove(j)
        print('To cache:', str(self.temp))
        self.__cache.append(self.temp)
        
    def __cfind(self, val):
        self.t = time.time()
        self.found = []
        for i in self.__cache:
            self.fnd = i.find(val) 
            if self.fnd != -1:
                self.fnd = i[:i.find(TIME_HEAD)]
                self.found.append(self.fnd)
        print('Searching:', val,'-', self.found, 'in', round(time.time() - self.t, 6))
        return self.found
        
    def __clearOnTTL(self):
        print('Clear on TTL')
        for i in self.__cache:
            self.tm = time.time()
            self.t_offs = i.find(TIME_HEAD)
            if self.tm > DNSPacket.btoi(i[self.t_offs+4:self.t_offs+8]) + \
            DNSPacket.btoi(i[self.t_offs+8:self.t_offs+12]):
                self.__cache.remove(i)
                self.__rewrite()

    def __onclose(self):
        print('Closing...')
        self.__rewrite()
        
    def __rewrite(self):
        with open(CACHEFILE, 'wb') as fo:
            fo.write(PCKT_SEPARATOR.join(self.__cache))
                