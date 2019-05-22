usage: Client.py [-h] [-r] [-T] [-o TIMEOUT] [-p PORT] [-d] [-s DNSSERV]
                 [-t {A,AAAA,NS,TXT,MX,CNAME} [{A,AAAA,NS,TXT,MX,CNAME} ...]]
                 host

positional arguments:
  host                  Host name

optional arguments:
  -h, --help            show this help message and exit
  -r, --recursive       Recursive query
  -T                    Use TCP
  -o TIMEOUT, --timeout TIMEOUT
                        Timeout
  -p PORT               Port
  -d, --debug           Debug-mode
  -s DNSSERV            DNS server
  -t {A,AAAA,NS,TXT,MX,CNAME} [{A,AAAA,NS,TXT,MX,CNAME} ...]
                        Type(s) of DNS record
