import unittest
import socket as s
from Client import dnsing


class DNSTest(unittest.TestCase):

    def setUp(self):
        self.host = 'vk.com'
        self.timeout = 3
        self.ips = s.gethostbyname_ex(self.host)[2]

    def assrt(self, resp):
        self.assertTrue(resp[0]['Answers'][0]['Address'] in self.ips)

    def test_dns_default(self):
        self.assrt(dnsing(self.host, ['A'], '8.8.8.8'))

    def test_dns_tcp_recursive(self):
        self.assrt(dnsing(self.host, ['A'], '8.8.8.8', 
            tcp=True, recursive=True))

    def test_dns_error_too_small_timeout(self):
        with self.assertRaises(s.timeout):
            dnsing(self.host, ['A'], '8.8.8.8', timeout=0.0001)

    def test_dns_timeout_error_by_wrong_port(self):
        with self.assertRaises(s.timeout):
            dnsing(self.host, ['A'], '8.8.8.8', port=54321)
