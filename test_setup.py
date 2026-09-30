import unittest,base64,json,zlib
from install import hostname,free_domain
from awg import AWG
class Adapter(AWG):
 def snapshot(self):return '[Interface]\n',dict(Address='10.8.1.0/24',ListenPort='12345',PrivateKey='server',Jc='4',S1='29',S2='15',S3='18',S4='0',H1='1',H2='2',H3='3',H4='4')
 def cmd(self,*args,data=None):return 'test-key\n'
class SetupTests(unittest.TestCase):
 def test_domain_validation(self):
  self.assertEqual(hostname('VPN.Example.com'),'vpn.example.com')
  for bad in ['https://x.com','x.com/path','x.com;bad','-a.com','1.2.3.4','a..com']:
   with self.assertRaises(ValueError):hostname(bad)
 def test_free_domain(self):
  self.assertEqual(free_domain('8.8.8.8','sslip.io'),'am-8-8-8-8.sslip.io')
  with self.assertRaises(ValueError):free_domain('127.0.0.1','sslip.io')
 def test_domain_in_export(self):
  item=Adapter('test','vpn.example.com').prepare('Name [M]','M',[])
  self.assertIn('Endpoint = vpn.example.com:12345',item['conf'])
  enc=item['vpn'][6:];raw=base64.urlsafe_b64decode(enc+'='*(-len(enc)%4));data=zlib.decompress(raw[4:]);self.assertEqual(len(data),int.from_bytes(raw[:4],'big'))
  value=json.loads(data);self.assertEqual(value['hostName'],'vpn.example.com')
  last=json.loads(value['containers'][0]['awg']['last_config']);self.assertEqual(last['hostName'],'vpn.example.com');self.assertEqual(last['config'],item['conf'])
if __name__=='__main__':unittest.main()
