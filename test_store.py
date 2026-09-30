import concurrent.futures,json,tempfile,unittest,uuid
from pathlib import Path
from store import Store,Problem
class Fake:
 def __init__(self):self.count=0;self.peers={};self.fail=False;self.remove_fail=False
 def prepare(self,name,device,reserved):
  self.count+=1
  return {'name':name,'device':device,'ip':'10.8.1.'+str(self.count),'public_key':'pub'+str(self.count),'psk':'test','conf':'test-conf','vpn':'vpn://test'}
 def apply(self,item):
  self.peers[item['public_key']]=item
  if self.fail:self.fail=False;raise RuntimeError('simulated process interruption')
 def remove(self,item):
  if self.remove_fail:self.remove_fail=False;raise RuntimeError('simulated revoke interruption')
  self.peers.pop(item['public_key'],None)
class Tests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.fake=Fake();self.store=Store(Path(self.temp.name)/'db.sqlite',self.fake)
 def link(self,n=1):return self.store.create('Тест',n)['token']
 def test_parallel_quota(self):
  token=self.link(2)
  def one(n):
   try:return self.store.issue(token,'Иван','P',str(uuid.uuid4()))
   except Problem as e:return e.status
  with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:out=list(pool.map(one,range(10)))
  self.assertEqual(sum(isinstance(x,dict) for x in out),2);self.assertEqual(out.count(409),8);self.assertEqual(len(self.fake.peers),2)
 def test_retry_after_failure_and_restart(self):
  token=self.link();req=str(uuid.uuid4());self.fake.fail=True
  with self.assertRaises(RuntimeError):self.store.issue(token,'Мария','M',req)
  other=Store(self.store.path,self.fake);other.recover();r=other.issue(token,'Мария','M',req)
  self.assertEqual(r['name'],'Мария [M]');self.assertEqual(self.fake.count,1);self.assertEqual(other.info(token)['remaining'],0)
 def test_changed_retry(self):
  token=self.link();req=str(uuid.uuid4());self.store.issue(token,'А','P',req)
  with self.assertRaises(Problem):self.store.issue(token,'Б','G',req)
 def test_revoke_does_not_reset_quota(self):
  token=self.link();req=str(uuid.uuid4());r=self.store.issue(token,'Роутер','G',req);self.fake.remove_fail=True
  with self.assertRaises(RuntimeError):self.store.revoke(r['id'])
  self.store.recover();self.assertFalse(self.fake.peers);self.assertEqual(self.store.info(token)['remaining'],0)
  with self.assertRaises(Problem):self.store.issue(token,'Роутер','G',req)
 def test_disable(self):
  d=self.store.create('Тест',2);self.store.disable(d['id'])
  with self.assertRaises(Problem):self.store.issue(d['token'],'Name','P',str(uuid.uuid4()))
 def test_received(self):
  a=self.link();b=self.link();r=self.store.issue(a,'Name','P',str(uuid.uuid4()))
  self.assertEqual(self.store.received(a)['keys'][0]['vpn'],r['vpn'])
  self.assertEqual(self.store.received(b)['keys'],[])
  self.assertEqual(self.store.info(a)['remaining'],0)
  self.store.revoke(r['id']);self.assertEqual(self.store.received(a)['keys'],[])
  d=self.store.create('Disabled',1);self.store.disable(d['id'])
  with self.assertRaises(Problem):self.store.received(d['token'])
  with self.assertRaises(Problem):self.store.received('invalid')
 def test_validation(self):
  for q in [0,-1,1001,True,'5']:
   with self.assertRaises(Problem):self.store.create('Test',q)
  for name in ["';touch /tmp/x;#",'<script>','a'*49,'']:
   with self.assertRaises(Problem):self.store.issue(self.link(),name,'M',str(uuid.uuid4()))
if __name__=='__main__':unittest.main()
