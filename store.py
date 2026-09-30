import hashlib, hmac, json, re, secrets, sqlite3, threading, time
from pathlib import Path
from contextlib import contextmanager

class Problem(Exception):
    def __init__(self, status, message): self.status,self.message=status,message

def token_hash(value): return hashlib.sha256(value.encode()).hexdigest()
def clean_name(value, maximum=48):
    if not isinstance(value,str): raise Problem(400,'Введите имя.')
    value=' '.join(value.split())
    if not 1<=len(value)<=maximum or any(not (c.isalnum() or c in ' ._-()') for c in value):
        raise Problem(400,'Имя: буквы, цифры, пробел, точка, дефис; до '+str(maximum)+' символов.')
    return value

class Store:
    def __init__(self,path,adapter):
        self.path,self.adapter=str(path),adapter;self.lock=threading.RLock()
        Path(self.path).parent.mkdir(parents=True,exist_ok=True)
        with self.db() as db:
            db.executescript('''
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS invitations(id TEXT PRIMARY KEY,token_hash TEXT UNIQUE NOT NULL,raw_token TEXT NOT NULL,label TEXT NOT NULL,quota INTEGER NOT NULL CHECK(quota BETWEEN 1 AND 1000),active INTEGER NOT NULL DEFAULT 1,created INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS issues(id TEXT PRIMARY KEY,invitation TEXT NOT NULL REFERENCES invitations(id),request_id TEXT NOT NULL,name TEXT NOT NULL,device TEXT NOT NULL,ip TEXT NOT NULL,public_key TEXT NOT NULL,state TEXT NOT NULL,payload TEXT NOT NULL,created INTEGER NOT NULL,UNIQUE(invitation,request_id));
            ''')
        Path(self.path).chmod(0o600)
    @contextmanager
    def db(self):
        db=sqlite3.connect(self.path,timeout=45);db.row_factory=sqlite3.Row;db.execute('PRAGMA foreign_keys=ON')
        try:
            with db:yield db
        finally:db.close()
    def invitation(self,db,token):
        row=db.execute('SELECT * FROM invitations WHERE token_hash=?',(token_hash(token),)).fetchone()
        if row is None or not row['active']: raise Problem(404,'Ссылка недействительна или отключена.')
        return row
    def info(self,token):
        with self.db() as db:
            row=self.invitation(db,token);used=db.execute('SELECT count(*) FROM issues WHERE invitation=?',(row['id'],)).fetchone()[0]
            return {'remaining':max(0,row['quota']-used),'quota':row['quota'],'label':row['label']}
    def received(self,token):
        with self.db() as db:
            inv=self.invitation(db,token)
            rows=db.execute("SELECT payload FROM issues WHERE invitation=? AND state='active' ORDER BY created DESC",(inv['id'],)).fetchall()
            return {'keys':[{k:json.loads(r['payload'])[k] for k in ('name','device','vpn','conf')} for r in rows]}
    def create(self,label,quota):
        label=clean_name(label,64)
        if type(quota) is not int or not 1<=quota<=1000: raise Problem(400,'Лимит должен быть от 1 до 1000.')
        token=secrets.token_urlsafe(32);ident=secrets.token_hex(12)
        with self.db() as db:db.execute('INSERT INTO invitations VALUES(?,?,?,?,?,1,?)',(ident,token_hash(token),token,label,quota,int(time.time())))
        return {'id':ident,'token':token,'quota':quota,'label':label}
    def listing(self):
        with self.db() as db:
            links=[dict(r) for r in db.execute('SELECT i.id,i.raw_token token,i.label,i.quota,i.active,i.created,count(k.id) used FROM invitations i LEFT JOIN issues k ON k.invitation=i.id GROUP BY i.id ORDER BY i.created DESC')]
            keys=[dict(r) for r in db.execute('SELECT id,invitation,name,device,ip,state,created FROM issues ORDER BY created DESC')]
        return {'links':links,'keys':keys}
    def disable(self,ident):
        with self.lock,self.db() as db:
            if db.execute('UPDATE invitations SET active=0 WHERE id=?',(ident,)).rowcount!=1: raise Problem(404,'Ссылка не найдена.')
    def issue(self,token,name,device,request_id):
        name=clean_name(name)
        if device not in ('P','G','M'): raise Problem(400,'Выберите устройство.')
        if not isinstance(request_id,str) or not re.fullmatch(r'[a-f0-9-]{32,36}',request_id): raise Problem(400,'Некорректный номер запроса.')
        full_name=name+' ['+device+']'
        with self.lock:
            with self.db() as db:
                db.execute('BEGIN IMMEDIATE');inv=self.invitation(db,token)
                row=db.execute('SELECT * FROM issues WHERE invitation=? AND request_id=?',(inv['id'],request_id)).fetchone()
                if row:
                    if row['name']!=full_name or row['device']!=device: raise Problem(409,'Этот запрос уже использован с другим именем или устройством.')
                    if row['state'] in ('revoking','revoked'): raise Problem(410,'Этот ключ отозван.')
                    item=json.loads(row['payload']);ident=row['id']
                else:
                    used=db.execute('SELECT count(*) FROM issues WHERE invitation=?',(inv['id'],)).fetchone()[0]
                    if used>=inv['quota']: raise Problem(409,'Все ключи по этой ссылке уже выданы.')
                    reserved=[r[0] for r in db.execute('SELECT ip FROM issues WHERE state!=?',('revoked',))]
                    item=self.adapter.prepare(full_name,device,reserved);ident=secrets.token_hex(16)
                    db.execute('INSERT INTO issues VALUES(?,?,?,?,?,?,?,?,?,?)',(ident,inv['id'],request_id,full_name,device,item['ip'],item['public_key'],'pending',json.dumps(item),int(time.time())))
                # Reservation is durable before touching the VPN. Crash retries reuse it.
            if not row or row['state']=='pending':
                self.adapter.apply(item)
                with self.db() as db:db.execute('UPDATE issues SET state=? WHERE id=?',('active',ident))
            return {k:item[k] for k in ('name','device','conf','vpn')} | {'id':ident,'remaining':self.info(token)['remaining']}
    def revoke(self,ident):
        with self.lock:
            with self.db() as db:
                row=db.execute('SELECT * FROM issues WHERE id=?',(ident,)).fetchone()
                if row is None:raise Problem(404,'Ключ не найден.')
                if row['state']=='revoked':return
                item=json.loads(row['payload']);db.execute('UPDATE issues SET state=? WHERE id=?',('revoking',ident))
            self.adapter.remove(item)
            with self.db() as db:db.execute('UPDATE issues SET state=?,payload=? WHERE id=?',('revoked','{}',ident))
    def recover(self):
        with self.lock:
            with self.db() as db:pending=[dict(r) for r in db.execute("SELECT * FROM issues WHERE state IN ('pending','revoking')")]
            for row in pending:
                item=json.loads(row['payload'])
                if row['state']=='pending':
                    self.adapter.apply(item)
                    with self.db() as db:db.execute("UPDATE issues SET state='active' WHERE id=?",(row['id'],))
                else:self.revoke(row['id'])
