import io,json,os,secrets,time,threading
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
import hmac
from awg import AWG
from store import Store,Problem

BASE=Path(__file__).parent
CONFIG=json.loads(Path(os.environ.get('PORTAL_CONFIG','/etc/am-portal/config.json')).read_text())
os.umask(0o077)
store=Store(CONFIG['database'],AWG(CONFIG['container'],CONFIG['endpoint']))
# Finish any interrupted issuance/revocation before serving new requests.
store.recover()
limits={};rate_lock=threading.Lock()
class Handler(BaseHTTPRequestHandler):
    server_version='ART1'
    def log_message(self,*args):pass
    def send(self,status,content,kind='application/json; charset=utf-8'):
        if isinstance(content,dict):content=json.dumps(content,ensure_ascii=False).encode()
        elif isinstance(content,str):content=content.encode()
        self.send_response(status)
        for k,v in {'Content-Type':kind,'Content-Length':str(len(content)),'Cache-Control':'no-store','Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' blob: data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'",'Permissions-Policy':'camera=(), microphone=(), geolocation=()'}.items():self.send_header(k,v)
        self.end_headers();self.wfile.write(content)
    def auth(self,admin=False):
        if admin:
            allowed=set(CONFIG.get('admin_ips',[]))
            # Only the loopback nginx proxy may supply the client IP.
            addresses=self.headers.get_all('X-Real-IP',[])
            if allowed and (self.client_address[0]!='127.0.0.1' or len(addresses)!=1 or addresses[0] not in allowed):
                raise Problem(403,'Мастер-доступ разрешён только с IP владельца или его VPN.')
        raw=self.headers.get('Authorization','')
        if not raw.startswith('Bearer ') or not 32<=len(raw[7:])<=120:raise Problem(401,'Нужна секретная ссылка.')
        token=raw[7:]
        if admin and not hmac.compare_digest(token,CONFIG['master_token']):raise Problem(403,'Нет доступа.')
        return token
    def data(self):
        if self.headers.get('Origin')!=CONFIG['origin']:raise Problem(403,'Недопустимый источник запроса.')
        if self.headers.get('Content-Type','').split(';')[0]!='application/json':raise Problem(415,'Ожидается JSON.')
        try:n=int(self.headers.get('Content-Length','0'))
        except ValueError:raise Problem(400,'Некорректный запрос.')
        if not 1<=n<=16384:raise Problem(413,'Слишком большой запрос.')
        try:
            result=json.loads(self.rfile.read(n))
            if not isinstance(result,dict):raise ValueError()
            return result
        except (ValueError,UnicodeDecodeError):raise Problem(400,'Некорректный запрос.')
    def rate(self):
        ip=self.headers.get('X-Real-IP',self.client_address[0]);now=time.monotonic()
        with rate_lock:
            if len(limits)>2000:
                for k in list(limits):
                    if now-limits[k][0]>60:limits.pop(k)
            start,count=limits.get(ip,(now,0))
            if now-start>=60:start,count=now,0
            if count>=120:raise Problem(429,'Слишком много запросов. Подождите минуту.')
            limits[ip]=(start,count+1)
    def do_GET(self):self.dispatch(False)
    def do_POST(self):self.dispatch(True)
    def dispatch(self,post):
        try:
            self.rate();path=self.path.split('?',1)[0]
            if not post and path in ('/access/','/access/app.js','/access/style.css'):
                file,kind={'/access/':('index.html','text/html; charset=utf-8'),'/access/app.js':('app.js','text/javascript; charset=utf-8'),'/access/style.css':('style.css','text/css; charset=utf-8')}[path]
                return self.send(200,(BASE/file).read_bytes(),kind)
            if not path.startswith('/access/api/'):raise Problem(404,'Не найдено.')
            if path.startswith('/access/api/master/'):
                self.auth(True)
                if not post and path.endswith('/list'):return self.send(200,store.listing())
                d=self.data() if post else {}
                if post and path.endswith('/create'):return self.send(201,store.create(d.get('label'),d.get('quota')))
                if post and path.endswith('/disable'):store.disable(d.get('id'));return self.send(200,{'ok':True})
                if post and path.endswith('/revoke'):store.revoke(d.get('id'));return self.send(200,{'ok':True})
            else:
                token=self.auth()
                if not post and path=='/access/api/received':return self.send(200,store.received(token))
                if not post and path=='/access/api/info':return self.send(200,store.info(token))
                if post and path=='/access/api/issue':
                    d=self.data();return self.send(200,store.issue(token,d.get('name'),d.get('device'),d.get('request_id')))
                if post and path=='/access/api/qr':
                    d=self.data();store.info(token)
                    import qrcode
                    text=d.get('text','')
                    if not isinstance(text,str) or not text.startswith('vpn://') or len(text)>6000:raise Problem(400,'Некорректный ключ.')
                    out=io.BytesIO();qrcode.make(text).save(out,format='PNG')
                    return self.send(200,out.getvalue(),'image/png')
            raise Problem(404,'Не найдено.')
        except Problem as e:self.send(e.status,{'error':e.message})
        except (BrokenPipeError,ConnectionResetError):pass
        except Exception as e:
            print('Request failed:',type(e).__name__,flush=True)
            self.send(503,{'error':'Не удалось завершить выдачу. Повторите запрос: повтор не списывает ещё один ключ.'})
if __name__=='__main__':
    ThreadingHTTPServer(('127.0.0.1',CONFIG.get('port',8792)),Handler).serve_forever()
