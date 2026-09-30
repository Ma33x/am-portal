#!/usr/bin/env python3
"""Interactive installer for an existing AmneziaWG 2 Docker server."""
import ipaddress,json,os,re,secrets,shutil,socket,subprocess,sys,time
from pathlib import Path

def run(*args,**kw):
    return subprocess.run(args,check=True,text=True,**kw)
def hostname(value):
    value=value.strip().lower().rstrip('.')
    if len(value)>253 or '.' not in value or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',p) for p in value.split('.')):
        raise ValueError('Введите домен без https://, пути и порта.')
    try:ipaddress.ip_address(value)
    except ValueError:return value
    raise ValueError('Нужен домен, а не IP.')
def free_domain(ip,provider):
    address=ipaddress.IPv4Address(ip)
    if not address.is_global:raise ValueError('Нужен публичный IPv4 сервера.')
    if provider not in ('sslip.io','nip.io'):raise ValueError('Неизвестный DNS-сервис')
    return 'am-'+str(address).replace('.','-')+'.'+provider

def main():
    if os.geteuid()!=0:raise RuntimeError('Запустите sudo python3 install.py')
    if not shutil.which('apt-get') or not shutil.which('systemctl'):raise RuntimeError('Нужен Ubuntu 24.04 / Debian 12 с systemd.')
    cfg=Path('/etc/am-portal/config.json')
    if cfg.exists():raise RuntimeError('Портал уже установлен. Обновление: см. README. Установщик не перезаписывает ключи.')
    print('AM Portal — портал для вашего установленного AmneziaWG 2')
    print('1 — свой домен; 2 — бесплатный sslip.io; 3 — бесплатный nip.io')
    choice=input('Выбор [2]: ').strip() or '2'
    if choice not in ('1','2','3'):raise ValueError('Выберите 1, 2 или 3')
    ip=str(ipaddress.IPv4Address(input('Публичный IPv4 этого сервера: ').strip()))
    if not ipaddress.ip_address(ip).is_global:raise ValueError('Нужен публичный IPv4')
    domain=hostname(input('Домен (A-запись уже должна указывать на сервер): ')) if choice=='1' else free_domain(ip,{'2':'sslip.io','3':'nip.io'}[choice])
    if choice!='1':print('Бесплатный адрес привязан к IP. При смене IP потребуется новый адрес и повторный импорт ключей.')
    addresses={x[4][0] for x in socket.getaddrinfo(domain,None)}
    if addresses!={ip}:raise ValueError(f'DNS {domain}: {addresses}. Оставьте только A-запись {ip}, уберите неподключённый AAAA.')
    container=input('Docker-контейнер [amnezia-awg2]: ').strip() or 'amnezia-awg2'
    if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]*',container):raise ValueError('Некорректное имя контейнера')
    run('docker','exec',container,'awg','show','awg0',stdout=subprocess.DEVNULL)
    run('docker','exec',container,'test','-f','/opt/amnezia/awg/clientsTable')
    from awg import AWG
    AWG(container,domain).snapshot()
    email=input('Email для сертификата HTTPS: ').strip()
    if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+',email):raise ValueError('Некорректный email')
    admin=[str(ipaddress.ip_address(x.strip())) for x in input('IP для мастер-доступа через запятую (пусто — только секретная ссылка): ').split(',') if x.strip()]
    for port in (8792,):
        with socket.socket() as s:s.bind(('127.0.0.1',port))
    # Refuse a conflicting virtual host; never replace another site's configuration.
    for folder in ('/etc/nginx/sites-enabled','/etc/nginx/conf.d'):
        if Path(folder).exists():
            for p in Path(folder).iterdir():
                if p.is_file() and domain in p.read_text(errors='replace'):raise RuntimeError(f'Домен уже настроен в {p}. Используйте отдельный поддомен.')
    print(f'Портал: https://{domain}/access/\nНужны входящие TCP 80,443 и существующий UDP-порт AWG. Принимаются условия Let’s Encrypt.')
    if input('Установить? [yes/no]: ').strip().lower()!='yes':return
    os.umask(0o077)
    run('apt-get','update')
    run('apt-get','install','-y','nginx','certbot','python3-qrcode','python3-pil',env={**os.environ,'DEBIAN_FRONTEND':'noninteractive','NEEDRESTART_MODE':'l'})
    source=Path(__file__).resolve().parent;target=Path('/opt/am-portal');target.mkdir(exist_ok=True)
    for name in ('server.py','store.py','awg.py','index.html','app.js','style.css','landing.html'):shutil.copyfile(source/name,target/name)
    cfg.parent.mkdir(mode=0o700,exist_ok=True);Path('/var/lib/am-portal').mkdir(mode=0o700,exist_ok=True)
    token=secrets.token_urlsafe(48)
    cfg.write_text(json.dumps(dict(database='/var/lib/am-portal/portal.sqlite',container=container,endpoint=domain,origin='https://'+domain,master_token=token,admin_ips=admin,port=8792),indent=2)+'\n');cfg.chmod(0o600)
    Path('/etc/systemd/system/am-portal.service').write_text('''[Unit]
Description=Amnezia key portal
After=network-online.target docker.service
Requires=docker.service
[Service]
WorkingDirectory=/opt/am-portal
ExecStart=/usr/bin/python3 /opt/am-portal/server.py
Restart=on-failure
RestartSec=4
UMask=0077
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/am-portal
[Install]
WantedBy=multi-user.target
''')
    webroot=Path('/var/www/am-portal-acme');webroot.mkdir(parents=True,exist_ok=True);webroot.chmod(0o755)
    landing=Path('/var/www/am-portal');landing.mkdir(exist_ok=True);landing.chmod(0o755)
    shutil.copyfile(source/'landing.html',landing/'index.html');(landing/'index.html').chmod(0o644)
    site=Path('/etc/nginx/sites-available/am-portal');enabled=Path('/etc/nginx/sites-enabled/am-portal')
    if site.exists() or enabled.exists():raise RuntimeError('Конфигурация nginx am-portal уже существует')
    http=f'''server {{
 listen 80;
 server_name {domain};
 location /.well-known/acme-challenge/ {{ root {webroot}; }}
 location / {{ return 301 https://{domain}$request_uri; }}
}}
'''
    site.write_text(http);enabled.symlink_to(site)
    run('nginx','-t');run('systemctl','enable','--now','nginx');run('systemctl','reload','nginx')
    # No public portal or credentials before a valid certificate is obtained.
    run('certbot','certonly','--webroot','-w',str(webroot),'-d',domain,'--email',email,'--agree-tos','--non-interactive')
    site.write_text(http+f'''server {{
 listen 443 ssl;
 server_name {domain};
 ssl_certificate /etc/letsencrypt/live/{domain}/fullchain.pem;
 ssl_certificate_key /etc/letsencrypt/live/{domain}/privkey.pem;
 ssl_protocols TLSv1.2 TLSv1.3;
 access_log off;
 error_log /var/log/nginx/am-portal-error.log crit;
 location = / {{ root /var/www/am-portal; try_files /index.html =404; }}
 location = /access {{ return 302 /access/; }}
 location /access/ {{
  proxy_pass http://127.0.0.1:8792;
  proxy_set_header Host $host;
  proxy_set_header X-Real-IP $remote_addr;
  client_max_body_size 16k;
  proxy_read_timeout 90s;
 }}
 location / {{ return 404; }}
}}
''')
    hook=Path('/etc/letsencrypt/renewal-hooks/deploy/am-portal');hook.parent.mkdir(parents=True,exist_ok=True)
    hook.write_text('#!/bin/sh\nnginx -t && systemctl reload nginx\n');hook.chmod(0o700)
    run('nginx','-t');run('systemctl','daemon-reload');run('systemctl','enable','--now','am-portal');run('systemctl','reload','nginx');run('systemctl','enable','--now','certbot.timer')
    import urllib.request
    for attempt in range(15):
        try:
            with urllib.request.urlopen('https://'+domain+'/access/',timeout=10) as response:assert response.status==200
            break
        except Exception:
            if attempt==14:raise
            time.sleep(1)
    print('\nГотово. Сохраните мастер-ссылку:\nhttps://'+domain+'/access/#m/'+token)
if __name__=='__main__':
    try:main()
    except (ValueError,RuntimeError,OSError,subprocess.CalledProcessError) as e:
        print('Установка остановлена:',e,file=sys.stderr);sys.exit(1)
