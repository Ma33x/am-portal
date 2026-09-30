"""Docker AmneziaWG 2 adapter. No user-supplied text is executed by a shell."""
import base64, ipaddress, json, re, subprocess, zlib
from datetime import datetime

FIELDS = ('Jc','Jmin','Jmax','S1','S2','S3','S4','H1','H2','H3','H4','I1','I2','I3','I4','I5')
class AWG:
    def __init__(self, container, endpoint):
        self.container, self.endpoint = container, endpoint
    def cmd(self, *args, data=None):
        p = subprocess.run(['docker','exec','-i',self.container,*args], input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=25)
        if p.returncode: raise RuntimeError('VPN command failed')
        return p.stdout.decode()
    def read(self, name):
        return self.cmd('cat','/opt/amnezia/awg/'+name)
    def write(self, name, text):
        assert name in ('awg0.conf','clientsTable')
        # The command contains only constant file names, never a client name.
        path='/opt/amnezia/awg/'+name
        self.cmd('sh','-c',f'umask 077; cat > {path}.portal-new && mv -f {path}.portal-new {path}',data=text.encode())
    def snapshot(self):
        conf=self.read('awg0.conf')
        values={}
        for line in conf.split('[Peer]')[0].splitlines():
            line=line.strip()
            if line.startswith('# I'): line=line[2:]
            if '=' in line:
                k,v=line.split('=',1);values[k.strip()]=v.strip()
        if not all(k in values for k in ('Address','ListenPort','PrivateKey')): raise RuntimeError('Invalid server config')
        return conf, values
    def prepare(self, name, device, reserved):
        conf,v=self.snapshot()
        network=ipaddress.ip_interface(v['Address'].split(',')[0].strip()).network
        used={ipaddress.ip_interface(v['Address'].split(',')[0].strip()).ip}
        for s in re.findall(r'(?m)^AllowedIPs\s*=\s*(.+)$',conf):
            for p in s.split(','):
                n=ipaddress.ip_network(p.strip(),strict=False)
                if n.version==4: used.update(n)
        used.update(ipaddress.ip_address(x) for x in reserved)
        available=next((str(x) for x in network.hosts() if x not in used),None)
        if available is None: raise RuntimeError('Address pool full')
        private=self.cmd('awg','genkey').strip()
        public=self.cmd('awg','pubkey',data=(private+'\n').encode()).strip()
        psk=self.cmd('awg','genpsk').strip()
        server=self.cmd('awg','pubkey',data=(v['PrivateKey']+'\n').encode()).strip()
        ob={k:v[k] for k in FIELDS if v.get(k)}
        text='[Interface]\nAddress = '+available+'/32\nDNS = 1.1.1.1, 1.0.0.1\nPrivateKey = '+private+'\nMTU = 1376\n'
        text+=''.join(k+' = '+val+'\n' for k,val in ob.items())
        text+='\n[Peer]\nPublicKey = '+server+'\nPresharedKey = '+psk+'\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = '+self.endpoint+':'+v['ListenPort']+'\nPersistentKeepalive = 25\n'
        last={**ob,'allowed_ips':['0.0.0.0/0','::/0'],'clientId':public,'client_ip':available,'client_priv_key':private,'client_pub_key':public,'config':text,'hostName':self.endpoint,'mtu':'1376','persistent_keep_alive':'25','port':int(v['ListenPort']),'psk_key':psk,'server_pub_key':server}
        awg={**ob,'last_config':json.dumps(last,ensure_ascii=False)+'\n','port':v['ListenPort'],'protocol_version':'2','subnet_address':str(network.network_address),'transport_proto':'udp'}
        payload={'containers':[{'awg':awg,'container':self.container}],'defaultContainer':self.container,'description':name,'dns1':'1.1.1.1','dns2':'1.0.0.1','hostName':self.endpoint,'nameOverriddenByUser':True}
        raw=json.dumps(payload,ensure_ascii=False,separators=(',',':')).encode()
        link='vpn://'+base64.urlsafe_b64encode(len(raw).to_bytes(4,'big')+zlib.compress(raw)).decode().rstrip('=')
        return {'name':name,'device':device,'ip':available,'public_key':public,'psk':psk,'conf':text,'vpn':link}
    def apply(self, item):
        conf,_=self.snapshot();public=item['public_key']
        if public not in re.findall(r'(?m)^PublicKey\s*=\s*(\S+)',conf):
            conf=conf.rstrip()+'\n\n[Peer]\nPublicKey = '+public+'\nPresharedKey = '+item['psk']+'\nAllowedIPs = '+item['ip']+'/32\n'
            self.write('awg0.conf',conf)
        table=json.loads(self.read('clientsTable'))
        if not isinstance(table,list): raise RuntimeError('Invalid clients table')
        if not any(x.get('clientId')==public for x in table):
            table.append({'clientId':public,'userData':{'clientName':item['name'],'creationDate':datetime.now().strftime('%a %b %d %H:%M:%S %Y')}})
            self.write('clientsTable',json.dumps(table,ensure_ascii=False,indent=4)+'\n')
        self.cmd('awg','set','awg0','peer',public,'preshared-key','/dev/stdin','allowed-ips',item['ip']+'/32',data=(item['psk']+'\n').encode())
    def remove(self,item):
        conf,_=self.snapshot();parts=re.split(r'(?m)^\[Peer\]\s*$',conf)
        kept=[p for p in parts[1:] if not re.search(r'(?m)^PublicKey\s*=\s*'+re.escape(item['public_key'])+r'\s*$',p)]
        self.write('awg0.conf',parts[0].rstrip()+'\n'+''.join('\n[Peer]\n'+p.strip()+'\n' for p in kept))
        table=json.loads(self.read('clientsTable'))
        self.write('clientsTable',json.dumps([x for x in table if x.get('clientId')!=item['public_key']],ensure_ascii=False,indent=4)+'\n')
        self.cmd('awg','set','awg0','peer',item['public_key'],'remove')
