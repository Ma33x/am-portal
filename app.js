'use strict';
window.addEventListener('hashchange',()=>location.reload());
const $=id=>document.getElementById(id);
const parts=location.hash.replace(/^#\/?/,'').split('/');
const mode=parts[0],token=parts[1]||'';
const isMaster=mode==='m';let info=null,current=null,qrURL=null;
const storageKey='am-portal-request:'+token;
const show=id=>{for(const key of ['loading','invalid','invite','result','master'])$(key).hidden=key!==id;$('installHelp').hidden=!['invite','result'].includes(id);$('receivedSection').hidden=!['invite','result'].includes(id);};
function toast(text){$('toast').textContent=text;$('toast').hidden=false;setTimeout(()=>$('toast').hidden=true,3000);}
function error(id,text){$(id).textContent=text;$(id).hidden=!text;}
async function api(path,data){
 const r=await fetch('/access/api/'+path,{method:data===undefined?'GET':'POST',headers:{Authorization:'Bearer '+token,...(data===undefined?{}:{'Content-Type':'application/json'})},...(data===undefined?{}:{body:JSON.stringify(data)}),cache:'no-store'});
 const result=await r.json();if(!r.ok){const e=new Error(result.error||'Не удалось выполнить запрос.');e.status=r.status;throw e;}return result;
}
async function copy(text){try{await navigator.clipboard.writeText(text);toast('Скопировано');}catch{toast('Копирование недоступно. Выделите текст и скопируйте вручную.');}}
function newURL(t){return location.origin+'/access/#i/'+t;}
function selectedDevice(){return document.querySelector('input[name="device"]:checked').value;}
function preview(){const name=$('clientName').value.trim()||'Ваше имя';$('namePreview').textContent=name+' ['+selectedDevice()+']';}
$('clientName').addEventListener('input',preview);
for(const r of document.querySelectorAll('input[name="device"]'))r.addEventListener('change',preview);
$('retryLink').addEventListener('click',init);
async function init(){
 show('loading');
 if(!['i','m'].includes(mode)||token.length<32){show('invalid');return;}
 try{
  if(isMaster){document.title='AM PORTAL · Мастер-доступ';$('barTitle').textContent='access-control.exe';await refreshMaster();show('master');}
  else{
   info=await api('info');show('invite');updateQuota();refreshReceived();
   const pending=sessionStorage.getItem(storageKey);
   if(pending){try{const d=JSON.parse(pending);$('clientName').value=d.name;document.querySelector('input[name="device"][value="'+d.device+'"]').checked=true;preview();await issue(d);}catch(e){if(e.status===410){sessionStorage.removeItem(storageKey);error('issueError',e.message);}else error('issueError',e.message);}}
  }
 }catch(e){$('invalidText').textContent=e.message;show('invalid');}
}
function updateQuota(){
 $('remaining').textContent='ОСТАЛОСЬ: '+info.remaining+' / '+info.quota;
 $('exhausted').hidden=info.remaining>0;
 $('issueForm').hidden=info.remaining<=0 && !sessionStorage.getItem(storageKey);
}
function lockForm(locked){$('clientName').disabled=locked;for(const r of document.querySelectorAll('input[name="device"]'))r.disabled=locked;}
async function issue(d){
 $('generate').disabled=true;$('generate').textContent='Готовим подключение…';error('issueError','');lockForm(true);
 try{
  current=await api('issue',d);refreshReceived();info.remaining=current.remaining;show('result');$('resultName').textContent=current.name;$('keyText').value=current.vpn;$('openApp').href=current.vpn;$('routerNote').hidden=current.device!=='G';$('another').hidden=current.remaining<=0;
  $('qr').hidden=true;$('qrLoading').hidden=false;
  try{
   const r=await fetch('/access/api/qr',{method:'POST',headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},body:JSON.stringify({text:current.vpn})});
   if(!r.ok)throw Error('QR');if(qrURL)URL.revokeObjectURL(qrURL);qrURL=URL.createObjectURL(await r.blob());$('qr').src=qrURL;$('qr').hidden=false;$('qrLoading').hidden=true;
  }catch{$('qrLoading').textContent='QR недоступен. Скопируйте ключ.';}
 }catch(e){
  if(e.status && e.status<500){sessionStorage.removeItem(storageKey);lockForm(false);}
  error('issueError',e.message);throw e;
 }finally{$('generate').disabled=false;$('generate').textContent='Создать ключ ↗';}
}
$('issueForm').addEventListener('submit',async e=>{
 e.preventDefault();let d;
 const saved=sessionStorage.getItem(storageKey);
 if(saved)d=JSON.parse(saved);else{d={name:$('clientName').value.trim(),device:selectedDevice(),request_id:crypto.randomUUID()};sessionStorage.setItem(storageKey,JSON.stringify(d));}
 try{await issue(d);}catch{}
});
$('copyKey').addEventListener('click',()=>copy(current.vpn));
$('download').addEventListener('click',()=>{const a=document.createElement('a');const u=URL.createObjectURL(new Blob([current.conf],{type:'text/plain;charset=utf-8'}));a.href=u;a.download='Amnezia-'+current.device+'.conf';a.click();setTimeout(()=>URL.revokeObjectURL(u),1000);});
$('another').addEventListener('click',()=>{sessionStorage.removeItem(storageKey);current=null;lockForm(false);$('clientName').value='';preview();show('invite');updateQuota();refreshReceived();});
$('copyInvite').addEventListener('click',()=>copy($('newUrl').value));
$('inviteForm').addEventListener('submit',async e=>{
 e.preventDefault();error('masterError','');$('createInvite').disabled=true;
 try{const d=await api('master/create',{label:$('label').value.trim(),quota:Number($('quota').value)});$('newUrl').value=newURL(d.token);$('newInvite').hidden=false;$('label').value='';await refreshMaster();toast('Ссылка создана');}
 catch(e){error('masterError',e.message);}finally{$('createInvite').disabled=false;}
});
function el(tag,text,cls){const e=document.createElement(tag);if(text!==undefined)e.textContent=text;if(cls)e.className=cls;return e;}
function action(label,fn,danger=false){const b=el('button',label,'secondary'+(danger?' danger':''));b.type='button';b.addEventListener('click',async()=>{b.disabled=true;try{await fn();}catch(e){error('masterError',e.message);}finally{b.disabled=false;}});return b;}
const states={active:'Работает',pending:'Завершаем выдачу',revoking:'Отзывается',revoked:'Отозван'};
async function refreshReceived(){
 try{
  const d=await api('received');$('receivedList').replaceChildren();error('receivedError','');
  if(!d.keys.length)$('receivedList').append(el('div','Нет действующих ключей.','empty'));
  for(const key of d.keys){
   const row=el('div',undefined,'received-row'),head=el('div',undefined,'received-head'),name=el('strong',key.name,'received-name'),buttons=el('div',undefined,'received-actions');
   const b=el('button','Скопировать','received-copy');b.type='button';b.onclick=()=>copy(key.vpn);
   const more=el('button','Ещё','received-more');more.type='button';more.setAttribute('aria-expanded','false');
   const panel=el('div',undefined,'received-panel');panel.hidden=true;panel.id='received-panel-'+$('receivedList').children.length;more.setAttribute('aria-controls',panel.id);
   more.onclick=()=>{panel.hidden=!panel.hidden;more.setAttribute('aria-expanded',String(!panel.hidden));more.textContent=panel.hidden?'Ещё':'Свернуть';};
   const text=el('textarea');text.readOnly=true;text.value=key.vpn;text.spellcheck=false;text.setAttribute('aria-label','Ключ '+key.name);
   const download=el('button','Скачать конфигурацию .conf','text-button');download.type='button';download.onclick=()=>{const a=document.createElement('a'),u=URL.createObjectURL(new Blob([key.conf],{type:'text/plain'}));a.href=u;a.download='Amnezia-'+key.device+'.conf';a.click();setTimeout(()=>URL.revokeObjectURL(u),1000);};
   panel.append(text,download);const qrButton=el('button','QR-код','received-more');qrButton.type='button';qrButton.onclick=()=>showReceivedQR(key,qrButton);buttons.append(b,qrButton,more);head.append(name,buttons);row.append(head,panel);$('receivedList').append(row);
  }
 }catch(e){error('receivedError','Не удалось загрузить ключи. Обновите страницу.');}
}
async function refreshMaster(){
 const d=await api('master/list');d.links=d.links.filter(x=>x.active);d.keys=d.keys.filter(x=>x.state!=='revoked');$('statLinks').textContent=d.links.filter(x=>x.active).length;$('statKeys').textContent=d.keys.filter(x=>x.state==='active').length;$('statLeft').textContent=d.links.filter(x=>x.active).reduce((n,x)=>n+Math.max(0,x.quota-x.used),0);
 $('linksList').replaceChildren();$('keysList').replaceChildren();
 if(!d.links.length)$('linksList').append(el('div','Нет активных ссылок. Создайте новую выше.','empty'));
 for(const x of d.links){
  const row=el('div',undefined,'list-item'),body=el('div'),buttons=el('div',undefined,'list-actions');body.append(el('strong',x.label),el('small',(x.active?'Активна':'Отключена')+' · Выдано '+x.used+' из '+x.quota));
  const progress=el('div',undefined,'progress'),fill=el('i');fill.style.width=Math.min(100,x.used/x.quota*100)+'%';progress.append(fill);body.append(progress);
  if(x.active){buttons.append(action('Копировать',()=>copy(newURL(x.token))),action('Отключить',async()=>{if(!confirm('Отключить ссылку «'+x.label+'»? Выданные ключи продолжат работать.'))return;await api('master/disable',{id:x.id});await refreshMaster();},true));}
  row.append(body,buttons);$('linksList').append(row);
 }
 if(!d.keys.length)$('keysList').append(el('div','Нет действующих ключей. Здесь появятся новые подключения.','empty'));
 for(const x of d.keys){
  const row=el('div',undefined,'list-item'),body=el('div');body.append(el('strong',x.name),el('small',(states[x.state]||x.state)+' · '+x.ip+' · '+new Date(x.created*1000).toLocaleDateString('ru-RU')));row.append(body);
  if(x.state!=='revoked')row.append(action('Отозвать ключ',async()=>{if(!confirm('Отозвать ключ «'+x.name+'»? Устройство потеряет VPN-доступ.'))return;await api('master/revoke',{id:x.id});await refreshMaster();},true));
  $('keysList').append(row);
 }
}
$('refresh').addEventListener('click',async()=>{try{await refreshMaster();toast('Обновлено');}catch(e){error('masterError',e.message);}});
init();

const qrDialog=document.createElement('dialog');qrDialog.className='qr-dialog';
const qrLarge=document.createElement('img');qrLarge.alt='QR подключения в полном размере';
const qrClose=document.createElement('button');qrClose.textContent='Закрыть';qrClose.className='secondary';qrClose.onclick=()=>qrDialog.close();
const qrSave=document.createElement('a');qrSave.textContent='Скачать QR';qrSave.className='secondary';qrSave.download='Amnezia-QR.png';
qrDialog.append(qrLarge,qrSave,qrClose);document.body.append(qrDialog);
const qrExpand=document.createElement('button');qrExpand.type='button';qrExpand.textContent='Увеличить / скачать QR';qrExpand.className='qr-expand';
function expandQR(){if(!qrURL)return;qrLarge.src=qrURL;qrSave.href=qrURL;qrDialog.showModal();}
qrExpand.onclick=expandQR;$('qr').after(qrExpand);$('qr').onclick=expandQR;
qrDialog.onclick=e=>{if(e.target===qrDialog)qrDialog.close();};

async function showReceivedQR(key,button){
 button.disabled=true;
 try{
  const r=await fetch('/access/api/qr',{method:'POST',headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},body:JSON.stringify({text:key.vpn})});
  if(!r.ok)throw Error('QR');
  const url=URL.createObjectURL(await r.blob());qrLarge.src=url;qrSave.href=url;qrDialog.showModal();
  qrDialog.addEventListener('close',()=>URL.revokeObjectURL(url),{once:true});
 }catch{toast('Не удалось загрузить QR. Попробуйте ещё раз.');}finally{button.disabled=false;}
}
