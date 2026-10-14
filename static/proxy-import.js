'use strict';
let proxyImportTimer=null,proxyImportResult=null,proxyImportPending='',proxyImportLoading=false,proxyImportEditing=false;
const proxyImportCountries={US:'美国',JP:'日本',SG:'新加坡',HK:'香港',TW:'台湾',KR:'韩国',TH:'泰国',MY:'马来西亚',IN:'印度',CA:'加拿大',GB:'英国',DE:'德国',FR:'法国',NL:'荷兰',AU:'澳大利亚'};
function clearProxyImportSecrets(){const input=$('#proxy-import-text');if(input)input.value='';if(proxyImportTimer)clearTimeout(proxyImportTimer);proxyImportTimer=null}
function renderProxyImport(value){
  proxyImportResult=value;
  const queued=Boolean(proxyImportPending&&proxyImportPending!==value.id),working=queued||['verifying','applying'].includes(value.status);
  $('#proxy-import-message').textContent=queued?'请求已提交，等待处理…':value.message;
  $('#proxy-import-form').setAttribute('aria-busy',String(working));
  $('#proxy-import-detect').disabled=working||value.status==='unavailable';
  $('#proxy-import-form').querySelectorAll('input,select,textarea').forEach(el=>el.disabled=working);
  const ready=!working&&value.status==='ready'&&value.expires>Date.now()/1000;
  $('#proxy-import-confirmation').hidden=!ready||proxyImportEditing;
  $('#proxy-import-apply').disabled=!ready;
  const rows=value.rows||[];
  const compact=!proxyImportEditing&&rows.length>0&&['ready','applying','complete'].includes(value.status);
  $('#proxy-import-form').hidden=compact;$('#proxy-import-edit').hidden=!compact||working;
  $('#proxy-import-results').innerHTML=rows.length?'<table><thead><tr><th>代理地址</th><th>出口 / 地区</th><th>检测结果</th></tr></thead><tbody>'+rows.map(r=>`<tr><td>${esc(r.address)}:${esc(r.port)}<br><small class="muted">${esc(r.protocol==='socks'?'SOCKS5':'HTTP CONNECT')}</small></td><td>${esc(r.exit_ip||'—')}<br>${esc(proxyImportCountries[r.country]||r.country||'等待检测')}</td><td><span class="badge ${r.status==='verified'?'good':'bad'}">${r.status==='verified'?'通过':'未通过'}</span><br><small>${r.status==='verified'?`HTTPS ${esc(r.https_ms)} ms · DoH ${esc(r.doh_ms)} ms`:esc(r.error||'连接失败')}</small></td></tr>`).join('')+'</tbody></table>':'';
  if(value.status==='complete'&&!queued){proxyImportPending='';refresh()}
}
async function loadProxyImport(){
  if(proxyImportLoading||!$('#proxy-import-dialog').open||!csrf)return;
  proxyImportLoading=true;
  try{const value=await api('proxy-import');if(value.id===proxyImportPending)proxyImportPending='';renderProxyImport(value);$('#proxy-import-error').textContent=''}
  catch(error){$('#proxy-import-error').textContent='读取导入进度失败，正在重试；请勿重复提交。'}
  finally{proxyImportLoading=false;if($('#proxy-import-dialog').open)proxyImportTimer=setTimeout(loadProxyImport,2000)}
}
$('#proxy-import-edit').onclick=()=>{proxyImportEditing=true;renderProxyImport(proxyImportResult);$('#proxy-import-text').focus()};
$('#proxy-import-open').onclick=()=>{clearProxyImportSecrets();proxyImportEditing=false;$('#proxy-import-dialog').showModal();loadProxyImport()};
$('#proxy-import-dialog').addEventListener('close',clearProxyImportSecrets);
$('#proxy-import-form').onsubmit=async e=>{
  e.preventDefault();const form=e.currentTarget;
  $('#proxy-import-error').textContent='';$('#proxy-import-detect').disabled=true;
  const payload={action:'preview',protocol:form.protocol.value,label:form.label.value,text:form.text.value};
  try{const value=await api('proxy-import','POST',payload);form.text.value='';proxyImportEditing=false;proxyImportPending=value.id;renderProxyImport({...proxyImportResult,status:'verifying',rows:[]});}
  catch(error){$('#proxy-import-error').textContent=error.message;$('#proxy-import-detect').disabled=false}
};
$('#proxy-import-apply').onclick=async()=>{
  if(proxyImportResult?.status!=='ready')return;
  $('#proxy-import-apply').disabled=true;$('#proxy-import-error').textContent='';
  try{const value=await api('proxy-import','POST',{action:'apply',preview_id:proxyImportResult.id});proxyImportPending=value.id;renderProxyImport({...proxyImportResult,status:'applying'});}
  catch(error){$('#proxy-import-error').textContent=error.message;$('#proxy-import-apply').disabled=false}
};
