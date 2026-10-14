'use strict';
let proxyImportTimer=null,proxyImportResult=null,proxyImportPending='',proxyImportLoading=false,proxyImportEditing=false;
const proxyImportCountries={US:'美国',JP:'日本',SG:'新加坡',HK:'香港',TW:'台湾',KR:'韩国',TH:'泰国',MY:'马来西亚',IN:'印度',CA:'加拿大',GB:'英国',DE:'德国',FR:'法国',NL:'荷兰',AU:'澳大利亚'};
function clearProxyImportSecrets(){if(typeof clearProxyManageSecrets==='function')clearProxyManageSecrets();const input=$('#proxy-import-text');if(input)input.value='';if(proxyImportTimer)clearTimeout(proxyImportTimer);proxyImportTimer=null}
function renderProxyImport(value){
  proxyImportResult=value;
  const queued=Boolean(proxyImportPending&&proxyImportPending!==value.id),working=queued||['verifying','applying'].includes(value.status);
  $('#proxy-import-message').textContent=queued?'请求已提交，等待处理…':value.message;
  $('#proxy-import-form').setAttribute('aria-busy',String(working));
  $('#proxy-import-detect').disabled=working||value.status==='unavailable';
  $('#proxy-import-form').querySelectorAll('input,select,textarea').forEach(el=>el.disabled=working);
  const ready=value.kind!=='manage'&&!working&&value.status==='ready'&&value.expires>Date.now()/1000;
  $('#proxy-import-confirmation').hidden=!ready||proxyImportEditing;
  $('#proxy-import-apply').disabled=!ready;
  const rows=value.kind==='manage'?[]:value.rows||[];
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

let proxyManageItems=[],proxyManageTrash=false,proxyManageTarget=null,proxyManageOperation='',proxyManageJob='',proxyManageReady='',proxyManageBusy=false,proxyManageLoading=false;
const proxyManageNames={edit:'编辑代理',enable:'启用代理',disable:'停用代理',delete:'移入回收站',restore:'找回代理'};
function clearProxyManageSecrets(){const f=$('#proxy-manage-form');if(f){f.username.value='';f.password.value=''}}
function renderProxyManage(value){
  proxyManageItems=value.items||[];
  const busy=['verifying','applying'].includes(value.status)||value.status==='unavailable';
  const items=proxyManageItems.filter(p=>Boolean(p.deleted_at)===proxyManageTrash);
  $('#proxy-manage-trash').textContent=`回收站 (${proxyManageItems.filter(p=>p.deleted_at).length})`;
  $('#proxy-manage-table').innerHTML=items.length?'<table><thead><tr><th>节点</th><th>代理地址</th><th>状态</th><th>操作</th></tr></thead><tbody>'+items.map(p=>`<tr><td>${esc(p.label)}<br><small class="muted">${esc(proxyImportCountries[p.country]||p.country)} · ${esc(p.exit_ip)}</small></td><td>${esc(p.address)}:${esc(p.port)}<br><small>${p.protocol==='socks'?'SOCKS5':'HTTP CONNECT'}</small></td><td><span class="badge ${p.enabled&&!p.deleted_at?'good':''}">${p.deleted_at?'已删除':p.enabled?'已启用':'已停用'}</span>${p.deleted_at?`<br><small>${esc(new Date(p.deleted_at*1000).toLocaleString())}</small>`:''}</td><td>${(p.deleted_at?['restore']:['edit',p.enabled?'disable':'enable','delete']).map(op=>`<button class="text-button ${op==='delete'?'danger':''}" type="button" data-proxy-tag="${esc(p.tag)}" data-proxy-operation="${op}" ${busy?'disabled':''}>${proxyManageNames[op]}</button>`).join(' ')}</td></tr>`).join('')+'</tbody></table>':`<p class="muted">${proxyManageTrash?'回收站为空。':'暂无手动导入的代理。'}</p>`;
  if($('#proxy-manage-dialog').open&&proxyManageJob){
    if(value.id!==proxyManageJob){$('#proxy-manage-message').textContent='请求已提交，等待处理…';return}
    $('#proxy-manage-message').textContent=value.message;
    proxyManageBusy=['verifying','applying'].includes(value.status);
    proxyManageReady=value.status==='ready'&&value.expires>Date.now()/1000?value.id:'';
    $('#proxy-manage-confirmation').hidden=!proxyManageReady;
    $('#proxy-manage-apply').disabled=!proxyManageReady;
    $('#proxy-manage-prepare').disabled=proxyManageBusy;
    $('#proxy-manage-form').hidden=Boolean(proxyManageReady)||value.status==='complete'||value.status==='applying';
    if(value.status==='complete'){proxyManageJob='';refresh()}
  }
}
async function loadProxyManage(){
  if(!csrf||proxyManageLoading)return;
  proxyManageLoading=true;
  try{renderProxyManage(await api('proxy-import'));$('#proxy-manage-list-error').textContent=''}
  catch(e){$('#proxy-manage-list-error').textContent='列表暂时无法读取，正在重试。';}
  finally{proxyManageLoading=false}
}
$('#proxy-manage-refresh').onclick=loadProxyManage;
for(const [id,trash] of [['active',false],['trash',true]])$('#proxy-manage-'+id).onclick=()=>{proxyManageTrash=trash;$('#proxy-manage-active').classList.toggle('selected',!trash);$('#proxy-manage-trash').classList.toggle('selected',trash);loadProxyManage()};
$('#proxy-manage-table').onclick=e=>{
  const b=e.target.closest('[data-proxy-operation]');if(!b)return;
  const p=proxyManageItems.find(p=>p.tag===b.dataset.proxyTag);if(!p)return;
  proxyManageTarget=p.tag;proxyManageOperation=b.dataset.proxyOperation;proxyManageJob='';proxyManageReady='';proxyManageBusy=false;
  const form=$('#proxy-manage-form');form.reset();form.hidden=false;
  for(const key of ['label','address','port','protocol'])form.elements[key].value=p[key];
  $('#proxy-manage-fields').hidden=proxyManageOperation!=='edit';
  $('#proxy-manage-fields').querySelectorAll('input,select').forEach(el=>el.disabled=proxyManageOperation!=='edit');
  $('#proxy-manage-title').textContent=proxyManageNames[proxyManageOperation]+' · '+p.label;
  $('#proxy-manage-description').textContent={edit:'修改后先检测 HTTPS 和加密 DNS；检测通过再确认保存。入口编号保持不变。',enable:'启用前会重新检测代理，确认后重新加入订阅。',disable:'停用后将关闭此代理入口，并从订阅移除；配置保留，可随时启用。',delete:'确认后关闭入口并从订阅移除。配置保存在回收站，不会自动清空，可随时找回。',restore:'从回收站找回原配置与入口编号。找回后保持停用，启用时再检测连接。'}[proxyManageOperation];
  $('#proxy-manage-prepare').textContent=['edit','enable'].includes(proxyManageOperation)?'检测并预览':'预览操作';
  $('#proxy-manage-prepare').disabled=false;$('#proxy-manage-confirmation').hidden=true;$('#proxy-manage-message').textContent='';$('#proxy-manage-error').textContent='';
  $('#proxy-manage-dialog').showModal();
};
$('#proxy-manage-dialog').addEventListener('close',clearProxyManageSecrets);
$('#proxy-manage-form').onsubmit=async e=>{
  e.preventDefault();if(proxyManageBusy)return;
  const f=e.currentTarget;const payload={action:'manage',operation:proxyManageOperation,tag:proxyManageTarget};
  if(proxyManageOperation==='edit')payload.changes={label:f.label.value,address:f.address.value,port:Number(f.port.value),protocol:f.protocol.value,username:f.username.value,password:f.password.value};
  proxyManageBusy=true;$('#proxy-manage-prepare').disabled=true;$('#proxy-manage-error').textContent='';
  try{const result=await api('proxy-import','POST',payload);clearProxyManageSecrets();proxyManageJob=result.id;$('#proxy-manage-message').textContent='请求已提交，等待处理…';loadProxyManage()}
  catch(e){proxyManageBusy=false;$('#proxy-manage-prepare').disabled=false;$('#proxy-manage-error').textContent=e.message}
};
$('#proxy-manage-apply').onclick=async()=>{
  if(!proxyManageReady||proxyManageBusy)return;proxyManageBusy=true;$('#proxy-manage-apply').disabled=true;
  try{const value=await api('proxy-import','POST',{action:'apply',preview_id:proxyManageReady});proxyManageJob=value.id;proxyManageReady='';$('#proxy-manage-confirmation').hidden=true;$('#proxy-manage-message').textContent='正在应用变更…';loadProxyManage()}
  catch(e){proxyManageBusy=false;$('#proxy-manage-apply').disabled=false;$('#proxy-manage-error').textContent=e.message}
};
setInterval(()=>{if(csrf&&(!$('#page-nodes').hidden||$('#proxy-manage-dialog').open))loadProxyManage()},2000);
