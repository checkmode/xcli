'use strict';
const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
let csrf='', state=null, page='overview', connectUser=null, connectLinks=null, qrKind='shadowrocket', busy=false;
const transportNames={reality:'REALITY',websocket:'WebSocket / TLS',hysteria2:'Hysteria 2'};
const transportLabel=kind=>transportNames[kind]||state?.server?.residential_exits?.find(e=>e.tag===kind)?.label||kind;
const enabledTransports=()=>state?.server?.transports||['reality','websocket'];
const labels={active:'可用',disabled:'已停用',expired:'已到期',exhausted:'配额用尽'};
const events={login:'管理员登录',login_failed:'登录失败',user_created:'新建用户',user_updated:'更新用户',user_deleted:'删除用户',credentials_rotated:'重置凭据',traffic_reset:'重置流量',password_changed:'修改密码',core_restart:'更新访问权限',mfa_setup:'准备绑定二次验证',mfa_enabled:'启用二次验证',mfa_disabled:'关闭二次验证',recovery_regenerated:'重新生成恢复码',backup_created:'创建加密备份',backup_restored:'恢复备份',notifications_configured:'通知配置变更',notification_test:'发送测试通知',fault_detected:'检测到持续故障',fault_recovered:'故障已恢复'};
const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function bytes(n){if(!n)return '0 B';const i=Math.min(4,Math.floor(Math.log(Math.max(1,n))/Math.log(1000)));return (n/1000**i).toFixed(i?1:0)+' '+['B','KB','MB','GB','TB'][i]}
function date(n){return n?new Date(n*1000).toLocaleString('zh-CN',{month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit'}):'不过期'}
function toast(message){$('#toast').textContent=message;$('#toast').hidden=false;setTimeout(()=>$('#toast').hidden=true,3600)}
async function api(path,method='GET',body){
  const bounded=method==='GET'&&['overview','runtime','diagnostics'].includes(path),controller=new AbortController();
  const timer=bounded?setTimeout(()=>controller.abort(),5000):null;
  try{
    const r=await fetch('/api/'+path,{method,credentials:'same-origin',signal:controller.signal,headers:{'Content-Type':'application/json',...(csrf?{'X-CSRF-Token':csrf}:{})},...(body!==undefined?{body:JSON.stringify(body)}:{})});
    let data;try{data=await r.json()}catch(error){if(error.name==='AbortError')throw error;data={}}
    if(!r.ok){if(r.status===401&&path!=='login')showLogin();throw new Error(typeof data.detail==='string'?data.detail:'操作失败，请稍后重试')}
    if(bounded&&(!data||typeof data!=='object'||(path==='overview'&&(!data.health||!data.runtime))||(path==='runtime'&&typeof data.sampled!=='number')||(path==='diagnostics'&&!data.runtime)))throw new Error('运行数据格式无效，请检查管理服务');
    return data;
  }catch(error){if(error.name==='AbortError')throw new Error('读取运行状态超时，请检查管理服务');throw error}
  finally{if(timer)clearTimeout(timer)}
}
function showLogin(){if(typeof clearWebshareSecrets==='function')clearWebshareSecrets();clearSecuritySecrets();if(typeof clearOperationsSecrets==='function')clearOperationsSecrets();csrf='';$('#app-view').hidden=true;$('#login-view').hidden=false;$$('dialog[open]').forEach(d=>d.close())}
async function enter(data){csrf=data.csrf;$('#login-view').hidden=true;$('#app-view').hidden=false;await refresh()}
$('#login-form').addEventListener('submit',async e=>{e.preventDefault();const form=e.currentTarget,button=form.querySelector('button');button.disabled=true;$('#login-error').textContent='';try{const data=await api('login','POST',Object.fromEntries(new FormData(form)));form.password.value='';form.code.value='';await enter(data)}catch(err){$('#login-error').textContent=err.message}finally{button.disabled=false}});
$('#logout-button').onclick=async()=>{try{await api('logout','POST',{});showLogin()}catch(err){toast(err.message)}};
function navigate(next){if(page==='webshare'&&next!=='webshare'&&typeof clearWebshareSecrets==='function')clearWebshareSecrets();if(page==='security'&&next!=='security')clearSecuritySecrets();if(page==='notifications'&&next!=='notifications'&&typeof clearOperationsSecrets==='function')clearOperationsSecrets();page=next;$$('.page').forEach(p=>p.hidden=p.id!=='page-'+page);$$('.nav-item').forEach(b=>b.classList.toggle('selected',b.dataset.page===page));$('#breadcrumb').textContent={overview:'概览',users:'用户管理',nodes:'接入节点',activity:'操作记录',devices:'设备活动',security:'安全与备份',history:'历史趋势',notifications:'故障通知',diagnostics:'运行诊断',webshare:'动态住宅池'}[page];if(page==='overview')drawChart();if(page==='webshare'&&typeof loadWebshare==='function')loadWebshare(true);if(page==='security')loadSecurity().catch(err=>toast(err.message));if(page==='history')loadHistory();if(page==='notifications')loadNotifications(true);if(page==='diagnostics')loadDiagnostics()}
$$('[data-page]').forEach(b=>b.onclick=()=>navigate(b.dataset.page));
$$('[data-close]').forEach(b=>b.onclick=()=>$('#'+b.dataset.close).close());
async function refresh(){if(!csrf||busy)return;busy=true;try{state=await api('overview');render()}catch(err){toast(err.message);if(state&&typeof renderRuntime==='function')renderRuntime(state.runtime,state.monitor)}finally{busy=false}}
function render(){const s=state;const hy2=enabledTransports().includes('hysteria2');$$('[data-hy2]').forEach(el=>el.hidden=!hy2);$('#node-intro').textContent=`配置了 ${enabledTransports().length} 种原有连接方式${s.server.residential_exits?.length?'，另有 '+s.server.residential_exits.filter(e=>!e.dynamic).length+' 个固定住宅出口和 '+s.server.residential_exits.filter(e=>e.dynamic).length+' 个动态入口':''}。下方显示实际读取的配置与状态。`;$('#server-protocols').textContent=hy2?'VLESS / Hysteria 2':'VLESS';renderMonitor();renderDevices();$('#total-traffic').textContent=bytes(s.totals.upload+s.totals.download);$('#download-rate').textContent=bytes(s.health.download_rate||0)+'/s';$('#upload-rate').textContent=bytes(s.health.upload_rate||0)+'/s';$('#active-users').textContent=s.users.filter(u=>u.status==='active').length;$('#all-users').textContent='共 '+s.users.length+' 位用户';$('#core-badge').textContent=s.health.core?'● 核心运行正常':'● '+(s.health.error||'等待连接');$('#core-badge').className='badge '+(s.health.core?'good':'bad');$('#server-status').textContent=s.health.core?'运行中':'应用中 / 异常';$('#server-ip').textContent=s.server.public_ip;$('#server-domain').textContent=s.server.domain;$('#updated').textContent='流量采样 '+(s.health.updated?date(s.health.updated):'未知');if(!s.health.updated||Date.now()/1000-s.health.updated>(s.runtime?.max_age_seconds||30)){$('#download-rate').textContent='未知';$('#upload-rate').textContent='未知'}$('#user-count').textContent=s.users.length;renderUsers();$('#recent-users').innerHTML=table(s.users.slice(0,4),false);$$('[data-pct]').forEach(el=>el.style.width=el.dataset.pct+'%');$('#event-list').innerHTML=s.events.length?s.events.map(e=>`<div class="event"><time>${date(e.ts)}</time><strong>${esc(events[e.action]||e.action)}</strong><span class="detail">${esc(e.detail)}</span></div>`).join(''):'<div class="empty">暂时没有操作记录</div>';if(typeof renderRuntime==='function')renderRuntime(s.runtime,s.monitor);if(page==='overview')drawChart();if(page==='diagnostics')loadDiagnostics()}
function table(users,actions=true){if(!users.length)return '<div class="empty">'+(state.users.length?'没有找到匹配用户':'还没有用户。新建用户后即可生成连接和订阅。')+'</div>';return `<table><thead><tr><th>用户</th><th>状态</th><th>流量 / 配额</th><th>到期</th>${actions?'<th>操作</th>':''}</tr></thead><tbody>`+users.map(u=>`<tr><td><div class="user-identity"><span class="user-avatar">${esc(u.name.slice(0,1).toUpperCase())}</span>${esc(u.name)}</div></td><td><span class="badge ${u.status==='active'?'good':''}">${labels[u.status]}</span></td><td>${bytes(u.upload+u.download)} <span class="muted">/ ${u.quota?bytes(u.quota):'不限'}</span><div class="usage-bar"><i data-pct="${u.quota?Math.min(100,(u.upload+u.download)/u.quota*100):0}"></i></div></td><td class="muted">${date(u.expires)}</td>${actions?`<td class="actions"><button data-action="connect" data-id="${u.id}">连接</button><button data-action="edit" data-id="${u.id}">编辑</button><button data-action="rotate" data-id="${u.id}">重置凭据</button><button data-action="reset" data-id="${u.id}">清零</button><button data-action="delete" data-id="${u.id}" class="danger">删除</button></td>`:''}</tr>`).join('')+'</tbody></table>'}
function renderUsers(){const q=$('#search-users').value.toLowerCase();$('#user-table').innerHTML=table(state.users.filter(u=>u.name.toLowerCase().includes(q)));$$('[data-pct]').forEach(el=>el.style.width=el.dataset.pct+'%')}
$('#search-users').oninput=renderUsers;
function editUser(u){const f=$('#user-form');f.reset();f.elements.id.value=u?.id||'';f.elements.name.value=u?.name||'';f.elements.quota.value=u?u.quota/1e9:0;f.elements.enabled.checked=u?!!u.enabled:true;const t=u?.expires?new Date(u.expires*1000):null;f.elements.expires.value=t?new Date(t-t.getTimezoneOffset()*60000).toISOString().slice(0,16):'';$('#user-dialog-title').textContent=u?'编辑用户':'新建用户';$('#user-error').textContent='';$('#user-dialog').showModal()}
$('#new-user').onclick=()=>editUser(null);
$('#user-form').onsubmit=async e=>{e.preventDefault();const f=e.currentTarget,b=f.querySelector('button.primary');b.disabled=true;try{const data={name:f.elements.name.value,quota:Math.round(Number(f.elements.quota.value)*1e9),enabled:f.elements.enabled.checked,expires:f.elements.expires.value?Math.floor(new Date(f.elements.expires.value).getTime()/1000):0};await api('users'+(f.elements.id.value?'/'+f.elements.id.value:''),f.elements.id.value?'PUT':'POST',data);$('#user-dialog').close();toast('已保存，访问权限将在几秒内更新');await refresh()}catch(err){$('#user-error').textContent=err.message}finally{b.disabled=false}};
$('#user-table').onclick=async e=>{const b=e.target.closest('[data-action]');if(!b)return;const u=state.users.find(u=>u.id===b.dataset.id),action=b.dataset.action;try{if(action==='edit')return editUser(u);if(action==='connect')return await showConnect(u);if(action==='delete'&&!confirm(`删除「${u.name}」？其节点和订阅将立即失效，其他设备会短暂重连。`))return;if(action==='rotate'&&!confirm(`重置「${u.name}」的所有凭据？旧节点和订阅将失效，需要重新导入；其他设备会短暂重连。`))return;if(action==='reset'&&!confirm(`将「${u.name}」的累计流量归零？已用尽配额的用户可能恢复连接。`))return;await api('users/'+u.id+(action==='rotate'?'/rotate':action==='reset'?'/reset-traffic':''),action==='delete'?'DELETE':'POST',action==='delete'?undefined:{});toast('操作已保存');await refresh()}catch(err){toast(err.message)}};
async function showConnect(u){const [nodes,client]=await Promise.all([api('users/'+u.id+'/links'),api('users/'+u.id+'/shadowrocket')]);connectUser=u;connectLinks={...nodes,...client};$('#connect-title').textContent=u.name;$$('[data-kind]').forEach(b=>b.hidden=!connectLinks[b.dataset.kind]);$('#connect-dialog').showModal();selectQR('shadowrocket')}
function selectQR(kind){
  qrKind=kind;const count=Object.keys(connectLinks).filter(k=>transportNames[k]||/^residential-[0-9]{2}$/.test(k)).length;
  $$('[data-kind]').forEach(b=>{b.classList.toggle('active',b.dataset.kind===kind);b.setAttribute('aria-pressed',String(b.dataset.kind===kind))});
  $('#qr-image').src='/api/users/'+connectUser.id+'/qr/'+kind;
  $('#node-link').value=connectLinks[kind];
  const descriptions={clash:'复制下面的 Clash 订阅地址，在 Clash Verge Rev 的订阅页面导入并启用，默认使用 HTTPS，也可从 PROXY 组选择节点。DNS 已配置为通过所选代理的 DoH。',shadowrocket:`用 iPhone 系统相机扫码，在引导页依次确认导入 ${count} 个节点和 DNS 模块。其他默认设置保留，无需再次扫码。`,dns:'已有节点时，可扫码安装 DNS 模块，再到「配置 → 模块」确认启用。首页全局路由选择「代理」。',subscription:`订阅包含 ${count} 个节点；客户端的 DNS 设置需另外安装模块。`};
  $('#qr-description').textContent=descriptions[kind]||'打开小火箭扫描二维码，导入此节点。';
  $('#connection-label').textContent=kind==='shadowrocket'?'手机引导地址':kind==='dns'?'DNS 模块地址':'连接地址';
  $('#connect-note').textContent=kind==='dns'?'模块不含节点凭据。停用模块即可撤销 DNS 覆盖。':'二维码和地址包含此用户的订阅或节点凭据，请只交给对应用户。重置凭据后旧地址失效。';
  const open=$('#open-client');open.hidden=!['shadowrocket','dns','clash'].includes(kind);
  if(!open.hidden){open.href=kind==='dns'?connectLinks.dns_install:kind==='clash'?connectLinks.clash_install:connectLinks.shadowrocket;open.textContent=kind==='dns'?'安装 DNS 模块':kind==='clash'?'导入 Clash Verge':'打开手机引导';open.target=kind==='dns'||kind==='clash'?'_self':'_blank'}else open.removeAttribute('href');
}
$$('[data-kind]').forEach(b=>b.onclick=()=>selectQR(b.dataset.kind));
$('#connect-dialog').addEventListener('close',()=>{connectUser=null;connectLinks=null;$('#qr-image').removeAttribute('src');$('#node-link').value='';$('#open-client').removeAttribute('href')});
$('#copy-link').onclick=async()=>{try{await navigator.clipboard.writeText($('#node-link').value);toast('地址已复制')}catch{$('#node-link').select();toast('请手动复制已选中的地址')}};
$('#download-qr').onclick=async()=>{try{const r=await fetch($('#qr-image').src);if(!r.ok)throw new Error('下载失败');const url=URL.createObjectURL(await r.blob());const a=document.createElement('a');a.href=url;a.download=connectUser.name+'-'+qrKind+'.png';a.click();setTimeout(()=>URL.revokeObjectURL(url),3000)}catch(err){toast(err.message)}};
$('#password-button').onclick=()=>{$('#password-form').reset();$('#password-error').textContent='';$('#password-dialog').showModal()};
$('#password-form').onsubmit=async e=>{e.preventDefault();try{await api('password','POST',Object.fromEntries(new FormData(e.currentTarget)));showLogin();toast('密码已修改，请重新登录')}catch(err){$('#password-error').textContent=err.message}};
function drawChart(){if(!state)return;const canvas=$('#traffic-chart'),w=canvas.clientWidth;if(!w)return;const h=215,dpr=window.devicePixelRatio||1;canvas.width=w*dpr;canvas.height=h*dpr;const c=canvas.getContext('2d');c.scale(dpr,dpr);const left=57,right=12,top=12,bottom=28;const samples=state.samples,now=Math.floor(Date.now()/60000)*60,start=now-59*60;const vals=new Map(samples.map(s=>[s.ts,s]));const points=Array.from({length:60},(_,i)=>vals.get(start+i*60)||{upload:null,download:null});const max=Math.max(1024,...points.flatMap(p=>[p.upload,p.download]).filter(n=>n!==null))*1.2;c.font='10px -apple-system,sans-serif';c.fillStyle='#98a7af';c.strokeStyle='#eef2f5';c.lineWidth=1;for(let i=0;i<4;i++){const y=top+i*(h-top-bottom)/3;c.beginPath();c.moveTo(left,y);c.lineTo(w-right,y);c.stroke();c.fillText(bytes(max*(1-i/3)),0,y+3)}for(const [i,label] of [[0,'60 分钟前'],[30,'30 分钟前'],[59,'现在']]){c.fillText(label,left+i/59*(w-left-right)-(i===59?23:0),h-5)}for(const [key,color] of [['download','#169d88'],['upload','#7095be']]){c.strokeStyle=color;c.lineWidth=2;c.beginPath();let pen=false;points.forEach((p,i)=>{if(p[key]===null){pen=false;return}const x=left+i/59*(w-left-right),y=top+(1-p[key]/max)*(h-top-bottom);if(pen)c.lineTo(x,y);else c.moveTo(x,y);pen=true});c.stroke()}$('#chart-note').textContent=samples.length?'统计按 Xray 用户流量累计，缺测时段留空；异常重启可能丢失最后一个采样周期。':'暂无流量数据。连接节点后，此处会显示真实流量。'}
window.addEventListener('resize',()=>{if(typeof renderRuntime==='function')renderRuntime(s.runtime,s.monitor);if(page==='overview')drawChart();if(page==='diagnostics')loadDiagnostics()});
function seen(ts){return ts?date(ts):'尚未观察到流量'}
function clearSecuritySecrets(){for(const id of ['mfa-form','restore-form','password-form'])$('#'+id)?.reset();$('#mfa-setup').hidden=true;$('#mfa-qr').removeAttribute('src');$('#mfa-secret').value='';$('#recovery-codes').value='';$('#recovery-box').hidden=true;$('#mfa-enable').hidden=true}
function renderMonitor(){
  const m=state.monitor||{},labels={healthy:'自检通过',failed:'检测失败',stale:'结果已过期',unknown:'等待自检'};
  $('#monitor-badge').textContent=labels[m.status]||'未知';$('#monitor-badge').className='badge '+(m.status==='healthy'?'good':'bad');
  $('#monitor-checks').innerHTML=(m.checks||[]).map(c=>`<div class="monitor-card"><strong>${esc(transportLabel(c.transport))}</strong><span class="badge ${c.status==='healthy'&&m.status!=='stale'?'good':'bad'}">${m.status==='stale'?'结果已过期':c.status==='healthy'?'通过':'失败'}</span><p>HTTPS ${c.https_ms===null?'失败':esc(c.https_ms)+' ms'} · ${c.udp_supported===false?'DoH '+(c.doh_ms===null?'失败':esc(c.doh_ms)+' ms')+' · UDP 不支持':'UDP DNS '+(c.udp_ms===null?'失败':esc(c.udp_ms)+' ms')}</p><small class="muted">最近成功：${c.last_success?date(c.last_success):'尚无'} · ${esc(c.error||'出口验证通过')}</small></div>`).join('')||`<p class="muted">${esc(m.message||'等待探测服务首次运行')}</p>`;
}
function renderDevices(){
  const rows=state.users.flatMap(u=>enabledTransports().map(kind=>{
    const a=state.activity?.[u.id]?.[kind]||{},status=a.status||'never';
    return `<tr><td>${esc(u.name)}</td><td>${esc(transportNames[kind]||kind)}</td><td><span class="badge ${status==='recent'?'good':''}">${({recent:'近期活跃',idle:'暂无近期流量',never:'尚未观察到流量',unknown:'采样中断'})[status]}</span></td><td>${seen(a.last_seen)}</td><td>↑ ${bytes(a.upload_rate||0)}/s<br>↓ ${bytes(a.download_rate||0)}/s</td></tr>`;
  }));
  $('#device-table').innerHTML=rows.length?'<table><thead><tr><th>用户 / 设备</th><th>入口</th><th>活动状态</th><th>最近流量</th><th>当前速率</th></tr></thead><tbody>'+rows.join('')+'</tbody></table>':'<div class="empty">新建独立用户后，设备活动会显示在这里。</div>';
}
async function loadSecurity(){
  const [m,b]=await Promise.all([api('security'),api('backups')]);
  $('#mfa-badge').textContent=m.enabled?'已启用':'未启用';$('#mfa-badge').className='badge '+(m.enabled?'good':'');
  $('#mfa-note').textContent=m.enabled?`登录需要管理密码和二次验证，剩余 ${m.recovery_remaining} 条恢复码。`:'使用验证器生成的 6 位动态码保护管理登录。完成扫描并验证后才会启用。';
  $('#mfa-start').hidden=m.enabled;$('#mfa-recovery').hidden=!m.enabled;$('#mfa-disable').hidden=!m.enabled;
  $('#backup-schedule').textContent=`${b.automatic?'每 '+Math.round(b.interval/3600)+' 小时自动备份':'自动备份已关闭'}，保留最近 ${b.retention} 份。最近备份：${b.last_backup?date(b.last_backup):'尚无'}。`;
  $('#backup-error').textContent=b.error;
  $('#backup-list').innerHTML=b.backups.length?b.backups.map(item=>`<div class="backup-item"><div><strong>${date(item.created)} · ${esc(({automatic:'自动',manual:'手动','before-restore':'恢复前快照'})[item.reason]||item.reason)}</strong><small class="muted">${item.valid?esc(item.users)+' 位用户 · '+bytes(item.bytes):'备份校验失败'}</small><code>${esc(item.id)}</code></div>${item.valid?`<div class="form-actions"><a class="text-button" href="/api/backups/${encodeURIComponent(item.id)}/download" download>下载</a><button class="secondary" data-restore="${esc(item.id)}">恢复…</button></div>`:''}</div>`).join(''):'<p class="muted">尚无备份</p>';
}
$('#refresh-security').onclick=()=>loadSecurity().catch(err=>toast(err.message));
$('#mfa-form').onsubmit=async e=>{
  e.preventDefault();const action=e.submitter?.value;if(!action)return;const f=e.currentTarget;
  if(action==='disable'&&!confirm('关闭二次验证后，管理登录只需要密码。确认关闭？'))return;
  const buttons=[...f.querySelectorAll('button')];buttons.forEach(b=>b.disabled=true);$('#mfa-error').textContent='';
  try{
    const result=await api('security/'+action,'POST',Object.fromEntries(new FormData(f)));
    if(action==='setup'){$('#mfa-qr').src=result.qr;$('#mfa-secret').value=result.secret;$('#mfa-setup').hidden=false;$('#mfa-enable').hidden=false;toast('请扫码后填写动态码并确认启用')}
    else{clearSecuritySecrets();if(result.recovery_codes){$('#recovery-codes').value=result.recovery_codes.join('\n');$('#recovery-box').hidden=false}if(action==='disable'){showLogin();toast('已关闭二次验证，请重新登录');return}toast(action==='enable'?'二次验证已启用':'恢复码已更新')}
    await loadSecurity();
  }catch(err){$('#mfa-error').textContent=err.message}finally{buttons.forEach(b=>b.disabled=false)}
};
$('#copy-recovery').onclick=async()=>{try{await navigator.clipboard.writeText($('#recovery-codes').value);toast('恢复码已复制，请安全保存')}catch{$('#recovery-codes').select();toast('请手动复制恢复码')}};
$('#backup-now').onclick=async()=>{const b=$('#backup-now');b.disabled=true;try{await api('backups','POST',{});await loadSecurity();toast('加密备份已完成')}catch(err){toast(err.message)}finally{b.disabled=false}};
$('#backup-list').onclick=async e=>{
  const button=e.target.closest('[data-restore]');if(!button)return;
  try{const item=await api('backups/'+encodeURIComponent(button.dataset.restore)+'/inspect');if(!item.same_server)throw new Error('此备份与当前服务器配置不同，请使用离线恢复工具');const f=$('#restore-form');f.reset();f.elements.id.value=item.id;$('#restore-preview').textContent=`${date(item.created)} · ${item.users} 位用户。备份编号：${item.id}`;$('#restore-error').textContent='';$('#restore-dialog').showModal()}catch(err){toast(err.message)}
};
$('#restore-form').onsubmit=async e=>{
  e.preventDefault();const b=e.currentTarget.querySelector('button.primary');b.disabled=true;
  try{await api('backups/restore','POST',Object.fromEntries(new FormData(e.currentTarget)));showLogin();toast('已恢复用户配置，请重新登录；节点权限将在几秒内更新')}catch(err){$('#restore-error').textContent=err.message}finally{b.disabled=false}
};

setInterval(refresh,5000);
api('session').then(enter).catch(()=>showLogin());
