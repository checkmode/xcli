'use strict';
const runtimeNames={running:'进程运行中',reachable:'管理接口可访问',unavailable:'不可用',unknown:'未知',ready:'权限同步完成',reconnecting:'等待核心重连',error:'同步异常',listening:'已确认监听',not_listening:'未监听',healthy:'自检通过',failed:'自检失败',stale:'采样过期'};
const runtimeTime=n=>n?date(n):'未知';
const duration=n=>n===undefined||n===null?'未知':Math.floor(n/86400)+' 天 '+Math.floor(n%86400/3600)+' 小时 '+Math.floor(n%3600/60)+' 分钟';
const detailValue=v=>v===null||v===undefined?'未知':Array.isArray(v)?v.join('、'):String(v);
function runtimeTile(label,value,note=''){return `<div class="runtime-tile"><span>${esc(label)}</span><strong>${esc(detailValue(value))}</strong>${note?`<small>${esc(note)}</small>`:''}</div>`}
function runtimeBadge(value){return `<span class="badge ${['running','reachable','ready','listening','healthy'].includes(value)?'good':['unavailable','error','not_listening','failed'].includes(value)?'bad':''}">${esc(runtimeNames[value]||'未知')}</span>`}
function resourceText(item){return item?bytes(item.used)+' / '+bytes(item.total):'未知'}
function renderRuntime(r={},monitor={}){
  const host=r.host||{},panel=r.panel||{},proc=r.process||{},apiState=r.management_api||{},sync=r.access_sync||{};
  const stale=r.stale||!r.sampled||Date.now()/1000-r.sampled>Math.max(30,r.max_age_seconds||30);
  $('#runtime-sampled').textContent=(stale?'采样过期／尚未采集':'服务器采样')+' · '+runtimeTime(r.sampled);
  $('#nodes-runtime-sampled').textContent=(stale?'配置采样已过期，摘要为上次记录':'配置与监听采样')+' · '+runtimeTime(r.sampled);
  const tile=(label,value,note='')=>runtimeTile(label,stale?'未知':value,stale?'采样已过期；上次记录 '+detailValue(value):note);
  $('#runtime-summary').innerHTML=tile('面板版本',panel.version,panel.revision==='unknown'?'构建提交未知':panel.revision?`构建提交 ${panel.revision}`:'')+
    tile('运行中的 Xray',proc.version,proc.version_reason||(proc.version?'来自运行进程的可执行镜像':'尚未确认运行版本'))+
    tile('核心运行时长',duration(proc.uptime_seconds),proc.pid?`PID ${proc.pid} · 启动 ${runtimeTime(proc.started_at)}`:proc.reason||'等待采集')+
    tile('面板运行时长',duration(panel.uptime_seconds),'启动 '+runtimeTime(panel.started_at))+
    tile('系统运行时长',duration(host.uptime_seconds))+
    tile('主机 CPU',host.cpu_percent===null||host.cpu_percent===undefined?'未知':host.cpu_percent.toFixed(1)+'%','相邻两次服务器采样的差值')+
    tile('主机内存',resourceText(host.memory),'使用量按 MemAvailable 计算')+
    tile('Swap',resourceText(host.swap))+
    tile('数据目录所在磁盘',resourceText(host.disk),host.disk?'普通用户可用 '+bytes(host.disk.available):'无法读取文件系统状态')+
    tile('系统负载',host.load?host.load.map(n=>n.toFixed(2)).join(' / '):'未知','最近 1 / 5 / 15 分钟');
  $('#server-pid').textContent=stale?'未知':detailValue(proc.pid);$('#server-version').textContent=stale?'未知':detailValue(proc.version);
  const good=!stale&&proc.state==='running'&&apiState.state==='reachable'&&sync.state==='ready';
  $('#core-badge').textContent=stale?'● 运行采样未知／过期':good?'● 进程与管理接口正常':'● '+(proc.state!=='running'?runtimeNames[proc.state]||'进程状态未知':apiState.state!=='reachable'?'管理接口 '+(runtimeNames[apiState.state]||'未知'):runtimeNames[sync.state]||'同步状态未知');
  $('#core-badge').className='badge '+(good?'good':'');
  $('#server-status').textContent=stale?'未知／过期':runtimeNames[proc.state]||'未知';
  const entries=proc.inbounds||[],exits=state?.server?.residential_exits||[],kinds=[...new Set([...enabledTransports(),...exits.map(e=>e.tag),...entries.map(e=>e.tag)])];
  $('#runtime-nodes').innerHTML=kinds.map(kind=>{
    const exit=exits.find(e=>e.tag===kind),entry=entries.find(n=>n.tag===kind),probe=(monitor.checks||[]).find(c=>c.transport===kind);
    const probeState=monitor.status==='stale'||!monitor.updated||Date.now()/1000-monitor.updated>180||!probe?'unknown':probe.status;
    let body=entry?`<dl>${[['配置监听地址',entry.listen],['配置端口',entry.port],['协议',entry.protocol],['传输',entry.network],['核心安全类型',entry.security],['REALITY 目标',entry.target],['服务端名称',entry.server_names||entry.server_name],['WebSocket 路径',entry.path],['ALPN',entry.alpn]].filter(([key,value])=>value!==undefined).map(([key,value])=>`<div><dt>${esc(key)}</dt><dd>${esc(detailValue(value))}</dd></div>`).join('')}</dl>`:`<p class="muted">${esc(proc.config?'当前启动配置文件未包含此入口':proc.config_reason||proc.reason||'尚未读取启动配置')}</p>`;
    if(entry?.certificate){const c=entry.certificate;body+=`<p class="small">证书文件到期：${runtimeTime(c.not_after)} · ${esc(({within_validity:'在有效期内',expired:'已过期',not_yet_valid:'尚未生效'})[c.state]||c.reason||'未知')}</p><p class="small muted">只检查文件有效期；不代表核心已加载此证书或证书链验证通过。</p>`}
    return `<article class="panel node-card"><h2>${esc(transportLabel(kind))}</h2><p>进程监听 ${runtimeBadge(stale?'unknown':entry?.listener?.state||'unknown')}</p>${entry?.listener?.reason?`<p class="small muted">${esc(entry.listener.reason)}</p>`:''}${entry?.listener?.bindings?.length?`<p class="small">实际套接字：${esc(entry.listener.bindings.map(b=>(b.address.includes(':')?'['+b.address+']':b.address)+':'+b.port+' / '+b.transport.toUpperCase()).join('、'))}</p>`:''}${body}${kind==='websocket'||exit?'<p class="small muted">这里显示核心内部 WebSocket 监听；公网 HTTPS 的 TLS 由前置服务处理。</p>':''}${exit?'<p class="small">'+(exit.dynamic?'动态住宅入口；出口与健康状态请查看“动态住宅池”':('配置住宅出口：'+esc(exit.exit_ip)))+' · 在小火箭订阅列表选择此节点。</p><p class="small muted">此出口只转发 TCP；UDP 明确拒绝。DNS 请使用随节点转发的 DoH 模块。</p>':''}<p>公网自检 ${runtimeBadge(probeState)}</p><p class="small muted">采样 ${runtimeTime(monitor.updated)} · 最近成功 ${runtimeTime(probe?.last_success)}</p>${probe?.error?`<p class="small error">${esc(probe.error)}</p>`:''}${proc.config?.changed_since_start?'<p class="small error">配置文件在核心启动后修改；当前文件内容可能尚未生效。</p>':''}<p class="small muted">配置源：${esc(proc.config?.path||'未知')}。自检探测点：服务器自身。</p></article>`;
  }).join('');
}
let diagnosticsBusy=false;
async function loadDiagnostics(){
  if(diagnosticsBusy||!csrf||page!=='diagnostics')return;
  diagnosticsBusy=true;
  try{
    const d=await api('diagnostics');if(!csrf||page!=='diagnostics')return;
    const r=d.runtime||{},p=r.process||{},m=r.management_api||{},s=r.access_sync||{};r.stale=r.stale||!r.sampled||Date.now()/1000-r.sampled>(r.max_age_seconds||30);
    $('#diagnostics-error').textContent='';$('#diagnostics-sampled').textContent='服务器采样 '+runtimeTime(r.sampled)+(r.stale?' · 已过期':'');
    const rows=[['核心进程',r.stale?'unknown':p.state,p.reason||p.version_reason||'',p.started_at],['管理接口',r.stale?'unknown':m.state,'最近成功 '+runtimeTime(m.last_success),m.sampled],['访问权限同步',r.stale?'unknown':s.state,s.message||'最近完成 '+runtimeTime(s.last_success),s.sampled],['公网入口自检',d.monitor.status==='stale'?'stale':d.monitor.status,'探测点为服务器；不代表手机可用',d.monitor.updated]];
    $('#diagnostics-states').innerHTML=rows.map(([label,status,note,time])=>`<div class="runtime-tile"><span>${esc(label)}</span><p>${runtimeBadge(status)}</p><small>${esc(note)}<br>${runtimeTime(time)}</small></div>`).join('');
    $('#diagnostics-config').innerHTML=p.config?`<p>启动参数指向：<code>${esc(p.config.path)}</code></p><p>文件 SHA-256：<code>${esc(p.config.sha256)}</code></p><p>文件修改：${runtimeTime(p.config.modified_at)} · ${p.config.changed_since_start===true?'核心启动后修改，需确认是否已加载':p.config.changed_since_start===false?'未观察到启动后的文件修改':'无法比较启动时间'}</p><p class="small muted">这是配置文件当前内容的摘要，未导出用户、私钥或完整配置。文件未修改也不能单独证明运行配置完全一致。</p>`:`<p class="muted">${esc(p.config_reason||p.reason||'尚未读取配置来源')}</p>`;
    $('#diagnostics-transitions').innerHTML=d.transitions.length?'<table><thead><tr><th>时间</th><th>进程</th><th>管理接口</th><th>权限同步</th><th>原因</th></tr></thead><tbody>'+[...d.transitions].reverse().map(e=>`<tr><td>${runtimeTime(e.ts)}</td><td>${runtimeBadge(e.process_state)}</td><td>${runtimeBadge(e.api_state)}</td><td>${runtimeBadge(e.sync_state)}</td><td>${esc(e.message||'状态已更新')}</td></tr>`).join('')+'</tbody></table>':'<div class="empty">暂无状态变化记录。</div>';
    $('#diagnostics-operations').innerHTML=d.operations.length?d.operations.map(e=>`<div class="event"><time>${runtimeTime(e.ts)}</time><strong>核心重连</strong><span class="detail">${esc(e.detail)}</span></div>`).join(''):'<div class="empty">暂无核心重连操作记录。外部重启原因需检查服务日志；进程变化记录不能确定外部重启原因。</div>';
  }catch(error){$('#diagnostics-error').textContent=error.message+'；上次显示的结果可能已过期。'}finally{diagnosticsBusy=false}
}
$('#refresh-diagnostics').onclick=loadDiagnostics;
// Expire cached status even when an HTTP request is still in flight.
setInterval(()=>{
  if(!csrf||!state?.runtime)return;
  const r=state.runtime;
  if(!r.sampled||Date.now()/1000-r.sampled>(r.max_age_seconds||30)) {
    renderRuntime(r,state.monitor);
    if(page==='diagnostics'){
      $('#diagnostics-sampled').textContent='运行采样已过期';
      $$('#diagnostics-states .badge').forEach(b=>{b.className='badge';b.textContent='未知／采样过期'});
    }
  }
},5000);
