let webshareBusy=false,webshareState=null,websharePlanDirty=false;
let webshareCountries={US:'美国',JP:'日本',SG:'新加坡',ZZ:'全球'};
function clearWebshareSecrets(){const f=$('#webshare-key-form');if(f)f.reset();}
async function loadWebshare(reset=false){
  if(webshareBusy||!csrf||page!=='webshare')return;
  webshareBusy=true;
  try{
    const s=await api('webshare');if(!csrf||page!=='webshare')return;webshareState=s;
    const labels={healthy:'运行正常',degraded:'部分地区不可用',disabled:'未启用',unconfigured:'待配置',unknown:'等待服务',stale:'状态已过期'};
    $('#webshare-badge').textContent=labels[s.status]||'等待服务';$('#webshare-badge').className='badge '+(s.status==='healthy'?'good':'');
    $('#webshare-message').textContent=!s.installed?'动态池服务尚未安装，请先完成服务器部署。':s.message+(s.requested_revision!==s.revision?' · 正在应用配置…':'');
    $('#webshare-error').textContent=s.sync_error||s.usage_error||'';
    $('#webshare-key-status').textContent=s.key_saved?'已保存 API Key。输入新值可替换，原密钥不回显。':'尚未保存 API Key。';
    const form=$('#webshare-plan-form'),select=form.elements.plan_id;
    if(reset||!websharePlanDirty){
      select.innerHTML='<option value="0">请选择动态住宅套餐</option>'+s.plans.map(p=>`<option value="${Number(p.id)}" ${p.eligible?'':'disabled'}>${esc(p.label)}${p.bandwidth_limit?' · '+esc(p.bandwidth_limit)+' GB':''}</option>`).join('');
      select.value=String(s.plan_id||0);form.elements.enabled.checked=!!s.enabled;websharePlanDirty=false;
    }
    form.querySelector('button').disabled=!s.installed||!s.key_saved;$('#webshare-sync').disabled=!s.key_saved;$('#webshare-clear').disabled=!s.key_saved;
    const rows=[['最后成功同步',s.last_sync?date(s.last_sync):'尚无'],['当前使用套餐',s.active_plan_id?'#'+s.active_plan_id:'未选择'],['最近 24 小时流量',s.bandwidth_total===undefined?'等待供应商统计':bytes(s.bandwidth_total)],['请求成功 / 总数',s.requests_total===undefined?'等待供应商统计':(s.requests_successful||0)+' / '+s.requests_total],['用量更新时间',s.usage_updated?date(s.usage_updated):'尚无']];
    $('#webshare-summary').innerHTML=rows.map(([k,v])=>`<div><dt>${esc(k)}</dt><dd>${esc(v)}</dd></div>`).join('');
    webshareCountries=Object.fromEntries((s.regions||[]).map(r=>[r.country,r.label]));
    renderWebsharePools(s);
    $('#webshare-events').innerHTML=s.events.length?s.events.map(e=>`<div class="event"><time>${date(e.ts)}</time><strong>${esc(webshareCountries[e.country]||e.country)}</strong><span class="detail">${esc(e.reason)}</span></div>`).join(''):'<p class="muted">尚无会话切换记录</p>';
  }catch(err){$('#webshare-error').textContent=err.message;}finally{webshareBusy=false;}
}
function renderWebsharePools(s){
  const query=$('#webshare-country-filter').value.trim().toLowerCase();
  const regions=(s.regions||[]).filter(r=>!query||(r.country+' '+r.label+' '+r.group).toLowerCase().includes(query));
  const groups=['亚洲','北美','欧洲','大洋洲','全球'];
  $('#webshare-pools').innerHTML=groups.map(group=>{
    const entries=regions.filter(r=>r.group===group);if(!entries.length)return '';
    return `<section class="country-section"><h2>${esc(group)} <span class="count">${entries.length}</span></h2><div class="node-grid">`+entries.map(r=>{
      const country=r.country,p=s.pools.find(v=>v.country===country)||{},healthy=p.status==='healthy'&&s.status!=='stale';
      const standby=Number(p.ready_standby??p.standby??0),label=healthy?(standby?'可用 · 有备用':'可用 · 补充备用'):s.status==='stale'?'状态已过期':s.enabled?'寻找出口':'未启用';
      return `<article class="panel"><div class="panel-heading"><h3>${esc(r.label)} <span class="small muted">${esc(country==='ZZ'?'WORLD':country)}</span></h3><span class="badge ${healthy?'good':''}">${esc(label)}</span></div><p>当前出口：${esc(p.exit_ip||'尚未分配')}${p.exit_country?' · '+esc(p.exit_country):''}</p><p>HTTPS ${p.https_ms===undefined?'—':esc(p.https_ms)+' ms'} · DoH ${p.doh_ms===undefined?'—':esc(p.doh_ms)+' ms'}</p><p class="small">可用备用 ${standby} / 3 · 本次运行连接故障切换 ${Number(p.failovers||0)} 次</p><p class="muted small">最近探测成功 ${p.last_success?date(p.last_success):'尚无'}<br>当前探测间隔 ${Math.round(Number(p.probe_interval||900)/60)} 分钟；有流量时自动加快。</p><button class="secondary" type="button" data-webshare-rotate="${esc(country)}" ${s.enabled&&s.status!=='stale'?'':'disabled'}>更换后续连接的出口</button></article>`;
    }).join('')+'</div></section>';
  }).join('')||'<p class="muted">没有匹配的国家/地区。</p>';
}
$('#webshare-country-filter').oninput=()=>{if(webshareState)renderWebsharePools(webshareState);};
async function webshareSave(button,body){
  button.disabled=true;
  try{await api('webshare','PUT',body);clearWebshareSecrets();websharePlanDirty=false;toast('已保存，后台正在应用');await loadWebshare(true);}catch(err){$('#webshare-error').textContent=err.message;}finally{button.disabled=false;}
}
$('#webshare-key-form').onsubmit=e=>{e.preventDefault();webshareSave(e.submitter,{api_key:e.currentTarget.elements.api_key.value.trim()});};
$('#webshare-plan-form').onchange=()=>{websharePlanDirty=true;};
$('#webshare-plan-form').onsubmit=e=>{e.preventDefault();webshareSave(e.submitter,{plan_id:Number(e.currentTarget.elements.plan_id.value),enabled:e.currentTarget.elements.enabled.checked});};
$('#webshare-clear').onclick=e=>{if(confirm('移除 Webshare API Key 并关闭所有动态住宅连接？固定住宅节点将继续可用。'))webshareSave(e.currentTarget,{clear_key:true});};
async function webshareAction(button,body){button.disabled=true;try{await api('webshare/action','POST',body);toast('请求已提交，后台正在处理');await loadWebshare();}catch(err){$('#webshare-error').textContent=err.message;}finally{button.disabled=false;}}
$('#webshare-sync').onclick=e=>webshareAction(e.currentTarget,{action:'sync'});
$('#webshare-pools').onclick=e=>{const b=e.target.closest('[data-webshare-rotate]');if(b)webshareAction(b,{action:'rotate',country:b.dataset.webshareRotate});};
setInterval(()=>loadWebshare(),5000);
