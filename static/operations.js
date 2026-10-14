'use strict';
let historyData=null, historyRequest=0, notificationBusy=false;
const serviceNames={reality:'REALITY 入口',websocket:'WebSocket / TLS 入口',hysteria2:'Hysteria 2 入口',vmess:'VMess / TLS 入口',probe:'探测结果采集',core:'Xray 管理接口',backup:'本地自动加密备份',test:'通知通道测试'};
const deliveryNames={pending:'等待投递',delivered:'已投递',failed:'投递失败',cancelled:'已取消',superseded:'已被新状态替代'};
const presentDate=stamp=>stamp?date(stamp):'—';
const milliseconds=n=>n===null||n===undefined?'—':Number(n).toFixed(0)+' ms';

async function loadHistory(){
  const request=++historyRequest;
  try{
    const data=await api('history?range='+encodeURIComponent($('#history-range').value));
    if(request!==historyRequest||!csrf)return;
    historyData=data;$('#history-error').textContent='';renderHistory();
  }catch(err){if(request===historyRequest)$('#history-error').textContent=err.message}
}
function renderHistory(){
  if(!historyData)return;
  const h=historyData,kinds=h.transports||enabledTransports(),totals=h.traffic.reduce((sum,p)=>({up:sum.up+p.upload,down:sum.down+p.download}),{up:0,down:0});
  $('#history-summary').innerHTML=kinds.map(kind=>{
    const s=h.summary.find(row=>row.transport===kind),known=s?(s.healthy+s.failed):0;
    return `<article><span>${esc(serviceNames[kind]||transportLabel(kind))} 探测成功率</span><strong>${known?s.success_percent.toFixed(2)+'%':'—'}</strong><small>${known?'成功 '+s.healthy+' / 已知 '+known:'暂无有效探测'}${s?.unknown?' · 未知 '+s.unknown:''}</small></article>`;
  }).join('')+`<article><span>所选范围下载</span><strong>${h.traffic.length?bytes(totals.down):'—'}</strong><small>已采集流量合计</small></article><article><span>所选范围上传</span><strong>${h.traffic.length?bytes(totals.up):'—'}</strong><small>缺测时段不计入</small></article>`;
  $('#history-traffic-note').textContent=`每 ${h.bucket_seconds/60} 分钟流量；当前时间档可能尚未结束。`;
  $('#history-probe-note').textContent=`成功率按已知探测计算，未知和缺测不算成功。${h.first_probe?'开始记录于 '+date(h.first_probe)+'。':'升级后首次探测完成时开始记录。'}探测点为服务器自身。`;
  const grouped=new Map();for(const row of h.probes){if(!grouped.has(row.ts))grouped.set(row.ts,{});grouped.get(row.ts)[row.transport]=row}
  const rows=[...grouped.entries()].sort((a,b)=>b[0]-a[0]).slice(0,12);
  function cell(row){return row?`${row.healthy} 成功 / ${row.failed} 失败${row.unknown?' / '+row.unknown+' 未知':''}<br><small class="muted">HTTPS ${milliseconds(row.https_ms)} · UDP ${milliseconds(row.udp_ms)}</small>`:'<span class="muted">无采样</span>'}
  $('#history-table').innerHTML=rows.length?'<table><thead><tr><th>时间档起点</th>'+kinds.map(kind=>`<th>${esc(transportLabel(kind))}</th>`).join('')+'</tr></thead><tbody>'+rows.map(([ts,row])=>`<tr><td>${date(ts)}</td>${kinds.map(kind=>`<td>${cell(row[kind])}</td>`).join('')}</tr>`).join('')+'</tbody></table>':'<div class="empty">此范围内还没有探测记录。</div>';
  drawHistoryCharts();
}
function drawHistoryCharts(){
  if(!historyData||page!=='history')return;
  const h=historyData;
  const traffic=[['download','#169d88'],['upload','#7095be']].map(([key,color])=>({color,points:new Map(h.traffic.map(p=>[p.ts,p[key]]))}));
  plotHistory($('#history-traffic'),traffic,bytes);
  const latency=[['reality','https_ms','#169d88'],['websocket','https_ms','#7095be'],['reality','udp_ms','#a275bf'],['websocket','udp_ms','#d49a51'],['hysteria2','https_ms','#b55e85'],['hysteria2','udp_ms','#68823c']].map(([transport,key,color])=>({color,points:new Map(h.probes.filter(p=>p.transport===transport).map(p=>[p.ts,p[key]]))}));
  plotHistory($('#history-latency'),latency,n=>Math.round(n)+' ms');
}
function plotHistory(canvas,series,format){
  const width=canvas.clientWidth;if(!width)return;
  const h=historyData,height=240,dpr=window.devicePixelRatio||1;
  canvas.width=width*dpr;canvas.height=height*dpr;
  const c=canvas.getContext('2d');c.scale(dpr,dpr);
  const left=66,right=14,top=18,bottom=35,usable=width-left-right;
  const valid=series.flatMap(s=>[...s.points.values()].filter(n=>n!==null&&Number.isFinite(n)));
  const max=Math.max(1,...valid)*1.15,end=Math.floor(h.end/h.bucket_seconds)*h.bucket_seconds,span=Math.max(h.bucket_seconds,end-h.start);
  c.font='11px -apple-system,sans-serif';c.fillStyle='#8797a2';c.strokeStyle='#eef2f5';c.lineWidth=1;
  for(let i=0;i<4;i++){const y=top+i*(height-top-bottom)/3;c.beginPath();c.moveTo(left,y);c.lineTo(width-right,y);c.stroke();c.fillText(format(max*(1-i/3)),0,y+4)}
  for(let i=0;i<3;i++){
    const stamp=h.start+span*i/2;
    const label=new Date(stamp*1000).toLocaleString('zh-CN',h.range==='1h'||h.range==='24h'?{hour:'2-digit',minute:'2-digit'}:{month:'2-digit',day:'2-digit',hour:'2-digit'});
    c.textAlign=i===0?'left':i===2?'right':'center';c.fillText(label,left+usable*i/2,height-9);
  }
  c.textAlign='left';
  if(!valid.length){c.fillText('此范围内暂无采样数据',left+18,top+45);return}
  for(const s of series){
    c.strokeStyle=s.color;c.fillStyle=s.color;c.lineWidth=2;c.beginPath();let pen=false;
    for(let ts=h.start;ts<=end;ts+=h.bucket_seconds){
      const value=s.points.get(ts);
      if(value===undefined||value===null||!Number.isFinite(value)){pen=false;continue}
      const x=left+(ts-h.start)/span*usable,y=top+(1-value/max)*(height-top-bottom);
      if(pen)c.lineTo(x,y);else c.moveTo(x,y);pen=true;
    }
    c.stroke();
    for(const [ts,value] of s.points){
      if(value===null||!Number.isFinite(value))continue;
      const x=left+(ts-h.start)/span*usable,y=top+(1-value/max)*(height-top-bottom);
      c.beginPath();c.arc(x,y,1.7,0,2*Math.PI);c.fill();
    }
  }
}
function clearOperationsSecrets(){
  const form=$('#notification-form');if(!form)return;
  for(const key of ['url','bearer','signing_secret','current_password','code'])form.elements[key].value='';
  form.elements.clear_auth.checked=false;form.elements.clear_url.checked=false;
}
async function loadNotifications(fill=false){
  if(notificationBusy)return;notificationBusy=true;
  try{
    const n=await api('notifications');if(!csrf)return;
    const f=$('#notification-form');
    if(fill){clearOperationsSecrets();f.elements.enabled.checked=n.enabled;f.elements.failures.value=n.failures;f.elements.recoveries.value=n.recoveries;$('#notification-error').textContent=''}
    $('#notification-badge').textContent=n.enabled?'通知已启用':n.configured?'已配置 · 未启用':'等待配置';
    $('#notification-badge').className='badge '+(n.enabled?'good':'');
    $('#notification-destination').textContent=n.configured?`当前目标：${n.destination}。${n.has_bearer?'已保存 Token。':''}${n.has_signing_secret?'已启用消息签名。':''}`:'尚未保存接收地址。填写地址并保存后，可发送测试通知。';
    $('#notification-test').disabled=!n.configured;
    $('#notification-alarms').innerHTML=n.alarms.length?n.alarms.map(a=>`<div class="alarm-card"><strong>${esc(serviceNames[a.service]||a.service)}</strong><span class="badge bad">持续异常</span><p class="small muted">开始于 ${presentDate(a.since)} · 最近观察 ${presentDate(a.last_seen)}</p></div>`).join(''):'<div class="empty">当前没有达到通知阈值的故障。</div>';
    $('#notification-deliveries').innerHTML=n.deliveries.length?'<table><thead><tr><th>事件</th><th>时间</th><th>投递状态</th><th>说明</th></tr></thead><tbody>'+n.deliveries.map(d=>`<tr><td>${esc(serviceNames[d.service]||d.service)}<br><small class="muted">${({fault:'故障',recovery:'恢复',test:'测试'})[d.kind]||esc(d.kind)}</small></td><td>${date(d.created)}</td><td><span class="badge ${d.status==='delivered'?'good':d.status==='failed'?'bad':''}">${d.status==='pending'&&d.attempts?'等待重试':esc(deliveryNames[d.status]||d.status)}</span><br><small class="muted">已尝试 ${d.attempts} 次${d.http_status?' · HTTP '+d.http_status:''}</small></td><td class="delivery-detail">${esc(d.last_error|| (d.delivered?'接收端已确认':'排队中'))}${d.status==='pending'&&d.attempts?'<br><small class="muted">下次尝试 '+date(d.next_attempt)+'</small>':''}</td></tr>`).join('')+'</tbody></table>':'<div class="empty">尚无通知。保存接收地址后，可先发送一条测试。</div>';
  }catch(err){$('#notification-error').textContent=err.message}finally{notificationBusy=false}
}
$('#history-range').onchange=loadHistory;
window.addEventListener('resize',drawHistoryCharts);
$('#notification-form').onsubmit=async e=>{
  e.preventDefault();const f=e.currentTarget,button=f.querySelector('button[type="submit"]');button.disabled=true;$('#notification-error').textContent='';
  try{
    const body=Object.fromEntries(new FormData(f));
    for(const key of ['enabled','clear_auth','clear_url'])body[key]=f.elements[key].checked;
    for(const key of ['failures','recoveries'])body[key]=Number(f.elements[key].value);
    await api('notifications','PUT',body);clearOperationsSecrets();toast('通知配置已保存');await loadNotifications(true);
  }catch(err){$('#notification-error').textContent=err.message}finally{button.disabled=false}
};
$('#notification-test').onclick=async()=>{
  const button=$('#notification-test');button.disabled=true;
  try{await api('notifications/test','POST',{});toast('测试通知已排队，请查看投递记录并确认收到消息');await loadNotifications()}
  catch(err){$('#notification-error').textContent=err.message}
  finally{button.disabled=false}
};
setInterval(()=>{if(!csrf)return;if(page==='history')loadHistory();if(page==='notifications')loadNotifications()},10000);
