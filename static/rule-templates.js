'use strict';
let ruleTemplateState=null;

async function loadRuleTemplates(){
  ruleTemplateState=await api('rule-templates');
  const {templates,users}=ruleTemplateState;
  $('#rule-template-list').innerHTML='<table><thead><tr><th>模板</th><th>状态</th><th>使用人数</th><th>操作</th></tr></thead><tbody>'+
    templates.map(t=>{
      const count=users.filter(u=>u.template_id===t.id).length;
      const status=t.builtin?(t.revision!==t.published_revision?'内置 · 草稿有修改':'内置 · 已发布'):
        !t.published?'未发布':t.revision!==t.published_revision?'已发布 · 草稿有修改':'已发布';
      const actions='<button data-template-action="edit" data-id="'+esc(t.id)+'">编辑草稿</button> '+
        '<button data-template-action="copy" data-id="'+esc(t.id)+'">'+(t.builtin?'复制为自定义':'复制')+'</button>'+
        (t.builtin?' <button data-template-action="reset" data-id="'+esc(t.id)+'">恢复默认</button>':'')+
        (t.builtin&&t.can_undo_reset?' <button data-template-action="undo-reset" data-id="'+esc(t.id)+'">撤销恢复</button>':'');
      return '<tr><td>'+esc(t.name)+'</td><td>'+status+'</td><td>'+count+'</td><td class="actions">'+actions+'</td></tr>';
    }).join('')+'</tbody></table>';
}

function templateById(id){return ruleTemplateState?.templates.find(t=>t.id===id)}
function templateUseCount(id){return ruleTemplateState?.users.filter(u=>u.template_id===id).length||0}

const ruleKinds={
  'DOMAIN-SUFFIX':{label:'域名及子域名',hint:'例如 example.com，匹配该域名及其子域名。'},
  'DOMAIN':{label:'完整域名',hint:'例如 www.example.com，只匹配这个完整域名。'},
  'DOMAIN-KEYWORD':{label:'域名关键词',hint:'例如 example，匹配域名中包含该关键词的连接。'},
  'IP-CIDR':{label:'IPv4 网段',hint:'例如 198.51.100.0/24；单个 IPv4 地址可使用 /32。'},
  'IP-CIDR6':{label:'IPv6 网段',hint:'例如 2001:db8::/32；需客户端启用 IPv6。'},
  'GEOIP':{label:'IP 所在国家或地区',hint:'输入两位国家或地区代码，例如 CN、US；匹配结果取决于客户端的 GeoIP 数据。'},
  'DST-PORT':{label:'目标端口',hint:'输入 1–65535 的单个目标端口；该规则会匹配所有使用此端口的连接。'}
};
let ruleEditing=null,ruleUndo=[],ruleSelection=new Set(),ruleLastText='',ruleSavedSnapshot='';
const ruleText=()=>$('#rule-template-form').elements.rules;
const ruleLines=()=>ruleText().value.replace(/\r\n/g,'\n').split('\n');
function ruleSnapshot(){const f=$('#rule-template-form');return JSON.stringify([f.elements.name.value,f.elements.base.value,f.elements.ai_outbound.value,f.elements.rules.value])}
function pendingBatchEdit(){return !$('#rule-batch-editor').hidden&&Boolean($('#rule-batch-type').value||$('#rule-batch-target').value||$('#rule-batch-resolution').value)}
function ruleEditorDirty(){return ruleSnapshot()!==ruleSavedSnapshot||ruleEditing!==null||Boolean($('#rule-entry-value').value.trim())||pendingBatchEdit()}
function mayCloseRuleEditor(){return !ruleEditorDirty()||confirm('模板有尚未保存的修改，关闭后这些修改会丢失。确定关闭吗？')}
function parsedRuleLines(){
  return ruleLines().map((line,index)=>{
    const text=line.trim();if(!text||text.startsWith('#'))return null;
    const fields=text.split(',').map(x=>x.trim());
    return {index,text,fields,valid:(fields.length===3||fields.length===4)&&Object.prototype.hasOwnProperty.call(ruleKinds,fields[0])};
  }).filter(Boolean);
}
function ruleTargets(base){
  return ['DIRECT','REJECT','PROXY',...(base==='standard'?['STUN']:
    ['EaseLian','独立 · AI','独立 · Telegram','独立 · YouTube','独立 · Netflix','独立 · 国外媒体','独立 · STUN','其他流量'])];
}
function updateRuleTargets(preferred){
  const select=$('#rule-entry-target'),targets=ruleTargets($('#rule-template-form').elements.base.value),old=preferred||select.value;
  select.innerHTML=targets.map(t=>'<option value="'+esc(t)+'">'+esc(t)+'</option>').join('');
  if(old&&!targets.includes(old))select.insertAdjacentHTML('beforeend','<option value="'+esc(old)+'" disabled>'+esc(old)+'（当前模板不可用）</option>');
  select.value=old||'PROXY';
  const batch=$('#rule-batch-target'),previous=batch.value;
  batch.innerHTML='<option value="">保持不变</option>'+targets.map(t=>'<option value="'+esc(t)+'">'+esc(t)+'</option>').join('');
  batch.value=targets.includes(previous)?previous:'';
}
function updateRuleHint(resetResolution=false){
  const type=$('#rule-entry-type').value,ip=['IP-CIDR','IP-CIDR6','GEOIP'].includes(type);
  $('#rule-entry-hint').textContent=ruleKinds[type]?.hint||'';
  $('#rule-entry-value').placeholder=type==='GEOIP'?'CN\nUS':type==='DST-PORT'?'443\n8443':type==='IP-CIDR'?'198.51.100.0/24':type==='IP-CIDR6'?'2001:db8::/32':'example.com';
  $('#rule-entry-resolution-label').hidden=!ip;
  if(resetResolution)$('#rule-entry-resolution').value=type==='GEOIP'?'resolve':'no-resolve';
}
function resetRuleEntry(){
  ruleEditing=null;$('#rule-entry-value').value='';$('#rule-entry-error').textContent='';
  $('#rule-builder-title').textContent='添加规则';$$('#rule-list tr.rule-editing').forEach(row=>row.classList.remove('rule-editing'));
  $('#rule-entry-add').textContent='添加规则';$('#rule-entry-cancel').hidden=true;$('#rule-entry-position-label').hidden=false;
}
function rememberRuleText(value,nextSelection=ruleSelection){
  if(value!==ruleText().value){
    ruleUndo.push({text:ruleText().value,selection:[...ruleSelection]});if(ruleUndo.length>30)ruleUndo.shift();
    ruleText().value=value;ruleLastText=value;
  }
  ruleSelection=new Set(nextSelection);renderRuleRows();
}
function visibleRuleLines(all){
  const query=$('#rule-list-search').value.trim().toLowerCase();
  return all.filter(r=>!query||r.text.toLowerCase().includes(query)||(ruleKinds[r.fields[0]]?.label||'').includes(query));
}
function syncRuleSelection(visible){
  const shown=visible.filter(r=>ruleSelection.has(r.index)).length,hidden=ruleSelection.size-shown;
  $('#rule-selection-count').textContent='已选择 '+ruleSelection.size+' 条'+(hidden?'（其中 '+hidden+' 条不在当前筛选结果）':'');
  for(const id of ['rule-selection-clear','rule-batch-open','rule-batch-delete'])$('#'+id).disabled=ruleSelection.size===0;
  const master=$('#rule-select-visible');
  if(master){master.checked=visible.length>0&&shown===visible.length;master.indeterminate=shown>0&&shown<visible.length}
  $$('#rule-list [data-rule-select]').forEach(input=>input.checked=ruleSelection.has(Number(input.dataset.ruleSelect)));
}
function renderRuleRows(){
  const all=parsedRuleLines(),visible=visibleRuleLines(all),query=$('#rule-list-search').value.trim();
  const validIndices=new Set(all.map(r=>r.index));ruleSelection=new Set([...ruleSelection].filter(i=>validIndices.has(i)));
  const scrollTop=$('#rule-list').scrollTop;
  $('#rule-list-count').textContent='共 '+all.length+' 条'+(query?'，显示 '+visible.length+' 条':'')+'；'+new TextEncoder().encode(ruleText().value).length+' / 14000 字节，最多 500 条。';
  $('#rule-list-undo').disabled=ruleUndo.length===0;
  const ordinal=new Map(all.map((r,i)=>[r.index,i]));
  $('#rule-list').innerHTML=visible.length?'<table><thead><tr><th class="rule-select-cell"><label class="rule-select-label"><input id="rule-select-visible" type="checkbox" aria-label="全选当前筛选结果">全选</label></th><th>顺序</th><th>类型</th><th>匹配内容</th><th>目标</th><th>操作</th></tr></thead><tbody>'+visible.map(r=>{
    const n=ordinal.get(r.index),f=r.fields,type=ruleKinds[f[0]]?.label||'格式待检查';
    const detail=r.valid?esc(f[1]):esc(r.text),option=r.valid&&f[3]?' <span class="muted">('+esc(f[3])+')</span>':'';
    const edit=r.valid?'<button type="button" data-rule-action="edit" data-index="'+r.index+'" aria-label="编辑第 '+(n+1)+' 条规则">编辑</button> ':'';
    const targetWarning=r.valid&&!ruleTargets($('#rule-template-form').elements.base.value).includes(f[2])?'<small class="error">当前模板不可用</small>':'';
    return '<tr'+(ruleEditing===r.index?' class="rule-editing"':'')+'><td class="rule-select-cell"><input type="checkbox" data-rule-select="'+r.index+'" aria-label="选择第 '+(n+1)+' 条规则" '+(ruleSelection.has(r.index)?'checked':'')+'></td><td>'+(n+1)+'</td><td class="rule-type">'+esc(type)+'<small>'+esc(f[0]||'')+'</small></td><td class="rule-value">'+detail+option+'</td><td>'+esc(r.valid?f[2]:'—')+targetWarning+'</td><td class="rule-row-actions">'+edit+
      '<button type="button" data-rule-action="up" data-index="'+r.index+'" aria-label="上移第 '+(n+1)+' 条规则" '+(n===0?'disabled':'')+'>↑</button> '+
      '<button type="button" data-rule-action="down" data-index="'+r.index+'" aria-label="下移第 '+(n+1)+' 条规则" '+(n===all.length-1?'disabled':'')+'>↓</button> '+
      '<button type="button" data-rule-action="delete" data-index="'+r.index+'" aria-label="删除第 '+(n+1)+' 条规则">删除</button></td></tr>';
  }).join('')+'</tbody></table>':'<p class="empty">'+(query?'没有匹配的规则':'还没有分类规则，可以在上方添加。')+'</p>';
  $('#rule-list').scrollTop=scrollTop;
  syncRuleSelection(visible);
}
function validateRuleEntry(type,value){
  if(value.includes(','))return '匹配内容不能包含逗号；完整规则请在下方文本编辑区填写。';
  if(type==='DOMAIN'||type==='DOMAIN-SUFFIX'){
    if(value.length>253||!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(value))return '请输入有效的英文域名，例如 example.com。';
  }else if(type==='DOMAIN-KEYWORD'){
    if(value.length>253||!/^[a-z0-9.-]+$/.test(value))return '关键词只能包含小写字母、数字、点和短横线。';
  }else if(type==='IP-CIDR'||type==='IP-CIDR6'){
    const parts=value.split('/'),prefix=parts[1],v6=type==='IP-CIDR6';
    if(parts.length!==2||!/^\d{1,3}$/.test(prefix)||Number(prefix)>(v6?128:32))return '请输入有效的 IP 网段和掩码。';
    if(v6){try{new URL('http://['+parts[0]+']/')}catch{return '请输入有效的 IPv6 网段，例如 2001:db8::/32。'}}
    else if(!/^(?:\d{1,3}\.){3}\d{1,3}$/.test(parts[0])||parts[0].split('.').some(x=>Number(x)>255||(x.length>1&&x[0]==='0')))
      return '请输入有效的 IPv4 网段，例如 198.51.100.0/24。';
  }else if(type==='GEOIP'){
    if(!/^[A-Z]{2}$/.test(value))return '请输入两位国家或地区代码，例如 CN。';
  }else if(type==='DST-PORT'){
    if(!/^\d{1,5}$/.test(value)||Number(value)<1||Number(value)>65535)return '请输入 1–65535 的单个端口。';
  }
  return '';
}
$('#rule-entry-type').onchange=()=>updateRuleHint(true);
$('#rule-template-form').elements.base.onchange=()=>{updateRuleTargets();renderRuleRows()};
$('#rule-list-search').oninput=()=>renderRuleRows();
$('#rule-entry-cancel').onclick=()=>resetRuleEntry();
$('#rule-list').addEventListener('change',e=>{
  const input=e.target,visible=visibleRuleLines(parsedRuleLines());
  if(input.id==='rule-select-visible')for(const row of visible){if(input.checked)ruleSelection.add(row.index);else ruleSelection.delete(row.index)}
  else if(input.dataset.ruleSelect!==undefined){const index=Number(input.dataset.ruleSelect);if(input.checked)ruleSelection.add(index);else ruleSelection.delete(index)}
  else return;
  $('#rule-batch-error').textContent='';syncRuleSelection(visible);
});
$('#rule-selection-clear').onclick=()=>{ruleSelection.clear();$('#rule-batch-error').textContent='';syncRuleSelection(visibleRuleLines(parsedRuleLines()))};
$('#rule-batch-open').onclick=()=>{if($('#rule-batch-editor').hidden){$('#rule-batch-type').value='';$('#rule-batch-target').value='';$('#rule-batch-resolution').value='';$('#rule-batch-editor').hidden=false;$('#rule-batch-error').textContent=''}$('#rule-batch-type').focus()};
$('#rule-batch-cancel').onclick=()=>{$('#rule-batch-editor').hidden=true;$('#rule-batch-error').textContent=''};
function batchReady(){
  const error=$('#rule-batch-error');error.textContent='';
  const reject=message=>{error.textContent=message;if($('#rule-batch-editor').hidden)toast(message);return false};
  if(!ruleSelection.size)return reject('请先选择规则。');
  if(ruleEditing!==null||$('#rule-entry-value').value.trim())return reject('请先应用或取消正在编辑的规则，或清空添加框。');
  return true;
}
$('#rule-batch-delete').onclick=()=>{
  if(!batchReady())return;
  if(pendingBatchEdit()){$('#rule-batch-error').textContent='请先应用或取消批量修改。';return}
  const removed=ruleSelection.size,lines=ruleLines().filter((_,index)=>!ruleSelection.has(index));
  rememberRuleText(lines.join('\n'),new Set());$('#rule-batch-editor').hidden=true;
  toast('已从草稿删除 '+removed+' 条规则，可撤销');
};
$('#rule-batch-apply').onclick=()=>{
  if(!batchReady())return;
  const changedType=$('#rule-batch-type').value,changedTarget=$('#rule-batch-target').value,resolution=$('#rule-batch-resolution').value;
  const error=$('#rule-batch-error'),ipTypes=['IP-CIDR','IP-CIDR6','GEOIP'];
  if(!changedType&&!changedTarget&&!resolution){error.textContent='请选择至少一个要修改的字段。';return}
  const lines=ruleLines(),all=parsedRuleLines(),selected=all.filter(row=>ruleSelection.has(row.index));
  for(const row of selected){
    const number=all.indexOf(row)+1,f=row.fields;
    if(!row.valid){error.textContent='第 '+number+' 条规则格式不完整，请先编辑或删除。';return}
    const type=changedType||f[0],target=changedTarget||f[2],problem=validateRuleEntry(type,f[1]);
    if(problem){error.textContent='第 '+number+' 条：'+problem+' 未应用任何修改。';return}
    if(!ruleTargets($('#rule-template-form').elements.base.value).includes(target)){error.textContent='第 '+number+' 条的目标不属于当前基础模板。';return}
    if(f.length===4&&(!ipTypes.includes(f[0])||!['resolve','no-resolve'].includes(f[3]))){error.textContent='第 '+number+' 条的解析选项无效，请先修正。';return}
    if(resolution&&!ipTypes.includes(type)){error.textContent='第 '+number+' 条不是 IP 网段或 GeoIP，不能设置 IP 解析方式。';return}
    let option='';
    if(ipTypes.includes(type)){
      if(resolution)option=resolution;
      else if(type===f[0])option=f[3]||'';
      else option=ipTypes.includes(f[0])?(f[3]||(f[0]==='GEOIP'?'resolve':'no-resolve')):(type==='GEOIP'?'resolve':'no-resolve');
    }
    lines[row.index]=[type,f[1],target,...(option?[option]:[])].join(',');
  }
  const text=lines.join('\n');
  if(new TextEncoder().encode(text).length>14000){error.textContent='修改后超过 14000 字节，未应用任何修改。';return}
  const unchanged=text===ruleText().value;rememberRuleText(text);$('#rule-batch-editor').hidden=true;
  toast(unchanged?'所选规则没有变化':'已修改 '+selected.length+' 条草稿规则，可撤销');
};
$('#rule-entry-add').onclick=()=>{
  const type=$('#rule-entry-type').value,target=$('#rule-entry-target').value;
  const values=$('#rule-entry-value').value.split(/\r?\n/).map(x=>x.trim()).filter(Boolean).map(x=>
    type==='GEOIP'?x.toUpperCase():type.startsWith('DOMAIN')?x.toLowerCase():x);
  const error=$('#rule-entry-error');error.textContent='';
  if(!values.length){error.textContent='请填写匹配内容。';return}
  if(!ruleTargets($('#rule-template-form').elements.base.value).includes(target)){error.textContent='请选择当前基础模板提供的目标策略。';return}
  if(ruleEditing!==null&&values.length!==1){error.textContent='修改规则时只能填写一行匹配内容。';return}
  for(let i=0;i<values.length;i++){const problem=validateRuleEntry(type,values[i]);if(problem){error.textContent='第 '+(i+1)+' 行：'+problem;return}}
  const ip=['IP-CIDR','IP-CIDR6','GEOIP'].includes(type),resolution=$('#rule-entry-resolution').value;
  const option=ip?','+resolution:'';
  const added=values.map(value=>[type,value,target].join(',')+option),lines=ruleLines();let nextSelection=new Set(ruleSelection);
  if(ruleEditing!==null)lines[ruleEditing]=added[0];
  else{if(lines.at(-1)==='')lines.pop();if($('#rule-entry-position').value==='start'){lines.unshift(...added);nextSelection=new Set([...ruleSelection].map(i=>i+added.length))}else lines.push(...added)}
  const text=lines.join('\n')+(lines.at(-1)===''?'':'\n'),count=lines.filter(x=>x.trim()&&!x.trim().startsWith('#')).length;
  if(count>500||new TextEncoder().encode(text).length>14000){error.textContent='规则最多 500 条，总内容最多 14000 字节。';return}
  const wasEditing=ruleEditing!==null;rememberRuleText(text,nextSelection);resetRuleEntry();toast(wasEditing?'规则已修改':'规则已加入草稿');
};
$('#rule-list').onclick=e=>{
  const button=e.target.closest('[data-rule-action]');if(!button)return;
  const index=Number(button.dataset.index),action=button.dataset.ruleAction,all=parsedRuleLines(),item=all.find(r=>r.index===index);
  if(!item)return;
  if(ruleEditing!==null||$('#rule-entry-value').value.trim()){$('#rule-entry-error').textContent='请先应用或取消正在编辑的规则，或清空添加框。';$('#rule-entry-value').focus();return}
  if(action==='edit'){
    if(!item.valid)return;
    const [type,value,target,option]=item.fields;ruleEditing=index;
    $('#rule-entry-type').value=type;updateRuleTargets(target);updateRuleHint();
    $('#rule-entry-value').value=value;
    $('#rule-entry-resolution').value=option||((type==='GEOIP')?'resolve':'no-resolve');
    $('#rule-entry-add').textContent='应用修改';$('#rule-entry-cancel').hidden=false;$('#rule-entry-position-label').hidden=true;
    $('#rule-builder-title').textContent='修改第 '+(all.indexOf(item)+1)+' 条规则';
    $('#rule-entry-error').textContent='';renderRuleRows();$('#rule-entry-value').focus();return;
  }
  const lines=ruleLines(),at=all.findIndex(r=>r.index===index);let nextSelection;
  if(action==='delete'){lines.splice(index,1);nextSelection=new Set([...ruleSelection].filter(i=>i!==index).map(i=>i>index?i-1:i))}
  else{const other=all[at+(action==='up'?-1:1)];if(!other)return;[lines[index],lines[other.index]]=[lines[other.index],lines[index]];nextSelection=new Set([...ruleSelection].map(i=>i===index?other.index:i===other.index?index:i))}
  resetRuleEntry();rememberRuleText(lines.join('\n'),nextSelection);
};
$('#rule-list-undo').onclick=()=>{if(!ruleUndo.length)return;if(ruleEditing!==null||$('#rule-entry-value').value.trim()){$('#rule-entry-error').textContent='请先应用或取消正在编辑的规则，或清空添加框。';$('#rule-entry-value').focus();return}if(pendingBatchEdit()){$('#rule-batch-error').textContent='请先应用或取消批量修改。';return}const previous=ruleUndo.pop();ruleText().value=previous.text;ruleSelection=new Set(previous.selection);ruleLastText=ruleText().value;resetRuleEntry();renderRuleRows()};
ruleText().addEventListener('input',()=>{if(ruleText().value!==ruleLastText){ruleUndo.push({text:ruleLastText,selection:[...ruleSelection]});if(ruleUndo.length>30)ruleUndo.shift();ruleLastText=ruleText().value;if(ruleSelection.size){ruleSelection.clear();toast('文本已修改，已清空规则选择')}}if(ruleEditing!==null)resetRuleEntry();renderRuleRows()});
$('#rule-list-search').addEventListener('keydown',e=>{if(e.key==='Enter')e.preventDefault()});
$$('[data-close="rule-template-dialog"]').forEach(button=>button.onclick=()=>{if(mayCloseRuleEditor())$('#rule-template-dialog').close()});
$('#rule-template-dialog').addEventListener('cancel',e=>{if(!mayCloseRuleEditor())e.preventDefault()});

async function showRuleAssignment(user){
  await loadRuleTemplates();
  const current=ruleTemplateState.users.find(u=>u.id===user.id);
  if(!current)throw new Error('用户不存在或已删除');
  const form=$('#rule-assignment-form');form.reset();form.elements.user_id.value=user.id;
  $('#rule-assignment-title').textContent=user.name+' · 规则模板';
  const legacy=current.legacy_independent?'沿用原配置（独立分组）':'沿用原配置';
  $('#rule-assignment-choice').innerHTML='<option value="legacy">'+legacy+'</option>'+
    ruleTemplateState.templates.filter(t=>t.published).map(t=>'<option value="'+esc(t.id)+'">'+esc(t.name)+'</option>').join('');
  form.elements.template_id.value=current.template_id;
  $('#rule-assignment-current').textContent='当前：'+(current.template_id==='legacy'?legacy:(templateById(current.template_id)?.name||'未知'));
  $('#rule-assignment-error').textContent='';$('#rule-assignment-dialog').showModal();
}

$('#rule-assignment-form').onsubmit=async e=>{
  e.preventDefault();const form=e.currentTarget,button=form.querySelector('button.primary');button.disabled=true;
  $('#rule-assignment-error').textContent='';
  try{
    await api('users/'+encodeURIComponent(form.elements.user_id.value)+'/rule-template','POST',{template_id:form.elements.template_id.value});
    $('#rule-assignment-dialog').close();await loadRuleTemplates();toast('模板已应用；客户端更新订阅后生效');
  }catch(err){$('#rule-assignment-error').textContent=err.message}finally{button.disabled=false}
};

function showRuleEditor(item,copy){
  const form=$('#rule-template-form');form.reset();
  const spec=item?.spec||templateById('independent').published_spec;
  form.elements.id.value=copy?'':item?.id||'';
  form.elements.revision.value=copy?'':item?.revision||'';
  form.elements.name.value=copy?(item.name+' 副本'):(item?.name||'');
  form.elements.base.value=spec.base;
  if(![...form.elements.ai_outbound.options].some(o=>o.value===spec.ai_outbound)){
    const option=document.createElement('option');option.value=spec.ai_outbound;option.textContent=transportLabel(spec.ai_outbound);form.elements.ai_outbound.append(option);
  }
  form.elements.ai_outbound.value=spec.ai_outbound;form.elements.rules.value=spec.rules;
  ruleUndo=[];ruleSelection=new Set();ruleLastText=spec.rules;$('#rule-batch-editor').hidden=true;$('#rule-batch-error').textContent='';resetRuleEntry();updateRuleTargets('PROXY');updateRuleHint(true);renderRuleRows();ruleSavedSnapshot=ruleSnapshot();
  $('#rule-template-title').textContent=form.elements.id.value?(item?.builtin?'编辑内置规则模板':'编辑规则模板'):'新建规则模板';
  $('#rule-template-reset').hidden=!(item?.builtin&&!copy);
  $('#rule-template-undo-reset').hidden=!(item?.builtin&&!copy&&item.can_undo_reset);
  $('#rule-template-impact').textContent=form.elements.id.value?
    '当前有 '+templateUseCount(form.elements.id.value)+' 位用户使用该模板；保存草稿不会改变订阅，发布后下一次更新订阅生效。':
    '新模板先保存为草稿；发布后才能分配给用户。';
  $('#rule-template-error').textContent='';$('#rule-template-dialog').showModal();
}

async function changeBuiltinDefault(item,action,fromEditor,button){
  if(!item?.builtin)return;
  const form=$('#rule-template-form'),undo=action==='undo-reset',revision=fromEditor?Number(form.elements.revision.value):item.revision;
  const effect=undo?'撤销上一次恢复，并用恢复前的草稿和已发布版本覆盖当前版本':
    '将名称、基础模板、AI 默认出口及规则恢复为系统默认，并立即发布';
  const pending=fromEditor&&ruleEditorDirty()?'当前编辑器中尚未保存的内容也会丢失。':'';
  if(!confirm('确定对“'+item.name+'”'+effect+'？\n当前有 '+templateUseCount(item.id)+' 位用户使用；所有使用此模板的用户将在下次更新订阅时生效。'+pending))return;
  const controls=fromEditor?[...form.querySelectorAll('button,input,select,textarea')]:[button],disabled=controls.map(c=>c.disabled);
  let restored=false,completed=false;
  const restore=()=>{controls.forEach((c,i)=>c.disabled=disabled[i]);restored=true};
  controls.forEach(c=>c.disabled=true);
  try{
    const result=await api('rule-templates/'+encodeURIComponent(item.id)+'/'+action,'POST',{expected_revision:revision});completed=true;
    await loadRuleTemplates();
    if(fromEditor){restore();$('#rule-template-dialog').close();showRuleEditor(templateById(item.id),false)}
    toast(result.unchanged?'该模板已经是默认状态':(undo?'已撤销恢复':'已恢复默认并发布')+'，影响 '+result.affected_users+' 位用户的下一次订阅');
  }catch(err){
    const message=completed?'操作已完成，但列表刷新失败；请重新加载页面。':err.message;
    if(fromEditor)$('#rule-template-error').textContent=message;else toast(message);
  }finally{if(!restored)restore()}
}

$('#rule-template-new').onclick=async()=>{try{await loadRuleTemplates();showRuleEditor(null,false)}catch(err){toast(err.message)}};
$('#rule-template-list').onclick=async e=>{
  const button=e.target.closest('[data-template-action]');if(!button)return;
  const item=templateById(button.dataset.id),action=button.dataset.templateAction;if(!item)return;
  if(action==='reset'||action==='undo-reset')await changeBuiltinDefault(item,action,false,button);
  else showRuleEditor(item,action==='copy');
};
$('#rule-template-reset').onclick=()=>changeBuiltinDefault(templateById($('#rule-template-form').elements.id.value),'reset',true,$('#rule-template-reset'));
$('#rule-template-undo-reset').onclick=()=>changeBuiltinDefault(templateById($('#rule-template-form').elements.id.value),'undo-reset',true,$('#rule-template-undo-reset'));
$('#rule-template-load-base').onclick=()=>{
  const form=$('#rule-template-form'),item=templateById(form.elements.base.value);
  if(item&&form.elements.rules.value!==item.factory_spec.rules){
    if(form.elements.rules.value.trim()&&!confirm('载入基础初始规则会替换当前规则列表。可以使用“撤销上一步”恢复。继续吗？'))return;
    resetRuleEntry();rememberRuleText(item.factory_spec.rules,new Set());
  }
};
$('#rule-template-form').onsubmit=async e=>{
  e.preventDefault();const form=e.currentTarget,action=e.submitter?.value||'save';
  $('#rule-template-error').textContent='';
  if(ruleEditing!==null||$('#rule-entry-value').value.trim()){$('#rule-template-error').textContent='请先添加或应用正在编辑的规则，或清空输入。';return}
  if(pendingBatchEdit()){$('#rule-template-error').textContent='请先应用或取消批量修改。';return}
  if(parsedRuleLines().length>500||new TextEncoder().encode(ruleText().value).length>14000){$('#rule-template-error').textContent='规则最多 500 条，总内容最多 14000 字节。';return}
  const buttons=[...form.querySelectorAll('button')],disabled=buttons.map(b=>b.disabled);buttons.forEach(b=>b.disabled=true);
  try{
    const name=form.elements.name.value,spec={base:form.elements.base.value,ai_outbound:form.elements.ai_outbound.value,rules:form.elements.rules.value};
    let id=form.elements.id.value,revision=Number(form.elements.revision.value);
    const payload=id?{name,spec,expected_revision:revision}:{name,spec};
    if(new TextEncoder().encode(JSON.stringify(payload)).length>16384)throw new Error('规则文本转成请求后超过入口大小限制，请减少注释或规则内容。');
    if(id){const result=await api('rule-templates/'+encodeURIComponent(id),'PUT',payload);revision=result.revision}
    else{const result=await api('rule-templates','POST',payload);id=result.id;revision=result.revision}
    form.elements.id.value=id;form.elements.revision.value=revision;
    ruleSavedSnapshot=ruleSnapshot();
    if(action==='publish'){
      const result=await api('rule-templates/'+encodeURIComponent(id)+'/publish','POST',{expected_revision:revision});
      $('#rule-template-dialog').close();toast('模板已发布，影响 '+result.affected_users+' 位用户的下一次订阅');
    }else{
      $('#rule-template-title').textContent=templateById(id)?.builtin?'编辑内置规则模板':'编辑规则模板';
      toast('草稿已保存，尚未更改用户订阅');
    }
    await loadRuleTemplates();
    if(action==='save')$('#rule-template-impact').textContent='当前有 '+templateUseCount(id)+' 位用户使用该模板；保存草稿不会改变订阅，发布后下一次更新订阅生效。';
  }catch(err){$('#rule-template-error').textContent=err.message}finally{buttons.forEach((b,i)=>b.disabled=disabled[i])}
};
