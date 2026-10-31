'use strict';
let ruleTemplateState=null;

async function loadRuleTemplates(){
  ruleTemplateState=await api('rule-templates');
  const {templates,users}=ruleTemplateState;
  $('#rule-template-list').innerHTML='<table><thead><tr><th>模板</th><th>状态</th><th>使用人数</th><th>操作</th></tr></thead><tbody>'+
    templates.map(t=>{
      const count=users.filter(u=>u.template_id===t.id).length;
      const status=t.builtin?'内置':!t.published?'未发布':t.revision!==t.published_revision?'已发布 · 草稿有修改':'已发布';
      const actions=t.builtin?'<button data-template-action="copy" data-id="'+esc(t.id)+'">复制为自定义</button>':
        '<button data-template-action="edit" data-id="'+esc(t.id)+'">编辑草稿</button> <button data-template-action="copy" data-id="'+esc(t.id)+'">复制</button>';
      return '<tr><td>'+esc(t.name)+'</td><td>'+status+'</td><td>'+count+'</td><td class="actions">'+actions+'</td></tr>';
    }).join('')+'</tbody></table>';
}

function templateById(id){return ruleTemplateState?.templates.find(t=>t.id===id)}
function templateUseCount(id){return ruleTemplateState?.users.filter(u=>u.template_id===id).length||0}

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
  const spec=item?.spec||templateById('independent').spec;
  form.elements.id.value=copy?'':item?.id||'';
  form.elements.revision.value=copy?'':item?.revision||'';
  form.elements.name.value=copy?(item.name+' 副本'):(item?.name||'');
  form.elements.base.value=spec.base;form.elements.ai_outbound.value=spec.ai_outbound;form.elements.rules.value=spec.rules;
  $('#rule-template-title').textContent=form.elements.id.value?'编辑规则模板':'新建规则模板';
  $('#rule-template-impact').textContent=form.elements.id.value?
    '当前有 '+templateUseCount(form.elements.id.value)+' 位用户使用该模板；保存草稿不会改变订阅，发布后下一次更新订阅生效。':
    '新模板先保存为草稿；发布后才能分配给用户。';
  $('#rule-template-error').textContent='';$('#rule-template-dialog').showModal();
}

$('#rule-template-new').onclick=async()=>{try{await loadRuleTemplates();showRuleEditor(null,false)}catch(err){toast(err.message)}};
$('#rule-template-list').onclick=e=>{
  const button=e.target.closest('[data-template-action]');if(!button)return;
  const item=templateById(button.dataset.id);if(item)showRuleEditor(item,button.dataset.templateAction==='copy');
};
$('#rule-template-load-base').onclick=()=>{
  const form=$('#rule-template-form'),item=templateById(form.elements.base.value);
  if(item)form.elements.rules.value=item.spec.rules;
};
$('#rule-template-form').onsubmit=async e=>{
  e.preventDefault();const form=e.currentTarget,action=e.submitter?.value||'save';
  const buttons=[...form.querySelectorAll('button')];buttons.forEach(b=>b.disabled=true);$('#rule-template-error').textContent='';
  try{
    const name=form.elements.name.value,spec={base:form.elements.base.value,ai_outbound:form.elements.ai_outbound.value,rules:form.elements.rules.value};
    let id=form.elements.id.value,revision=Number(form.elements.revision.value);
    if(id){const result=await api('rule-templates/'+encodeURIComponent(id),'PUT',{name,spec,expected_revision:revision});revision=result.revision}
    else{const result=await api('rule-templates','POST',{name,spec});id=result.id;revision=result.revision}
    form.elements.id.value=id;form.elements.revision.value=revision;
    if(action==='publish'){
      const result=await api('rule-templates/'+encodeURIComponent(id)+'/publish','POST',{expected_revision:revision});
      $('#rule-template-dialog').close();toast('模板已发布，影响 '+result.affected_users+' 位用户的下一次订阅');
    }else{
      $('#rule-template-title').textContent='编辑规则模板';
      toast('草稿已保存，尚未更改用户订阅');
    }
    await loadRuleTemplates();
    if(action==='save')$('#rule-template-impact').textContent='当前有 '+templateUseCount(id)+' 位用户使用该模板；保存草稿不会改变订阅，发布后下一次更新订阅生效。';
  }catch(err){$('#rule-template-error').textContent=err.message}finally{buttons.forEach(b=>b.disabled=false)}
};
