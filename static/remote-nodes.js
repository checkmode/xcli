'use strict';
let remoteNodes = [], remoteNodesLoading = false;
function clearRemoteNodeSecrets() { $('#remote-node-form').elements.registration.value = ''; }
async function loadRemoteNodes() {
  if (!csrf || remoteNodesLoading) return;
  remoteNodesLoading = true;
  try {
    const data = await api('remote-nodes');
    remoteNodes = data.nodes || [];
    $('#remote-node-list-error').textContent = '';
    $('#remote-node-list').innerHTML = remoteNodes.length ?
      '<table><thead><tr><th>服务器</th><th>连接状态</th><th>授权用户</th><th>操作</th></tr></thead><tbody>' +
      remoteNodes.map(n => {
        const online = n.enabled && n.last_seen && Date.now() / 1000 - n.last_seen < 30;
        const status = !n.enabled ? '已停用' : online ? '已连接' : '等待节点连接';
        return `<tr><td>${esc(n.name)}<br><small class="muted">${esc(n.endpoint.domain)} · ${esc(n.endpoint.public_ip)}</small></td><td><span class="badge ${online ? 'good' : ''}">${status}</span></td><td>${n.users.length} 位</td><td class="actions"><button type="button" data-remote-node-edit="${esc(n.id)}">编辑</button></td></tr>`;
      }).join('') + '</tbody></table>' : '<div class="empty">还没有独立服务器节点。</div>';
  } catch (error) { $('#remote-node-list-error').textContent = error.message; throw error; }
  finally { remoteNodesLoading = false; }
}
function editRemoteNode(node) {
  const f = $('#remote-node-form'); f.reset(); clearRemoteNodeSecrets();
  f.elements.id.value = node?.id || '';
  f.elements.node_name.value = node?.name || '';
  f.elements.enabled.checked = node ? node.enabled : true;
  $('#remote-node-title').textContent = node ? '编辑服务器节点' : '添加服务器节点';
  $('#remote-node-registration-label').hidden = !!node;
  f.elements.registration.required = !node;
  $('#remote-node-enabled-label').hidden = !node;
  const selected = new Set(node?.users || []);
  $('#remote-node-users').innerHTML = (state?.users || []).map(u =>
    `<label class="check-label"><input type="checkbox" name="node_user" value="${esc(u.id)}" ${selected.has(u.id) ? 'checked' : ''}>${esc(u.name)}</label>`
  ).join('') || '<p class="small muted">暂无用户，可先保存节点，之后再选择。</p>';
  $('#remote-node-error').textContent = ''; $('#remote-node-dialog').showModal();
}
$('#remote-node-add').onclick = () => editRemoteNode(null);
$('#remote-node-list').onclick = e => { const button = e.target.closest('[data-remote-node-edit]'); if (button) editRemoteNode(remoteNodes.find(n => n.id === button.dataset.remoteNodeEdit)); };
$('#remote-node-dialog').addEventListener('close', clearRemoteNodeSecrets);
setInterval(() => { if (csrf && page === 'nodes' && !$('#remote-node-dialog').open) loadRemoteNodes().catch(() => {}); }, 10000);
$('#remote-node-form').onsubmit = async e => {
  e.preventDefault(); const f = e.currentTarget, button = f.querySelector('button[type=submit]');
  button.disabled = true; $('#remote-node-error').textContent = '';
  try {
    // Pack the 128-bit IDs so all 500 users fit the server's 16 KiB request limit.
    const ids = [...f.querySelectorAll('[name=node_user]:checked')].map(x => x.value);
    const binary = ids.map(id => (id.match(/../g) || []).map(c => String.fromCharCode(parseInt(c, 16))).join('')).join('');
    const payload = {name: f.elements.node_name.value, users: btoa(binary)};
    if (f.elements.id.value) payload.enabled = f.elements.enabled.checked;
    else payload.registration = JSON.parse(f.elements.registration.value);
    await api('remote-nodes' + (f.elements.id.value ? '/' + f.elements.id.value : ''), f.elements.id.value ? 'PUT' : 'POST', payload);
    clearRemoteNodeSecrets(); $('#remote-node-dialog').close(); toast('节点配置已保存，等待节点同步');
    await loadRemoteNodes();
  } catch (error) { $('#remote-node-error').textContent = error instanceof SyntaxError ? '注册信息不是有效的 JSON' : error.message; }
  finally { button.disabled = false; }
};
