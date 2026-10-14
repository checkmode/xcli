'use strict';
(() => {
  const byId=id=>document.getElementById(id);
  const token=window.location.hash.slice(1);
  const validToken=/^[A-Za-z0-9_-]{43}$/.test(token);
  const subscription=validToken?window.location.origin+'/s/'+token:'';
  const moduleURL=window.location.origin+'/shadowrocket-dns.sgmodule';
  let ready=false;

  function status(message, state) {
    byId('setup-status').textContent=message;
    byId('setup-status').dataset.state=state;
  }

  async function check() {
    ready=false;
    byId('setup-steps').hidden=true;
    byId('retry-check').hidden=true;
    if(!validToken) {
      status('连接地址不完整。请在面板的「用户管理 → 连接 → 小火箭」重新扫码。','error');
      return;
    }
    status('正在检查连接地址…','loading');
    try {
      const response=await fetch(subscription,{credentials:'omit',cache:'no-store',referrerPolicy:'no-referrer'});
      if(!response.ok) {
        if(response.status===403)status('此订阅已停用、到期或达到配额，请联系面板管理员。','error');
        else if(response.status===404)status('连接地址已失效。请在面板重新获取二维码。','error');
        else throw new Error('unavailable');
        return;
      }
      await response.text();
      byId('import-nodes').href='shadowrocket://add/'+subscription;
      byId('install-dns').href='shadowrocket://install?module='+encodeURIComponent(moduleURL);
      byId('set-proxy').href='shadowrocket://route/proxy';
      ready=true;
      byId('setup-steps').hidden=false;
      status('连接地址可用。每一步确认后，返回此页继续。','ready');
    } catch {
      status('暂时无法检查连接地址。请确认网络可用后重试。','error');
      byId('retry-check').hidden=false;
    }
  }

  async function copy(value, label) {
    if(!ready)return;
    byId('copy-fallback').hidden=true;
    try {
      await navigator.clipboard.writeText(value);
      byId('action-status').textContent=label+'已复制';
    } catch {
      byId('copy-value').value=value;
      byId('copy-fallback').hidden=false;
      byId('copy-value').focus();
      byId('copy-value').select();
      byId('action-status').textContent='请手动复制所选地址';
    }
  }

  byId('retry-check').onclick=check;
  byId('copy-subscription').onclick=()=>copy(subscription,'订阅地址');
  byId('copy-module').onclick=()=>copy(moduleURL,'模块地址');
  check();
})();
