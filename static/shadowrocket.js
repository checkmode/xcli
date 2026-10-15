'use strict';
(() => {
  const byId=id=>document.getElementById(id);
  const token=window.location.hash.slice(1);
  const validToken=/^[A-Za-z0-9_-]{43}$/.test(token);
  const subscription=validToken?window.location.origin+'/s/'+token:'';
  let moduleURL=window.location.origin+'/shadowrocket-dns.sgmodule';
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
      const setupResponse=await fetch(subscription+'/shadowrocket.json',{credentials:'omit',cache:'no-store',referrerPolicy:'no-referrer'});
      if(!setupResponse.ok)throw new Error('setup unavailable');
      const setup=await setupResponse.json();
      const serviceRouting=setup.service_routing===true;
      moduleURL=window.location.origin+setup.resource;
      if(serviceRouting) {
        byId('intro').textContent='扫码或点击下方按钮，安装/更新你的专属远程配置。节点和分流规则一起更新，继承手机现有的完整 default.conf。';
        byId('nodes-title').textContent='安装或更新专属配置';
        byId('nodes-help').textContent='保留手机已有 default.conf。导入后使用本远程配置，全局路由保持「配置」。后续点击更新配置或启用自动更新，无需手工改规则。';
        byId('import-nodes').textContent='一键安装 / 更新配置 ↗';
        byId('copy-subscription').textContent='复制配置地址';
        for(const id of ['module-step','compatibility-step','route-step'])byId(id).hidden=true;
        byId('changes-detail').textContent='专属远程配置继承 default.conf，仅增加固定业务节点、策略组、域名规则和 UDP 拒绝兜底。Claude 固定住宅出口，GitHub 固定普通 Hysteria 2；现有完整默认设置和 DNS 保留。';
        byId('completion-detail').textContent='首次导入后选择使用此配置。后续在小火箭「设置 → 配置」启用自动更新，或再次扫码/点击本按钮更新。需要立即生效时请手动更新配置；只刷新首页节点订阅不会更新分流。切回 default.conf 可撤销本次增量。';
        byId('dns-troubleshooting').hidden=true;
      }
      byId('set-proxy').href='shadowrocket://route/'+(serviceRouting?'config':'proxy');
      byId('import-nodes').href=serviceRouting?'shadowrocket://config/add/'+moduleURL:'shadowrocket://add/'+subscription;
      byId('copy-subscription').onclick=()=>copy(serviceRouting?moduleURL:subscription,serviceRouting?'配置地址':'订阅地址');
      byId('install-dns').href='shadowrocket://install?module='+encodeURIComponent(moduleURL);

      ready=true;
      byId('setup-steps').hidden=false;
      status(serviceRouting?'专属配置可用。点击一次安装或更新。':'连接地址可用。每一步确认后，返回此页继续。','ready');
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
