#include "gateway.hpp"

namespace xg {
namespace {
// JSON quoting is also valid YAML quoting; never concatenate unescaped user names.
std::string yaml(const Json& value,int depth=0) {
  const std::string indent(static_cast<std::size_t>(depth),' ');std::string text;
  if(value.is_object())for(auto it=value.begin();it!=value.end();++it) {
    text+=indent+Json(it.key()).dump()+":";
    if(it.value().is_structured()&&!it.value().empty())text+="\n"+yaml(it.value(),depth+2);
    else text+=" "+it.value().dump()+"\n";
  }
  else if(value.is_array())for(const auto& item:value)text+=indent+"- "+item.dump()+"\n";
  return text;
}
}
Json Backend::clash_configuration(const User& user) const {
  const auto address=settings_.at("public_ip").get<std::string>(),domain=settings_.at("domain").get<std::string>();
  Json proxies=Json::array(),names=Json::array();
  auto add=[&](Json proxy){names.push_back(proxy.at("name"));proxies.push_back(std::move(proxy));};
  add({{"name","REALITY"},{"type","vless"},{"server",address},{"port",443},{"uuid",user.uuid},
    {"udp",true},{"tls",true},{"network","tcp"},{"flow","xtls-rprx-vision"},{"packet-encoding","xudp"},
    {"servername",settings_.at("reality_sni")},{"client-fingerprint","chrome"},
    {"reality-opts",{{"public-key",settings_.at("reality_public")},{"short-id",settings_.at("short_id")},{"support-x25519mlkem768",true}}}});
  auto websocket=[&](const std::string& name,const std::string& path,bool udp){
    add({{"name",name},{"type","vless"},{"server",address},{"port",443},{"uuid",user.uuid},
      {"udp",udp},{"tls",true},{"skip-cert-verify",false},{"servername",domain},{"client-fingerprint","chrome"},
      {"network","ws"},{"ws-opts",{{"path",path},{"headers",{{"Host",domain}}}}}});
  };
  websocket("HTTPS",settings_.at("ws_path").get<std::string>(),true);
  if(const auto port=settings_.value("hysteria2_port",0);port>0)
    add({{"name","Hysteria 2"},{"type","hysteria2"},{"server",address},{"port",port},{"password",user.uuid},{"sni",domain},{"skip-cert-verify",false}});
  const bool dynamic_enabled=dynamic_residential_enabled();
  for(const auto& exit:settings_.value("residential_exits",Json::array())) {
    const bool dynamic=exit.value("dynamic",false);if(dynamic&&!dynamic_enabled)continue;
    websocket(exit.at("label").get<std::string>()+(dynamic?"":" · "+exit.at("exit_ip").get<std::string>()),exit.at("ws_path").get<std::string>(),false);
  }
  // Prefer the HTTPS transport for interoperability with current Mihomo clients.
  std::swap(names[0],names[1]);
  return {{"mixed-port",7890},{"allow-lan",false},{"mode","rule"},{"log-level","warning"},{"ipv6",false},
    {"profile",{{"store-selected",true}}},{"hosts",{{domain,address}}},
    {"dns",{{"enable",true},{"ipv6",false},{"enhanced-mode","fake-ip"},{"fake-ip-range","198.18.0.1/16"},
      {"use-hosts",true},{"default-nameserver",Json::array({"https://1.1.1.1/dns-query"})},
      {"proxy-server-nameserver",Json::array({"https://1.1.1.1/dns-query"})},
      {"nameserver",Json::array({"https://1.1.1.1/dns-query#PROXY","https://1.0.0.1/dns-query#PROXY"})}}},
    {"proxies",proxies},{"proxy-groups",Json::array({{{"name","PROXY"},{"type","select"},{"proxies",names}}})},
    {"rules",Json::array({"IP-CIDR,127.0.0.0/8,DIRECT,no-resolve","IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
      "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve","IP-CIDR,192.168.0.0/16,DIRECT,no-resolve","MATCH,PROXY"})}};
}
std::pair<std::string,std::string> Backend::clash_subscription(const std::string& token) {
  auto database=db();auto row=database.one("SELECT * FROM users WHERE token=? AND deleted=0",{token});
  if(!row)throw HttpError(404,"Not Found");
  auto user=User::from(*row);if(!user.active())throw HttpError(403,"Subscription inactive");
  return {"# Xdistribute — Clash Verge Rev / Mihomo\n# Residential exits support TCP only. DNS follows PROXY via DoH.\n"+yaml(clash_configuration(user)),
    "upload="+std::to_string(user.upload)+"; download="+std::to_string(user.download)+"; total="+std::to_string(user.quota)+"; expire="+std::to_string(user.expires)};
}
}
