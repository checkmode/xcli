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
  std::map<std::string,std::string> outbound_names{{"reality","REALITY"},{"websocket","HTTPS"}};
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
  if(settings_.contains("vmess_ws_path"))
    add({{"name","VMess TLS"},{"type","vmess"},{"server",address},{"port",443},{"uuid",user.uuid},{"alterId",0},{"cipher","auto"},
      {"udp",true},{"tls",true},{"skip-cert-verify",false},{"servername",domain},{"network","ws"},
      {"ws-opts",{{"path",settings_["vmess_ws_path"]},{"headers",{{"Host",domain}}}}}});
  const bool dynamic_enabled=dynamic_residential_enabled();
  std::map<std::string,Json> country_nodes;
  Json protocol_groups=Json::array();
  for(const auto& exit:settings_.value("residential_exits",Json::array())) {
    const bool dynamic=exit.value("dynamic",false);if(dynamic&&!dynamic_enabled)continue;
    const auto name=exit.at("label").get<std::string>()+(dynamic?"":" · "+exit.at("exit_ip").get<std::string>());
    if(exit.value("hysteria2",false)) {
      const auto hy2=name+" · Hysteria2",https=name+" · HTTPS";
      add({{"name",hy2},{"type","hysteria2"},{"server",address},{"port",settings_.at("hysteria2_port")},
        {"password",user.uuid+"."+exit.at("tag").get<std::string>()+"-hy2"},{"sni",domain},{"skip-cert-verify",false},{"udp",false}});
      websocket(https,exit.at("ws_path").get<std::string>(),false);
      // Keep the previous selection/service target stable while exposing both transports.
      names.erase(names.end()-2,names.end());names.push_back(name);
      protocol_groups.push_back({{"name",name},{"type","select"},{"proxies",Json::array({hy2,https})}});
    } else websocket(name,exit.at("ws_path").get<std::string>(),false);
    const auto country=exit.at("country").get<std::string>();
    if(!country_nodes.contains(country))country_nodes[country]=Json::array();
    if(dynamic)country_nodes[country].insert(country_nodes[country].begin(),Json(name));
    else country_nodes[country].push_back(name);
  }
  if(settings_.value("hysteria2_port",0)>0)outbound_names["hysteria2"]="Hysteria 2";
  if(settings_.contains("vmess_ws_path"))outbound_names["vmess"]="VMess TLS";
  for(const auto& exit:settings_.value("residential_exits",Json::array())) {
    if(exit.value("dynamic",false)&&!dynamic_enabled)continue;
    outbound_names[exit.at("tag").get<std::string>()]=exit.at("label").get<std::string>()+
      (exit.value("dynamic",false)?"":" · "+exit.at("exit_ip").get<std::string>());
  }
  // Prefer the HTTPS transport for interoperability with current Mihomo clients.
  std::swap(names[0],names[1]);
  Json groups=std::move(protocol_groups);
  for(const auto& [country,nodes]:country_nodes) {
    std::string label=country;for(const auto& region:webshare_regions)if(region.country==country)label=region.label;
    const auto name="住宅分组 · "+label;names.push_back(name);
    groups.push_back({{"name",name},{"type","select"},{"proxies",nodes}});
  }
  groups.insert(groups.begin(),Json{{"name","PROXY"},{"type","select"},{"proxies",names}});
  // STUN needs an actual UDP-capable upstream; residential HTTP exits cannot carry it.
  Json stun_nodes=Json::array();
  if(settings_.value("hysteria2_port",0)>0)stun_nodes.push_back("Hysteria 2");
  stun_nodes.push_back("HTTPS");stun_nodes.push_back("REALITY");
  if(settings_.contains("vmess_ws_path"))stun_nodes.push_back("VMess TLS");
  groups.push_back({{"name","STUN"},{"type","select"},{"proxies",stun_nodes}});
  const auto domestic_dns=Json::array({"https://223.5.5.5/dns-query#DIRECT","https://1.12.12.12/dns-query#DIRECT"});
  Json rules=Json::array({"DOMAIN,"+domain+",DIRECT","IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
    "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve","IP-CIDR,172.16.0.0/12,DIRECT,no-resolve","IP-CIDR,192.168.0.0/16,DIRECT,no-resolve"});
  Json dns_policy=Json::object(),rule_providers=Json::object();
  const auto registry=settings_.value("clash_service_routes",Json::object());
  if(registry.contains(user.id))for(const auto& service:registry.at(user.id)) {
    const auto group=service.at("name").get<std::string>(),tag=service.at("outbound").get<std::string>();
    for(const auto& proxy:proxies)if(proxy.at("name")==group)throw HttpError(503,"Service routing name conflict");
    for(const auto& existing:groups)if(existing.at("name")==group)throw HttpError(503,"Service routing name conflict");
    // A missing/disabled exit fails closed for this user's service only.
    const auto found=outbound_names.find(tag);
    const auto target=found==outbound_names.end()?"REJECT":found->second;
    groups.push_back({{"name",group},{"type","select"},{"proxies",Json::array({target})}});
    const auto provider="service-"+group;
    Json payload=Json::array();
    if(service.at("udp")=="reject")rules.push_back("AND,((RULE-SET,"+provider+"),(NETWORK,UDP)),REJECT");
    rules.push_back("RULE-SET,"+provider+","+group);
    for(const auto& entry:service.at("domains")) {
      const auto host=entry.get<std::string>();
      payload.push_back("+."+host);
      dns_policy["+."+host]=Json::array({"https://1.1.1.1/dns-query#"+group,"https://1.0.0.1/dns-query#"+group});
    }
    rule_providers[provider]={{"type","inline"},{"behavior","domain"},{"payload",payload}};
  }
  // Exact endpoint + port + UDP matching leaves unrelated game/LAN/TCP traffic alone.
  // Domain rules require the client to retain DNS metadata (e.g. TUN with fake-IP).
  // https://webrtc.github.io/samples/src/content/peerconnection/trickle-ice/
  // https://developers.cloudflare.com/realtime/turn/#service-address-and-ports
  Json stun_payload=Json::array();
  for(const auto& [host,ports]:std::map<std::string,std::string>{
      {"stun.l.google.com","19302"},{"stun1.l.google.com","19302"},
      {"stun2.l.google.com","19302"},{"stun3.l.google.com","19302"},
      {"stun4.l.google.com","19302"},{"stun.cloudflare.com","3478"},
      {"turn.cloudflare.com","3478/443"}}) {
    stun_payload.push_back("AND,((NETWORK,UDP),(DOMAIN,"+host+"),(DST-PORT,"+ports+"))");
    dns_policy[host]=Json::array({"https://1.1.1.1/dns-query#STUN","https://1.0.0.1/dns-query#STUN"});
  }
  rule_providers["stun-endpoints"]={{"type","inline"},{"behavior","classical"},{"payload",stun_payload}};
  rules.push_back("RULE-SET,stun-endpoints,STUN");
  // Mihomo skips a UDP rule if its selected proxy lacks UDP; never fall back to DIRECT.
  rules.push_back("RULE-SET,stun-endpoints,REJECT");
  for(const auto* rule:{"GEOSITE,private,DIRECT","GEOSITE,cn,DIRECT","GEOSITE,geolocation-!cn,PROXY",
                       "GEOIP,private,DIRECT,no-resolve","GEOIP,CN,DIRECT","MATCH,PROXY"})rules.push_back(rule);
  dns_policy["geosite:cn,private"]=domestic_dns;
  Json result={{"mixed-port",7890},{"allow-lan",false},{"mode","rule"},{"log-level","warning"},{"ipv6",false},
    {"profile",{{"store-selected",true}}},{"hosts",{{domain,address}}},
    {"dns",{{"enable",true},{"ipv6",false},{"enhanced-mode","fake-ip"},{"fake-ip-range","198.18.0.1/16"},
      {"use-hosts",true},{"default-nameserver",Json::array({"223.5.5.5","119.29.29.29"})},
      {"proxy-server-nameserver",domestic_dns},{"direct-nameserver",domestic_dns},
      {"nameserver-policy",dns_policy},
      {"nameserver",Json::array({"https://1.1.1.1/dns-query#PROXY","https://1.0.0.1/dns-query#PROXY"})}}},
    {"proxies",proxies},{"proxy-groups",groups},
    {"rules",rules}};
  if(!rule_providers.empty())result["rule-providers"]=rule_providers;
  return result;
}
std::pair<std::string,std::string> Backend::clash_subscription(const std::string& token) {
  auto database=db();auto row=database.one("SELECT * FROM users WHERE token=? AND deleted=0",{token});
  if(!row)throw HttpError(404,"Not Found");
  auto user=User::from(*row);if(!user.active())throw HttpError(403,"Subscription inactive");
  return {"# Xdistribute — Clash Verge Rev / Mihomo\n# China/private destinations use DIRECT; other traffic uses PROXY.\n# Domestic DNS uses direct DoH; overseas DNS follows PROXY. Residential exits support TCP only.\n# Listed Google/Cloudflare STUN UDP endpoints use STUN (server egress, not residential egress).\n# Requires UDP capture and DNS metadata, e.g. TUN + fake-IP. Other/custom STUN endpoints are not covered.\n"+yaml(clash_configuration(user)),
    "upload="+std::to_string(user.upload)+"; download="+std::to_string(user.download)+"; total="+std::to_string(user.quota)+"; expire="+std::to_string(user.expires)};
}
}
