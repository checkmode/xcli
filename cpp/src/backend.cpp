#include "gateway.hpp"
#include "client_policy.hpp"
#include <algorithm>
#include <fcntl.h>
#include <iostream>
#include <limits>
#include <regex>
#include <set>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

namespace xg {
namespace {
void fields(const Json& input,const std::set<std::string>& allowed,const std::set<std::string>& required) {
  if(!input.is_object())throw HttpError(422,"请求必须是 JSON 对象");
  for(auto it=input.begin();it!=input.end();++it)if(!allowed.contains(it.key()))throw HttpError(422,"包含不支持的字段");
  for(const auto& name:required)if(!input.contains(name))throw HttpError(422,"缺少必要字段");
}
Int integer(const Json& value,Int maximum) {
  if(!value.is_number_integer())throw HttpError(422,"请输入有效整数");
  if(value.is_number_unsigned()&&value.get<std::uint64_t>()>static_cast<std::uint64_t>(maximum))throw HttpError(422,"数值超出允许范围");
  Int number=value.get<Int>();if(number<0||number>maximum)throw HttpError(422,"数值超出允许范围");return number;
}
Int sum_checked(Int a,Int b) {
  if(a<0||b<0||a>std::numeric_limits<Int>::max()-b)throw std::runtime_error("Traffic counter exceeds supported range");
  return a+b;
}
}
User User::from(const Json& row) {
  User u;u.id=row.at("id");u.name=row.at("name");u.uuid=row.at("uuid");u.token=row.at("token");
  u.enabled=row.at("enabled").get<Int>()!=0;u.deleted=row.at("deleted").get<Int>()!=0;
  u.quota=row.at("quota");u.expires=row.at("expires");u.upload=row.at("upload");u.download=row.at("download");u.created=row.at("created");return u;
}
bool User::active(Int timestamp) const {return !deleted&&status(timestamp)=="active";}
std::string User::status(Int timestamp) const {
  if(!enabled)return "disabled";
  if(expires&&expires<=timestamp)return "expired";
  if(quota&&(upload>=quota||download>=quota-upload))return "exhausted";
  return "active";
}
Json User::public_json() const {return {{"id",id},{"name",name},{"enabled",enabled?1:0},{"quota",quota},{"expires",expires},{"upload",upload},{"download",download},{"created",created},{"status",status()}};}
std::string User::email(std::string_view tag) const {return id+"."+uuid.substr(0,8)+"@"+std::string(tag);}

Backend::Backend(Options options,std::unique_ptr<Core> core,WebhookSender sender) : options_(std::move(options)),settings_(Json::parse(read_file(options_.settings))),core_(std::move(core)),webhook_sender_(std::move(sender)) {
  for(const auto& key:{"domain","public_ip","origin","reality_sni","reality_public","short_id","ws_path"})
    if(!settings_.contains(key)||!settings_[key].is_string())throw std::runtime_error("Required settings are missing");
  auto hy2=settings_.value("hysteria2_port",Json(0));
  if(!hy2.is_number_integer()||hy2<0||hy2>65535)throw std::runtime_error("Invalid Hysteria 2 port");
  if(settings_.contains("vmess_ws_path")) {
    auto path=checked_string(settings_["vmess_ws_path"],1,256);
    if(path!=settings_.at("ws_path").get<std::string>()+"/vmess"||settings_.value("vmess_port",0)!=10081)
      throw std::runtime_error("Invalid VMess entry settings");
  }
  auto exits=settings_.value("residential_exits",Json::array());
  if(!exits.is_array()||exits.size()>40)throw std::runtime_error("Invalid residential exit registry");
  std::set<std::string> exit_tags,exit_paths;std::set<Int> exit_ports;
  for(const auto& exit:exits) {
    fields(exit,{"tag","label","exit_ip","country","ws_path","port","dynamic","hysteria2"},{"tag","label","exit_ip","country","ws_path","port"});
    auto tag=checked_string(exit.at("tag"),14,14),path=checked_string(exit.at("ws_path"),1,256);
    const bool dynamic=exit.value("dynamic",false);
    if(exit.contains("hysteria2")&&(!exit["hysteria2"].is_boolean()||(exit["hysteria2"].get<bool>()&&(dynamic||hy2==0))))throw std::runtime_error("Invalid residential Hysteria settings");
    auto address=checked_string(exit.at("exit_ip"),dynamic?0:7,15),country=checked_string(exit.at("country"),2,2);
    auto port=integer(exit.at("port"),65535);
    if(!std::regex_match(tag,std::regex("residential-[0-9]{2}"))||path!=settings_.at("ws_path").get<std::string>()+"/"+tag||
       (dynamic?!address.empty():!public_webhook_address(address))||!std::regex_match(country,std::regex("[A-Z]{2}"))||port<1024||
       !exit_tags.insert(tag).second||!exit_paths.insert(path).second||!exit_ports.insert(port).second)
      throw std::runtime_error("Invalid residential exit metadata");
    if(dynamic) {
      bool valid=false;for(const auto& region:webshare_regions)if(region.tag==tag&&region.country==country&&region.port==port)valid=true;
      if(!valid)throw std::runtime_error("Invalid dynamic residential registry");
    }
    (void)user_name(exit.at("label"));
  }
  // Optional business routes are scoped to immutable user IDs, never global defaults.
  const auto routes=settings_.value("clash_service_routes",Json::object());
  if(!routes.is_object()||routes.size()>1000)throw std::runtime_error("Invalid Clash service routing registry");
  for(const auto& [user_id,services]:routes.items()) {
    if(!std::regex_match(user_id,std::regex("[0-9a-f]{32}"))||!services.is_array()||services.size()>32)
      throw std::runtime_error("Invalid Clash service routing owner");
    std::set<std::string> service_names,domains;
    for(const auto& service:services) {
      fields(service,{"name","outbound","domains","udp"},{"name","outbound","domains","udp"});
      const auto name=checked_string(service.at("name"),1,32),outbound=checked_string(service.at("outbound"),1,32);
      const auto udp=checked_string(service.at("udp"),5,6);
      if(!std::regex_match(name,std::regex("[A-Z][A-Z0-9_-]*"))||
         std::set<std::string>{"PROXY","STUN","DIRECT","REJECT","REJECT-DROP","PASS","COMPATIBLE","GLOBAL","REALITY","HTTPS"}.contains(name)||
         !service_names.insert(name).second||
         !(outbound=="hysteria2"||outbound=="reality"||outbound=="websocket"||outbound=="vmess"||std::regex_match(outbound,std::regex("residential-[0-9]{2}")))||
         (udp!="reject"&&udp!="proxy"))throw std::runtime_error("Invalid Clash service route");
      // Residential exits are TCP-only: never allow UDP to fall through to PROXY.
      if(outbound.starts_with("residential-")&&udp!="reject")throw std::runtime_error("Residential service routes must reject UDP");
      const auto& list=service.at("domains");
      if(!list.is_array()||list.empty()||list.size()>128)throw std::runtime_error("Invalid Clash service domains");
      for(const auto& item:list) {
        const auto domain=checked_string(item,3,253);
        if(!std::regex_match(domain,std::regex("[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+")))
          throw std::runtime_error("Invalid Clash service domain");
        for(const auto& previous:domains)
          if(domain==previous||domain.ends_with("."+previous)||previous.ends_with("."+domain))
            throw std::runtime_error("Overlapping Clash service domains");
        domains.insert(domain);
      }
    }
  }
  const auto policies=settings_.value("client_policies",Json::object());
  if(!policies.is_object()||policies.size()>1000)throw std::runtime_error("Invalid client policy registry");
  for(const auto& [id,policy]:policies.items()) {
    if(!std::regex_match(id,std::regex("[0-9a-f]{32}")))throw std::runtime_error("Invalid client policy owner");
    fields(policy,{"ai_outbound"},{"ai_outbound"});
    const auto target=checked_string(policy.at("ai_outbound"),1,32);
    if(!(target=="proxy"||target=="reality"||target=="websocket"||target=="vmess"||target=="hysteria2"||
         std::regex_match(target,std::regex("residential-[0-9]{2}"))))
      throw std::runtime_error("Invalid client policy AI outbound");
    if(routes.contains(id))for(const auto& service:routes.at(id))
      if(std::set<std::string>{"AI","CLAUDE","Telegram","YouTube","Netflix","Apple"}.contains(service.at("name").get<std::string>()))
        throw std::runtime_error("Client policy requires merging overlapping service routes");
    if(!settings_.value("shadowrocket_base_profiles",Json::object()).contains(id))
      throw std::runtime_error("Client policy requires a complete Shadowrocket base");
  }
  const auto shadow_users=settings_.value("shadowrocket_service_users",Json::array());
  if(!shadow_users.is_array()||shadow_users.size()>1000)throw std::runtime_error("Invalid Shadowrocket service users");
  std::set<std::string> shadow_ids;
  for(const auto& entry:shadow_users) {
    const auto id=checked_string(entry,32,32);
    if(!routes.contains(id)||routes.at(id).empty()||!shadow_ids.insert(id).second)
      throw std::runtime_error("Shadowrocket service user requires a unique existing policy");
    for(const auto& service:routes.at(id)) {
      const auto tag=service.at("outbound").get<std::string>();
      if(tag!="hysteria2"&&!tag.starts_with("residential-"))
        throw std::runtime_error("Shadowrocket service routing currently requires Hysteria 2");
      for(const auto& exit:settings_.value("residential_exits",Json::array()))
        if(exit.at("tag")==tag&&!exit.value("hysteria2",false))
          throw std::runtime_error("Shadowrocket residential service requires Hysteria 2");
    }
  }
  const auto shadow_bases=settings_.value("shadowrocket_base_profiles",Json::object());
  if(!shadow_bases.is_object()||shadow_bases.size()>16)
    throw std::runtime_error("Invalid Shadowrocket base profile registry");
  std::size_t shadow_base_bytes=0;
  for(const auto& [id,base]:shadow_bases.items()) {
    if((!shadow_ids.contains(id)&&!policies.contains(id))||!base.is_string())
      throw std::runtime_error("Shadowrocket base requires an enabled service user");
    const auto& text=base.get_ref<const std::string&>();
    shadow_base_bytes+=text.size();
    if(text.empty()||shadow_base_bytes>512*1024||text.find('\0')!=std::string::npos)
      throw std::runtime_error("Invalid Shadowrocket base profile size");
  }
  if(!fs::is_directory(options_.state)) {fs::create_directories(options_.state);::chmod(options_.state.c_str(),0700);}
  {auto database=db();database.initialize();}
  if(options_.secret_key.empty())options_.secret_key=options_.state/"security.key";
  secret_key_=load_secret_key(options_.secret_key);
  if(!options_.monitor_config.empty()) {
    auto config=Json::parse(read_file(options_.monitor_config,16384));auto uuid=config.at("uuid").get<std::string>();
    if(!std::regex_match(uuid,std::regex("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")))throw std::runtime_error("Invalid monitor identity");
    User probe;probe.id="health-probe";probe.name="Internal health probe";probe.uuid=uuid;probe_user_=probe;
  }
  if(::chmod((options_.state/"gateway.sqlite").c_str(),0600)<0)throw std::runtime_error("Cannot secure database permissions");
  if(!core_&&!options_.offline)core_=make_core(options_);
}
Backend::~Backend() {stop_worker();}
std::vector<std::string> Backend::transports() const {
  std::vector<std::string> result={"reality","websocket"};
  if(settings_.value("hysteria2_port",0)>0)result.push_back("hysteria2");
  if(settings_.contains("vmess_ws_path"))result.push_back("vmess");
  return result;
}
std::vector<std::string> Backend::inbound_tags() const {
  auto result=transports();
  for(const auto& exit:settings_.value("residential_exits",Json::array())) {
    auto tag=exit.at("tag").get<std::string>();result.push_back(tag);
    if(exit.value("hysteria2",false))result.push_back(tag+"-hy2");
  }
  return result;
}
User Backend::get_user(Database& database,const std::string& id) {
  auto row=database.one("SELECT * FROM users WHERE id=? AND deleted=0",{id});
  if(!row)throw HttpError(404,"用户不存在");
  return User::from(*row);
}
void Backend::audit(Database& database,const std::string& action,const std::string& detail) {
  database.run("INSERT INTO events(ts,action,detail) VALUES(?,?,?)",{now(),action,detail});
  database.run("DELETE FROM events WHERE id < (SELECT COALESCE(MAX(id),0)-2000 FROM events)");
}
Json Backend::validated_user(const Json& input) {
  fields(input,{"name","enabled","quota","expires"},{"name"});
  auto enabled=input.value("enabled",Json(true));
  if(!enabled.is_boolean())throw HttpError(422,"enabled 必须为布尔值");
  return {{"name",user_name(input.at("name"))},{"enabled",enabled.get<bool>()?1:0},
    {"quota",integer(input.value("quota",Json(0)),10000000000000000LL)},
    {"expires",integer(input.value("expires",Json(0)),4102444800LL)}};
}
Json Backend::login(const Json& input,const std::string& ip,std::string& cookie) {
  fields(input,{"username","password","code"},{"username","password"});
  auto username=checked_string(input.at("username"),0,64),password=checked_string(input.at("password"),0,256);
  std::lock_guard guard(mutation_mutex_);auto stamp=std::chrono::steady_clock::now();
  // Evict only expired buckets; a full table must not reset active lockouts.
  for(auto it=rate_.begin();it!=rate_.end();) {
    while(!it->second.empty()&&stamp-it->second.front()>std::chrono::minutes(15))it->second.pop_front();
    if(it->second.empty())it=rate_.erase(it);else ++it;
  }
  if(!rate_.contains(ip)&&rate_.size()>=10000)throw HttpError(429,"尝试过于频繁，请稍后重试");
  auto& attempts=rate_[ip];if(attempts.size()>=8)throw HttpError(429,"尝试过于频繁，请 15 分钟后重试");
  auto database=db();Transaction transaction(database);
  auto row=database.one("SELECT password FROM admin WHERE id=1");
  bool match=row&&password_check(password,row->at("password").get<std::string>())&&username=="admin";
  if(match)match=check_second_factor(database,checked_string(input.value("code",Json("")),0,128));
  if(!match) {
    attempts.push_back(stamp);audit(database,"login_failed",ip);transaction.commit();throw HttpError(401,"账号、密码或二次验证码错误");
  }
  attempts.clear();cookie=random_token();auto csrf=random_token();
  database.run("DELETE FROM sessions WHERE expires<?",{now()});
  database.run("INSERT INTO sessions VALUES(?,?,?)",{sha256(cookie),csrf,now()+8*3600});
  database.run("DELETE FROM mfa_sessions WHERE hash NOT IN (SELECT hash FROM sessions)");
  database.run("INSERT INTO mfa_sessions VALUES(?)",{sha256(cookie)});
  audit(database,"login",ip);transaction.commit();return {{"csrf",csrf},{"username","admin"}};
}
Json Backend::session(const std::string& token,const std::string& csrf,bool write) {
  if(token.size()!=43)throw HttpError(401,"请先登录");
  auto database=db();auto row=database.one("SELECT * FROM sessions WHERE hash=? AND expires>?",{sha256(token),now()});
  if(!row)throw HttpError(401,"请先登录");
  if(database.one("SELECT enabled FROM mfa WHERE id=1")->at("enabled").get<Int>()&&!database.one("SELECT hash FROM mfa_sessions WHERE hash=?",{sha256(token)}))throw HttpError(401,"请重新完成二次验证登录");
  if(write&&!secure_equal(csrf,row->at("csrf").get<std::string>()))throw HttpError(403,"请求校验失败，请刷新页面");
  return {{"csrf",row->at("csrf")},{"username","admin"}};
}
void Backend::logout(const std::string& token,const std::string& csrf) {
  std::lock_guard guard(mutation_mutex_);session(token,csrf,true);auto database=db();
  database.run("DELETE FROM sessions WHERE hash=?",{sha256(token)});
}
Json Backend::health() {std::lock_guard guard(health_mutex_);return health_;}
Json Backend::overview(const std::string& token) {
  session(token);auto database=db();database.exec("BEGIN");
  Json users=Json::array();for(const auto& row:database.all("SELECT * FROM users WHERE deleted=0 ORDER BY created"))users.push_back(User::from(row).public_json());
  auto totals=database.one("SELECT COALESCE(SUM(upload),0) AS upload,COALESCE(SUM(download),0) AS download FROM users");
  auto samples=database.all("SELECT (ts/60)*60 AS ts,SUM(upload) AS upload,SUM(download) AS download FROM samples WHERE ts>? GROUP BY ts/60 ORDER BY ts/60",{now()-3600});
  auto events=database.all("SELECT ts,action,detail FROM events ORDER BY id DESC LIMIT 30");database.exec("COMMIT");
  return {{"health",health()},{"runtime",runtime(token)},{"activity",activity_status(database)},{"monitor",monitor_status()},{"users",users},{"totals",*totals},{"samples",samples},{"events",events},
    {"server",{{"domain",settings_["domain"]},{"public_ip",settings_["public_ip"]},{"reality_sni",settings_["reality_sni"]},{"transports",transports()},{"residential_exits",settings_.value("residential_exits",Json::array())},{"hysteria2_port",settings_.value("hysteria2_port",0)}}}};
}
Json Backend::create_user(const std::string& token,const std::string& csrf,const Json& input) {
  auto values=validated_user(input);std::lock_guard guard(mutation_mutex_);session(token,csrf,true);
  auto database=db();Transaction transaction(database);
  if(database.one("SELECT COUNT(*) AS n FROM users WHERE deleted=0")->at("n").get<Int>()>=500)throw HttpError(409,"最多支持 500 位用户");
  auto id=random_id();auto name=values["name"].get<std::string>();
  database.run("INSERT INTO users(id,name,uuid,token,enabled,quota,expires,created) VALUES(?,?,?,?,?,?,?,?)",
    {id,name,random_uuid(),random_token(),values["enabled"].get<Int>(),values["quota"].get<Int>(),values["expires"].get<Int>(),now()});
  audit(database,"user_created",name);transaction.commit();return {{"id",id}};
}
void Backend::update_user(const std::string& token,const std::string& csrf,const std::string& id,const Json& input) {
  auto values=validated_user(input);std::lock_guard guard(mutation_mutex_);session(token,csrf,true);
  auto database=db();Transaction transaction(database);get_user(database,id);auto name=values["name"].get<std::string>();
  database.run("UPDATE users SET name=?,enabled=?,quota=?,expires=? WHERE id=?",{name,values["enabled"].get<Int>(),values["quota"].get<Int>(),values["expires"].get<Int>(),id});
  audit(database,"user_updated",name);transaction.commit();
}
void Backend::delete_user(const std::string& token,const std::string& csrf,const std::string& id) {
  std::lock_guard guard(mutation_mutex_);session(token,csrf,true);auto database=db();Transaction transaction(database);auto user=get_user(database,id);
  database.run("UPDATE users SET deleted=1,enabled=0,token=? WHERE id=?",{random_token(),id});audit(database,"user_deleted",user.name);transaction.commit();
}
void Backend::rotate_user(const std::string& token,const std::string& csrf,const std::string& id) {
  std::lock_guard guard(mutation_mutex_);session(token,csrf,true);auto database=db();Transaction transaction(database);auto user=get_user(database,id);
  database.run("UPDATE users SET uuid=?,token=? WHERE id=?",{random_uuid(),random_token(),id});audit(database,"credentials_rotated",user.name);transaction.commit();
}
void Backend::reset_traffic(const std::string& token,const std::string& csrf,const std::string& id) {
  std::lock_guard guard(mutation_mutex_);session(token,csrf,true);
  if(!core_)throw HttpError(503,"Xray 管理接口不可用");
  auto database=db();auto user=get_user(database,id);
  auto gen=core_->generation();auto counters=core_->counters();
  if(core_->generation()!=gen)throw HttpError(503,"核心正在重启，请稍后重试");
  Transaction transaction(database);apply_stats(database,gen,counters);
  database.run("UPDATE users SET upload=0,download=0 WHERE id=?",{id});audit(database,"traffic_reset",user.name);transaction.commit();
}
Json Backend::links_for(const User& user) const {
  auto s=[&](const char* key){return settings_.at(key).get<std::string>();};
  std::string reality="vless://"+user.uuid+"@"+s("public_ip")+":443?encryption=none&fp=chrome&sni="+url_quote(s("reality_sni"),true)+"&pbk="+url_quote(s("reality_public"),true)+"&sid="+url_quote(s("short_id"),true)+"&type=tcp&security=reality&flow=xtls-rprx-vision#"+url_quote(user.name+" · REALITY",false,true);
  std::string websocket="vless://"+user.uuid+"@"+s("domain")+":443?encryption=none&security=tls&sni="+url_quote(s("domain"),true)+"&type=ws&host="+url_quote(s("domain"),true)+"&path="+url_quote(s("ws_path"),true)+"#"+url_quote(user.name+" · HTTPS",false,true);
  Json result={{"reality",reality},{"websocket",websocket},{"subscription","https://"+s("domain")+"/s/"+user.token}};
  if(auto port=settings_.value("hysteria2_port",0);port>0)
    result["hysteria2"]="hysteria2://"+url_quote(user.uuid)+"@"+s("domain")+":"+std::to_string(port)+"/?sni="+url_quote(s("domain"))+"#"+url_quote(user.name+" · Hysteria 2",false,true);
  if(settings_.contains("vmess_ws_path")) {
    Json node={{"v","2"},{"ps",user.name+" · VMess TLS"},{"add",s("domain")},{"port","443"},{"id",user.uuid},
      {"aid","0"},{"scy","auto"},{"net","ws"},{"type","none"},{"host",s("domain")},{"path",s("vmess_ws_path")},{"tls","tls"},{"sni",s("domain")}};
    result["vmess"]="vmess://"+base64(node.dump());
  }
  const bool dynamic_enabled=dynamic_residential_enabled();
  for(const auto& exit:settings_.value("residential_exits",Json::array())) {
    const bool dynamic=exit.value("dynamic",false);if(dynamic&&!dynamic_enabled)continue;
    const auto tag=exit.at("tag").get<std::string>();
    const auto name=user.name+" · "+exit.at("label").get<std::string>()+(dynamic?"":" · "+exit.at("exit_ip").get<std::string>());
    if(exit.value("hysteria2",false)) {
      // Retain the existing Hysteria display name used by installed Shadowrocket service groups.
      result[tag+"-hy2"]="hysteria2://"+url_quote(user.uuid+"."+tag+"-hy2")+"@"+s("domain")+":"+std::to_string(settings_.at("hysteria2_port").get<int>())+"/?sni="+url_quote(s("domain"))+"#"+url_quote(name,false,true);
    }
    result[tag]="vless://"+user.uuid+"@"+s("domain")+":443?encryption=none&security=tls&sni="+url_quote(s("domain"),true)+"&type=ws&host="+url_quote(s("domain"),true)+"&path="+url_quote(exit.at("ws_path").get<std::string>(),true)+"#"+url_quote(name+(exit.value("hysteria2",false)?" · HTTPS":""),false,true);
  }
  return result;
}
Json Backend::links(const std::string& token,const std::string& id) {session(token);auto database=db();return links_for(get_user(database,id));}
Json Backend::shadowrocket_links_for(const User& user) const {
  auto origin=settings_.at("origin").get<std::string>();
  auto module=origin+"/shadowrocket-dns.sgmodule";
  auto clash=origin+"/s/"+user.token+"/clash.yaml";
  // A fragment keeps the subscription credential out of landing-page requests.
  auto entry=origin+"/client/shadowrocket#"+user.token;
  const auto users=settings_.value("shadowrocket_service_users",Json::array());
  if(std::find(users.begin(),users.end(),Json(user.id))!=users.end()||client_policy_enabled(settings_,user.id))
    entry="shadowrocket://config/add/"+origin+"/s/"+user.token+"/shadowrocket.conf";
  return {{"shadowrocket",entry},
    {"dns",module},{"dns_install","shadowrocket://install?module="+url_quote(module)},
    {"clash",clash},{"clash_install","clash://install-config?url="+url_quote(clash)+"&name="+url_quote("Xdistribute · "+user.name)}};
}
Json Backend::shadowrocket_links(const std::string& token,const std::string& id) {
  session(token);auto database=db();return shadowrocket_links_for(get_user(database,id));
}
std::string Backend::shadowrocket_dns() const {
  auto domain=settings_.at("domain").get<std::string>(),address=settings_.at("public_ip").get<std::string>();
  if(domain.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-")!=std::string::npos||
     address.find_first_not_of("0123456789abcdefABCDEF.:")!=std::string::npos||domain.empty()||address.empty())
    throw std::runtime_error("Invalid DNS module host mapping");
  return "#!name=Xcli DNS 随所选节点\n"
    "#!desc=DNS 通过首页所选节点；关闭系统 DNS 与不支持 UDP 时的直连回退。启用后将首页全局路由设为代理。已包含本服务器节点域名的 IP 映射。\n\n"
    "[General]\n"
    "dns-server = https://1.1.1.1/dns-query#proxy\n"
    "fallback-dns-server = https://1.0.0.1/dns-query#proxy\n"
    "dns-direct-system = false\n"
    "hijack-dns = :53\n"
    "udp-policy-not-supported-behaviour = REJECT\n\n"
    "[Host]\n"+domain+" = "+address+"\n";
}
std::string Backend::qr(const std::string& token,const std::string& id,const std::string& kind) {
  session(token);auto database=db();auto user=get_user(database,id);
  if(kind=="shadowrocket"||kind=="dns"||kind=="clash") {
    auto client=shadowrocket_links_for(user);
    return qr_png(client.at(kind=="dns"?"dns_install":kind=="clash"?"clash":"shadowrocket").get<std::string>());
  }
  auto node=links_for(user);
  if(!node.contains(kind))throw HttpError(404,"Not Found");
  return qr_png(node.at(kind).get<std::string>());
}
void Backend::change_password(const std::string& token,const std::string& csrf,const Json& input) {
  fields(input,{"current_password","new_password","code"},{"current_password","new_password"});
  auto next=checked_string(input.at("new_password"),16,256);
  std::lock_guard guard(mutation_mutex_);session(token,csrf,true);auto database=db();Transaction transaction(database);
  confirm_admin(database,token,input);
  database.run("UPDATE admin SET password=? WHERE id=1",{password_hash(next)});database.run("DELETE FROM sessions");audit(database,"password_changed");transaction.commit();
}
std::pair<std::string,std::string> Backend::subscription(const std::string& token) {
  static const std::regex format("[A-Za-z0-9_-]{43}");if(!std::regex_match(token,format))throw HttpError(404,"Not Found");
  auto database=db();auto row=database.one("SELECT * FROM users WHERE token=? AND deleted=0",{token});if(!row)throw HttpError(404,"Not Found");
  auto user=User::from(*row);if(!user.active())throw HttpError(403,"Subscription inactive");auto node=links_for(user);
  std::string body;for(const auto& kind:inbound_tags())if(node.contains(kind))body+=node.at(kind).get<std::string>()+"\n";
  return {base64(body),
    "upload="+std::to_string(user.upload)+"; download="+std::to_string(user.download)+"; total="+std::to_string(user.quota)+"; expire="+std::to_string(user.expires)};
}
std::pair<Int,Int> Backend::apply_stats(Database& database,const std::string& generation,const std::vector<Counter>& counters) {
  static const std::regex format(R"(user>>>([0-9a-f]{32})\.([0-9a-f]{8})@(reality|websocket|hysteria2|vmess|residential-[0-9]{2}(?:-hy2)?)>>>traffic>>>(uplink|downlink))");
  Int up=0,down=0;auto stamp=now();
  auto previous_sample=database.one("SELECT value FROM metadata WHERE key='activity_sample'");
  Int interval=previous_sample?std::clamp<Int>(stamp-std::stoll(previous_sample->at("value").get<std::string>()),1,300):options_.poll_seconds;
  database.run("UPDATE device_activity SET upload_delta=0,download_delta=0,sampled=?,interval_seconds=?",{stamp,interval});
  for(const auto& counter:counters) {
    std::smatch match;if(counter.value<0||!std::regex_match(counter.name,match,format))continue;
    auto previous=database.one("SELECT value,generation FROM counters WHERE name=?",{counter.name});
    Int delta=counter.value;
    if(previous&&previous->at("generation")==generation&&previous->at("value").get<Int>()<=counter.value)delta-=previous->at("value").get<Int>();
    database.run("INSERT OR REPLACE INTO counters VALUES(?,?,?)",{counter.name,counter.value,generation});
    std::string column=match[4]=="uplink"?"upload":"download";
    auto existing=database.one("SELECT "+column+" AS value FROM users WHERE id=?",{match[1].str()});
    if(existing) {
      database.run("UPDATE users SET "+column+"=? WHERE id=?",{sum_checked(existing->at("value").get<Int>(),delta),match[1].str()});
      // A first observation establishes a baseline; historical bytes are not current activity.
      Int activity_delta=previous_sample&&previous?delta:0;
      const std::string transport=match[3].str().ends_with("-hy2")?"hysteria2":match[3].str().starts_with("residential-")?"websocket":match[3].str();
      database.run("INSERT OR IGNORE INTO device_activity(user_id,transport,sampled,interval_seconds) VALUES(?,?,?,?)",{match[1].str(),transport,stamp,interval});
      database.run("UPDATE device_activity SET "+column+"_delta="+column+"_delta+?,last_seen=CASE WHEN ?>0 THEN ? ELSE last_seen END WHERE user_id=? AND transport=?",{activity_delta,activity_delta,stamp,match[1].str(),transport});
    }
    if(column=="upload")up=sum_checked(up,delta);else down=sum_checked(down,delta);
  }
  database.run("INSERT OR REPLACE INTO metadata VALUES('activity_sample',?)",{std::to_string(stamp)});
  database.run("INSERT INTO traffic_history VALUES(?,?,?) ON CONFLICT(ts) DO UPDATE SET upload=upload+excluded.upload,download=download+excluded.download",{stamp/60*60,up,down});
  database.run("INSERT INTO samples VALUES(?,?,?)",{now(),up,down});database.run("DELETE FROM samples WHERE ts<?",{now()-7*86400});return {up,down};
}
Json Backend::preflight() {
  if(!core_)throw std::runtime_error("Preflight requires a live core");
  std::lock_guard guard(mutation_mutex_);auto database=db();auto all=desired_users(database);auto gen=core_->generation();
  Json result={{"generation",gen},{"active_users",0},{"pending_additions",0},{"pending_revocations",0},{"database_integrity",database.one("PRAGMA quick_check")->begin().value()}};
  for(const auto& user:all)if(user.active()&&user.id!="health-probe")result["active_users"]=result["active_users"].get<int>()+1;
  for(const auto& tag:inbound_tags()) {
    auto current=core_->users(tag);std::map<std::string,std::string> desired;
    for(const auto& user:all)if(user.active())desired.emplace(user.email(tag),user.uuid);
    for(const auto& [email,id]:current)if(!desired.contains(email)||desired[email]!=id)result["pending_revocations"]=result["pending_revocations"].get<int>()+1;
    for(const auto& [email,id]:desired)if(!current.contains(email))result["pending_additions"]=result["pending_additions"].get<int>()+1;
  }
  result["counter_count"]=core_->counters().size();
  if(core_->generation()!=gen)throw std::runtime_error("Core changed during preflight");
  return result;
}
void Backend::poll_once() {
  if(!core_)throw std::runtime_error("Xray API disabled");
  // Serialize against reset/rotation so each generation is accounted for once.
  std::lock_guard guard(mutation_mutex_);auto gen=core_->generation();std::vector<Counter> counters;
  {
    std::lock_guard health_guard(health_mutex_);
    if(health_.value("sync_generation",std::string())!=gen)health_["sync_state"]="unknown";
    health_["sync_generation"]=gen;health_["attempted"]=now();
  }
  try {
    counters=core_->counters();
    std::lock_guard health_guard(health_mutex_);health_["api_state"]="reachable";health_["api_generation"]=gen;health_["api_sampled"]=now();health_["api_last_success"]=now();
  } catch (...) {
    std::lock_guard health_guard(health_mutex_);health_["api_state"]="unavailable";health_["api_sampled"]=now();throw;
  }
  std::map<std::string,std::map<std::string,std::string>> current;
  for(const auto& tag:inbound_tags())current[tag]=core_->users(tag);
  if(core_->generation()!=gen)throw std::runtime_error("Core changed while sampling");
  auto database=db();Transaction transaction(database);auto [up,down]=apply_stats(database,gen,counters);auto all=desired_users(database);
  bool revoke=false;std::vector<std::pair<std::string,User>> additions;
  for(const auto& tag:inbound_tags()) {
    std::map<std::string,User> desired;
    for(const auto& user:all)if(user.active())desired.emplace(user.email(tag),user);
    for(const auto& [email,id]:current[tag])if(!desired.contains(email)||desired.at(email).uuid!=id)revoke=true;
    for(const auto& [email,user]:desired)if(!current[tag].contains(email))additions.emplace_back(tag,user);
  }
  // Commit sampled counters before any external mutation or restart.
  transaction.commit();
  if(revoke) {
    core_->restart(gen);auto event_db=db();audit(event_db,"core_restart","凭据撤销、停用、到期或配额触发；现有连接将重新建立");
  } else for(const auto& [tag,user]:additions)core_->add_user(tag,user);
  std::lock_guard health_guard(health_mutex_);
  const auto stamp=now();
  health_["core"]=!revoke;health_["updated"]=stamp;health_["attempted"]=stamp;health_["last_success"]=stamp;
  health_["error"]=revoke?"正在应用访问权限":"";health_["sync_state"]=revoke?"reconnecting":"ready";
  health_["upload_rate"]=static_cast<double>(up)/options_.poll_seconds;health_["download_rate"]=static_cast<double>(down)/options_.poll_seconds;
}
void Backend::start_worker() {
  if(worker_.joinable())throw std::runtime_error("Controller already started");
  lock_fd_=::open((options_.state/"controller.lock").c_str(),O_RDWR|O_CREAT|O_CLOEXEC|O_NOFOLLOW,0600);
  if(lock_fd_<0||::flock(lock_fd_,LOCK_EX|LOCK_NB)<0) {
    if(lock_fd_>=0)::close(lock_fd_);
    lock_fd_=-1;
    throw std::runtime_error("Another controller owns this state directory");
  }
  stop_=false;
  worker_=std::thread([this] {
    while(true) {
      try {if(!options_.offline)poll_once();}
      catch(const std::exception& error) {
        std::string message="管理接口或访问权限同步异常";std::smatch match;const std::string detail=error.what();
        if(std::regex_match(detail,match,std::regex("Xray API unavailable: (QueryStats|GetInboundUsers|AddUser) \\(([0-9]{1,2})\\)")))
          message="管理接口调用失败："+match[1].str()+"（gRPC 状态 "+match[2].str()+"）";
        else if(detail=="Xray core is not running")message="核心进程未运行或无法确认身份";
        else if(detail=="Core changed while sampling")message="采集期间核心进程已改变，等待重试";
        {std::lock_guard guard(health_mutex_);health_["core"]=false;health_["sync_state"]="error";health_["attempted"]=now();health_["error"]=message;}
        std::cerr<<"Controller: "<<error.what()<<'\n';
      }
      try {sample_runtime();}catch(...){std::cerr<<"Runtime sampling unavailable; previous snapshot will expire\n";}
      try {scheduled_backup();}catch(const std::exception&){std::cerr<<"Automatic backup failed; will retry\n";}
      std::unique_lock guard(worker_mutex_);
      if(worker_cv_.wait_for(guard,std::chrono::seconds(options_.poll_seconds),[this]{return stop_;}))break;
    }
  });
  operations_worker_=std::thread([this] {
    while(true) {
      try {collect_operations();}catch(const std::exception&){std::cerr<<"Operations sampling failed; will retry\n";}
      try {deliver_notifications();}catch(const std::exception&){std::cerr<<"Notification delivery failed; will retry\n";}
      std::unique_lock guard(worker_mutex_);
      if(worker_cv_.wait_for(guard,std::chrono::seconds(options_.poll_seconds),[this]{return stop_;}))break;
    }
  });
}
void Backend::stop_worker() {
  {std::lock_guard guard(worker_mutex_);stop_=true;}worker_cv_.notify_all();
  if(worker_.joinable())worker_.join();
  if(operations_worker_.joinable())operations_worker_.join();
  if(lock_fd_>=0){::close(lock_fd_);lock_fd_=-1;}
}
}
