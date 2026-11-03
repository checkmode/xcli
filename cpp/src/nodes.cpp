#include "gateway.hpp"
#include <algorithm>
#include <limits>
#include <regex>
#include <set>

namespace xg {
namespace {
constexpr std::string_view registry_key="remote_nodes_v1";
const std::regex id_re("[0-9a-f]{32}"), token_re("[A-Za-z0-9_-]{43}"), pub_re("[A-Za-z0-9_-]{43}"),
  short_re("[0-9a-f]{16}"), path_re("/connect/[0-9a-f]{24}"), revision_re("[0-9a-f]{64}");
void shape(const Json& value,const std::set<std::string>& names) {
  if(!value.is_object()||value.size()!=names.size())throw HttpError(422,"节点请求字段不正确");
  for(auto it=value.begin();it!=value.end();++it)if(!names.contains(it.key()))throw HttpError(422,"节点请求包含不支持的字段");
}
Int number(const Json& value,Int max) {
  if(!value.is_number_integer()||(value.is_number_unsigned()&&value.get<std::uint64_t>()>static_cast<std::uint64_t>(max)))
    throw HttpError(422,"节点数值不正确");
  auto v=value.get<Int>();if(v<0||v>max)throw HttpError(422,"节点数值超出范围");return v;
}
std::string match(const Json& value,const std::regex& pattern) {
  auto s=checked_string(value,1,256);if(!std::regex_match(s,pattern))throw HttpError(422,"节点信息格式不正确");return s;
}
std::string domain(const Json& value) {
  auto s=checked_string(value,3,253);
  if(!std::regex_match(s,std::regex("[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+")))throw HttpError(422,"节点域名格式不正确");
  std::size_t start=0;while(start<s.size()){auto end=s.find('.',start);if(end==std::string::npos)end=s.size();if(end-start>63)throw HttpError(422,"节点域名格式不正确");start=end+1;}
  return s;
}
Json load(Database& db) {
  auto row=db.one("SELECT value FROM metadata WHERE key=?",{std::string(registry_key)});
  if(!row)return Json::array();
  auto result=Json::parse(row->at("value").get<std::string>());
  if(!result.is_array()||result.size()>20)throw std::runtime_error("Invalid remote node registry");
  return result;
}
void save(Database& db,const Json& registry) {
  db.run("INSERT OR REPLACE INTO metadata(key,value) VALUES(?,?)",{std::string(registry_key),registry.dump()});
}
Json& find_node(Json& registry,const std::string& id) {
  for(auto& node:registry)if(node.at("id")==id)return node;
  throw HttpError(404,"节点不存在");
}
Json selected(Database& db,const Json& value) {
  Json unpacked=value;
  if(value.is_string()) {
    const auto packed=value.get<std::string>();std::string raw;
    try {raw=unbase64(packed,8000);} catch(const std::exception&) {throw HttpError(422,"用户选择格式不正确");}
    if(raw.size()%16||raw.size()>8000||base64(raw)!=packed)throw HttpError(422,"用户选择格式不正确");
    unpacked=Json::array();const char* digits="0123456789abcdef";
    for(std::size_t pos=0;pos<raw.size();pos+=16) {
      std::string id;id.reserve(32);for(std::size_t i=0;i<16;i++){auto n=static_cast<unsigned char>(raw[pos+i]);id+=digits[n>>4];id+=digits[n&15];}unpacked.push_back(id);
    }
  }
  if(!unpacked.is_array()||unpacked.size()>500)throw HttpError(422,"请选择有效的用户");
  Json result=Json::array();std::set<std::string> seen;
  for(const auto& item:unpacked) {
    auto id=match(item,id_re);
    if(!seen.insert(id).second||!db.one("SELECT id FROM users WHERE id=? AND deleted=0",{id}))throw HttpError(422,"所选用户不存在或重复");
    result.push_back(id);
  }
  std::sort(result.begin(),result.end());return result;
}
Json desired(Database& db,const Json& node) {
  Json users=Json::array();
  if(!node.at("enabled").get<bool>())return users;
  for(const auto& id:node.at("users")) {
    auto row=db.one("SELECT * FROM users WHERE id=? AND deleted=0",{id.get<std::string>()});
    if(!row)continue;
    auto user=User::from(*row);
    if(user.active())users.push_back({{"id",user.id},{"uuid",user.uuid},{"expires",user.expires}});
  }
  return users;
}
Json display(const Json& node) {
  return {{"id",node.at("id")},{"name",node.at("name")},{"endpoint",node.at("endpoint")},
          {"users",node.at("users")},{"enabled",node.at("enabled")},
          {"last_seen",node.value("last_seen",Int(0))},{"applied_revision",node.value("applied_revision",std::string())},
          {"pending_revision",node.value("pending_revision",std::string())}};
}
Json validate_registration(const Json& registration) {
  shape(registration,{"version","id","key","public_ip","domain","public_port","reality_sni","reality_public","short_id","ws_path","hysteria2_port"});
  if(number(registration.at("version"),1)!=1)throw HttpError(422,"不支持的节点注册格式");
  const auto ip=checked_string(registration.at("public_ip"),7,15);
  if(ip.find(':')!=std::string::npos||!public_webhook_address(ip))throw HttpError(422,"节点需要公网 IPv4 地址");
  auto port=number(registration.at("public_port"),65535),hy=number(registration.at("hysteria2_port"),65535);
  if(port==0||hy==0)throw HttpError(422,"节点端口不正确");
  return {{"id",match(registration.at("id"),id_re)},
          {"key_hash",sha256(match(registration.at("key"),token_re))},
          {"endpoint",{{"public_ip",ip},{"domain",domain(registration.at("domain"))},{"public_port",port},
            {"reality_sni",domain(registration.at("reality_sni"))},{"reality_public",match(registration.at("reality_public"),pub_re)},
            {"short_id",match(registration.at("short_id"),short_re)},{"ws_path",match(registration.at("ws_path"),path_re)},
            {"hysteria2_port",hy}}}};
}
std::string node_name(const Json& value) {
  auto result=user_name(value);
  if(result.find_first_of(",=\r\n")!=std::string::npos)throw HttpError(422,"节点名称不能包含逗号、等号或换行");
  return result;
}
Int add_safe(Int a,Int b) {
  if(a<0||b<0||a>std::numeric_limits<Int>::max()-b)throw HttpError(422,"节点流量超出范围");
  return a+b;
}
}

Json Backend::remote_nodes(const std::string& token) {
  session(token);auto database=db();auto registry=load(database);Json result=Json::array();
  for(const auto& node:registry)result.push_back(display(node));
  return {{"nodes",result}};
}
bool Backend::remote_has_history(Database& db,const std::string& id) const {
  auto registry=load(db);
  for(const auto& node:registry)if(std::find(node.at("history").begin(),node.at("history").end(),Json(id))!=node.at("history").end())return true;
  return false;
}
Json Backend::add_remote_node(const std::string& token,const std::string& csrf,const Json& input) {
  shape(input,{"name","registration","users"});
  auto registration=validate_registration(input.at("registration"));auto name=node_name(input.at("name"));
  std::lock_guard guard(mutation_mutex_);session(token,csrf,true);auto database=db();Transaction tx(database);
  auto registry=load(database);if(registry.size()>=20)throw HttpError(409,"最多支持 20 个远程节点");
  for(const auto& node:registry) {
    const auto existing=node.at("id").get<std::string>(),created=registration.at("id").get<std::string>();
    if(existing==created)throw HttpError(409,"节点已添加");
    if(existing.substr(0,8)==created.substr(0,8))throw HttpError(409,"节点编号与已有节点冲突，请重新生成节点身份");
  }
  auto users=selected(database,input.at("users"));
  registration["name"]=name;registration["users"]=users;registration["history"]=users;
  registration["enabled"]=true;registration["last_seen"]=0;registration["pending_revision"]="";
  registration["applied_revision"]="";registration["pending_users"]=Json::array();
  registration["applied_users"]=Json::array();registration["counters"]=Json::object();
  registry.push_back(registration);save(database,registry);audit(database,"node_added",name);tx.commit();
  return display(registration);
}
Json Backend::update_remote_node(const std::string& token,const std::string& csrf,const std::string& id,const Json& input) {
  shape(input,{"name","users","enabled"});if(!std::regex_match(id,id_re)||!input.at("enabled").is_boolean())throw HttpError(422,"节点信息格式不正确");
  const auto name=node_name(input.at("name"));
  std::lock_guard guard(mutation_mutex_);session(token,csrf,true);auto database=db();Transaction tx(database);
  auto registry=load(database);auto& node=find_node(registry,id);auto users=selected(database,input.at("users"));
  std::set<std::string> history;for(const auto& item:node.at("history"))history.insert(item.get<std::string>());
  for(const auto& item:users)history.insert(item.get<std::string>());
  if(history.size()>5000)throw HttpError(409,"节点历史用户过多，请停用并重新注册节点");
  node["name"]=name;node["users"]=users;node["history"]=Json::array();for(const auto& item:history)node["history"].push_back(item);
  node["enabled"]=input.at("enabled");save(database,registry);audit(database,"node_updated",name);auto result=display(node);tx.commit();return result;
}
Json Backend::sync_remote_node(const std::string& authorization,const Json& input) {
  const std::string prefix="Xcli-Node ";
  if(!authorization.starts_with(prefix)||authorization.size()!=prefix.size()+32+1+43||authorization[prefix.size()+32]!='.')throw HttpError(401,"节点认证失败");
  const auto id=authorization.substr(prefix.size(),32),secret=authorization.substr(prefix.size()+33);
  if(!std::regex_match(id,id_re)||!std::regex_match(secret,token_re))throw HttpError(401,"节点认证失败");
  shape(input,{"revision","counters"});const auto revision=checked_string(input.at("revision"),0,64);
  if(!revision.empty()&&!std::regex_match(revision,revision_re))throw HttpError(422,"节点版本不正确");
  if(!input.at("counters").is_array()||input.at("counters").size()>100)throw HttpError(422,"节点计数格式不正确");
  std::lock_guard guard(mutation_mutex_);auto database=db();Transaction tx(database);auto registry=load(database);
  auto found=std::find_if(registry.begin(),registry.end(),[&](const Json& item){return item.at("id")==id;});
  if(found==registry.end())throw HttpError(401,"节点认证失败");
  auto& node=*found;
  if(!secure_equal(node.at("key_hash").get<std::string>(),sha256(secret)))throw HttpError(401,"节点认证失败");
  std::set<std::string> history,seen;for(const auto& item:node.at("history"))history.insert(item.get<std::string>());
  Int upload=0,download=0;auto& last=node["counters"];
  for(const auto& entry:input.at("counters")) {
    shape(entry,{"id","upload","download"});auto uid=match(entry.at("id"),id_re);
    if(!seen.insert(uid).second||!history.contains(uid))throw HttpError(422,"节点报告了未授权的用户");
    const auto up=number(entry.at("upload"),std::numeric_limits<Int>::max()),down=number(entry.at("download"),std::numeric_limits<Int>::max());
    auto previous=last.value(uid,Json{{"upload",0},{"download",0}});
    const auto old_up=previous.at("upload").get<Int>(),old_down=previous.at("download").get<Int>();
    if(up<old_up||down<old_down)throw HttpError(409,"节点流量计数回退，需要重新核对节点状态");
    const auto du=up-old_up,dd=down-old_down;auto row=database.one("SELECT upload,download FROM users WHERE id=?",{uid});
    // A backup restore can remove a user created since that backup. Consume its
    // late report without preventing the other accounts on this node from syncing.
    if(row) {
      database.run("UPDATE users SET upload=?,download=? WHERE id=?",{add_safe(row->at("upload").get<Int>(),du),add_safe(row->at("download").get<Int>(),dd),uid});
      upload=add_safe(upload,du);download=add_safe(download,dd);
    }
    last[uid]={{"upload",up},{"download",down}};
  }
  const auto stamp=now();
  if(upload||download) {
    const auto minute=stamp/60*60;auto existing=database.one("SELECT upload,download FROM traffic_history WHERE ts=?",{minute});
    if(existing){upload=add_safe(existing->at("upload").get<Int>(),upload);download=add_safe(existing->at("download").get<Int>(),download);}
    database.run("INSERT OR REPLACE INTO traffic_history VALUES(?,?,?)",{minute,upload,download});
    // Samples contain this report's delta, not the cumulative minute bucket.
    database.run("INSERT INTO samples VALUES(?,?,?)",{stamp,upload-(existing?existing->at("upload").get<Int>():0),download-(existing?existing->at("download").get<Int>():0)});
  }
  if(revision==node.value("pending_revision",std::string())&&!revision.empty()) {
    node["applied_revision"]=revision;node["applied_users"]=node.at("pending_users");
  }
  node["last_seen"]=stamp;auto users=desired(database,node);const auto desired_revision=sha256(users.dump());
  node["pending_revision"]=desired_revision;node["pending_users"]=users;save(database,registry);tx.commit();
  return {{"revision",desired_revision},{"users",users},{"lease_seconds",30},{"issued_at",stamp},{"ack",input.at("counters")}};
}
Json Backend::remote_nodes_for(const User& user) const {
  auto database=db();auto registry=load(database);Json result=Json::array();
  for(const auto& node:registry) {
    // Keep previously applied entries stable across short outages. An offline
    // node still enforces its local lease; the UI reports connectivity separately.
    if(!node.at("enabled").get<bool>())continue;
    const auto& users=node.at("users");
    if(std::find(users.begin(),users.end(),Json(user.id))==users.end())continue;
    bool applied=false;for(const auto& item:node.at("applied_users"))
      if(item.at("id")==user.id&&item.at("uuid")==user.uuid)applied=true;
    if(applied)result.push_back(display(node));
  }
  return result;
}
}
