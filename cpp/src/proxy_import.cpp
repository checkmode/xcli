#include "gateway.hpp"
#include <algorithm>
#include <array>
#include <regex>
#include <set>
#include <sstream>
#include <sys/stat.h>

namespace xg {
namespace {
constexpr auto context="xcli:proxy-import:request:v1";
void fields(const Json& input,const std::set<std::string>& allowed,const std::set<std::string>& required) {
  if(!input.is_object())throw HttpError(422,"请求必须是 JSON 对象");
  for(auto it=input.begin();it!=input.end();++it)if(!allowed.contains(it.key()))throw HttpError(422,"包含不支持的字段");
  for(const auto& key:required)if(!input.contains(key))throw HttpError(422,"缺少必要字段");
}
Json report(const Options& options) {
  Json out={{"id",""},{"status","unavailable"},{"message","导入服务尚未就绪，请检查服务安装状态"},{"rows",Json::array()},{"updated",0}};
  try {
    auto value=Json::parse(read_file(options.state.parent_path()/"xray-gateway-import/report.json",32768));
    for(const auto* key:{"id","status","message"})if(value.contains(key)&&value[key].is_string())out[key]=value[key].get<std::string>().substr(0,256);
    for(const auto* key:{"updated","expires","added"})if(value.contains(key)&&value[key].is_number_integer())out[key]=value[key];
    for(const auto& row:value.value("rows",Json::array())) {
      if(out["rows"].size()>=20)break;
      Json item=Json::object();
      for(const auto* key:{"address","exit_ip","country","protocol","label","status","error"})if(row.contains(key)&&row[key].is_string())item[key]=row[key].get<std::string>().substr(0,200);
      for(const auto* key:{"port","https_ms","doh_ms"})if(row.contains(key)&&row[key].is_number_integer())item[key]=row[key];
      out["rows"].push_back(item);
    }
    if(now()-out["updated"].get<Int>()>30){out["status"]="unavailable";out["message"]="导入服务状态已过期，请检查服务";}
  }catch(...){}
  return out;
}
Json parse_proxies(const Json& input) {
  auto text=checked_string(input,1,12000);std::istringstream stream(text);std::string line;Json rows=Json::array();std::set<std::string> peers;
  while(std::getline(stream,line)) {
    if(!line.empty()&&line.back()=='\r')line.pop_back();
    if(line.find_first_not_of(" \t")==std::string::npos)continue;
    if(rows.size()>=20)throw HttpError(422,"每次最多导入 20 个代理");
    std::array<std::string,4> parts;std::size_t offset=0;
    for(std::size_t i=0;i<3;++i){auto colon=line.find(':',offset);if(colon==std::string::npos)throw HttpError(422,"每行格式应为 HOST:PORT:USER:PASS");parts[i]=line.substr(offset,colon-offset);offset=colon+1;}
    parts[3]=line.substr(offset);
    if(!std::regex_match(parts[0],std::regex("[0-9]{1,3}(\\.[0-9]{1,3}){3}"))||!public_webhook_address(parts[0]))throw HttpError(422,"仅支持公网 IPv4 地址");
    if(!std::regex_match(parts[1],std::regex("[0-9]{1,5}")))throw HttpError(422,"代理端口不正确");
    auto port=std::stoi(parts[1]);if(port<1||port>65535)throw HttpError(422,"代理端口不正确");
    for(std::size_t i=2;i<4;++i)if(parts[i].empty()||parts[i].size()>255||std::any_of(parts[i].begin(),parts[i].end(),[](unsigned char c){return c<32||c==127;}))throw HttpError(422,"账号或密码格式不正确");
    if(!peers.insert(parts[0]+":"+std::to_string(port)).second)throw HttpError(422,"列表包含重复地址和端口");
    rows.push_back({{"address",parts[0]},{"port",port},{"username",parts[2]},{"password",parts[3]}});
  }
  if(rows.empty())throw HttpError(422,"请填写至少一个代理");
  return rows;
}
}
Json Backend::proxy_import_status(const std::string& token) {
  session(token);std::lock_guard guard(mutation_mutex_);auto result=report(options_);
  result["available_slots"]=40-settings_.value("residential_exits",Json::array()).size();return result;
}
Json Backend::request_proxy_import(const std::string& token,const std::string& csrf,const Json& input) {
  std::lock_guard guard(mutation_mutex_);session(token,csrf,true);
  fields(input,{"action","protocol","label","text","preview_id"},{"action"});
  auto action=checked_string(input["action"],1,16);auto current=report(options_);
  if(current["status"]=="unavailable")throw HttpError(503,"导入服务尚未就绪，请检查服务");
  if(current["status"]=="verifying"||current["status"]=="applying")throw HttpError(409,"已有导入任务正在处理");
  const auto directory=options_.state/"proxy-import",path=directory/"request.xgb";
  if(fs::exists(path)) {
    auto pending=Json::parse(unseal(read_file(path,20000),secret_key_,context));
    if(pending.value("id",std::string())!=current.value("id",std::string())&&now()-pending.value("requested_at",Int(0))<900)throw HttpError(409,"导入请求正在排队，请稍后重试");
  }
  Json request={{"id",random_id()},{"action",action},{"requested_at",now()}};
  if(action=="preview") {
    fields(input,{"action","protocol","label","text"},{"action","protocol","label","text"});
    auto protocol=checked_string(input["protocol"],1,8),label=user_name(input["label"]);
    if(protocol!="socks"&&protocol!="http")throw HttpError(422,"请选择 SOCKS5 或 HTTP 协议");
    if(label.size()>120)throw HttpError(422,"名称前缀过长");
    auto proxies=parse_proxies(input["text"]);
    if(settings_.value("residential_exits",Json::array()).size()+proxies.size()>40)throw HttpError(422,"固定和动态入口合计最多 40 个，请减少导入数量");
    request["protocol"]=protocol;request["label"]=label;request["proxies"]=proxies;
  }else if(action=="apply") {
    fields(input,{"action","preview_id"},{"action","preview_id"});auto id=checked_string(input["preview_id"],32,32);
    if(!std::regex_match(id,std::regex("[0-9a-f]{32}"))||current["status"]!="ready"||current["id"]!=id||current.value("expires",Int(0))<=now())throw HttpError(409,"检测结果已过期或不匹配，请重新检测");
    request["preview_id"]=id;
  }else throw HttpError(422,"不支持此操作");
  fs::create_directories(directory);if(::chmod(directory.c_str(),0700)<0)throw std::runtime_error("Cannot secure import queue");
  write_private_file(path,seal(request.dump(),secret_key_,context),true);
  auto database=db();audit(database,"proxy_import_requested",action=="preview"?"请求检测固定代理":"确认导入固定代理");
  return {{"id",request["id"]},{"pending",true}};
}
}
