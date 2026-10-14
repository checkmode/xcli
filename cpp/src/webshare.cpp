#include "gateway.hpp"
#include <algorithm>
#include <regex>
#include <set>
#include <sys/stat.h>

namespace xg {
namespace {
constexpr auto context="xcli:webshare:config:v1";
bool region(const std::string& value){return value=="US"||value=="JP"||value=="SG"||value=="ZZ";}
void fields(const Json& input,const std::set<std::string>& allowed,const std::set<std::string>& required) {
  if(!input.is_object())throw HttpError(422,"请求必须是 JSON 对象");
  for(auto it=input.begin();it!=input.end();++it)if(!allowed.contains(it.key()))throw HttpError(422,"包含不支持的字段");
  for(const auto& name:required)if(!input.contains(name))throw HttpError(422,"缺少必要字段");
}
Int integer(const Json& value,Int maximum) {
  if(!value.is_number_integer()||(value.is_number_unsigned()&&value.get<std::uint64_t>()>static_cast<std::uint64_t>(maximum)))throw HttpError(422,"请输入有效整数");
  auto number=value.get<Int>();if(number<0||number>maximum)throw HttpError(422,"数值超出允许范围");return number;
}
bool boolean(const Json& value){if(!value.is_boolean())throw HttpError(422,"请输入有效布尔值");return value.get<bool>();}
}
Json Backend::webshare_configuration() const {
  const auto path=options_.state/"webshare/config.xgb";
  if(!fs::exists(path))return {{"api_key",""},{"plan_id",0},{"enabled",false},{"revision",""}};
  return Json::parse(unseal(read_file(path,16384),secret_key_,context));
}
bool Backend::dynamic_residential_enabled() const {
  try {return webshare_configuration().value("enabled",false);}catch(...){return false;}
}
Json Backend::webshare_public_status() const {
  Json result={{"updated",0},{"status","unconfigured"},{"message","填写 API Key 后读取可用套餐"},{"plans",Json::array()},{"pools",Json::array()},{"events",Json::array()}};
  try {
    auto value=Json::parse(read_file(options_.state/"webshare/report.json",65536));
    for(const auto* key:{"updated","last_sync","last_attempt","next_sync","active_plan_id","usage_updated","requests_total","requests_successful","requests_failed"})
      if(value.contains(key)&&value.at(key).is_number_integer())result[key]=value.at(key);
    for(const auto* key:{"status","message","revision","sync_error","usage_error"})
      if(value.contains(key)&&value.at(key).is_string())result[key]=value.at(key).get<std::string>().substr(0,256);
    if(value.contains("bandwidth_total")&&value.at("bandwidth_total").is_number())result["bandwidth_total"]=value.at("bandwidth_total");
    if(value.contains("enabled")&&value.at("enabled").is_boolean())result["active_enabled"]=value.at("enabled");
    for(const auto& plan:value.value("plans",Json::array())) {
      if(result["plans"].size()>=100)break;
      if(!plan.is_object()||!plan.contains("id")||!plan.at("id").is_number_integer())continue;
      Json out={{"id",plan.at("id")}};
      for(const auto* key:{"label","status","pool_filter","proxy_subtype"})if(plan.contains(key)&&plan.at(key).is_string())out[key]=plan.at(key).get<std::string>().substr(0,100);
      if(plan.contains("bandwidth_limit")&&plan.at("bandwidth_limit").is_number())out["bandwidth_limit"]=plan.at("bandwidth_limit");
      if(plan.contains("eligible")&&plan.at("eligible").is_boolean())out["eligible"]=plan.at("eligible");
      result["plans"].push_back(out);
    }
    for(const auto& pool:value.value("pools",Json::array())) {
      auto country=pool.value("country",std::string());if(!region(country)||result["pools"].size()>=4)continue;
      Json out={{"country",country}};
      for(const auto* key:{"label","status","error","exit_ip","exit_country"})if(pool.contains(key)&&pool.at(key).is_string())out[key]=pool.at(key).get<std::string>().substr(0,256);
      for(const auto* key:{"last_success","selected_at","expires_at","standby","failures","https_ms","doh_ms"})if(pool.contains(key)&&pool.at(key).is_number_integer())out[key]=pool.at(key);
      result["pools"].push_back(out);
    }
    for(const auto& event:value.value("events",Json::array())) {
      if(result["events"].size()>=20)break;
      auto country=event.value("country",std::string());if(!region(country))continue;
      result["events"].push_back({{"country",country},{"ts",event.value("ts",Int(0))},{"reason",event.value("reason",std::string()).substr(0,120)}});
    }
    if(now()-result.at("updated").get<Int>()>30){result["status"]="stale";result["message"]="池管理服务状态已过期，请检查服务";}
  }catch(...){result["status"]="unknown";result["message"]="等待池管理服务";}
  return result;
}
Json Backend::webshare_status(const std::string& token) {
  session(token);std::lock_guard guard(mutation_mutex_);auto result=webshare_public_status();auto config=webshare_configuration();
  result["key_saved"]=!config.value("api_key",std::string()).empty();result["plan_id"]=config.value("plan_id",Int(0));
  result["enabled"]=config.value("enabled",false);result["requested_revision"]=config.value("revision",std::string());
  result["installed"]=false;for(const auto& exit:settings_.value("residential_exits",Json::array()))if(exit.value("dynamic",false))result["installed"]=true;
  return result;
}
void Backend::configure_webshare(const std::string& token,const std::string& csrf,const Json& input) {
  fields(input,{"api_key","plan_id","enabled","clear_key"},{});
  std::lock_guard guard(mutation_mutex_);session(token,csrf,true);auto config=webshare_configuration();
  if(input.contains("api_key")) {
    auto key=checked_string(input.at("api_key"),0,256);
    if(!key.empty()) {
      if(!std::regex_match(key,std::regex("[A-Za-z0-9_-]{16,256}")))throw HttpError(422,"API Key 格式不正确");
      config["api_key"]=key;
    }
  }
  if(input.contains("clear_key")&&boolean(input.at("clear_key"))) {config["api_key"]="";config["enabled"]=false;config["plan_id"]=0;}
  if(input.contains("plan_id")) {
    const auto id=integer(input.at("plan_id"),2147483647);
    if(id!=0) {
      const auto report=webshare_public_status();bool found=false;for(const auto& plan:report.at("plans"))if(plan.at("id")==id&&plan.value("eligible",false))found=true;
      if(!found)throw HttpError(422,"请先读取套餐，再选择可用的动态住宅套餐");
    }
    config["plan_id"]=id;
  }
  if(input.contains("enabled"))config["enabled"]=boolean(input.at("enabled"));
  if(config.value("enabled",false)&&(config.value("api_key",std::string()).empty()||config.value("plan_id",Int(0))==0))throw HttpError(422,"启用前请填写 API Key 并选择套餐");
  config["revision"]=random_id();config["requested_at"]=now();config.erase("action");config.erase("country");
  auto directory=options_.state/"webshare";fs::create_directories(directory);if(::chmod(directory.c_str(),0700)<0)throw std::runtime_error("Cannot secure Webshare state");
  write_private_file(directory/"config.xgb",seal(config.dump(),secret_key_,context),true);
  auto database=db();audit(database,"webshare_configured",config.value("enabled",false)?"动态住宅池已请求启用":"Webshare 配置已保存");
}
void Backend::request_webshare(const std::string& token,const std::string& csrf,const Json& input) {
  fields(input,{"action","country"},{"action"});std::lock_guard guard(mutation_mutex_);session(token,csrf,true);
  auto action=checked_string(input.at("action"),1,16);if(action!="sync"&&action!="rotate")throw HttpError(422,"不支持此操作");
  auto config=webshare_configuration();if(config.value("api_key",std::string()).empty())throw HttpError(422,"请先保存 API Key");
  if(action=="rotate") {auto country=checked_string(input.value("country",Json("")),2,2);if(!region(country)||!config.value("enabled",false))throw HttpError(422,"请先启用对应地区的动态池");config["country"]=country;}
  config["action"]=action;config["revision"]=random_id();config["requested_at"]=now();
  write_private_file(options_.state/"webshare/config.xgb",seal(config.dump(),secret_key_,context),true);
  auto database=db();audit(database,"webshare_requested",action=="sync"?"请求同步 Webshare":"请求更换动态住宅会话");
}
}
