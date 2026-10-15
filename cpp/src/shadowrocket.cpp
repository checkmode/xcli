#include "gateway.hpp"
#include <regex>

namespace xg {
Json Backend::shadowrocket_setup(const std::string& token) {
  auto database=db();auto row=database.one("SELECT * FROM users WHERE token=? AND deleted=0",{token});
  if(!row)throw HttpError(404,"Not Found");
  const auto user=User::from(*row);if(!user.active())throw HttpError(403,"Subscription inactive");
  const auto users=settings_.value("shadowrocket_service_users",Json::array());
  const bool enabled=std::find(users.begin(),users.end(),Json(user.id))!=users.end();
  return {{"service_routing",enabled},{"resource",enabled?"/s/"+token+"/shadowrocket.conf":"/shadowrocket-dns.sgmodule"}};
}

std::string Backend::shadowrocket_profile(const std::string& token) {
  if(!shadowrocket_setup(token).at("service_routing").get<bool>())throw HttpError(404,"Not Found");
  auto database=db();auto row=database.one("SELECT * FROM users WHERE token=? AND deleted=0",{token});
  if(!row)throw HttpError(404,"Not Found");
  const auto user=User::from(*row);if(!user.active())throw HttpError(403,"Subscription inactive");
  const auto address=settings_.at("public_ip").get<std::string>(),domain=settings_.at("domain").get<std::string>();
  if(domain.empty()||address.empty()||domain.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-")!=std::string::npos||
     address.find_first_not_of("0123456789abcdefABCDEF.:")!=std::string::npos||
     !std::regex_match(user.uuid,std::regex("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")))
    throw HttpError(503,"Invalid Shadowrocket node metadata");
  // Reject delimiters instead of permitting settings to inject INI fields.
  std::string proxies,groups,rules;
  for(const auto& service:settings_.at("clash_service_routes").at(user.id)) {
    const auto name=service.at("name").get<std::string>(),tag=service.at("outbound").get<std::string>();
    const auto group="XCLI-"+name,node=group+"-"+user.id.substr(0,8);
    bool available=settings_.value("hysteria2_port",0)>0;
    std::string auth=user.uuid;
    if(tag!="hysteria2") {
      bool found=false;
      for(const auto& exit:settings_.value("residential_exits",Json::array()))
        if(exit.at("tag")==tag&&exit.value("hysteria2",false)&&
           (!exit.value("dynamic",false)||dynamic_residential_enabled()))found=true;
      available=available&&found;auth+="."+tag+"-hy2";
    }
    if(available)proxies+=node+" = hysteria2,"+address+","+std::to_string(settings_.at("hysteria2_port").get<int>())+
      ",auth="+auth+",peer="+domain+",udp="+(service.at("udp")=="reject"?"0":"1")+"\n";
    groups+=group+" = select,"+(available?node:"REJECT")+"\n";
    for(const auto& entry:service.at("domains")) {
      const auto host=entry.get<std::string>();
      if(service.at("udp")=="reject")rules+="AND,((DOMAIN-SUFFIX,"+host+"),(PROTOCOL,UDP)),REJECT\n";
      rules+="DOMAIN-SUFFIX,"+host+","+group+"\n";
    }
  }
  // Inherit the existing complete local base. This one remote resource owns nodes and rules.
  return "# Xcli 专属业务分流；继承手机现有 default.conf，请保留该文件。\n"
    "# 全局路由必须为配置。节点与规则随本远程配置一同更新；含个人凭据，请勿分享。\n\n"
    "[General]\ninclude = default.conf\nupdate-url = "+settings_.at("origin").get<std::string>()+"/s/"+token+"/shadowrocket.conf\nudp-policy-not-supported-behaviour = REJECT\n\n"
    "[Proxy]\n"+proxies+"\n[Proxy Group]\n"+groups+"\n[Rule]\n"+rules;
}
}
