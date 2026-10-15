#include "gateway.hpp"
#include <map>
#include <regex>

namespace xg {
namespace {
std::string trimmed(std::string value) {
  const auto first=value.find_first_not_of(" \t\r\n");
  if(first==std::string::npos)return {};
  return value.substr(first,value.find_last_not_of(" \t\r\n")-first+1);
}

// Keep the user's complete file, including comments, DNS and unrelated sections.
// Only insert the managed groups/rules and set this resource's update URL.
std::string extend_base(const std::string& base,const std::string& groups,
                        const std::string& rules,const std::string& update_url) {
  if(base.empty()||base.size()>512*1024||base.find('\0')!=std::string::npos)
    throw HttpError(503,"Invalid Shadowrocket base profile");
  const std::string eol=base.find("\r\n")!=std::string::npos?"\r\n":"\n";
  auto lines=[&](const std::string& value) {
    std::string result;
    for(char ch:value)result+=ch=='\n'?eol:std::string(1,ch);
    return result;
  };
  std::map<std::string,int> sections;
  std::string section;
  int updates=0;
  const std::regex header(R"(^\[([^\]]+)\]\s*(#.*)?$)");
  for(std::size_t offset=0;offset<base.size();) {
    auto end=base.find('\n',offset);if(end==std::string::npos)end=base.size();
    auto line=trimmed(base.substr(offset,end-offset));
    if(offset==0&&line.starts_with("\xef\xbb\xbf"))line.erase(0,3);
    std::smatch match;
    if(std::regex_match(line,match,header)) {section=match[1];++sections[section];}
    else if(section=="General"&&line.starts_with("update-url")&&
            trimmed(line.substr(0,line.find('=')))=="update-url")++updates;
    else if(section=="Proxy Group"&&line.starts_with("XCLI-"))
      throw HttpError(503,"Shadowrocket base contains reserved service groups");
    offset=end==base.size()?end:end+1;
  }
  if(sections["General"]!=1||sections["Rule"]!=1||sections["Proxy Group"]>1||updates>1)
    throw HttpError(503,"Ambiguous Shadowrocket base sections");
  std::string result;
  section.clear();
  for(std::size_t offset=0;offset<base.size();) {
    auto end=base.find('\n',offset);const bool newline=end!=std::string::npos;
    if(!newline)end=base.size();
    const auto original=base.substr(offset,end-offset+(newline?1:0));
    auto line=trimmed(original);
    if(offset==0&&line.starts_with("\xef\xbb\xbf"))line.erase(0,3);
    std::smatch match;
    if(std::regex_match(line,match,header)) {
      section=match[1];
      if(section=="Rule"&&!sections["Proxy Group"])
        result+="[Proxy Group]"+eol+lines(groups)+eol;
      result+=original;if(!newline)result+=eol;
      if(section=="General"&&!updates)result+="update-url = "+update_url+eol;
      if(section=="Proxy Group")result+=lines(groups);
      if(section=="Rule")result+=lines(rules);
    } else if(section=="General"&&line.starts_with("update-url")&&
              trimmed(line.substr(0,line.find('=')))=="update-url") {
      result+="update-url = "+update_url+eol;
    } else result+=original;
    offset=end==base.size()?end:end+1;
  }
  return result;
}
}

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
  const auto bases=settings_.value("shadowrocket_base_profiles",Json::object());
  const bool complete_base=bases.contains(user.id);
  std::string proxies,groups,rules;
  for(const auto& service:settings_.at("clash_service_routes").at(user.id)) {
    const auto name=service.at("name").get<std::string>(),tag=service.at("outbound").get<std::string>();
    const auto group="XCLI-"+name,node=group+"-"+user.id.substr(0,8);
    bool available=settings_.value("hysteria2_port",0)>0;
    std::string auth=user.uuid;
    std::string existing_name=user.name+" · Hysteria 2";
    if(tag!="hysteria2") {
      bool found=false;
      for(const auto& exit:settings_.value("residential_exits",Json::array()))
        if(exit.at("tag")==tag&&exit.value("hysteria2",false)&&
           (!exit.value("dynamic",false)||dynamic_residential_enabled())) {
          found=true;existing_name=user.name+" · "+exit.at("label").get<std::string>()+" · "+exit.at("exit_ip").get<std::string>();
        }
      available=available&&found;auth+="."+tag+"-hy2";
    }
    if(available)proxies+=node+" = hysteria2,"+address+","+std::to_string(settings_.at("hysteria2_port").get<int>())+
      ",auth="+auth+",peer="+domain+",udp="+(service.at("udp")=="reject"?"0":"1")+"\n";
    if(complete_base&&existing_name.find_first_of(",=\r\n")!=std::string::npos)
      throw HttpError(503,"Shadowrocket node name contains policy delimiters");
    groups+=group+" = select,"+(available?(complete_base?existing_name:node):"REJECT")+"\n";
    for(const auto& entry:service.at("domains")) {
      const auto host=entry.get<std::string>();
      if(service.at("udp")=="reject")rules+="AND,((DOMAIN-SUFFIX,"+host+"),(PROTOCOL,UDP)),REJECT\n";
      rules+="DOMAIN-SUFFIX,"+host+","+group+"\n";
    }
  }
  if(complete_base) {
    // The gateway blocks proxy connections to its own address. Fetch this private
    // configuration directly so updates work while the tunnel is connected.
    rules="DOMAIN,"+domain+",DIRECT\n"+rules;
    return extend_base(bases.at(user.id).get<std::string>(),groups,rules,
      settings_.at("origin").get<std::string>()+"/s/"+token+"/shadowrocket.conf");
  }
  // Inherit the existing complete local base. This one remote resource owns nodes and rules.
  return "# Xcli 专属业务分流；继承手机现有 default.conf，请保留该文件。\n"
    "# 全局路由必须为配置。节点与规则随本远程配置一同更新；含个人凭据，请勿分享。\n\n"
    "[General]\ninclude = default.conf\nupdate-url = "+settings_.at("origin").get<std::string>()+"/s/"+token+"/shadowrocket.conf\nudp-policy-not-supported-behaviour = REJECT\n\n"
    "[Proxy]\n"+proxies+"\n[Proxy Group]\n"+groups+"\n[Rule]\n"+rules;
}
}
