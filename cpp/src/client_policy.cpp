#include "client_policy.hpp"
#include <algorithm>
#include <functional>
#include <arpa/inet.h>
#include <cctype>
#include <regex>
#include <set>
#include <sstream>

namespace xg {
namespace {
struct Category {
  std::string name;
  bool direct;
  std::vector<std::string> suffixes,hosts,cidrs;
};
std::string independent(const std::string& name) {return name=="EaseLian"?name:"独立 · "+name;}
// A selector can reach DIRECT indirectly, for example EaseLian -> PROXY -> 直连.
// Its DNS transport follows that selector, so its resolvers must be reachable
// both directly and through the selected proxy.
bool can_select_direct(const Json& groups,const std::string& target) {
  std::set<std::string> visited;
  std::function<bool(const std::string&)> visit=[&](const std::string& name) {
    if(name=="DIRECT")return true;
    if(!visited.insert(name).second)return false;
    for(const auto& group:groups)if(group.at("name")==name)
      for(const auto& member:group.at("proxies"))
        if(visit(member.get<std::string>()))return true;
    return false;
  };
  return visit(target);
}
// Both clients consume this catalog through clash_configuration(). Keep shared
// CDN/login domains out of AI: only service-owned suffixes or exact hosts belong here.
// AI sources: MetaCubeX/meta-rules-dat geo/geosite/{openai,anthropic,google-gemini,
// perplexity,xai}.list (reviewed 2026-10-20). Telegram CIDRs: core.telegram.org/resources/cidr.txt.
const std::vector<Category>& categories() {
  static const std::vector<Category> value{
    {"EaseLian",false,{"easelian.com"},{},{}},
    {"AI",false,
      {"openai.com","chatgpt.com","chat.com","sora.com","oaistatic.com","oaistatsig.com","oaiusercontent.com",
       "anthropic.com","clau.de","claude.ai","claude.com","claude.dev","claudemcpclient.com","claudemcpcontent.com","claudeusercontent.com",
       "gemini.google.com","gemini.google","gemini.gstatic.com","bard.google.com","aistudio.google.com","makersuite.google.com",
       "notebooklm.google.com","notebooklm.google","notebook.google","generativeai.google",
       "generativelanguage.googleapis.com","perplexity.ai","perplexity.com","pplx.ai",
       "grok.com","x.ai","grok.x.com","githubcopilot.com"},
      {"ai.google.dev","alkalicore-pa.clients6.google.com","alkalimakersuite-pa.clients6.google.com",
       "webchannel-alkalimakersuite-pa.clients6.google.com","geminiweb-pa.clients.google.com","geminiweb-pa.clients6.google.com",
       "cloudaicompanion.googleapis.com","cloudcode-pa.googleapis.com","daily-cloudcode-pa.googleapis.com",
       "notebooklm-pa.googleapis.com","notebooklm.googleapis.com",
       "openaiapi-site.azureedge.net","openaiassets.blob.core.windows.net","openaicom.imgix.net",
       "servd-anthropic-website.b-cdn.net","ppl-ai-file-upload.s3.amazonaws.com","pplx-res.cloudinary.com",
       "copilot.microsoft.com","copilot-proxy.githubusercontent.com"},{}},
    {"Telegram",false,{"t.me","tdesktop.com","telegra.ph","telegram.me","telegram.org","telegram.dog","telesco.pe"},{},
      {"91.108.56.0/22","91.108.4.0/22","91.108.8.0/22","91.108.16.0/22","91.108.12.0/22","149.154.160.0/20",
       "91.105.192.0/23","91.108.20.0/22","185.76.151.0/24","2001:b28:f23d::/48","2001:b28:f23f::/48",
       "2001:67c:4e8::/48","2001:b28:f23c::/48","2a0a:f280::/32"}},
    {"YouTube",false,{"youtube.com","youtu.be","googlevideo.com","ytimg.com","youtube-nocookie.com","yt.be"},
      {"youtubei.googleapis.com","youtube.googleapis.com"},{}},
    {"Netflix",false,{"netflix.com","netflix.net","nflxext.com","nflximg.com","nflximg.net","nflxso.net","nflxvideo.net"},{},{}},
    {"国外媒体",false,{"disneyplus.com","disney-plus.net","bamgrid.com","dssott.com","hbo.com","hbomax.com","max.com",
      "hulu.com","huluim.com","hulustream.com","primevideo.com","amazonvideo.com","aiv-cdn.net","aiv-delivery.net",
      "spotify.com","scdn.co","spoti.fi","twitch.tv","twitchcdn.net","ttvnw.net","jtvnw.net",
      "soundcloud.com","sndcdn.com","deezer.com","dzcdn.net","tidal.com","bbc.co.uk","bbci.co.uk"},{},{}},
    {"哔哩哔哩",true,{"bilibili.com","biliapi.com","biliapi.net","bilivideo.com","hdslb.com"},{},{}},
    {"Apple",true,{"apple.com","apple.co","apple-cloudkit.com","aaplimg.com","appstore.com","cdn-apple.com",
      "icloud.com","icloud-content.com","me.com","mzstatic.com"},{"www-cdn.icloud.com.akadns.net"},{}},
  };
  return value;
}
}

bool client_policy_enabled(const Json& settings,const std::string& user_id) {
  return settings.value("client_policies",Json::object()).contains(user_id);
}

void apply_client_policy(Json& config,const Json& settings,const User& user,
                         const std::map<std::string,std::string>& outbound_names) {
  if(!client_policy_enabled(settings,user.id))return;
  auto& groups=config["proxy-groups"];
  Json servers=Json::array(),countries=Json::array();
  for(const auto* tag:{"reality","websocket","vmess","hysteria2"})
    if(outbound_names.contains(tag))servers.push_back(outbound_names.at(tag));
  for(const auto& [tag,name]:outbound_names)
    if(tag.starts_with("remote-"))servers.push_back(name);
  for(auto& group:groups) {
    const auto name=group.at("name").get<std::string>();
    if(name.starts_with("住宅分组 · "))countries.push_back(name);
    if(name=="STUN") {
      group["name"]=independent(name);
      group["proxies"]=servers;
    }
    // Same exit IP, different access transport. Prefer TCP on a fresh selection.
    auto& members=group["proxies"];
    if(members.size()==2&&members[0].is_string()&&members[1].is_string()&&
       members[0].get<std::string>().ends_with(" · Hysteria2")&&members[1].get<std::string>().ends_with(" · HTTPS"))
      std::swap(members[0],members[1]);
  }
  Json top=Json::array();
  auto select=[&](const std::string& name,Json members) {
    top.push_back({{"name",name},{"type","select"},{"proxies",std::move(members)}});
  };
  Json main=Json::array({"故障转移","自动选择"});
  for(const auto& node:servers)main.push_back(node);
  if(!countries.empty())main.push_back("住宅节点");
  main.push_back("直连");
  select("PROXY",main);
  select("直连",Json::array({"DIRECT"}));
  for(const auto& [name,type]:std::vector<std::pair<std::string,std::string>>{
      {"故障转移","fallback"},{"自动选择","url-test"}}) {
    Json group={{"name",name},{"type",type},{"proxies",servers},
      {"url","https://www.gstatic.com/generate_204"},{"interval",120},{"timeout",5000},{"lazy",true}};
    if(type=="url-test")group["tolerance"]=100;
    top.push_back(group);
  }
  if(!countries.empty())select("住宅节点",countries);
  const auto ai_tag=settings.at("client_policies").at(user.id).at("ai_outbound").get<std::string>();
  const auto found=outbound_names.find(ai_tag);
  // Keep the legacy setting valid, but do not let independent AI traffic
  // inherit the main selector's new direct option.
  const auto ai_default=ai_tag=="proxy"?std::string("故障转移"):
    found==outbound_names.end()?std::string("REJECT"):found->second;
  for(const auto& category:categories()) {
    if(category.direct)continue;
    Json choices=Json::array({"故障转移","自动选择"});
    if(category.name=="EaseLian") {choices.insert(choices.begin(),"DIRECT");choices.insert(choices.begin(),"PROXY");}
    if(category.name=="AI"&&ai_default!="故障转移")choices.insert(choices.begin(),ai_default);
    for(const auto& country:countries)choices.push_back(country);
    for(const auto& node:servers)
      if(std::find(choices.begin(),choices.end(),node)==choices.end())choices.push_back(node);
    select(independent(category.name),choices);
  }
  Json google_choices=Json::array({"故障转移","自动选择"});
  for(const auto& country:countries)google_choices.push_back(country);
  for(const auto& node:servers)google_choices.push_back(node);
  select(independent("Google"),google_choices);
  select("其他流量",Json::array({"PROXY","DIRECT"}));
  for(const auto& group:groups)if(group.at("name")!="PROXY")top.push_back(group);
  std::set<std::string> names;
  for(const auto& proxy:config.at("proxies"))names.insert(proxy.at("name").get<std::string>());
  for(const auto& group:top)
    if(!names.insert(group.at("name").get<std::string>()).second)throw HttpError(503,"Client policy name conflict");
  groups=std::move(top);

  Json rules=Json::array();
  auto& dns=config["dns"]["nameserver-policy"];
  for(auto& resolvers:dns)for(auto& resolver:resolvers) {
    const auto value=resolver.get<std::string>();
    if(value.ends_with("#STUN"))resolver=value.substr(0,value.size()-4)+independent("STUN");
  }
  for(const auto& category:categories()) {
    const auto target=category.direct?std::string("DIRECT"):independent(category.name);
    const bool needs_direct_reachable_dns=category.direct||can_select_direct(groups,target);
    Json payload=Json::array();
    auto add=[&](const std::string& kind,const std::string& domain) {
      payload.push_back(kind+","+domain);
      const auto key=kind=="DOMAIN-SUFFIX"?"+."+domain:domain;
      dns[key]=needs_direct_reachable_dns
        ?Json::array({"https://223.5.5.5/dns-query#"+target,"https://1.12.12.12/dns-query#"+target})
        :Json::array({"https://1.1.1.1/dns-query#"+target,"https://1.0.0.1/dns-query#"+target});
    };
    for(const auto& domain:category.suffixes)add("DOMAIN-SUFFIX",domain);
    for(const auto& domain:category.hosts)add("DOMAIN",domain);
    for(const auto& cidr:category.cidrs)payload.push_back(
      std::string(cidr.find(':')==std::string::npos?"IP-CIDR,":"IP-CIDR6,")+cidr+",no-resolve");
    const auto provider="category-"+category.name;
    config["rule-providers"][provider]={{"type","inline"},{"behavior","classical"},{"payload",payload}};
    // AI may select a TCP-only residential exit. Do not let unsupported UDP
    // skip the category and escape via another exit or DIRECT.
    if(category.name=="AI")rules.push_back("AND,((RULE-SET,"+provider+"),(NETWORK,UDP)),REJECT");
    rules.push_back("RULE-SET,"+provider+","+target);
  }
  auto& old_rules=config["rules"];
  for(auto& rule:old_rules)
    if(rule=="RULE-SET,stun-endpoints,STUN")rule="RULE-SET,stun-endpoints,"+independent("STUN");
  auto position=std::find(old_rules.begin(),old_rules.end(),Json("GEOSITE,private,DIRECT"));
  old_rules.insert(position,rules.begin(),rules.end());
  old_rules.back()="MATCH,其他流量";
}

void apply_google_policy(Json& config) {
  const std::string group="独立 · Google",provider="category-Google";
  auto& providers=config["rule-providers"];
  if(providers.contains(provider))throw HttpError(503,"Google policy provider conflict");
  const auto domains=Json::array({"google.com","google.cn","google.com.hk","google.com.sg","google.com.tw",
    "google.com.au","google.co.jp","google.co.uk","google.co.in","google.com.br","google.de","google.fr",
    "g.co","android.com","googleapis.com","gstatic.com","googleusercontent.com","googleplay.com","ggpht.com",
    "gvt1.com","gvt2.com","google-analytics.com","googletagmanager.com","googleadservices.com",
    "googlesyndication.com"});
  Json payload=Json::array();
  for(const auto& domain:domains)payload.push_back("DOMAIN-SUFFIX,"+domain.get<std::string>());
  providers[provider]={{"type","inline"},{"behavior","classical"},{"payload",payload}};
  auto& rules=config["rules"];
  auto position=std::find(rules.begin(),rules.end(),Json("GEOSITE,private,DIRECT"));
  position=rules.insert(position,"RULE-SET,"+provider+","+group);
  rules.insert(++position,"RULE-SET,"+provider+",REJECT");
  auto& dns=config["dns"]["nameserver-policy"];
  Json ordered=Json::object();
  for(auto it=dns.begin();it!=dns.end();++it)
    if(!it.key().starts_with("geosite:"))ordered[it.key()]=it.value();
  for(const auto& domain:domains) {
    const auto key="+."+domain.get<std::string>();
    if(!ordered.contains(key))ordered[key]=Json::array({"https://1.1.1.1/dns-query#"+group,"https://1.0.0.1/dns-query#"+group});
  }
  for(auto it=dns.begin();it!=dns.end();++it)
    if(it.key().starts_with("geosite:"))ordered[it.key()]=it.value();
  dns=std::move(ordered);
}

namespace {
struct EditableRule {std::string type, value, target;bool no_resolve=false,explicit_resolution=false;};

std::string trim_rule(std::string text) {
  auto first=text.find_first_not_of(" \t\r");
  if(first==std::string::npos)return {};
  return text.substr(first,text.find_last_not_of(" \t\r")-first+1);
}

bool valid_network(const std::string& value,bool v6) {
  const auto slash=value.find('/');
  if(slash==std::string::npos||slash==0||slash+1==value.size()||value.find('/',slash+1)!=std::string::npos)return false;
  const auto prefix=value.substr(slash+1);
  if(prefix.size()>3||prefix.empty()||!std::all_of(prefix.begin(),prefix.end(),[](unsigned char c){return std::isdigit(c);}))return false;
  const int bits=std::stoi(prefix);
  if(bits<0||bits>(v6?128:32))return false;
  unsigned char bytes[16]{};
  return ::inet_pton(v6?AF_INET6:AF_INET,value.substr(0,slash).c_str(),bytes)==1;
}

std::vector<EditableRule> parse_editable_rules(const std::string& text,const std::string& base,
                                               const std::set<std::string>& custom_groups={}) {
  if(text.size()>14000)throw HttpError(422,"规则内容过长，最多 14000 字节");
  const std::set<std::string> common={"DIRECT","REJECT","PROXY"};
  const std::set<std::string> independent_targets={"EaseLian","独立 · AI","独立 · Google","独立 · Telegram",
    "独立 · YouTube","独立 · Netflix","独立 · 国外媒体","独立 · STUN","其他流量"};
  std::vector<EditableRule> result;std::istringstream input(text);std::string line;std::size_t line_number=0;
  const std::regex domain(R"([a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+)");
  while(std::getline(input,line)) {
    ++line_number;
    auto fail=[&](const std::string& detail){throw HttpError(422,"第 "+std::to_string(line_number)+" 行："+detail);};
    line=trim_rule(line);if(line.empty()||line.starts_with('#'))continue;
    if(line.size()>400||result.size()>=500)fail("单条规则过长或规则超过 500 条");
    auto first=line.find(','),second=first==std::string::npos?first:line.find(',',first+1);
    const auto third=second==std::string::npos?second:line.find(',',second+1);
    if(first==std::string::npos||second==std::string::npos||(third!=std::string::npos&&line.find(',',third+1)!=std::string::npos))
      fail("规则格式应为 类型,内容,目标，IP 规则可附加解析选项");
    EditableRule rule{trim_rule(line.substr(0,first)),trim_rule(line.substr(first+1,second-first-1)),
      trim_rule(line.substr(second+1,third==std::string::npos?third:third-second-1))};
    const bool domain_rule=rule.type=="DOMAIN"||rule.type=="DOMAIN-SUFFIX";
    if(domain_rule) {
      if(rule.value.size()>253||!std::regex_match(rule.value,domain))fail("域名规则需要小写英文域名");
    } else if(rule.type=="DOMAIN-KEYWORD") {
      if(rule.value.empty()||rule.value.size()>253||!std::regex_match(rule.value,std::regex("[a-z0-9.-]+")))
        fail("域名关键词只能包含小写字母、数字、点和短横线");
    } else if(rule.type=="IP-CIDR"||rule.type=="IP-CIDR6") {
      if(!valid_network(rule.value,rule.type=="IP-CIDR6"))fail("IP 网段格式不正确");
      rule.no_resolve=true; // Preserve the meaning of existing three-field CIDR rules.
    } else if(rule.type=="GEOIP") {
      if(!std::regex_match(rule.value,std::regex("[A-Z]{2}")))fail("国家或地区代码应为两个大写字母，例如 CN");
    } else if(rule.type=="DST-PORT") {
      if(rule.value.empty()||rule.value.size()>5||!std::all_of(rule.value.begin(),rule.value.end(),[](unsigned char c){return std::isdigit(c);})||
         std::stoi(rule.value)<1||std::stoi(rule.value)>65535)fail("目标端口应为 1 到 65535 的单个数字");
    } else fail("不支持的规则类型");
    if(third!=std::string::npos) {
      const auto option=trim_rule(line.substr(third+1));
      if(rule.type!="IP-CIDR"&&rule.type!="IP-CIDR6"&&rule.type!="GEOIP")fail("此类型不支持解析选项");
      if(option!="resolve"&&option!="no-resolve")fail("解析选项应为 resolve 或 no-resolve");
      rule.no_resolve=option=="no-resolve";rule.explicit_resolution=true;
    }
    if(!common.contains(rule.target)&&!(base=="standard"&&rule.target=="STUN")&&
       !(base=="independent"&&independent_targets.contains(rule.target))&&!custom_groups.contains(rule.target))
      fail("规则目标不属于所选模板");
    result.push_back(std::move(rule));
  }
  return result;
}
}

std::string independent_template_rules() {
  std::string text;
  for(const auto& category:categories()) {
    const auto target=category.direct?std::string("DIRECT"):independent(category.name);
    for(const auto& host:category.suffixes)text+="DOMAIN-SUFFIX,"+host+","+target+"\n";
    for(const auto& host:category.hosts)text+="DOMAIN,"+host+","+target+"\n";
    for(const auto& cidr:category.cidrs)text+=(cidr.find(':')==std::string::npos?"IP-CIDR,":"IP-CIDR6,")+cidr+","+target+"\n";
  }
  return text;
}

Json validate_rule_template(const Json& input) {
  if(!input.is_object()||(input.size()!=3&&input.size()!=4)||!input.contains("base")||!input.contains("ai_outbound")||!input.contains("rules")||
     !input["base"].is_string()||!input["ai_outbound"].is_string()||!input["rules"].is_string())
    throw HttpError(422,"模板格式不正确");
  if(input.size()==4&&!input.contains("groups"))throw HttpError(422,"模板格式不正确");
  const auto base=input.at("base").get<std::string>(),ai=input.at("ai_outbound").get<std::string>();
  if(base!="standard"&&base!="independent")throw HttpError(422,"模板类型不正确");
  if(!(ai=="proxy"||ai=="reality"||ai=="websocket"||ai=="vmess"||ai=="hysteria2"||
       std::regex_match(ai,std::regex("residential-[0-9]{2}"))))throw HttpError(422,"AI 默认出口不正确");
  const auto rules=input.at("rules").get<std::string>();
  std::set<std::string> names;
  Json groups=Json::array();
  if(input.contains("groups")) {
    if(!input.at("groups").is_array()||input.at("groups").size()>16)throw HttpError(422,"自定义策略组最多 16 个");
    const std::set<std::string> reserved={"DIRECT","REJECT","PROXY","STUN","直连","故障转移","自动选择","住宅节点",
      "EaseLian","独立 · AI","独立 · Google","独立 · Telegram","独立 · YouTube","独立 · Netflix",
      "独立 · 国外媒体","独立 · STUN","其他流量","oracle-cloud"};
    for(const auto& group:input.at("groups")) {
      if(!group.is_object()||group.size()!=2||!group.contains("name")||!group.contains("default")||
         !group.at("name").is_string()||!group.at("default").is_string())throw HttpError(422,"策略组格式不正确");
      const auto name=group.at("name").get<std::string>(),choice=group.at("default").get<std::string>();
      if(name.empty()||name.size()>64||trim_rule(name)!=name||name.find_first_of(",=\r\n\t#")!=std::string::npos||
         std::any_of(name.begin(),name.end(),[](unsigned char c){return c<32||c==127;})||
         reserved.contains(name)||!names.insert(name).second)throw HttpError(422,"策略组名称无效、重复或与内置名称冲突");
      if(choice!="PROXY"&&choice!="DIRECT"&&!(base=="independent"&&(choice=="故障转移"||choice=="自动选择")))
        throw HttpError(422,"策略组默认出口不属于当前基础模板");
      groups.push_back({{"name",name},{"default",choice}});
    }
  }
  (void)parse_editable_rules(rules,base,names);
  Json output={{"base",base},{"ai_outbound",ai},{"rules",rules}};
  if(!groups.empty())output["groups"]=groups;
  return output;
}

void apply_template_rules(Json& config,const Json& spec,const Json& baseline_dns) {
  const auto base=spec.at("base").get<std::string>(),text=spec.at("rules").get<std::string>();
  std::set<std::string> custom_groups,available_names={"DIRECT","REJECT"};
  for(const auto& proxy:config.at("proxies"))available_names.insert(proxy.at("name").get<std::string>());
  for(const auto& group:config.at("proxy-groups"))available_names.insert(group.at("name").get<std::string>());
  const auto groups=spec.value("groups",Json::array());
  const auto& existing=config.at("proxy-groups");
  auto proxy=std::find_if(existing.begin(),existing.end(),[](const Json& group){return group.at("name")=="PROXY";});
  if(proxy==existing.end())throw HttpError(503,"缺少 PROXY 策略组");
  const Json candidates=proxy->at("proxies");
  for(const auto& group:groups) {
    const auto name=group.at("name").get<std::string>(),choice=group.at("default").get<std::string>();
    if(!available_names.insert(name).second)throw HttpError(422,"策略组与现有节点或策略组重名："+name);
    if(!available_names.contains(choice))throw HttpError(422,"策略组默认出口不可用："+choice);
    Json members=Json::array({choice});
    for(const auto& item:Json::array({"PROXY","DIRECT"}))if(std::find(members.begin(),members.end(),item)==members.end())members.push_back(item);
    for(const auto& item:candidates)if(std::find(members.begin(),members.end(),item)==members.end())members.push_back(item);
    config["proxy-groups"].push_back({{"name",name},{"type","select"},{"proxies",members}});
    custom_groups.insert(name);
  }
  if(base=="independent"&&text==independent_template_rules())return;
  const auto parsed=parse_editable_rules(text,base,custom_groups);
  auto& rules=config["rules"];auto& dns=config["dns"]["nameserver-policy"];
  if(base=="independent") {
    Json remaining=Json::array();
    for(const auto& item:rules)if(item.get<std::string>().find("RULE-SET,category-")==std::string::npos)remaining.push_back(item);
    rules=std::move(remaining);
    for(const auto& category:categories()) {
      config["rule-providers"].erase("category-"+category.name);
      auto restore=[&](const std::string& key) {if(baseline_dns.contains(key))dns[key]=baseline_dns.at(key);else dns.erase(key);};
      for(const auto& host:category.suffixes)restore("+."+host);
      for(const auto& host:category.hosts)restore(host);
    }
  }
  std::set<std::string> available={"DIRECT","REJECT"};
  for(const auto& group:config.at("proxy-groups"))available.insert(group.at("name").get<std::string>());
  Json inserted=Json::array();
  for(const auto& rule:parsed) {
    if(!available.contains(rule.target))throw HttpError(422,"模板引用的策略组当前不可用："+rule.target);
    const auto condition=rule.type+","+rule.value;
    const auto suffix=rule.no_resolve?std::string(",no-resolve"):std::string();
    const auto nested=condition+(rule.no_resolve&&rule.explicit_resolution?",no-resolve":"");
    if(rule.target=="独立 · AI")inserted.push_back("AND,(("+nested+"),(NETWORK,UDP)),REJECT");
    inserted.push_back(condition+","+rule.target+suffix);
    if(rule.target!="DIRECT"&&rule.target!="REJECT")inserted.push_back(condition+",REJECT"+suffix);
  }
  const bool has_keyword=std::any_of(parsed.begin(),parsed.end(),[](const auto& rule){return rule.type=="DOMAIN-KEYWORD";});
  if(has_keyword) {
    // DNS policy must follow the same domain-rule order as routing, including
    // keywords. Keep the protected server/STUN and local overrides first.
    Json ordered=Json::object();
    for(auto it=dns.begin();it!=dns.end();++it)
      if(!it.key().starts_with("geosite:")&&!it.key().starts_with("rule-set:"))ordered[it.key()]=it.value();
    std::string last_target,provider;
    std::size_t number=0;
    for(const auto& rule:parsed) {
      if(rule.type!="DOMAIN"&&rule.type!="DOMAIN-SUFFIX"&&rule.type!="DOMAIN-KEYWORD")continue;
      if(provider.empty()||rule.target!=last_target) {
        last_target=rule.target;provider="xcli-dns-"+std::to_string(++number);
        config["rule-providers"][provider]={{"type","inline"},{"behavior","classical"},{"payload",Json::array()}};
        const bool direct=rule.target=="DIRECT"||can_select_direct(config.at("proxy-groups"),rule.target);
        const auto a=direct?"https://223.5.5.5/dns-query#":"https://1.1.1.1/dns-query#";
        const auto b=direct?"https://1.12.12.12/dns-query#":"https://1.0.0.1/dns-query#";
        ordered["rule-set:"+provider]=Json::array({a+rule.target,b+rule.target});
      }
      config["rule-providers"][provider]["payload"].push_back(rule.type+","+rule.value);
    }
    for(auto it=dns.begin();it!=dns.end();++it)
      if(it.key().starts_with("geosite:")||it.key().starts_with("rule-set:"))ordered[it.key()]=it.value();
    dns=std::move(ordered);
  } else {
    // Earlier rules win. Restore DNS overrides in reverse so specific earlier rules survive.
    for(auto it=parsed.rbegin();it!=parsed.rend();++it) {
      if(it->type!="DOMAIN"&&it->type!="DOMAIN-SUFFIX")continue;
      if(it->type=="DOMAIN-SUFFIX") {
        std::vector<std::string> remove;
        for(auto p=dns.begin();p!=dns.end();++p) {
          const auto key=p.key();const auto name=key.starts_with("+.")?key.substr(2):key;
          if(name==it->value||name.ends_with("."+it->value))remove.push_back(key);
        }
        for(const auto& key:remove)dns.erase(key);
      }
      const auto key=(it->type=="DOMAIN-SUFFIX"?"+.":"")+it->value;
      const bool direct=it->target=="DIRECT"||can_select_direct(config.at("proxy-groups"),it->target);
      const auto a=direct?"https://223.5.5.5/dns-query#":"https://1.1.1.1/dns-query#";
      const auto b=direct?"https://1.12.12.12/dns-query#":"https://1.0.0.1/dns-query#";
      dns[key]=Json::array({a+it->target,b+it->target});
    }
    // Mihomo evaluates policy entries in order. Domain-specific custom
    // resolvers must precede broad geosite/rule-set policies.
    Json ordered=Json::object();
    for(auto it=dns.begin();it!=dns.end();++it)
      if(!it.key().starts_with("geosite:")&&!it.key().starts_with("rule-set:"))ordered[it.key()]=it.value();
    for(auto it=dns.begin();it!=dns.end();++it)
      if(it.key().starts_with("geosite:")||it.key().starts_with("rule-set:"))ordered[it.key()]=it.value();
    dns=std::move(ordered);
  }
  auto position=std::find(rules.begin(),rules.end(),Json("GEOSITE,private,DIRECT"));
  rules.insert(position,inserted.begin(),inserted.end());
}
}
