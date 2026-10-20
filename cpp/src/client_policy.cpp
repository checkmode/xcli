#include "client_policy.hpp"
#include <algorithm>
#include <set>

namespace xg {
namespace {
struct Category {
  std::string name;
  bool direct;
  std::vector<std::string> suffixes,hosts,cidrs;
};
// Both clients consume this catalog through clash_configuration(). Keep shared
// CDN/login domains out of AI: only service-owned suffixes or exact hosts belong here.
// AI sources: MetaCubeX/meta-rules-dat geo/geosite/{openai,anthropic,google-gemini,
// perplexity,xai}.list (reviewed 2026-10-20). Telegram CIDRs: core.telegram.org/resources/cidr.txt.
const std::vector<Category>& categories() {
  static const std::vector<Category> value{
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
  for(auto& group:groups) {
    const auto name=group.at("name").get<std::string>();
    if(name.starts_with("住宅分组 · "))countries.push_back(name);
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
  select("PROXY",main);
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
  const auto ai_default=ai_tag=="proxy"?std::string("PROXY"):
    found==outbound_names.end()?std::string("REJECT"):found->second;
  for(const auto& category:categories()) {
    Json choices=category.direct?Json::array({"DIRECT","PROXY"}):Json::array({"PROXY"});
    if(category.name=="AI"&&ai_default!="PROXY")choices.insert(choices.begin(),ai_default);
    for(const auto& country:countries)choices.push_back(country);
    for(const auto& node:servers)choices.push_back(node);
    select(category.name,choices);
  }
  select("其他流量",Json::array({"PROXY","DIRECT"}));
  for(const auto& group:groups)if(group.at("name")!="PROXY")top.push_back(group);
  std::set<std::string> names;
  for(const auto& proxy:config.at("proxies"))names.insert(proxy.at("name").get<std::string>());
  for(const auto& group:top)
    if(!names.insert(group.at("name").get<std::string>()).second)throw HttpError(503,"Client policy name conflict");
  groups=std::move(top);

  Json rules=Json::array();
  auto& dns=config["dns"]["nameserver-policy"];
  for(const auto& category:categories()) {
    Json payload=Json::array();
    auto add=[&](const std::string& kind,const std::string& domain) {
      payload.push_back(kind+","+domain);
      const auto key=kind=="DOMAIN-SUFFIX"?"+."+domain:domain;
      dns[key]=category.direct
        ?Json::array({"https://223.5.5.5/dns-query#"+category.name,"https://1.12.12.12/dns-query#"+category.name})
        :Json::array({"https://1.1.1.1/dns-query#"+category.name,"https://1.0.0.1/dns-query#"+category.name});
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
    rules.push_back("RULE-SET,"+provider+","+category.name);
  }
  auto& old_rules=config["rules"];
  auto position=std::find(old_rules.begin(),old_rules.end(),Json("GEOSITE,private,DIRECT"));
  old_rules.insert(position,rules.begin(),rules.end());
  old_rules.back()="MATCH,其他流量";
}
}
