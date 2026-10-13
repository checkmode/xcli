#include "gateway.hpp"
#include <arpa/inet.h>
#include <curl/curl.h>
#include <openssl/hmac.h>
#include <array>
#include <algorithm>
#include <cctype>
#include <sys/socket.h>

namespace xg {
namespace {
struct CurlRuntime {
  CurlRuntime(){if(curl_global_init(CURL_GLOBAL_DEFAULT)!=CURLE_OK)throw std::runtime_error("HTTP client initialization failed");}
  ~CurlRuntime(){curl_global_cleanup();}
};
void initialize_curl(){static CurlRuntime runtime;}
struct Url {
  CURLU* value = curl_url();
  ~Url(){curl_url_cleanup(value);}
  std::string part(CURLUPart name) const {
    char* data=nullptr;
    if(curl_url_get(value,name,&data,0)!=CURLUE_OK)return {};
    std::string result(data);curl_free(data);return result;
  }
};
bool public_v4(const unsigned char* b) {
  // Deny private, loopback, link-local, CGNAT, documentation, benchmarking and multicast ranges.
  if(b[0]==0||b[0]==10||b[0]==127||b[0]>=224)return false;
  if(b[0]==100&&b[1]>=64&&b[1]<=127)return false;
  if(b[0]==169&&b[1]==254)return false;
  if(b[0]==172&&b[1]>=16&&b[1]<=31)return false;
  if(b[0]==192&&(b[1]==168||(b[1]==0&&(b[2]==0||b[2]==2))||(b[1]==88&&b[2]==99)))return false;
  if(b[0]==198&&(b[1]==18||b[1]==19||(b[1]==51&&b[2]==100)))return false;
  if(b[0]==203&&b[1]==0&&b[2]==113)return false;
  return true;
}
bool public_v6(const unsigned char* b) {
  // Allow native global unicast only; reject transition/tunnel and documentation prefixes.
  if((b[0]&0xe0)!=0x20)return false;
  if(b[0]==0x20&&b[1]==0x02)return false;
  if(b[0]==0x20&&b[1]==0x01&&((b[2]==0x0d&&b[3]==0xb8)||(b[2]==0&&b[3]<0x20)))return false;
  if(b[0]==0x3f&&b[1]==0xff&&(b[2]&0xf0)==0)return false;
  return true;
}
curl_socket_t open_public_socket(void*,curlsocktype purpose,curl_sockaddr* target) {
  if(purpose!=CURLSOCKTYPE_IPCXN)return CURL_SOCKET_BAD;
  bool allowed=false;
  if(target->family==AF_INET)allowed=public_v4(reinterpret_cast<const unsigned char*>(&reinterpret_cast<sockaddr_in*>(&target->addr)->sin_addr));
  else if(target->family==AF_INET6)allowed=public_v6(reinterpret_cast<const unsigned char*>(&reinterpret_cast<sockaddr_in6*>(&target->addr)->sin6_addr));
  if(!allowed)return CURL_SOCKET_BAD;
  return ::socket(target->family,target->socktype|SOCK_CLOEXEC,target->protocol);
}
size_t discard_response(char*,size_t size,size_t count,void* context) {
  auto* remaining=static_cast<std::size_t*>(context);
  if(size&&count>*remaining/size)return 0;
  auto bytes=size*count;*remaining-=bytes;return bytes;
}
std::string signature(std::string_view secret,std::string_view body) {
  std::array<unsigned char,EVP_MAX_MD_SIZE> hash{};unsigned size=0;
  if(!HMAC(EVP_sha256(),secret.data(),static_cast<int>(secret.size()),reinterpret_cast<const unsigned char*>(body.data()),body.size(),hash.data(),&size))throw std::runtime_error("Webhook signature failed");
  static constexpr char digits[]="0123456789abcdef";std::string result;
  for(unsigned i=0;i<size;++i){result.push_back(digits[hash[i]>>4]);result.push_back(digits[hash[i]&15]);}return result;
}
}
bool public_webhook_address(const std::string& address) {
  in_addr v4{};in6_addr v6{};
  if(inet_pton(AF_INET,address.c_str(),&v4)==1)return public_v4(reinterpret_cast<unsigned char*>(&v4));
  if(inet_pton(AF_INET6,address.c_str(),&v6)==1)return public_v6(reinterpret_cast<unsigned char*>(&v6));
  return false;
}
std::string validate_webhook_url(const std::string& url) {
  initialize_curl();
  if(url.empty()||url.size()>4096||std::any_of(url.begin(),url.end(),[](unsigned char c){return c<=32||c==127;}))throw HttpError(422,"Webhook 地址格式不正确");
  Url parsed;
  if(!parsed.value||curl_url_set(parsed.value,CURLUPART_URL,url.c_str(),0)!=CURLUE_OK||parsed.part(CURLUPART_SCHEME)!="https")throw HttpError(422,"Webhook 必须使用 HTTPS");
  if(!parsed.part(CURLUPART_USER).empty()||!parsed.part(CURLUPART_PASSWORD).empty()||!parsed.part(CURLUPART_FRAGMENT).empty())throw HttpError(422,"地址不能包含用户名、密码或片段；请使用独立的认证字段");
  auto host=parsed.part(CURLUPART_HOST);if(host.empty())throw HttpError(422,"Webhook 缺少主机名");
  auto bare=host;if(bare.front()=='['&&bare.back()==']')bare=bare.substr(1,bare.size()-2);
  if(bare.find('%')!=std::string::npos||std::any_of(bare.begin(),bare.end(),[](unsigned char c){return !(std::isalnum(c)||c=='.'||c=='-'||c==':');}))throw HttpError(422,"Webhook 主机名格式不正确");
  std::string lower=bare;std::transform(lower.begin(),lower.end(),lower.begin(),[](unsigned char c){return static_cast<char>(std::tolower(c));});
  if(lower=="localhost"||lower.ends_with(".localhost")||lower.ends_with(".local"))throw HttpError(422,"Webhook 必须指向公网地址");
  in_addr v4{};in6_addr v6{};
  if((inet_pton(AF_INET,bare.c_str(),&v4)==1||inet_pton(AF_INET6,bare.c_str(),&v6)==1)&&!public_webhook_address(bare))throw HttpError(422,"Webhook 必须指向公网地址");
  auto port=parsed.part(CURLUPART_PORT);return host+(port.empty()?"":":"+port);
}
WebhookResult post_webhook(const Json& configuration,const Json& payload) {
  auto url=configuration.at("url").get<std::string>();(void)validate_webhook_url(url);
  std::unique_ptr<CURL,decltype(&curl_easy_cleanup)> handle(curl_easy_init(),curl_easy_cleanup);
  if(!handle)return {0,"无法初始化通知连接"};
  auto body=payload.dump();std::string timestamp=std::to_string(now());
  curl_slist* list=nullptr;
  auto header=[&](const std::string& value){auto* updated=curl_slist_append(list,value.c_str());if(!updated){curl_slist_free_all(list);throw std::runtime_error("Webhook headers allocation failed");}list=updated;};
  header("Content-Type: application/json");header("User-Agent: xcli/" XG_VERSION);
  header("X-Xcli-Event-Id: "+payload.at("id").get<std::string>());header("X-Xcli-Timestamp: "+timestamp);
  auto bearer=configuration.value("bearer",std::string());if(!bearer.empty())header("Authorization: Bearer "+bearer);
  auto secret=configuration.value("signing",std::string());if(!secret.empty())header("X-Xcli-Signature: sha256="+signature(secret,timestamp+"."+body));
  std::unique_ptr<curl_slist,decltype(&curl_slist_free_all)> headers(list,curl_slist_free_all);
  auto* h=handle.get();std::size_t response_limit=16384;
  curl_easy_setopt(h,CURLOPT_URL,url.c_str());curl_easy_setopt(h,CURLOPT_HTTPHEADER,list);
  curl_easy_setopt(h,CURLOPT_POSTFIELDS,body.c_str());curl_easy_setopt(h,CURLOPT_POSTFIELDSIZE_LARGE,static_cast<curl_off_t>(body.size()));
  curl_easy_setopt(h,CURLOPT_PROTOCOLS_STR,"https");curl_easy_setopt(h,CURLOPT_REDIR_PROTOCOLS_STR,"https");
  curl_easy_setopt(h,CURLOPT_FOLLOWLOCATION,0L);curl_easy_setopt(h,CURLOPT_PROXY,"");curl_easy_setopt(h,CURLOPT_NOPROXY,"*");
  curl_easy_setopt(h,CURLOPT_SSL_VERIFYPEER,1L);curl_easy_setopt(h,CURLOPT_SSL_VERIFYHOST,2L);
  curl_easy_setopt(h,CURLOPT_CONNECTTIMEOUT_MS,4000L);curl_easy_setopt(h,CURLOPT_TIMEOUT_MS,8000L);curl_easy_setopt(h,CURLOPT_NOSIGNAL,1L);
  // Validate the actual destination of every socket, after DNS resolution; never trust only the URL text.
  curl_easy_setopt(h,CURLOPT_OPENSOCKETFUNCTION,open_public_socket);
  curl_easy_setopt(h,CURLOPT_WRITEFUNCTION,discard_response);curl_easy_setopt(h,CURLOPT_WRITEDATA,&response_limit);
  auto result=curl_easy_perform(h);long code=0;curl_easy_getinfo(h,CURLINFO_RESPONSE_CODE,&code);
  if(result!=CURLE_OK)return {static_cast<int>(code),"连接失败、超时、证书不受信任或目标不是公网地址"};
  if(code<200||code>=300)return {static_cast<int>(code),"接收端未返回成功状态（HTTP "+std::to_string(code)+"）"};
  return {static_cast<int>(code),""};
}
}
