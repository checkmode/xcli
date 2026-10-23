#include "gateway.hpp"
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <pwd.h>
#include <regex>
#include <set>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

namespace xg {
namespace {
std::string identifier(const Json& input,const char* key) {
  if(!input.contains(key)||!input.at(key).is_string())throw HttpError(422,"Missing identifier");
  auto value=input.at(key).get<std::string>();
  if(!std::regex_match(value,std::regex("[0-9a-f]{32}")))throw HttpError(422,"Invalid identifier");
  return value;
}
Int positive(const Json& input,const char* key,Int maximum) {
  if(!input.contains(key)||!input.at(key).is_number_integer()||input.at(key)<1||input.at(key)>maximum)
    throw HttpError(422,"Invalid integer");
  return input.at(key).get<Int>();
}
void send_all(int fd,const std::string& data) {
  std::size_t offset=0;
  while(offset<data.size()) {
    auto count=::send(fd,data.data()+offset,data.size()-offset,MSG_NOSIGNAL);
    if(count<=0)return;
    offset+=static_cast<std::size_t>(count);
  }
}
}

Json Backend::provision(const Json& input) {
  if(options_.provision_socket.empty()||options_.provision_uid<1)throw HttpError(403,"Provisioning disabled");
  if(!input.is_object()||!input.contains("action")||!input.at("action").is_string())throw HttpError(422,"Invalid request");
  const auto action=input.at("action").get<std::string>();
  std::set<std::string> allowed={"action","operation_id","account_id"};
  if(action=="grant")allowed.insert({"reservation_id","version","term_seconds"});
  else if(action=="release")allowed.insert("reservation_id");
  else if(action!="reserve"&&action!="status")throw HttpError(422,"Unsupported operation");
  for(const auto& entry:input.items())if(!allowed.contains(entry.key()))throw HttpError(422,"Unsupported field");
  const auto account=identifier(input,"account_id"),operation=identifier(input,"operation_id");
  // nlohmann::json sorts object keys; equivalent wire field order has the same hash.
  const auto digest=sha256(nlohmann::json(input).dump());
  std::lock_guard guard(mutation_mutex_);
  auto database=db();Transaction transaction(database);
  if(action!="status") {
    if(auto previous=database.one("SELECT request_hash,response FROM portal_operations WHERE operation_id=?",{operation})) {
      if(previous->at("request_hash")!=digest)throw HttpError(409,"Operation identifier was reused with different parameters");
      return Json::parse(previous->at("response").get<std::string>());
    }
  }
  const auto stamp=now();
  auto owner=database.one("SELECT * FROM portal_accounts WHERE account_id=?",{account});
  Json result;
  if(action=="reserve") {
    database.run("DELETE FROM portal_reservations WHERE expires<=?",{stamp});
    if(owner) {
      auto user=get_user(database,owner->at("user_id").get<std::string>());
      if(!user.enabled)throw HttpError(409,"Account was suspended by an administrator");
    }
    auto existing=database.one("SELECT * FROM portal_reservations WHERE account_id=?",{account});
    if(!existing) {
      if(!owner) {
        const auto held=database.one("SELECT COUNT(*) AS n FROM portal_reservations r WHERE NOT EXISTS(SELECT 1 FROM portal_accounts a WHERE a.account_id=r.account_id)")->at("n").get<Int>();
        const auto total=database.one("SELECT COUNT(*) AS n FROM users WHERE deleted=0")->at("n").get<Int>();
        const auto portal=database.one("SELECT COUNT(*) AS n FROM portal_accounts a JOIN users u ON u.id=a.user_id WHERE u.deleted=0")->at("n").get<Int>();
        if(total+held>=500||portal+held>=options_.portal_limit)throw HttpError(409,"Provisioning capacity is full");
      }
      database.run("INSERT INTO portal_reservations VALUES(?,?,?)",{account,operation,stamp+1800});
      existing=database.one("SELECT * FROM portal_reservations WHERE account_id=?",{account});
    }
    result={{"reservation_id",existing->at("reservation_id")},{"expires",existing->at("expires")}};
  } else if(action=="release") {
    database.run("DELETE FROM portal_reservations WHERE account_id=? AND reservation_id=?",{account,identifier(input,"reservation_id")});
    result={{"released",true}};
  } else if(action=="grant") {
    const auto reservation=identifier(input,"reservation_id");
    const auto version=positive(input,"version",1000000),term=positive(input,"term_seconds",366*86400);
    if(!database.one("SELECT 1 FROM portal_reservations WHERE account_id=? AND reservation_id=? AND expires>?",{account,reservation,stamp}))
      throw HttpError(409,"Reservation expired or does not belong to this account");
    const auto previous=owner?owner->at("version").get<Int>():0;
    if(version!=previous+1)throw HttpError(409,"Entitlement version is stale or out of order");
    std::string id;Int expires=stamp+term;
    if(owner) {
      id=owner->at("user_id").get<std::string>();auto user=get_user(database,id);
      if(!user.enabled||user.quota!=0)throw HttpError(409,"Administrator changed account policy; manual review required");
      expires=std::max(stamp,user.expires)+term;
      if(expires>stamp+2*366*86400)throw HttpError(422,"Maximum prepaid term exceeded");
      database.run("UPDATE users SET expires=? WHERE id=?",{expires,id});
      database.run("UPDATE portal_accounts SET version=? WHERE account_id=?",{version,account});
    } else {
      id=random_id();
      database.run("INSERT INTO users(id,name,uuid,token,expires,created) VALUES(?,?,?,?,?,?)",{id,"Portal "+account.substr(0,12),random_uuid(),random_token(),expires,stamp});
      database.run("INSERT INTO portal_accounts VALUES(?,?,?)",{account,id,version});
    }
    database.run("DELETE FROM portal_reservations WHERE account_id=?",{account});
    result={{"account_id",account},{"user_id",id},{"version",version},{"expires",expires},{"links",links_for(get_user(database,id))}};
    audit(database,"portal_grant",operation);
  } else {
    if(!owner)throw HttpError(404,"Portal account is not provisioned");
    auto user=get_user(database,owner->at("user_id").get<std::string>());
    bool applied=core_&&user.active();
    if(applied) {
      try {
        for(const auto& tag:inbound_tags()) {
          auto live=core_->users(tag);auto match=live.find(user.email(tag));
          if(match==live.end()||match->second!=user.uuid){applied=false;break;}
        }
      }catch(...){applied=false;}
    }
    result={{"account_id",account},{"user_id",user.id},{"version",owner->at("version")},{"expires",user.expires},
      {"status",user.status()},{"applied",applied},{"offline",options_.offline},{"links",links_for(user)}};
  }
  if(action!="status")database.run("INSERT INTO portal_operations VALUES(?,?,?,?)",{operation,digest,result.dump(),stamp});
  transaction.commit();return result;
}

ProvisionServer::ProvisionServer(Backend& backend):backend_(backend) {}
ProvisionServer::~ProvisionServer(){stop();}
void ProvisionServer::start() {
  const auto& options=backend_.options();if(options.provision_socket.empty())return;
  if(options.provision_uid<1||fd_>=0)throw std::runtime_error("Invalid provisioning UID or lifecycle");
  const auto path=options.provision_socket.string();sockaddr_un address{};address.sun_family=AF_UNIX;
  if(path.size()>=sizeof(address.sun_path))throw std::runtime_error("Provisioning socket path is too long");
  struct stat directory{};
  if(::lstat(options.provision_socket.parent_path().c_str(),&directory)<0||!S_ISDIR(directory.st_mode)||
     directory.st_uid!=::geteuid()||(directory.st_mode&0022))throw std::runtime_error("Provisioning directory must be owned by the controller and not writable by others");
  std::memcpy(address.sun_path,path.c_str(),path.size()+1);
  // Recover only our own stale socket. A live endpoint, symlink, or foreign file is never removed.
  struct stat existing{};
  if(::lstat(path.c_str(),&existing)==0) {
    if(!S_ISSOCK(existing.st_mode)||existing.st_uid!=::geteuid())throw std::runtime_error("Provisioning path is not our socket");
    int probe=::socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK,0);
    if(probe<0)throw std::runtime_error("Cannot inspect existing provisioning socket");
    const auto connected=::connect(probe,reinterpret_cast<sockaddr*>(&address),sizeof(address));const auto error=errno;::close(probe);
    if(connected==0||error!=ECONNREFUSED)throw std::runtime_error("Provisioning socket is already active");
    struct stat recheck{};
    if(::lstat(path.c_str(),&recheck)<0||recheck.st_dev!=existing.st_dev||recheck.st_ino!=existing.st_ino||::unlink(path.c_str())<0)
      throw std::runtime_error("Provisioning socket changed during stale recovery");
  } else if(errno!=ENOENT)throw std::runtime_error("Cannot inspect provisioning path");
  auto peer=::getpwuid(static_cast<uid_t>(options.provision_uid));
  if(!peer)throw std::runtime_error("Provisioning worker UID does not exist");
  fd_=::socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);
  if(fd_<0)throw std::runtime_error("Cannot create provisioning socket");
  if(::bind(fd_,reinterpret_cast<sockaddr*>(&address),sizeof(address))<0){::close(fd_);fd_=-1;throw std::runtime_error("Cannot bind provisioning socket");}
  // The controller owns the socket; its supplementary worker group permits access.
  // SO_PEERCRED remains authoritative even for other members of that group.
  if(::chown(path.c_str(),static_cast<uid_t>(-1),peer->pw_gid)<0||::chmod(path.c_str(),0660)<0||::listen(fd_,8)<0) {
    ::close(fd_);fd_=-1;::unlink(path.c_str());throw std::runtime_error("Cannot secure provisioning socket");
  }
  stopping_=false;thread_=std::thread([this]{serve();});
}
void ProvisionServer::stop() {
  if(fd_<0)return;
  stopping_=true;::shutdown(fd_,SHUT_RDWR);
  if(thread_.joinable())thread_.join();
  ::close(fd_);fd_=-1;::unlink(backend_.options().provision_socket.c_str());
}
void ProvisionServer::serve() {
  while(!stopping_) {
    int client=::accept4(fd_,nullptr,nullptr,SOCK_CLOEXEC);
    if(client<0){if(stopping_)break;continue;}
    struct ucred credential{};socklen_t length=sizeof(credential);
    if(::getsockopt(client,SOL_SOCKET,SO_PEERCRED,&credential,&length)<0||credential.uid!=static_cast<uid_t>(backend_.options().provision_uid)) {::close(client);continue;}
    timeval timeout{2,0};::setsockopt(client,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));::setsockopt(client,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
    Json response;std::string request;bool complete=false;
    const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(3);
    try {
      char buffer[1024];
      while(request.size()<=8192&&std::chrono::steady_clock::now()<deadline) {
        auto count=::recv(client,buffer,sizeof(buffer),0);if(count<=0)break;
        request.append(buffer,static_cast<std::size_t>(count));
        if(request.find('\n')!=std::string::npos){complete=true;break;}
      }
      if(!complete||request.size()>8192||request.back()!='\n'||request.find('\n')!=request.size()-1)throw HttpError(422,"Invalid request frame");
      response={{"ok",true},{"result",backend_.provision(Json::parse(request))}};
    }catch(const HttpError& error){response={{"ok",false},{"status",error.status},{"error",error.what()}};}
    catch(const Json::exception&){response={{"ok",false},{"status",422},{"error","Invalid JSON"}};}
    catch(const std::exception&){response={{"ok",false},{"status",503},{"error","Provisioning temporarily unavailable"}};}
    send_all(client,response.dump()+"\n");::close(client);
  }
}
}
