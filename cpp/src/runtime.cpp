#include "gateway.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <charconv>
#include <cerrno>
#include <cstring>
#include <cmath>
#include <fcntl.h>
#include <ctime>
#include <fstream>
#include <poll.h>
#include <spawn.h>
#include <sstream>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/wait.h>
#include <unistd.h>
#include <csignal>
#include <set>

extern char** environ;
namespace xg {
namespace {
std::optional<std::string> text(const fs::path& path, std::size_t bound=1024*1024) {
  struct Descriptor {int fd;~Descriptor(){if(fd>=0)::close(fd);}} file{::open(path.c_str(),O_RDONLY|O_CLOEXEC|O_NONBLOCK)};
  if(file.fd<0)return std::nullopt;
  struct stat info{};
  // A diagnostic read must never wait for a FIFO/device and stall permission
  // reconciliation. Procfs text files are regular files with zero st_size.
  if(::fstat(file.fd,&info)!=0||!S_ISREG(info.st_mode))return std::nullopt;
  std::string result;char buffer[8192];
  for(;;) {
    const auto n=::read(file.fd,buffer,sizeof(buffer));
    if(n==0)return result;
    if(n<0){if(errno==EINTR)continue;return std::nullopt;}
    if(result.size()+static_cast<std::size_t>(n)>bound)return std::nullopt;
    result.append(buffer,static_cast<std::size_t>(n));
  }
}
Json unknown_process(std::string_view reason) { return {{"state","unknown"},{"reason",reason}}; }
std::optional<std::string> running_version(const fs::path& executable) {
  // Execute the pinned running image, never a shell or a configured version.
  int pipefd[2];if(::pipe2(pipefd,O_CLOEXEC|O_NONBLOCK)!=0)return std::nullopt;
  posix_spawn_file_actions_t actions;posix_spawn_file_actions_init(&actions);
  posix_spawn_file_actions_adddup2(&actions,pipefd[1],STDOUT_FILENO);
  posix_spawn_file_actions_adddup2(&actions,pipefd[1],STDERR_FILENO);
  posix_spawn_file_actions_addclose(&actions,pipefd[0]);
  std::string path=executable.string();std::array<char*,3> args{path.data(),const_cast<char*>("version"),nullptr};pid_t pid=0;
  int error=::posix_spawn(&pid,path.c_str(),&actions,nullptr,args.data(),environ);
  posix_spawn_file_actions_destroy(&actions);::close(pipefd[1]);
  if(error){::close(pipefd[0]);return std::nullopt;}
  std::string output;int status=0;bool done=false;
  auto deadline=std::chrono::steady_clock::now()+std::chrono::milliseconds(750);
  while(std::chrono::steady_clock::now()<deadline&&output.size()<16384) {
    char buffer[2048];auto n=::read(pipefd[0],buffer,sizeof(buffer));if(n>0)output.append(buffer,static_cast<std::size_t>(n));
    if(::waitpid(pid,&status,WNOHANG)==pid){done=true;break;}
    pollfd fd{pipefd[0],POLLIN,0};::poll(&fd,1,10);
  }
  if(!done){::kill(pid,SIGKILL);::waitpid(pid,&status,0);}
  if(done) {
    char buffer[2048];ssize_t n=0;
    while(output.size()<16384&&(n=::read(pipefd[0],buffer,sizeof(buffer)))>0)output.append(buffer,static_cast<std::size_t>(n));
  }
  ::close(pipefd[0]);
  if(!done||!WIFEXITED(status)||WEXITSTATUS(status)!=0)return std::nullopt;
  std::istringstream line(output);std::string name,version;line>>name>>version;
  if(name!="Xray"||version.empty()||version.size()>64||version.find_first_not_of("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-+")!=std::string::npos)return std::nullopt;
  return version;
}
Json certificate(const fs::path& path); // implemented below using OpenSSL
Json port_state(const fs::path& proc, const Json& inbound, const std::set<std::string>& owned, bool ownership_known) {
  if(!inbound.contains("port")||!inbound["port"].is_number_integer())return {{"state","unknown"},{"reason","配置未提供单一端口"}};
  const int port=inbound["port"];const bool udp=inbound.value("protocol",std::string())=="hysteria";
  auto files=udp?std::array<const char*,2>{"udp","udp6"}:std::array<const char*,2>{"tcp","tcp6"};
  bool read_any=false,found=false,matched=false;Json bindings=Json::array();
  for(auto name:files)if(auto data=text(proc/"net"/name,4*1024*1024)) {
    read_any=true;std::istringstream rows(*data);std::string row;std::getline(rows,row);
    while(std::getline(rows,row)) {
      std::istringstream fields(row);std::string index,local,remote,state,queue,timer,retries,uid,timeout,inode;
      if(!(fields>>index>>local>>remote>>state>>queue>>timer>>retries>>uid>>timeout>>inode))continue;
      auto colon=local.rfind(':');if(colon==std::string::npos)continue;
      unsigned parsed=0;auto value=std::string_view(local).substr(colon+1);
      auto rc=std::from_chars(value.data(),value.data()+value.size(),parsed,16);
      if(rc.ec!=std::errc()||parsed!=static_cast<unsigned>(port)||(!udp&&state!="0A"))continue;
      found=true;if(owned.contains(inode)) {
        matched=true;auto address=std::string_view(local).substr(0,colon);std::array<unsigned char,16> binary{};
        bool valid=address.size()==8||address.size()==32;
        for(std::size_t i=0;valid&&i<address.size()/8;++i) {
          std::uint32_t word=0;auto part=address.substr(i*8,8);auto parsed_word=std::from_chars(part.data(),part.data()+part.size(),word,16);
          valid=parsed_word.ec==std::errc();if(valid)std::memcpy(binary.data()+i*4,&word,4);
        }
        char rendered[INET6_ADDRSTRLEN]{};
        if(valid&&::inet_ntop(address.size()==8?AF_INET:AF_INET6,binary.data(),rendered,sizeof(rendered)))bindings.push_back({{"address",rendered},{"port",parsed},{"transport",udp?"udp":"tcp"}});
      }
    }
  }
  if(matched)return {{"state","listening"},{"source","process_socket_inode"},{"bindings",bindings}};
  if(!read_any)return {{"state","unknown"},{"reason","无法读取内核端口表"}};
  if(ownership_known)return {{"state","not_listening"},{"reason","未找到属于该进程的监听套接字"}};
  return {{"state","unknown"},{"port_visible",found},{"reason",found?"端口可见，但无权确认进程归属":"无法确认进程套接字；内核未观察到该端口"}};
}
}

Json linux_host_sample(const fs::path& proc,const fs::path& disk) {
  Json out={{"uptime_seconds",nullptr},{"memory",nullptr},{"swap",nullptr},{"disk",nullptr},{"load",nullptr},{"cpu_ticks",nullptr}};
  if(auto value=text(proc/"uptime",1024)){std::istringstream in(*value);double seconds=0;if(in>>seconds&&seconds>=0)out["uptime_seconds"]=seconds;}
  if(auto value=text(proc/"loadavg",1024)){std::istringstream in(*value);double a=0,b=0,c=0;if(in>>a>>b>>c)out["load"]={a,b,c};}
  if(auto value=text(proc/"meminfo",65536)) {
    std::map<std::string,Int> fields;std::istringstream in(*value);std::string line;
    while(std::getline(in,line)){std::istringstream row(line);std::string key,unit;Int n=0;if(row>>key>>n>>unit&&n>=0&&unit=="kB")fields[key]=n*1024;}
    if(fields.contains("MemTotal:")&&fields.contains("MemAvailable:"))out["memory"]={{"total",fields["MemTotal:"]},{"used",std::max(Int(0),fields["MemTotal:"]-fields["MemAvailable:"])}};
    if(fields.contains("SwapTotal:")&&fields.contains("SwapFree:"))out["swap"]={{"total",fields["SwapTotal:"]},{"used",std::max(Int(0),fields["SwapTotal:"]-fields["SwapFree:"])}};
  }
  if(auto value=text(proc/"stat",65536)) {
    std::istringstream in(*value);std::string line;
    while(std::getline(in,line)) {
      std::istringstream row(line);std::string key;row>>key;
      if(key=="cpu") {
        Int n=0,total=0,idle=0;int i=0;
        // guest and guest_nice are already included in user and nice.
        while(i<8&&row>>n){total+=n;if(i==3||i==4)idle+=n;++i;}
        if(i>=4)out["cpu_ticks"]={total,idle};
      } else if(key=="btime"){Int stamp=0;if(row>>stamp)out["booted_at"]=stamp;}
    }
  }
  struct statvfs space{};
  if(::statvfs(disk.c_str(),&space)==0)out["disk"]={{"path",disk.string()},{"total",static_cast<std::uint64_t>(space.f_blocks)*space.f_frsize},{"used",static_cast<std::uint64_t>(space.f_blocks-space.f_bfree)*space.f_frsize},{"available",static_cast<std::uint64_t>(space.f_bavail)*space.f_frsize}};
  return out;
}

Json inspect_core_process(const Options&,const std::string& generation,bool read_version) {
  const auto colon=generation.find(':');if(colon==std::string::npos)return unknown_process("无法确认核心进程身份");
  const std::string pid=generation.substr(0,colon);fs::path proc=fs::path("/proc")/pid;
  auto raw=text(proc/"stat",8192);if(!raw)return unknown_process("无法读取核心进程");
  auto end=raw->rfind(')');if(end==std::string::npos)return unknown_process("核心进程信息无效");
  std::istringstream fields(raw->substr(end+2));std::vector<std::string> values;std::string value;while(fields>>value)values.push_back(value);
  if(values.size()<22||values[19]!=generation.substr(colon+1))return unknown_process("采集期间核心进程已改变");
  auto host=linux_host_sample("/proc","/");const long ticks=::sysconf(_SC_CLK_TCK);
  Json out={{"state","running"},{"generation",generation},{"pid",std::stoi(pid)},{"version",nullptr},{"inbounds",Json::array()}};
  const double start=std::stod(values[19])/static_cast<double>(ticks);
  std::optional<double> started_at;
  if(host["uptime_seconds"].is_number()) {
    const double elapsed=std::max(0.0,host["uptime_seconds"].get<double>()-start);out["uptime_seconds"]=elapsed;
    // btime has only whole-second precision; translate uptime against current
    // realtime rather than reporting pre-launch file writes as post-launch.
    started_at=std::chrono::duration<double>(std::chrono::system_clock::now().time_since_epoch()).count()-elapsed;
    out["started_at"]=static_cast<Int>(*started_at);
  }
  if(auto status=text(proc/"status",65536)) {
    std::istringstream rows(*status);std::string line;while(std::getline(rows,line)) {
      std::istringstream row(line);std::string key;Int n=0;if(row>>key>>n&&key=="VmRSS:")out["resident_bytes"]=n*1024;
    }
  }
  if(read_version) {
    auto version=running_version(proc/"exe");if(version){out["version"]=*version;out["version_source"]="running_process_executable";}
    else out["version_reason"]="无权执行运行进程的镜像或无法获取版本；不使用安装配置中的版本代替";
  }
  auto command=text(proc/"cmdline",65536);std::string config;
  if(command) {
    std::vector<std::string> args;std::istringstream in(*command);std::string arg;while(std::getline(in,arg,'\0'))args.push_back(arg);
    int count=0;
    for(std::size_t i=1;i<args.size();++i) {
      if(args[i]=="-c"||args[i]=="-config"||args[i]=="--config"){if(i+1<args.size()){config=args[++i];++count;}}
      else if(args[i].starts_with("-config=")||args[i].starts_with("--config=")){config=args[i].substr(args[i].find('=')+1);++count;}
      else if(args[i]=="-confdir"||args[i].starts_with("-confdir="))count+=2;
    }
    if(count!=1)config.clear();
  }
  if(config.empty()){out["config_reason"]="启动参数未提供可读取的单一配置文件";return out;}
  fs::path file(config);if(file.is_relative()){std::error_code error;file=fs::read_symlink(proc/"cwd",error)/file;if(error){out["config_reason"]="无法读取进程工作目录";return out;}}
  auto content=text(file);if(!content){out["config_reason"]="无权读取启动配置文件";return out;}
  try {
    auto data=Json::parse(*content);out["config"]={{"source","process_command_line_file"},{"path",file.string()},{"sha256",sha256(*content)},{"scope","file_snapshot"}};
    struct stat st{};
    if(::stat(file.c_str(),&st)==0) {
      out["config"]["modified_at"]=st.st_mtime;out["config"]["changed_since_start"]=nullptr;
      const double modified=static_cast<double>(st.st_mtim.tv_sec)+static_cast<double>(st.st_mtim.tv_nsec)/1e9;
      if(started_at&&std::abs(modified-*started_at)>0.1)out["config"]["changed_since_start"]=modified>*started_at;
    }
    std::set<std::string> sockets;bool ownership_known=true;std::error_code error;
    fs::directory_iterator it(proc/"fd",error);if(error)ownership_known=false;
    for(;!error&&it!=fs::directory_iterator();it.increment(error)) {
      auto target=fs::read_symlink(it->path(),error);if(error){ownership_known=false;break;}
      auto link=target.string();if(link.starts_with("socket:[")&&link.ends_with(']'))sockets.insert(link.substr(8,link.size()-9));
    }
    if(error)ownership_known=false;
    for(const auto& inbound:data.value("inbounds",Json::array())) {
      const std::string tag=inbound.value("tag",std::string());
      const bool residential=tag.size()==14&&tag.starts_with("residential-")&&tag[12]>='0'&&tag[12]<='9'&&tag[13]>='0'&&tag[13]<='9';
      if(tag!="reality"&&tag!="websocket"&&tag!="hysteria2"&&tag!="vmess"&&!residential)continue;
      auto stream=inbound.value("streamSettings",Json::object());
      Json entry={{"tag",tag},{"listen",inbound.value("listen",Json(nullptr))},{"port",inbound.value("port",Json(nullptr))},{"protocol",inbound.value("protocol",Json(nullptr))},{"network",stream.value("network",Json(nullptr))},{"security",stream.value("security",Json("none"))},{"listener",port_state(proc,inbound,sockets,ownership_known)}};
      // Strict allowlist: no users, UUIDs, private keys, short IDs, or raw config.
      if(stream.contains("realitySettings")){auto r=stream["realitySettings"];entry["server_names"]=r.value("serverNames",Json::array());entry["target"]=r.value("target",r.value("dest",Json(nullptr)));}
      if(stream.contains("wsSettings"))entry["path"]=stream["wsSettings"].value("path",Json(nullptr));
      if(stream.contains("tlsSettings")) {
        auto tls=stream["tlsSettings"];entry["server_name"]=tls.value("serverName",Json(nullptr));entry["alpn"]=tls.value("alpn",Json::array());
        const auto certs=tls.value("certificates",Json::array());
        if(!certs.empty()&&certs[0].contains("certificateFile"))entry["certificate"]=certificate(certs[0]["certificateFile"].get<std::string>());
      }
      out["inbounds"].push_back(entry);
    }
  } catch (...) {out["inbounds"]=Json::array();out["config_reason"]="无法解析启动配置文件";}
  return out;
}

void Backend::sample_runtime() {
  std::lock_guard collect(runtime_mutex_);
  const Int stamp=now();auto host=linux_host_sample("/proc",options_.state);host["cpu_percent"]=nullptr;
  if(host["cpu_ticks"].is_array()) {
    std::pair<Int,Int> current{host["cpu_ticks"][0],host["cpu_ticks"][1]};
    if(cpu_previous_&&current.first>cpu_previous_->first&&current.second>=cpu_previous_->second)host["cpu_percent"]=std::clamp(100.0*(1.0-static_cast<double>(current.second-cpu_previous_->second)/static_cast<double>(current.first-cpu_previous_->first)),0.0,100.0);
    cpu_previous_=current;
  }
  host.erase("cpu_ticks");Json process=unknown_process(options_.offline?"离线模式未接入核心":"等待核心进程信息");
  if(core_)try{process=core_->runtime();}catch(...){process={{"state","unavailable"},{"reason","无法确认正在运行的核心进程"}};}
  auto h=health();const bool fresh=h.value("api_sampled",Int(0))>0&&stamp-h.value("api_sampled",Int(0))<=std::max(30,options_.poll_seconds*3);
  Json api={{"state",!fresh?"unknown":h.value("api_state",std::string("unknown"))},{"generation",h.value("api_generation",std::string())},{"sampled",h.value("api_sampled",Int(0))},{"last_success",h.value("api_last_success",Int(0))},{"source","grpc_QueryStats"}};
  if(process.value("state",std::string())!="running"||process.value("generation",std::string())!=h.value("api_generation",std::string()))api["state"]="unknown";
  Json sync={{"state",h.value("sync_state",std::string("unknown"))},{"generation",h.value("sync_generation",std::string())},{"sampled",h.value("attempted",Int(0))},{"last_success",h.value("last_success",Int(0))},{"message",h.value("error",std::string("等待连接"))}};
  if(process.value("state",std::string())!="running"||process.value("generation",std::string())!=h.value("sync_generation",std::string()))sync["state"]="unknown";
  if(sync["sampled"]==0||stamp-sync["sampled"].get<Int>()>std::max(30,options_.poll_seconds*3))sync["state"]="unknown";
  std::string signature=process.value("state",std::string("unknown"))+":"+process.value("generation",std::string())+":"+api["state"].get<std::string>()+":"+sync["state"].get<std::string>();
  if(signature!=diagnostic_state_) {
    diagnostic_events_.push_back({{"ts",stamp},{"process_state",process.value("state",std::string("unknown"))},{"api_state",api["state"]},{"generation",process.value("generation",std::string())},{"sync_state",sync["state"]},{"message",sync["message"]}});
    while(diagnostic_events_.size()>50)diagnostic_events_.erase(diagnostic_events_.begin());
    diagnostic_state_=signature;
  }
  runtime_={{"sampled",stamp},{"host",host},{"panel",{{"version",XG_VERSION},{"revision",XG_REVISION},{"pid",::getpid()},{"started_at",panel_started_at_},{"uptime_seconds",std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now()-panel_started_).count()}}},{"process",process},{"management_api",api},{"access_sync",sync}};
}
Json Backend::runtime(const std::string& token) {
  session(token);std::lock_guard guard(runtime_mutex_);auto result=runtime_;const Int stamp=result.value("sampled",Int(0));
  result["max_age_seconds"]=std::max(30,options_.poll_seconds*3);
  result["stale"]=stamp==0||now()-stamp>std::max(30,options_.poll_seconds*3);return result;
}
Json Backend::diagnostics(const std::string& token) {
  auto snapshot=runtime(token);Json events;{std::lock_guard guard(runtime_mutex_);events=diagnostic_events_;}
  auto database=db();return {{"runtime",snapshot},{"monitor",monitor_status()},{"transitions",events},{"operations",database.all("SELECT ts,action,detail FROM events WHERE action='core_restart' ORDER BY id DESC LIMIT 20")},{"scope","server"}};
}
}

#include <openssl/pem.h>
#include <openssl/x509.h>
namespace xg { namespace {
Json certificate(const fs::path& path) {
  auto data=text(path,256*1024);if(!data)return {{"state","unknown"},{"reason","无权读取证书文件"}};
  BIO* bio=BIO_new_mem_buf(data->data(),static_cast<int>(data->size()));if(!bio)return {{"state","unknown"}};
  X509* cert=PEM_read_bio_X509(bio,nullptr,nullptr,nullptr);BIO_free(bio);if(!cert)return {{"state","unknown"},{"reason","无法解析证书"}};
  std::tm from{},until{};const bool valid=ASN1_TIME_to_tm(X509_get0_notBefore(cert),&from)==1&&ASN1_TIME_to_tm(X509_get0_notAfter(cert),&until)==1;
  X509_free(cert);if(!valid)return {{"state","unknown"}};
  const auto start=::timegm(&from),end=::timegm(&until);
  return {{"state",now()<start?"not_yet_valid":now()>end?"expired":"within_validity"},{"not_before",start},{"not_after",end},{"source","certificate_file"},{"scope","file_validity_only"}};
}
}}
