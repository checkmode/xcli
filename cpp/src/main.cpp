#include "gateway.hpp"
#include <charconv>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <pthread.h>
#include <sys/stat.h>

namespace {
std::string env(const char* name,const std::string& fallback) {auto value=std::getenv(name);return value?value:fallback;}
int number(const std::string& text,int min,int max) {
  int value=0;auto result=std::from_chars(text.data(),text.data()+text.size(),value);
  if(result.ec!=std::errc()||result.ptr!=text.data()+text.size()||value<min||value>max)throw std::runtime_error("Invalid numeric option");return value;
}
}
int main(int argc,char** argv) {
  ::umask(0077);
  try {
    xg::Options options;
    options.state=env("XG_STATE",options.state.string());options.settings=env("XG_SETTINGS",options.settings.string());
    options.static_dir=env("XG_STATIC",options.static_dir.string());options.api=env("XG_API",options.api);
    options.core_binary=env("XG_XRAY",options.core_binary.string());options.core_pid_file=env("XG_CORE_PID_FILE",options.core_pid_file.string());
    options.secret_key=env("XG_SECRET_KEY","");options.monitor_config=env("XG_MONITOR_CONFIG","");
    options.monitor_report=env("XG_MONITOR_REPORT",options.monitor_report.string());
    options.backup_interval=number(env("XG_BACKUP_INTERVAL","21600"),60,604800);
    options.backup_retention=number(env("XG_BACKUP_RETENTION","28"),2,365);
    options.port=number(env("XG_PORT","8080"),1,65535);
    bool preflight=false;std::string backup,extract,destination;
    for(int i=1;i<argc;++i) {
      std::string arg=argv[i];
      auto value=[&] {if(i+1>=argc)throw std::runtime_error("Missing option value");return std::string(argv[++i]);};
      if(arg=="--version"){std::cout<<"xray-gateway-panel " XG_VERSION " (C++20)\n";return 0;}
      else if(arg=="--state")options.state=value();else if(arg=="--settings")options.settings=value();
      else if(arg=="--static")options.static_dir=value();else if(arg=="--api")options.api=value();
      else if(arg=="--core-binary")options.core_binary=value();else if(arg=="--core-pid-file")options.core_pid_file=value();
      else if(arg=="--port")options.port=number(value(),1,65535);else if(arg=="--poll-seconds")options.poll_seconds=number(value(),1,60);
      else if(arg=="--secret-key")options.secret_key=value();else if(arg=="--monitor-config")options.monitor_config=value();
      else if(arg=="--monitor-report")options.monitor_report=value();else if(arg=="--no-auto-backup")options.automatic_backups=false;
      else if(arg=="--extract-backup")extract=value();else if(arg=="--destination")destination=value();
      else if(arg=="--offline")options.offline=true;else if(arg=="--preflight")preflight=true;else if(arg=="--backup")backup=value();
      else if(arg=="--help") {std::cout<<"Options: --state DIR --settings FILE --static DIR --port PORT --api LOOPBACK:PORT --core-binary FILE --core-pid-file FILE --poll-seconds N --offline --preflight --backup NEW_FILE --secret-key FILE --monitor-config FILE --monitor-report FILE --no-auto-backup --extract-backup FILE --destination NEW_DIRECTORY\n";return 0;}
      else throw std::runtime_error("Unknown command line option");
    }
    if(!backup.empty()){xg::Database database(options.state/"gateway.sqlite",true);database.backup(backup);std::cout<<"Database backup completed\n";return 0;}
    if(!extract.empty()) {
      if(destination.empty()||options.secret_key.empty()||!xg::fs::is_regular_file(options.secret_key))throw std::runtime_error("Extraction requires an existing security key and a new destination directory");
      auto key=xg::load_secret_key(options.secret_key);
      auto bundle=xg::Json::parse(xg::unseal(xg::read_file(extract,64*1024*1024),key,"xcli:backup:v1"));
      if(bundle.value("format",0)!=1||bundle.value("application",std::string())!="xcli")throw std::runtime_error("Unsupported backup format");
      auto bytes=xg::unbase64(bundle.at("database").get<std::string>(),40*1024*1024);
      if(!xg::fs::create_directory(destination))throw std::runtime_error("Destination must not already exist");
      ::chmod(destination.c_str(),0700);xg::fs::path target(destination);
      try {
        xg::write_private_file(target/"gateway.sqlite",bytes);
        {xg::Database restored(target/"gateway.sqlite");if(restored.one("PRAGMA quick_check")->begin().value()!="ok")throw std::runtime_error("Database integrity check failed");restored.run("DELETE FROM sessions");restored.run("DELETE FROM mfa_sessions");}
        xg::write_private_file(target/"settings.json",bundle.at("settings").dump(2));
        xg::write_private_file(target/"security.key",key);
      }catch(...){xg::fs::remove_all(target);throw;}
      std::cout<<"Backup verified and extracted; no running service or existing data changed\n";return 0;
    }
    sigset_t signals;sigemptyset(&signals);sigaddset(&signals,SIGTERM);sigaddset(&signals,SIGINT);
    if(pthread_sigmask(SIG_BLOCK,&signals,nullptr)!=0)throw std::runtime_error("Cannot configure signal handling");
    std::signal(SIGPIPE,SIG_IGN);
    xg::Backend backend(options);
    if(preflight){std::cout<<backend.preflight().dump(2)<<'\n';return 0;}
    xg::HttpServer server(backend);
    if(!server.bind())throw std::runtime_error("Cannot bind management port");
    std::jthread signal_thread([&](std::stop_token stop) {
      while(!stop.stop_requested()) {
        timespec timeout{0,200000000};int signal=sigtimedwait(&signals,nullptr,&timeout);
        if(signal==SIGTERM||signal==SIGINT){server.stop();break;}
      }
    });
    backend.start_worker();
    std::cout<<"C++ management backend ready on loopback port "<<options.port<<std::endl;
    bool ok=server.listen();backend.stop_worker();
    return ok?0:1;
  } catch(const std::exception& error) {std::cerr<<"Startup failed: "<<error.what()<<'\n';return 1;}
}
