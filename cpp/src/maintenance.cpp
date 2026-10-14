#include "gateway.hpp"
#include <algorithm>
#include <regex>
#include <sys/stat.h>

namespace xg {
namespace {
constexpr std::size_t maximum_backup=64*1024*1024;
struct Temporary {
  fs::path path;
  ~Temporary(){std::error_code ec;fs::remove(path,ec);fs::remove(path.string()+"-wal",ec);fs::remove(path.string()+"-shm",ec);}
};
Json summary(const Json& bundle,const std::string& id) {
  return {{"id",id},{"created",bundle.at("created")},{"reason",bundle.at("reason")},{"users",bundle.at("users")},{"version",bundle.at("version")},{"domain",bundle.at("settings").at("domain")}};
}
}
std::vector<User> Backend::desired_users(Database& database) {
  std::vector<User> result;for(const auto& row:database.all("SELECT * FROM users"))result.push_back(User::from(row));
  if(probe_user_)result.push_back(*probe_user_);
  return result;
}
Json Backend::activity_status(Database& database) {
  Json result=Json::object();auto stamp=now();
  for(auto row:database.all("SELECT * FROM device_activity WHERE user_id IN (SELECT id FROM users WHERE deleted=0)")) {
    auto id=row.at("user_id").get<std::string>();auto transport=row.at("transport").get<std::string>();
    Int last=row.at("last_seen"),sample=row.at("sampled"),interval=row.at("interval_seconds");bool stale=stamp-sample>30;
    row["status"]=stale?"unknown":last==0?"never":stamp-last<=60?"recent":"idle";
    row["upload_rate"]=stale?0.0:row.at("upload_delta").get<double>()/static_cast<double>(std::max(Int(1),interval));
    row["download_rate"]=stale?0.0:row.at("download_delta").get<double>()/static_cast<double>(std::max(Int(1),interval));
    result[id][transport]=row;
  }
  return result;
}
Json Backend::monitor_status(Int timestamp) {
  Json unknown={{"scope","server"},{"status","unknown"},{"message","尚未收到服务器自检结果"},{"updated",0}};
  try {
    auto report=Json::parse(read_file(options_.monitor_report,32768));
    if(!report.is_object()||report.value("schema",0)!=1||!report.contains("updated")||!report.at("updated").is_number_integer())return unknown;
    Json result={{"scope",report.value("scope",std::string("server"))},{"updated",report.at("updated")},{"status",report.value("status",std::string("unknown"))},{"checks",Json::array()}};
    auto age=timestamp-report.at("updated").get<Int>();
    if(age>180||age< -60){result["status"]="stale";result["message"]="自检结果已过期，请检查探测服务";}
    for(const auto& check:report.value("checks",Json::array())) {
      if(result["checks"].size()>=32)break;
      result["checks"].push_back({{"transport",check.value("transport",std::string("unknown"))},{"status",check.value("status",std::string("unknown"))},
        {"https_ms",check.value("https_ms",Json(nullptr))},{"udp_ms",check.value("udp_ms",Json(nullptr))},{"udp_supported",check.value("udp_supported",true)},{"doh_ms",check.value("doh_ms",Json(nullptr))},
        {"last_success",check.value("last_success",Int(0))},{"error",check.value("error",std::string(""))}});
    }
    if(result["status"]!="stale")for(const auto& kind:inbound_tags()) {
      bool dynamic=false;for(const auto& entry:settings_.value("residential_exits",Json::array()))if(entry.at("tag")==kind&&entry.value("dynamic",false))dynamic=true;
      if(dynamic)continue; // Dynamic upstream probes have their own pool status and do not impersonate public-entry checks.
      bool found=false;for(const auto& check:result["checks"])if(check["transport"]==kind)found=true;
      if(!found){result["status"]="unknown";result["message"]="等待全部入口的自检结果";}
    }
    return result;
  }catch(...){return unknown;}
}
fs::path Backend::backup_path(const std::string& id) const {
  if(!std::regex_match(id,std::regex("[0-9]{10,12}-[0-9a-f]{32}\\.xgb")))throw HttpError(404,"备份不存在");
  auto path=options_.state/"backups"/id;
  if(fs::is_symlink(fs::symlink_status(path))||!fs::is_regular_file(path))throw HttpError(404,"备份不存在");
  return path;
}
Json Backend::open_backup(const std::string& id) {
  auto encrypted=read_file(backup_path(id),maximum_backup);auto bundle=Json::parse(unseal(encrypted,secret_key_,"xcli:backup:v1"));
  if(bundle.value("format",0)!=1||bundle.value("application",std::string())!="xcli")throw HttpError(422,"备份格式不支持");
  return bundle;
}
Json Backend::list_backups() {
  Json list=Json::array();auto directory=options_.state/"backups";if(!fs::exists(directory))return list;
  for(const auto& file:fs::directory_iterator(directory)) {
    auto id=file.path().filename().string();if(!id.ends_with(".xgb"))continue;
    try {auto entry=summary(open_backup(id),id);entry["bytes"]=fs::file_size(file.path());entry["valid"]=true;list.push_back(entry);}
    catch(...){list.push_back({{"id",id},{"valid",false},{"created",0},{"reason","校验失败"}});}
  }
  std::sort(list.begin(),list.end(),[&](const Json& a,const Json& b){return fs::last_write_time(directory/a.at("id").get<std::string>())>fs::last_write_time(directory/b.at("id").get<std::string>());});return list;
}
Json Backend::make_backup(const std::string& reason) {
  auto directory=options_.state/"backups";fs::create_directories(directory);::chmod(directory.c_str(),0700);
  Temporary snapshot{directory/("snapshot-"+random_id()+".sqlite")};auto database=db();database.backup(snapshot.path);
  Json count;{Database copy(snapshot.path,true);if(copy.one("PRAGMA quick_check")->begin().value()!="ok")throw std::runtime_error("Backup integrity check failed");count=copy.one("SELECT COUNT(*) AS n FROM users WHERE deleted=0")->at("n");}
  auto stamp=now();auto id=std::to_string(stamp)+"-"+random_id()+".xgb";
  Json bundle={{"format",1},{"application","xcli"},{"version",XG_VERSION},{"created",stamp},{"reason",reason},{"users",count},{"settings",settings_},
    {"database",base64(read_file(snapshot.path,40*1024*1024))}};
  write_private_file(directory/id,seal(bundle.dump(),secret_key_,"xcli:backup:v1"));
  database.run("INSERT OR REPLACE INTO metadata VALUES('last_backup',?)",{std::to_string(stamp)});database.run("DELETE FROM metadata WHERE key='backup_error'");
  audit(database,"backup_created",id);
  auto list=list_backups();int kept=0;
  for(const auto& entry:list)if(entry.value("valid",false)&&++kept>options_.backup_retention)fs::remove(backup_path(entry.at("id").get<std::string>()));
  return summary(bundle,id);
}
void Backend::scheduled_backup() {
  if(!options_.automatic_backups||now()<backup_retry_after_)return;
  std::lock_guard guard(mutation_mutex_);auto database=db();auto previous=database.one("SELECT value FROM metadata WHERE key='last_backup'");
  if(previous&&now()-std::stoll(previous->at("value").get<std::string>())<options_.backup_interval)return;
  try {make_backup("automatic");}
  catch(...) {backup_retry_after_=now()+300;database.run("INSERT OR REPLACE INTO metadata VALUES('backup_error','自动备份失败；5 分钟后重试')");throw;}
}
Json Backend::backup_status(const std::string& token) {
  std::lock_guard guard(mutation_mutex_);session(token);auto database=db();auto previous=database.one("SELECT value FROM metadata WHERE key='last_backup'");auto error=database.one("SELECT value FROM metadata WHERE key='backup_error'");
  Int last=previous?std::stoll(previous->at("value").get<std::string>()):0;
  return {{"automatic",options_.automatic_backups},{"interval",options_.backup_interval},{"retention",options_.backup_retention},{"last_backup",last},
    {"next_backup",options_.automatic_backups?std::max(last+options_.backup_interval,backup_retry_after_):0},{"error",error?error->at("value"):Json("")},{"backups",list_backups()}};
}
Json Backend::create_backup(const std::string& token,const std::string& csrf) {
  std::lock_guard guard(mutation_mutex_);session(token,csrf,true);return make_backup("manual");
}
Json Backend::inspect_backup(const std::string& token,const std::string& id) {
  std::lock_guard guard(mutation_mutex_);session(token);auto bundle=open_backup(id);auto result=summary(bundle,id);
  result["same_server"]=secure_equal(sha256(bundle.at("settings").dump()),sha256(settings_.dump()));
  result["preserves"]=Json::array({"当前管理员密码和二次验证","当前流量累计下限","当前服务器入口与证书"});return result;
}
std::string Backend::download_backup(const std::string& token,const std::string& id) {
  std::lock_guard guard(mutation_mutex_);session(token);return read_file(backup_path(id),maximum_backup);
}
void Backend::restore_backup(const std::string& token,const std::string& csrf,const Json& input) {
  std::lock_guard guard(mutation_mutex_);session(token,csrf,true);
  auto id=checked_string(input.value("id",Json("")),1,80);
  if(input.value("confirm",Json(""))!=Json(id))throw HttpError(422,"请确认指定备份编号");
  auto database=db();{Transaction auth(database);confirm_admin(database,token,input);auth.commit();}
  auto bundle=open_backup(id);
  if(!secure_equal(sha256(bundle.at("settings").dump()),sha256(settings_.dump())))throw HttpError(409,"备份来自不同的服务器配置；请使用离线恢复工具");
  Temporary candidate{options_.state/("restore-"+random_id()+".sqlite")};write_private_file(candidate.path,unbase64(bundle.at("database").get<std::string>(),40*1024*1024));
  Json users;{Database copy(candidate.path,true);if(copy.one("PRAGMA quick_check")->begin().value()!="ok")throw HttpError(422,"备份数据库损坏");users=copy.all("SELECT * FROM users");for(const auto& row:users)(void)User::from(row);}
  // Flush current traffic when possible, without changing runtime authorization yet.
  if(core_){auto gen=core_->generation();auto counters=core_->counters();if(core_->generation()!=gen)throw HttpError(503,"核心正在重启，请稍后恢复");Transaction stats(database);apply_stats(database,gen,counters);stats.commit();}
  make_backup("before-restore");
  Transaction transaction(database);auto current=database.all("SELECT id,upload,download FROM users");
  std::map<std::string,std::pair<Int,Int>> usage;for(const auto& row:current)usage[row.at("id").get<std::string>()]={row.at("upload").get<Int>(),row.at("download").get<Int>()};
  database.run("DELETE FROM users");
  for(const auto& row:users) {
    auto user=User::from(row);auto previous=usage[user.id];
    database.run("INSERT INTO users(id,name,uuid,token,enabled,quota,expires,upload,download,created,deleted) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
      {user.id,user.name,user.uuid,user.token,Int(user.enabled),user.quota,user.expires,std::max(user.upload,previous.first),std::max(user.download,previous.second),user.created,Int(user.deleted)});
  }
  database.run("DELETE FROM sessions");database.run("DELETE FROM mfa_sessions");database.run("DELETE FROM device_activity");database.run("DELETE FROM metadata WHERE key='activity_sample'");
  audit(database,"backup_restored",id);transaction.commit();
}
}
