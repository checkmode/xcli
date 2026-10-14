#include "gateway.hpp"
#include <algorithm>
#include <cmath>
#include <set>

namespace xg {
namespace {
constexpr Int retention = 30*86400;
const std::map<std::string,std::string> service_names={{"reality","REALITY 入口"},{"websocket","WebSocket / TLS 入口"},
  {"hysteria2","Hysteria 2 入口"},
  {"probe","探测结果采集"},{"core","Xray 管理接口"},{"backup","本地自动加密备份"},{"test","通知通道测试"}};
Int numeric(const Json& input,const std::string& key,Int fallback,Int low,Int high) {
  auto value=input.value(key,Json(fallback));
  if(!value.is_number_integer()||(value.is_number_unsigned()&&value.get<std::uint64_t>()>static_cast<std::uint64_t>(high)))throw HttpError(422,"通知阈值必须是有效整数");
  auto n=value.get<Int>();if(n<low||n>high)throw HttpError(422,"通知阈值超出允许范围");return n;
}
bool boolean(const Json& input,const std::string& key,bool fallback=false) {
  auto value=input.value(key,Json(fallback));if(!value.is_boolean())throw HttpError(422,"通知开关必须是布尔值");return value.get<bool>();
}
std::string secret_input(const Json& input,const std::string& key,std::size_t maximum) {
  auto value=checked_string(input.value(key,Json("")),0,maximum);
  if(std::any_of(value.begin(),value.end(),[](unsigned char c){return c<32||c==127;}))throw HttpError(422,"凭据不能包含控制字符");
  return value;
}
Value latency(const Json& check,const std::string& key) {
  auto value=check.value(key,Json());
  if(!value.is_number())return std::string();
  double n=value.get<double>();
  if(!std::isfinite(n)||n<0||n>300000)return std::string();
  return std::to_string(n);
}
}

Json Backend::history(const std::string& token,const std::string& range) {
  session(token);
  static const std::map<std::string,std::pair<Int,Int>> spans={{"1h",{3600,60}},{"24h",{86400,300}},{"7d",{7*86400,1800}},{"30d",{30*86400,7200}}};
  auto found=spans.find(range);if(found==spans.end())throw HttpError(422,"请选择 1h、24h、7d 或 30d");
  auto [duration,bucket]=found->second;auto end=now();auto start=(end-duration)/bucket*bucket;
  auto database=db();database.exec("BEGIN");
  auto traffic=database.all("SELECT (ts/?)*? AS ts,SUM(upload) AS upload,SUM(download) AS download,COUNT(*) AS minutes FROM traffic_history WHERE ts>=? AND ts<=? GROUP BY ts/? ORDER BY ts/?",{bucket,bucket,start,end,bucket,bucket});
  auto probes=database.all("SELECT (ts/?)*? AS ts,transport,SUM(status='healthy') AS healthy,SUM(status='failed') AS failed,SUM(status='unknown') AS unknown,AVG(https_ms) AS https_ms,AVG(udp_ms) AS udp_ms FROM probe_history WHERE ts>=? AND ts<=? GROUP BY ts/?,transport ORDER BY ts/?,transport",{bucket,bucket,start,end,bucket,bucket});
  auto summary=database.all("SELECT transport,SUM(status='healthy') AS healthy,SUM(status='failed') AS failed,SUM(status='unknown') AS unknown,AVG(https_ms) AS https_ms,AVG(udp_ms) AS udp_ms FROM probe_history WHERE ts>=? AND ts<=? GROUP BY transport",{start,end});
  auto first=database.one("SELECT MIN(ts) AS ts FROM probe_history");
  database.exec("COMMIT");
  for(auto& row:summary){auto known=row.at("healthy").get<Int>()+row.at("failed").get<Int>();row["success_percent"]=known?Json(100.0*row.at("healthy").get<double>()/static_cast<double>(known)):Json(nullptr);}
  return {{"range",range},{"start",start},{"end",end},{"bucket_seconds",bucket},{"retention_days",30},{"transports",inbound_tags()},{"first_probe",first->at("ts")},{"traffic",traffic},{"probes",probes},{"summary",summary}};
}
Json Backend::webhook_configuration(Database& database) {
  auto value=*database.one("SELECT * FROM notification_config WHERE id=1");
  for(const auto* field:{"url","bearer","signing"}) {
    auto encrypted=value.at(field).get<std::string>();
    value[field]=encrypted.empty()?"":unseal(unbase64(encrypted,16384),secret_key_,std::string("xcli:webhook:")+field+":v1");
  }
  return value;
}
Json Backend::notification_status(const std::string& token) {
  session(token);std::lock_guard guard(mutation_mutex_);auto database=db();auto cfg=webhook_configuration(database);
  auto url=cfg.at("url").get<std::string>();
  return {{"enabled",cfg.at("enabled").get<Int>()!=0},{"configured",!url.empty()},{"destination",url.empty()?"":validate_webhook_url(url)},
    {"has_bearer",!cfg.at("bearer").get<std::string>().empty()},{"has_signing_secret",!cfg.at("signing").get<std::string>().empty()},
    {"failures",cfg.at("failures")},{"recoveries",cfg.at("recoveries")},
    {"alarms",database.all("SELECT service,firing,since,bad,good,last_seen FROM alarm_state WHERE firing=1 ORDER BY since")},
    {"deliveries",database.all("SELECT id,created,service,kind,status,attempts,next_attempt,delivered,last_error,http_status FROM notifications ORDER BY created DESC,rowid DESC LIMIT 50")}};
}
void Backend::configure_notifications(const std::string& token,const std::string& csrf,const Json& input) {
  std::lock_guard guard(mutation_mutex_);session(token,csrf,true);
  static const std::set<std::string> fields={"enabled","url","bearer","signing_secret","clear_auth","clear_url","failures","recoveries","current_password","code"};
  if(!input.is_object())throw HttpError(422,"请求必须是 JSON 对象");
  for(auto it=input.begin();it!=input.end();++it)if(!fields.contains(it.key()))throw HttpError(422,"包含不支持的通知字段");
  auto database=db();auto cfg=webhook_configuration(database);
  auto enabled=boolean(input,"enabled",cfg.at("enabled").get<Int>()!=0);
  auto url=secret_input(input,"url",4096),bearer=secret_input(input,"bearer",2048),signing=secret_input(input,"signing_secret",256);
  if(!url.empty()){(void)validate_webhook_url(url);cfg["url"]=url;}
  if(boolean(input,"clear_auth")){cfg["bearer"]="";cfg["signing"]="";}
  if(!bearer.empty())cfg["bearer"]=bearer;
  if(!signing.empty()){if(signing.size()<16)throw HttpError(422,"签名密钥至少 16 个字符");cfg["signing"]=signing;}
  if(boolean(input,"clear_url")){cfg["url"]="";cfg["bearer"]="";cfg["signing"]="";enabled=false;}
  if(enabled&&cfg.at("url").get<std::string>().empty())throw HttpError(422,"请先填写 Webhook 地址");
  Int failures=numeric(input,"failures",cfg.at("failures"),1,10),recoveries=numeric(input,"recoveries",cfg.at("recoveries"),1,10);
  Transaction transaction(database);confirm_admin(database,token,input);
  for(const auto* field:{"url","bearer","signing"}) {auto value=cfg.at(field).get<std::string>();cfg[field]=value.empty()?"":base64(seal(value,secret_key_,std::string("xcli:webhook:")+field+":v1"));}
  database.run("UPDATE notification_config SET enabled=?,url=?,bearer=?,signing=?,generation=?,failures=?,recoveries=? WHERE id=1",
    {Int(enabled),cfg.at("url").get<std::string>(),cfg.at("bearer").get<std::string>(),cfg.at("signing").get<std::string>(),random_id(),failures,recoveries});
  // Configuration changes invalidate queued work for the previous destination; an in-flight request may finish.
  database.run("UPDATE notifications SET status='cancelled',last_error='通知配置已变更' WHERE status='pending'");
  if(enabled)for(const auto& alarm:database.all("SELECT service,since FROM alarm_state WHERE firing=1"))queue_notification(database,alarm.at("service"),"fault",now(),alarm.at("since"));
  audit(database,"notifications_configured",enabled?"已启用 Webhook 通知":"已关闭 Webhook 通知");transaction.commit();
}
std::string Backend::queue_notification(Database& database,const std::string& service,const std::string& kind,Int timestamp,Int started) {
  auto config=*database.one("SELECT enabled,url,generation FROM notification_config WHERE id=1");
  if(config.at("url")==""||(kind!="test"&&!config.at("enabled").get<Int>()))return {};
  auto id=random_id();auto label=service_names.at(service);
  std::string title=kind=="test"?"xcli 测试通知":label+(kind=="fault"?"持续异常":"已恢复");
  std::string message=kind=="test"?"通知通道测试，不代表节点发生故障。":
    kind=="recovery"?"已达到连续恢复阈值。":service=="probe"?"探测结果缺失或已过期，当前无法判断节点可用性。":
    service=="backup"?"自动备份失败或未在预期时间完成，请查看面板备份状态。":
    service=="core"?"管理接口持续不可用，请检查核心和统计服务。":"公网入口探测连续失败，请检查面板中的 HTTPS 和 UDP DNS 自检结果。";
  Json payload={{"schema",1},{"id",id},{"site",settings_.at("domain")},{"event",kind},{"service",service},
    {"title",title},{"message",message},{"time",timestamp},{"started",started},{"duration_seconds",std::max(Int(0),timestamp-started)}};
  if(kind!="test")database.run("UPDATE notifications SET status='superseded',last_error='已有更新的故障状态' WHERE service=? AND status='pending'",{service});
  database.run("INSERT INTO notifications(id,created,service,kind,payload,generation,next_attempt) VALUES(?,?,?,?,?,?,?)",
    {id,timestamp,service,kind,payload.dump(),config.at("generation").get<std::string>(),timestamp});return id;
}
Json Backend::test_notification(const std::string& token,const std::string& csrf) {
  std::lock_guard guard(mutation_mutex_);session(token,csrf,true);auto database=db();Transaction transaction(database);
  if(database.one("SELECT url FROM notification_config WHERE id=1")->at("url")=="")throw HttpError(409,"请先保存 Webhook 地址");
  if(database.one("SELECT id FROM notifications WHERE kind='test' AND created>?",{now()-30}))throw HttpError(429,"请等待 30 秒后再发送测试");
  auto id=queue_notification(database,"test","test",now(),now());audit(database,"notification_test","测试通知已排队");transaction.commit();worker_cv_.notify_all();return {{"id",id},{"status","pending"}};
}
void Backend::observe_alarm(Database& database,const std::string& service,bool failed,Int sample,Int timestamp,int failure_threshold,int recovery_threshold) {
  database.run("INSERT OR IGNORE INTO alarm_state(service) VALUES(?)",{service});auto row=*database.one("SELECT * FROM alarm_state WHERE service=?",{service});
  if(sample<=row.at("last_sample").get<Int>())return;
  Int bad=failed?row.at("bad").get<Int>()+1:0,good=failed?0:row.at("good").get<Int>()+1;
  // A gap in observations breaks consecutiveness; a currently firing alarm remains open until recovery is observed.
  if(timestamp-row.at("last_seen").get<Int>()>180){bad=failed?1:0;good=failed?0:1;}
  auto since=row.at("since").get<Int>();bool firing=row.at("firing").get<Int>()!=0;
  if(failed&&bad==1&&!firing)since=timestamp;
  if(failed&&!firing&&bad>=failure_threshold){firing=true;queue_notification(database,service,"fault",timestamp,since);audit(database,"fault_detected",service_names.at(service));}
  if(!failed&&firing&&good>=recovery_threshold){firing=false;queue_notification(database,service,"recovery",timestamp,since);audit(database,"fault_recovered",service_names.at(service));since=0;}
  if(!failed&&!firing)since=0;
  database.run("UPDATE alarm_state SET bad=?,good=?,firing=?,since=?,last_sample=?,last_seen=? WHERE service=?",
    {std::min(bad,Int(100)),std::min(good,Int(100)),Int(firing),since,sample,timestamp,service});
}
void Backend::collect_operations(Int timestamp) {
  auto monitor=monitor_status(timestamp);auto core=health();
  std::lock_guard guard(mutation_mutex_);auto database=db();Transaction transaction(database);
  auto cfg=*database.one("SELECT failures,recoveries FROM notification_config WHERE id=1");int failures=cfg.at("failures"),recoveries=cfg.at("recoveries");
  auto status=monitor.value("status",std::string("unknown"));bool fresh=status=="healthy"||status=="failed";
  auto enabled=inbound_tags();
  Json checks=Json::object();
  if(fresh)for(const auto& check:monitor.value("checks",Json::array())) {
    auto transport=check.value("transport",std::string());auto state=check.value("status",std::string());
    if(std::find(enabled.begin(),enabled.end(),transport)!=enabled.end()&&(state=="healthy"||state=="failed"))checks[transport]=check;
  }
  bool complete=fresh&&checks.size()==enabled.size();
  // Sensor health uses minute ticks. Node health uses distinct probe timestamps, never repeated reads of one report.
  observe_alarm(database,"probe",!complete,timestamp/60,timestamp,failures,recoveries);
  for(const auto& transport:enabled) {
    bool known=fresh&&checks.contains(transport);Int sampled=known?monitor.at("updated").get<Int>():timestamp/60*60;
    std::string state=known?checks[transport].at("status").get<std::string>():"unknown";
    Value https=known?latency(checks[transport],"https_ms"):Value(std::string());
    Value udp=known?latency(checks[transport],"udp_ms"):Value(std::string());
    database.run("INSERT OR IGNORE INTO probe_history VALUES(?,?,?,CAST(NULLIF(?,'') AS REAL),CAST(NULLIF(?,'') AS REAL))",{sampled,transport,state,https,udp});
    if(known)observe_alarm(database,transport,state!="healthy",sampled,timestamp,failures,recoveries);
    else database.run("UPDATE alarm_state SET bad=0,good=0 WHERE service=?",{transport});
  }
  if(!options_.offline)observe_alarm(database,"core",!core.value("core",false),timestamp/60,timestamp,failures,recoveries);
  if(options_.automatic_backups) {
    auto error=database.one("SELECT value FROM metadata WHERE key='backup_error'");auto previous=database.one("SELECT value FROM metadata WHERE key='last_backup'");
    Int last=previous?std::stoll(previous->at("value").get<std::string>()):operations_started_;
    bool failed=(error&&error->at("value")!="")||timestamp-last>options_.backup_interval+900;
    observe_alarm(database,"backup",failed,timestamp/60,timestamp,1,1);
  }
  auto pruned=database.one("SELECT value FROM metadata WHERE key='operations_pruned'");
  if(!pruned||timestamp-std::stoll(pruned->at("value").get<std::string>())>=3600) {
    database.run("DELETE FROM traffic_history WHERE ts<?",{timestamp-retention});database.run("DELETE FROM probe_history WHERE ts<?",{timestamp-retention});
    database.run("DELETE FROM notifications WHERE status<>'pending' AND (created<? OR rowid NOT IN (SELECT rowid FROM notifications ORDER BY created DESC,rowid DESC LIMIT 1000))",{timestamp-retention});
    database.run("INSERT OR REPLACE INTO metadata VALUES('operations_pruned',?)",{std::to_string(timestamp)});
  }
  transaction.commit();
}
void Backend::deliver_notifications(Int timestamp) {
  Json item,cfg;
  {
    std::lock_guard guard(mutation_mutex_);auto database=db();cfg=webhook_configuration(database);
    auto pending=database.one("SELECT * FROM notifications WHERE status='pending' AND generation=? AND next_attempt<=? AND (?=1 OR kind='test') ORDER BY created,rowid LIMIT 1",
      {cfg.at("generation").get<std::string>(),timestamp,cfg.at("enabled").get<Int>()});
    if(!pending)return;
    item=*pending;
  }
  WebhookResult result;
  try {result=webhook_sender_(cfg,Json::parse(item.at("payload").get<std::string>()));}
  catch(...) {result={0,"通知投递失败"};}
  bool success=result.error.empty()&&result.status>=200&&result.status<300;Int attempts=item.at("attempts").get<Int>()+1;
  static constexpr Int delay[]={30,120,600,1800,3600};
  std::string status=success?"delivered":attempts>=6?"failed":"pending";
  std::lock_guard guard(mutation_mutex_);auto database=db();
  database.run("UPDATE notifications SET status=?,attempts=?,next_attempt=?,delivered=?,last_error=?,http_status=? WHERE id=? AND generation=? AND status='pending'",
    {status,attempts,success||attempts>=6?Int(0):timestamp+delay[attempts-1],success?timestamp:Int(0),success?"":result.error,Int(result.status),item.at("id").get<std::string>(),cfg.at("generation").get<std::string>()});
}
}
