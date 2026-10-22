#include "gateway.hpp"
#include <fstream>
#include <iostream>
#include <unistd.h>

using namespace xg;
namespace {
void check(bool value,const char* message){if(!value)throw std::runtime_error(message);}
template<class F>void status(int expected,F fn){try{fn();throw std::runtime_error("Expected rejection");}catch(const HttpError& e){check(e.status==expected,"Wrong rejection status");}}
struct Temp {fs::path path;Temp(){char p[]="/tmp/xcli-operations-XXXXXX";auto* value=mkdtemp(p);if(!value)throw std::runtime_error("mkdtemp");path=value;}~Temp(){fs::remove_all(path);}};
void report(const fs::path& path,Int stamp,const std::string& state) {
  std::ofstream(path)<<Json({{"schema",1},{"scope","server"},{"updated",stamp},{"status",state},{"checks",Json::array({
    {{"transport","reality"},{"status",state},{"https_ms",state=="healthy"?Json(150):Json(nullptr)},{"udp_ms",state=="healthy"?Json(50):Json(nullptr)}},
    {{"transport","websocket"},{"status","healthy"},{"https_ms",200},{"udp_ms",70}}
  })}}).dump();
}
}
int main(){try{
  Temp temp;Options options;options.offline=true;options.state=temp.path/"state";options.settings=temp.path/"settings.json";options.monitor_report=temp.path/"probe.json";
  std::ofstream(options.settings)<<Json({{"origin","https://testserver"},{"domain","testserver"},{"public_ip","203.0.113.2"},
    {"reality_sni","example.com"},{"reality_public",std::string(43,'p')},{"short_id","aabbccdd"},{"ws_path","/test"}}).dump();
  int calls=0;bool fail_delivery=true;Json received;
  auto sender=[&](const Json& cfg,const Json& payload){++calls;received=payload;check(cfg["bearer"]=="private-bearer","Bearer decryption failed");return fail_delivery?WebhookResult{503,"接收端暂不可用"}:WebhookResult{204,""};};
  auto backend=std::make_unique<Backend>(options,nullptr,sender);
  {Database db(options.state/"gateway.sqlite");db.run("INSERT INTO admin VALUES(1,?)",{password_hash("operations-test-password")});}
  std::string token;auto session=backend->login({{"username","admin"},{"password","operations-test-password"}},"127.0.0.1",token);std::string csrf=session.at("csrf");
  Json config={{"enabled",true},{"url","https://receiver.example.net/hook?private-key=secret-value"},{"bearer","private-bearer"},{"signing_secret","private-signature-key"},{"current_password","operations-test-password"}};
  status(401,[&]{backend->history("","1h");});status(422,[&]{backend->history(token,"unbounded");});
  status(403,[&]{backend->configure_notifications(token,"wrong",config);});
  status(403,[&]{auto c=config;c["current_password"]="wrong";backend->configure_notifications(token,csrf,c);});
  for(const std::string url:{"http://example.com/","file:///etc/passwd","https://127.0.0.1/","https://[::1]/","https://169.254.169.254/","https://user:pass@example.com/","https://example.com/#token","https://localhost/"})
    status(422,[&]{validate_webhook_url(url);});
  for(const std::string address:{"10.0.0.1","127.0.0.1","169.254.169.254","100.64.0.1","192.168.0.1","198.18.0.1","224.0.0.1","::1","::ffff:8.8.8.8","64:ff9b::a00:1","2001:db8::1","2002:a00:1::"})check(!public_webhook_address(address),"Nonpublic address allowed");
  check(public_webhook_address("1.1.1.1")&&public_webhook_address("2606:4700:4700::1111"),"Public address rejected");
  backend->configure_notifications(token,csrf,config);
  auto view=backend->notification_status(token).dump();check(view.find("secret-value")==std::string::npos&&view.find("private-bearer")==std::string::npos&&view.find("private-signature-key")==std::string::npos,"Secrets in API");
  {Database db(options.state/"gateway.sqlite");auto stored=db.one("SELECT url,bearer,signing FROM notification_config")->dump();check(stored.find("secret-value")==std::string::npos&&stored.find("private-bearer")==std::string::npos,"Secrets in database");}
  Int t=now();report(options.monitor_report,t,"failed");backend->collect_operations(t);
  for(int i=1;i<8;++i)backend->collect_operations(t+i);
  check(backend->notification_status(token)["deliveries"].empty(),"Duplicate reads triggered a fault");
  report(options.monitor_report,t+60,"failed");backend->collect_operations(t+60);
  report(options.monitor_report,t+120,"failed");backend->collect_operations(t+120);
  auto deliveries=backend->notification_status(token)["deliveries"];check(deliveries.size()==1&&deliveries[0]["kind"]=="fault","Missing debounced fault");
  backend->deliver_notifications(t+120);check(calls==1,"First delivery missing");backend->deliver_notifications(t+121);check(calls==1,"Retry ignored delay");
  auto id=received.at("id");backend.reset();backend=std::make_unique<Backend>(options,nullptr,sender);
  fail_delivery=false;backend->deliver_notifications(t+151);check(calls==2&&received.at("id")==id,"Restart lost retry or idempotency id");
  check(backend->notification_status(token)["deliveries"][0]["status"]=="delivered","Retry result missing");
  // Missing probes may open a separate sensor alarm, but cannot claim the failed node recovered.
  fs::remove(options.monitor_report);backend->collect_operations(t+180);backend->collect_operations(t+240);
  {Database db(options.state/"gateway.sqlite");check(db.one("SELECT firing FROM alarm_state WHERE service='reality'")->at("firing")==1,"Unknown probe cleared node alarm");}
  report(options.monitor_report,t+300,"healthy");backend->collect_operations(t+300);
  report(options.monitor_report,t+360,"healthy");backend->collect_operations(t+360);
  deliveries=backend->notification_status(token)["deliveries"];check(deliveries.size()==2&&deliveries[0]["kind"]=="recovery","Recovery debounce failed");
  // History retains successful latency even if another check fails; gaps are not fabricated as zero or success.
  auto hist=backend->history(token,"1h");check(hist["retention_days"]==30&&hist["summary"].size()==2,"History query failed");
  {Database db(options.state/"gateway.sqlite");check(db.one("SELECT COUNT(*) AS n FROM probe_history WHERE ts=? AND transport='reality'",{t})->at("n")==1,"Duplicate history sample");
    db.run("INSERT INTO traffic_history VALUES(?,?,?)",{(t-120)/60*60,Int(1000),Int(2000)});
    db.run("INSERT INTO traffic_history VALUES(?,?,?)",{t-31*86400,Int(999),Int(999)});
    db.run("DELETE FROM metadata WHERE key='operations_pruned'");}
  backend->collect_operations(t+361);
  {Database db(options.state/"gateway.sqlite");check(!db.one("SELECT ts FROM traffic_history WHERE ts<?",{t-30*86400}),"History retention failed");}
  auto disabled=config;disabled["enabled"]=false;disabled["url"]="";disabled["bearer"]="";disabled["signing_secret"]="";
  backend->configure_notifications(token,csrf,disabled);backend->deliver_notifications(t+400);check(calls==2,"Disabled configuration sent queued recovery");
  auto test=backend->test_notification(token,csrf);backend->deliver_notifications(t+401);check(calls==3&&received["event"]=="test","Disabled config cannot be tested");
  status(429,[&]{backend->test_notification(token,csrf);});
  auto clear=disabled;clear["clear_url"]=true;backend->configure_notifications(token,csrf,clear);
  check(!backend->notification_status(token)["configured"].get<bool>(),"Clear destination failed");status(409,[&]{backend->test_notification(token,csrf);});
  backend->configure_notifications(token,csrf,config);
  // Backup alarms use one failure/recovery; retries must not generate a new event every minute.
  {Database db(options.state/"gateway.sqlite");db.run("INSERT OR REPLACE INTO metadata VALUES('backup_error','temporary failure')");}
  report(options.monitor_report,t+600,"healthy");backend->collect_operations(t+600);backend->collect_operations(t+660);
  {Database db(options.state/"gateway.sqlite");
    check(db.one("SELECT COUNT(*) AS n FROM notifications WHERE service='backup' AND kind='fault'")->at("n")==1,"Backup error was missed or repeated");
    db.run("DELETE FROM metadata WHERE key='backup_error'");db.run("INSERT OR REPLACE INTO metadata VALUES('last_backup',?)",{std::to_string(t+660)});}
  report(options.monitor_report,t+720,"healthy");backend->collect_operations(t+720);
  {Database db(options.state/"gateway.sqlite");check(db.one("SELECT COUNT(*) AS n FROM notifications WHERE service='backup' AND kind='recovery'")->at("n")==1,"Backup recovery missing");}
  // Three distinct minutes without fresh observations raise a separate sensor alarm.
  fs::remove(options.monitor_report);backend->collect_operations(t+780);backend->collect_operations(t+840);backend->collect_operations(t+900);
  {Database db(options.state/"gateway.sqlite");check(db.one("SELECT firing FROM alarm_state WHERE service='probe'")->at("firing")==1,"Missing sensor alarm");}
  // Six failed attempts exhaust the queue, and subsequent worker passes do not send it again.
  backend->configure_notifications(token,csrf,disabled);
  {Database db(options.state/"gateway.sqlite");db.run("UPDATE notifications SET created=? WHERE kind='test'",{t-60});}
  auto retry=backend->test_notification(token,csrf);fail_delivery=true;int before=calls;
  for(Int elapsed:{1000,1030,1150,1750,3550,7150,20000})backend->deliver_notifications(t+elapsed);
  {Database db(options.state/"gateway.sqlite");auto exhausted=*db.one("SELECT status,attempts FROM notifications WHERE id=?",{retry.at("id").get<std::string>()});
    check(exhausted.at("status")=="failed"&&exhausted.at("attempts")==6&&calls==before+6,"Retry limit failed");}
  {
    Temp exits;auto cfg=options;cfg.state=exits.path/"state";cfg.settings=exits.path/"settings.json";cfg.monitor_report=exits.path/"report.json";
    auto settings=Json::parse(read_file(options.settings));settings["hysteria2_port"]=443;
    settings["residential_exits"]=Json::array({{{"tag","residential-28"},{"label","Fixed fixture"},{"exit_ip","8.8.4.4"},
      {"country","SG"},{"ws_path","/test/residential-28"},{"port",12028},{"hysteria2",true}}});
    const auto& region=webshare_regions.front();
    settings["residential_exits"].push_back({{"tag",region.tag},{"label","Dynamic fixture"},{"exit_ip",""},
      {"country",region.country},{"ws_path",std::string("/test/")+std::string(region.tag)},{"port",region.port},{"dynamic",true}});
    std::ofstream(cfg.settings)<<settings.dump();Backend panel(cfg,nullptr,sender);
    {Database db(cfg.state/"gateway.sqlite");db.run("INSERT INTO admin VALUES(1,?)",{password_hash("operations-test-password")});}
    std::string cookie;auto auth=panel.login({{"username","admin"},{"password","operations-test-password"}},"127.0.0.1",cookie);
    panel.configure_notifications(cookie,auth.at("csrf"),config);
    check(panel.inbound_tags().size()==6&&panel.probe_tags().size()==4,"Probe and credential inventories were conflated");
    Json payload={{"schema",1},{"scope","server"},{"updated",t},{"status","healthy"},{"checks",Json::array()}};
    for(const auto& kind:panel.probe_tags())payload["checks"].push_back({{"transport",kind},{"status","healthy"},{"https_ms",100}});
    std::ofstream(cfg.monitor_report)<<payload.dump();
    check(panel.monitor_status(t).at("status")=="healthy","Dual-protocol fixed exit or dynamic pool required a nonexistent probe");
    panel.collect_operations(t);panel.collect_operations(t+60);panel.collect_operations(t+120);
    {Database db(cfg.state/"gateway.sqlite");
      check(db.one("SELECT firing FROM alarm_state WHERE service='probe'")->at("firing")==0,"Complete fixed-exit probes raised sensor alarm");
      check(!db.one("SELECT transport FROM probe_history WHERE transport LIKE '%-hy2'"),"Credential alias polluted probe history");}
    check(panel.history(cookie,"1h").at("transports")==Json(panel.probe_tags()),"History listed unprobed entries");
    auto missing=payload;missing["checks"].erase(3);std::ofstream(cfg.monitor_report)<<missing.dump();
    check(panel.monitor_status(t).at("status")=="unknown","Missing fixed exit probe claimed healthy");
    payload["status"]="failed";payload["checks"][3]["status"]="failed";
    for(Int elapsed:{180,240,300}){payload["updated"]=t+elapsed;std::ofstream(cfg.monitor_report)<<payload.dump();panel.collect_operations(t+elapsed);}
    check(panel.monitor_status(t+300).at("status")=="failed","Fixed exit failure was hidden");
    {Database db(cfg.state/"gateway.sqlite");
      auto event=db.one("SELECT payload FROM notifications WHERE service='residential-28' AND kind='fault'");
      check(event&&Json::parse(event->at("payload").get<std::string>()).at("title")=="Fixed fixture持续异常","Fixed exit alarm label failed");}
  }
  std::cout<<"PASS: history, distinct probe debounce, missing-data semantics, recovery, encrypted settings, auth, URL and socket address policy, retries across restart, cancellation, idempotency, test throttling, retention, dual-protocol fixed exits\n";
  return 0;
}catch(const std::exception& e){std::cerr<<"FAIL: "<<e.what()<<'\n';return 1;}}
