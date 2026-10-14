#include "gateway.hpp"
#include <algorithm>
#include <fstream>
#include <iostream>
#include <limits>
#include <sys/stat.h>
#include <unistd.h>

using namespace xg;
namespace {
void check(bool condition,const char* message) {if(!condition)throw std::runtime_error(message);}
template<class F> void status(int expected,F operation) {
  try {operation();throw std::runtime_error("Expected HTTP failure");}
  catch(const HttpError& error){check(error.status==expected,"Wrong HTTP status");}
}
class FakeCore final : public Core {
 public:
  std::string gen="42:12345";
  std::vector<Counter> values;
  std::map<std::string,std::map<std::string,std::string>> live;
  int restarts=0;
  bool fail_add=false,fail_query=false;
  std::string generation() override{return gen;}
  std::vector<Counter> counters() override{if(fail_query)throw std::runtime_error("unavailable");return values;}
  std::map<std::string,std::string> users(const std::string& tag) override{return live[tag];}
  void add_user(const std::string& tag,const User& user) override{if(fail_add)throw std::runtime_error("unavailable");live[tag][user.email(tag)]=user.uuid;}
  void restart(const std::string& expected) override{check(expected==gen,"Generation mismatch");++restarts;gen="43:12346";live.clear();values.clear();}
};
struct Temp {
  fs::path path;
  Temp(){char value[]="/tmp/xg-cpp-unit-XXXXXX";auto p=::mkdtemp(value);if(!p)throw std::runtime_error("mkdtemp failed");path=p;}
  ~Temp(){fs::remove_all(path);}
};
std::size_t fds(){return static_cast<std::size_t>(std::distance(fs::directory_iterator("/proc/self/fd"),fs::directory_iterator{}));}
}
int main() {
  try {
    Temp temp;Options opts;opts.state=temp.path/"state";opts.settings=temp.path/"settings.json";opts.offline=true;opts.backup_retention=2;
    Json settings={{"origin","https://testserver"},{"domain","testserver"},{"public_ip","203.0.113.2"},{"reality_sni","example.com"},{"reality_public",std::string(43,'p')},{"short_id","aabbccdd"},{"ws_path","/connect/test"}};
    std::ofstream(opts.settings)<<settings.dump();
    auto fake=std::make_unique<FakeCore>();auto core=fake.get();Backend backend(opts,std::move(fake));
    {Database db(opts.state/"gateway.sqlite");db.run("INSERT INTO admin VALUES(1,?)",{password_hash("correct-password-for-tests")});}
    check(sha256("abc")=="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","SHA256 mismatch");
    const std::string vector_secret="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    for(const auto& [timestamp,expected]:std::vector<std::pair<Int,std::string>>{{59,"94287082"},{1111111109,"07081804"},{1111111111,"14050471"},{1234567890,"89005924"},{2000000000,"69279037"},{20000000000LL,"65353130"}})
      check(totp_code(vector_secret,timestamp,8)==expected,"RFC 6238 test vector");
    auto key=load_secret_key(opts.state/"security.key"),sealed=seal("private payload",key,"test");
    check(unseal(sealed,key,"test")=="private payload","AEAD roundtrip");
    bool rejected=false;try{unseal(sealed,key,"wrong-context");}catch(...){rejected=true;}check(rejected,"AEAD context accepted");
    check(unbase64(base64(std::string("a\0b",3)))==std::string("a\0b",3),"Binary base64 roundtrip");
    auto encoded=password_hash("密码 password");check(password_check("密码 password",encoded),"Password round trip");check(!password_check("wrong",encoded),"Wrong password accepted");
    check(!password_check("x","invalid"),"Invalid stored hash accepted");
    check(random_token().size()==43&&random_uuid().size()==36&&random_id().size()==32,"Random token formats");
    check(user_name("　测试用户　")=="测试用户","Unicode whitespace");status(422,[]{user_name(" \n\t");});
    check(url_quote("名 / +",true)=="%E5%90%8D+%2F+%2B","URL query encoding");
    std::string token;auto logged=backend.login({{"username","admin"},{"password","correct-password-for-tests"}},"127.0.0.1",token);auto csrf=logged["csrf"].get<std::string>();
    status(401,[&]{backend.session("bad");});status(403,[&]{backend.create_user(token,"bad",{{"name","test"}});});
    {
      status(401,[&]{backend.proxy_import_status("bad");});
      status(403,[&]{backend.request_proxy_import(token,"bad",{{"action","preview"}});});
      const auto import_state=opts.state.parent_path()/"xray-gateway-import";fs::create_directories(import_state);
      auto report=[&](const Json& value){write_private_file(import_state/"report.json",value.dump(),true);};
      report({{"id",""},{"updated",now()},{"status","idle"},{"rows",Json::array({{{"address","1.1.1.1"},{"password","must-not-leak"}}})}});
      check(backend.proxy_import_status(token).dump().find("must-not-leak")==std::string::npos,"Import status leaked credentials");
      Json input={{"action","preview"},{"protocol","socks"},{"label","IPRoyal ISP"},{"text","1.1.1.1:12324:fixture:secret-password"}};
      for(const auto& bad:std::vector<std::string>{"127.0.0.1:1080:u:p","169.254.169.254:80:u:p","1.1.1.1:70000:u:p","1.1.1.1:80:u:p\n1.1.1.1:80:u:p"}) {
        auto invalid=input;invalid["text"]=bad;status(422,[&]{backend.request_proxy_import(token,csrf,invalid);});
      }
      write_private_file(import_state/"catalog.json",Json({{"items",Json::array({{{"tag","residential-27"},{"password","must-not-leak"},{"username","must-not-leak"},{"enabled",true}}})}}).dump(),true);
      check(backend.proxy_import_status(token).dump().find("must-not-leak")==std::string::npos,"Catalog leaked credentials");
      status(422,[&]{backend.request_proxy_import(token,csrf,{{"action","manage"},{"operation","delete"},{"tag","reality"}});});
      status(422,[&]{backend.request_proxy_import(token,csrf,{{"action","manage"},{"operation","erase"},{"tag","residential-27"}});});
      Json edit={{"action","manage"},{"operation","edit"},{"tag","residential-27"},{"changes",{{"label","Edited"},{"address","127.0.0.1"},{"port",12324},{"protocol","socks"}}}};
      status(422,[&]{backend.request_proxy_import(token,csrf,edit);});
      edit["changes"]["address"]="1.1.1.1";edit["changes"]["password"]="edited-secret";
      auto management=backend.request_proxy_import(token,csrf,edit);
      auto sealed_edit=read_file(opts.state/"proxy-import/request.xgb");
      check(sealed_edit.find("edited-secret")==std::string::npos,"Edit credentials not sealed");
      check(Json::parse(unseal(sealed_edit,key,"xcli:proxy-import:request:v1"))["changes"]["password"]=="edited-secret","Edit not queued");
      report({{"id",management["id"]},{"updated",now()},{"status","complete"}});
      auto share="vmess://"+base64(Json({{"v","2"},{"id","11111111-1111-4111-8111-111111111111"},{"add","1.1.1.1"},{"port","443"}}).dump());
      auto vmrequest=backend.request_proxy_import(token,csrf,{{"action","preview"},{"protocol","vmess"},{"label","VMess"},{"text",share}});
      auto vmsealed=read_file(opts.state/"proxy-import/request.xgb");check(vmsealed.find(share)==std::string::npos,"VMess link stored plaintext");
      check(Json::parse(unseal(vmsealed,key,"xcli:proxy-import:request:v1"))["links"]==share,"VMess link not queued");
      report({{"id",vmrequest["id"]},{"updated",now()},{"status","complete"}});
      auto queued=backend.request_proxy_import(token,csrf,input);auto job=queued["id"].get<std::string>();
      auto ciphertext=read_file(opts.state/"proxy-import/request.xgb");check(ciphertext.find("secret-password")==std::string::npos,"Import queue stored plaintext password");
      auto decoded=Json::parse(unseal(ciphertext,key,"xcli:proxy-import:request:v1"));check(decoded["proxies"][0]["port"]==12324,"Import parser port");
      status(409,[&]{backend.request_proxy_import(token,csrf,input);});
      report({{"id",job},{"updated",now()},{"status","ready"},{"expires",now()+900}});
      status(409,[&]{backend.request_proxy_import(token,csrf,{{"action","apply"},{"preview_id",std::string(32,'a')}});});
      auto applied=backend.request_proxy_import(token,csrf,{{"action","apply"},{"preview_id",job}});
      report({{"id",applied["id"]},{"updated",now()},{"status","applying"}});
      status(409,[&]{backend.request_proxy_import(token,csrf,input);});
      report({{"id",applied["id"]},{"updated",now()-60},{"status","complete"}});
      status(503,[&]{backend.request_proxy_import(token,csrf,input);});
    }
    auto id=backend.create_user(token,csrf,{{"name","测试 / A"}})["id"].get<std::string>();
    User user;{Database db(opts.state/"gateway.sqlite");user=User::from(*db.one("SELECT * FROM users WHERE id=?",{id}));}
    auto links=backend.links(token,id);check(links["subscription"]=="https://testserver/s/"+user.token,"Subscription address");
    auto [body,info]=backend.subscription(user.token);check(body==base64(links["reality"].get<std::string>()+"\n"+links["websocket"].get<std::string>()+"\n"),"Subscription content");
    check(backend.qr(token,id,"reality").substr(0,8)==std::string("\x89PNG\r\n\x1a\n",8),"QR PNG");
    backend.poll_once();check(core->live["reality"].contains(user.email("reality")),"RPC user add");check(core->restarts==0,"Initial reconcile restarted core");
    const auto name="user>>>"+user.email("reality")+">>>traffic>>>uplink";
    core->values={{name,100}};backend.poll_once();backend.poll_once();core->values={{name,180}};backend.poll_once();
    {Database db(opts.state/"gateway.sqlite");auto activity=backend.activity_status(db);check(activity[id]["reality"]["last_seen"].get<Int>()>0,"Activity last seen missing");check(activity[id]["reality"]["upload_delta"]==80,"Activity delta invalid");}
    core->gen="42:98765";core->values={{name,250}};backend.poll_once();
    {Database db(opts.state/"gateway.sqlite");check(db.one("SELECT upload FROM users WHERE id=?",{id})->at("upload")==430,"Counter deduplication/generation");}
    backend.reset_traffic(token,csrf,id);backend.poll_once();
    {Database db(opts.state/"gateway.sqlite");check(db.one("SELECT upload FROM users WHERE id=?",{id})->at("upload")==0,"Reset re-counted traffic");}
    core->values={{name,280}};backend.poll_once();
    {Database db(opts.state/"gateway.sqlite");check(db.one("SELECT upload FROM users WHERE id=?",{id})->at("upload")==30,"Post-reset delta");}
    backend.update_user(token,csrf,id,{{"name","test"},{"quota",30}});backend.poll_once();check(core->restarts==1,"Quota did not revoke live connection");status(403,[&]{backend.subscription(user.token);});
    backend.update_user(token,csrf,id,{{"name","test"}});backend.poll_once();
    backend.rotate_user(token,csrf,id);status(404,[&]{backend.subscription(user.token);});backend.poll_once();check(core->restarts==2,"Rotation did not revoke live connection");backend.poll_once();
    auto second=backend.create_user(token,csrf,{{"name","second"}})["id"].get<std::string>();
    core->fail_add=true;try{backend.poll_once();}catch(const std::exception&){}core->fail_add=false;backend.poll_once();
    check(core->live["reality"].size()==2,"Failed add did not recover");
    backend.delete_user(token,csrf,second);backend.poll_once();check(core->restarts==3,"Delete did not revoke live connection");
    status(404,[&]{backend.links(token,second);});
    {Database db(opts.state/"gateway.sqlite");try{Transaction tx(db);db.run("INSERT INTO metadata VALUES('rollback','x')");throw 1;}catch(int){}check(!db.one("SELECT * FROM metadata WHERE key='rollback'"),"Transaction rollback");db.backup(temp.path/"backup.sqlite");}
    {Database copy(temp.path/"backup.sqlite");check(copy.one("PRAGMA quick_check")->begin().value()=="ok","Backup integrity");}
    backend.create_backup(token,csrf);backend.create_backup(token,csrf);backend.create_backup(token,csrf);
    check(backend.backup_status(token)["backups"].size()==2,"Backup retention failed");
    {Database db(opts.state/"gateway.sqlite");db.run("UPDATE metadata SET value='0' WHERE key='last_backup'");}
    backend.scheduled_backup();check(backend.backup_status(token)["backups"][0]["reason"]=="automatic","Due automatic backup failed");
    auto before=fds();for(int i=0;i<2000;++i){Database db(opts.state/"gateway.sqlite");db.one("SELECT 1");}check(fds()<=before+1,"Database descriptor leak");
    for(int i=0;i<8;++i)status(401,[&]{std::string ignored;backend.login({{"username","admin"},{"password","wrong"}},"192.0.2.1",ignored);});
    status(429,[&]{std::string ignored;backend.login({{"username","admin"},{"password","correct-password-for-tests"}},"192.0.2.1",ignored);});
    backend.change_password(token,csrf,{{"current_password","correct-password-for-tests"},{"new_password","replacement-password"}});status(401,[&]{backend.session(token);});
    {
      Temp hy2;Options config;config.state=hy2.path/"state";config.settings=hy2.path/"settings.json";config.offline=true;
      settings["hysteria2_port"]=443;std::ofstream(config.settings)<<settings.dump();
      auto adapter=std::make_unique<FakeCore>();auto live=adapter.get();Backend panel(config,std::move(adapter));
      {Database db(config.state/"gateway.sqlite");db.run("INSERT INTO admin VALUES(1,?)",{password_hash("correct-password-for-tests")});}
      std::string session;auto auth=panel.login({{"username","admin"},{"password","correct-password-for-tests"}},"127.0.0.1",session);
      auto guard=auth.at("csrf").get<std::string>();auto id3=panel.create_user(session,guard,{{"name","Hy2 测试"},{"quota",1000}}).at("id").get<std::string>();
      User u;{Database db(config.state/"gateway.sqlite");u=User::from(*db.one("SELECT * FROM users WHERE id=?",{id3}));}
      auto node=panel.links(session,id3);check(node.at("hysteria2").get<std::string>().starts_with("hysteria2://"+u.uuid+"@testserver:443/?sni=testserver#"),"Hy2 link invalid");
      auto data=unbase64(panel.subscription(u.token).first);check(data.find(node.at("hysteria2").get<std::string>()+"\n")!=std::string::npos,"Hy2 missing from subscription");
      check(panel.qr(session,id3,"hysteria2").starts_with("\x89PNG"),"Hy2 QR missing");
      panel.poll_once();check(live->live.size()==3&&live->live["hysteria2"].at(u.email("hysteria2"))==u.uuid,"Hy2 account missing");
      check(panel.preflight().at("pending_additions")==0,"Hy2 preflight pending");
      live->values={{"user>>>"+u.email("reality")+">>>traffic>>>downlink",350},{"user>>>"+u.email("hysteria2")+">>>traffic>>>downlink",650}};
      panel.poll_once();check(live->restarts==1,"Shared VLESS / Hy2 quota did not revoke");
      {Database db(config.state/"gateway.sqlite");check(db.one("SELECT download FROM users WHERE id=?",{id3})->at("download")==1000,"Hy2 accounting missing");}
      status(403,[&]{panel.subscription(u.token);});
      config.monitor_report=hy2.path/"report.json";
      std::ofstream(config.monitor_report)<<Json({{"schema",1},{"scope","server"},{"updated",now()},{"status","healthy"},
        {"checks",Json::array({Json{{"transport","reality"},{"status","healthy"}},Json{{"transport","websocket"},{"status","healthy"}}})}}).dump();
      Backend missing(config);check(missing.monitor_status().at("status")=="unknown","Missing Hy2 probe claimed healthy");
    }
    {
      Temp vmess;Options config;config.state=vmess.path/"state";config.settings=vmess.path/"settings.json";config.offline=true;
      auto vm_settings=settings;vm_settings["vmess_ws_path"]="/connect/test/vmess";vm_settings["vmess_port"]=10081;
      std::ofstream(config.settings)<<vm_settings.dump();auto adapter=std::make_unique<FakeCore>();auto live=adapter.get();Backend panel(config,std::move(adapter));
      {Database db(config.state/"gateway.sqlite");db.run("INSERT INTO admin VALUES(1,?)",{password_hash("correct-password-for-tests")});}
      std::string session;auto auth=panel.login({{"username","admin"},{"password","correct-password-for-tests"}},"127.0.0.1",session);
      auto guard=auth.at("csrf").get<std::string>();auto uid=panel.create_user(session,guard,{{"name","VMess 测试"},{"quota",1000}}).at("id").get<std::string>();
      User u;{Database db(config.state/"gateway.sqlite");u=User::from(*db.one("SELECT * FROM users WHERE id=?",{uid}));}
      auto link=panel.links(session,uid).at("vmess").get<std::string>();check(link.starts_with("vmess://"),"VMess link missing");
      auto decoded=Json::parse(unbase64(link.substr(8)));check(decoded["id"]==u.uuid&&decoded["net"]=="ws"&&decoded["tls"]=="tls"&&decoded["aid"]=="0","VMess share settings wrong");
      check(unbase64(panel.subscription(u.token).first).find(link)!=std::string::npos,"VMess subscription missing");
      auto clash=panel.clash_configuration(u);check(clash["proxies"].back()["type"]=="vmess"&&clash["proxies"].back()["alterId"]==0,"VMess Clash export wrong");
      check(panel.qr(session,uid,"vmess").starts_with("\x89PNG"),"VMess QR missing");panel.poll_once();
      check(live->live["vmess"].at(u.email("vmess"))==u.uuid,"VMess account not synchronized");
      live->values={{"user>>>"+u.email("vmess")+">>>traffic>>>downlink",1000}};panel.poll_once();
      check(live->restarts==1,"VMess quota did not revoke");status(403,[&]{panel.subscription(u.token);});
    }
    {
      Temp residence;Options config;config.state=residence.path/"state";config.settings=residence.path/"settings.json";config.offline=true;
      settings["residential_exits"]=Json::array();
      for(int i=1;i<=10;++i) {
        const std::string tag="residential-"+(i<10?std::string("0"):std::string())+std::to_string(i);
        settings["residential_exits"].push_back({{"tag",tag},{"label","住宅 "+std::to_string(i)},{"exit_ip","8.8.4.4"},{"country","US"},{"ws_path","/connect/test/"+tag},{"port",10100+i}});
      }
      std::ofstream(config.settings)<<settings.dump();auto adapter=std::make_unique<FakeCore>();auto live=adapter.get();Backend panel(config,std::move(adapter));
      {Database db(config.state/"gateway.sqlite");db.run("INSERT INTO admin VALUES(1,?)",{password_hash("correct-password-for-tests")});}
      std::string session;auto auth=panel.login({{"username","admin"},{"password","correct-password-for-tests"}},"127.0.0.1",session);
      auto guard=auth.at("csrf").get<std::string>();auto uid=panel.create_user(session,guard,{{"name","住宅测试"},{"quota",1000}}).at("id").get<std::string>();
      User u;{Database db(config.state/"gateway.sqlite");u=User::from(*db.one("SELECT * FROM users WHERE id=?",{uid}));}
      const auto links=panel.links(session,uid);const auto subscription=unbase64(panel.subscription(u.token).first);
      check(std::count(subscription.begin(),subscription.end(),'\n')==13,"Residential subscription must contain thirteen nodes");
      for(const auto& tag:panel.inbound_tags())check(subscription.find(links.at(tag).get<std::string>()+"\n")!=std::string::npos,"Residential subscription omitted an entry");
      const auto clash=panel.clash_configuration(u);
      check(clash.at("proxy-groups")[0].at("proxies")[0]=="HTTPS","Clash default should use HTTPS");
      check(clash.at("proxies")[0].at("reality-opts").at("support-x25519mlkem768")==true,"Missing modern REALITY handshake support");
      check(clash.at("proxies").size()==13,"Clash export omitted nodes");
      check(clash.at("proxies")[0].at("reality-opts").at("public-key")==settings.at("reality_public"),"Wrong REALITY key");
      check(clash.at("proxies")[2].at("type")=="hysteria2","Missing Hysteria 2");
      for(int i=3;i<13;++i)check(clash.at("proxies")[i].at("udp")==false,"Residential UDP enabled");
      for(const auto& proxy:clash.at("proxies")) {
        const auto& choices=clash.at("proxy-groups")[0].at("proxies");
        check(std::find(choices.begin(),choices.end(),proxy.at("name"))!=choices.end(),"Clash group omitted a node");
      }
      panel.poll_once();check(live->live.size()==13,"Not every residential inbound was reconciled");
      for(const auto& tag:panel.inbound_tags())check(live->live.at(tag).at(u.email(tag))==u.uuid,"Residential identity differs from its owner");
      check(panel.preflight().at("pending_additions")==0,"Residential preflight incomplete");
      panel.rotate_user(session,guard,uid);panel.poll_once();check(live->restarts==1,"Rotation did not revoke residential connections");status(404,[&]{panel.subscription(u.token);});panel.poll_once();
      {Database db(config.state/"gateway.sqlite");u=User::from(*db.one("SELECT * FROM users WHERE id=?",{uid}));}
      live->values.clear();for(const auto& exit:settings["residential_exits"])live->values.push_back({"user>>>"+u.email(exit.at("tag").get<std::string>())+">>>traffic>>>downlink",100});
      panel.poll_once();check(live->restarts==2,"Shared residential quota did not revoke all accounts");status(403,[&]{panel.subscription(u.token);});
      {Database db(config.state/"gateway.sqlite");check(db.one("SELECT download FROM users WHERE id=?",{uid})->at("download")==1000,"Residential traffic was not charged to its owner");}
      settings["residential_exits"][0]["password"]="fixture-secret";std::ofstream(config.settings)<<settings.dump();
      bool denied=false;try{Backend invalid(config);}catch(const HttpError&){denied=true;}check(denied,"Provider credentials accepted in public exit metadata");
    }
    {
      Temp dynamic;Options config;config.state=dynamic.path/"state";config.settings=dynamic.path/"settings.json";config.offline=true;
      settings["residential_exits"]=Json::array();
      for(const auto& region:webshare_regions){
        const std::string tag(region.tag),country(region.country);
        settings["residential_exits"].push_back({{"tag",tag},{"label",std::string("动态住宅 · ")+std::string(region.label)},{"exit_ip",""},{"country",country},{"ws_path","/connect/test/"+tag},{"port",region.port},{"dynamic",true}});
      }
      std::ofstream(config.settings)<<settings.dump();Backend panel(config,std::make_unique<FakeCore>());
      {Database db(config.state/"gateway.sqlite");db.run("INSERT INTO admin VALUES(1,?)",{password_hash("correct-password-for-tests")});}
      std::string session;auto auth=panel.login({{"username","admin"},{"password","correct-password-for-tests"}},"127.0.0.1",session);auto csrf=auth.at("csrf").get<std::string>();
      auto uid=panel.create_user(session,csrf,{{"name","Clash 测试: \\\""}}).at("id").get<std::string>();User u;
      {Database db(config.state/"gateway.sqlite");u=User::from(*db.one("SELECT * FROM users WHERE id=?",{uid}));}
      check(panel.clash_configuration(u).at("proxies").size()==3,"Disabled dynamic entries leaked into Clash subscription");
      status(401,[&]{panel.webshare_status("bad");});status(403,[&]{panel.configure_webshare(session,"bad",{{"enabled",false}});});
      status(422,[&]{panel.configure_webshare(session,csrf,{{"api_key","bad\nheader"}});});
      panel.configure_webshare(session,csrf,{{"api_key","fixture-api-key-private-value"}});
      const auto encrypted=read_file(config.state/"webshare/config.xgb");check(encrypted.find("fixture-api-key")==std::string::npos,"API key stored in plaintext");
      check(panel.webshare_status(session).dump().find("fixture-api-key")==std::string::npos,"API key returned by status");
      write_private_file(config.state/"webshare/report.json",Json({{"updated",now()},{"plans",Json::array({{{"id",17},{"eligible",true},{"label","住宅"},{"password","must-not-leak"}}})}}).dump());
      check(panel.webshare_status(session).dump().find("must-not-leak")==std::string::npos,"Provider data escaped public allowlist");
      panel.configure_webshare(session,csrf,{{"plan_id",17},{"enabled",true}});
      auto clash=panel.clash_configuration(u);check(clash.at("proxies").size()==19,"Clash must include all sixteen enabled dynamic entries");
      check(clash.at("proxy-groups").size()==17,"Country groups missing from Clash export");
      check(panel.webshare_status(session).at("regions").size()==16,"Installed country registry missing");
      check(clash.at("proxies").at(0).at("reality-opts").at("public-key")==settings.at("reality_public"),"Clash Reality key differs");
      check(clash.at("proxies").at(1).at("ws-opts").at("path")==settings.at("ws_path"),"Clash WebSocket path differs");
      check(clash.at("proxies").at(2).at("password")==u.uuid,"Clash Hysteria authentication differs");
      for(std::size_t index=3;index<19;++index)check(clash.at("proxies").at(index).at("udp")==false,"Residential UDP must remain disabled");
      check(clash.at("dns").at("nameserver").at(0)=="https://1.1.1.1/dns-query#PROXY","Clash DNS did not follow selected proxy");
      auto [yaml,info]=panel.clash_subscription(u.token);check(yaml.find("fixture-api-key")==std::string::npos&&yaml.find("type\":\"vless")!=std::string::npos,"Invalid Clash export");
      panel.configure_webshare(session,csrf,{{"clear_key",true}});check(!panel.dynamic_residential_enabled(),"Clearing key left dynamic pool enabled");
      panel.update_user(session,csrf,uid,{{"name","disabled"},{"enabled",false}});status(403,[&]{panel.clash_subscription(u.token);});
      panel.rotate_user(session,csrf,uid);status(404,[&]{panel.clash_subscription(u.token);});
    }
    std::cout<<"PASS: backend, authentication, subscriptions, accounting, backups, Webshare encryption and redaction, Clash export, dynamic entries and revocation\n";
    return 0;
  }catch(const std::exception& error){std::cerr<<"FAIL: "<<error.what()<<'\n';return 1;}
}
