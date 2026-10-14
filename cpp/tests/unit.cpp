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
      check(clash.at("proxy-groups")[0].at("proxies").size()==13,"Clash group omitted nodes");
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
    std::cout<<"PASS: crypto, Unicode, authentication, CSRF, subscriptions, QR, accounting, reset, RPC reconciliation, quota, rotation, deletion, retry, rollback, backup, residential subscriptions and shared quota, 2000 DB lifetimes, login throttling, session revocation\n";
    return 0;
  }catch(const std::exception& error){std::cerr<<"FAIL: "<<error.what()<<'\n';return 1;}
}
