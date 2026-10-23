#include "gateway.hpp"
#include <fstream>
#include <iostream>
#include <sys/stat.h>
#include <unistd.h>

using namespace xg;
namespace {
void check(bool value,const char* message){if(!value)throw std::runtime_error(message);}
template<class F> void rejected(int status,F fn){try{fn();throw std::runtime_error("Expected rejection");}catch(const HttpError& e){check(e.status==status,"Wrong rejection status");}}
class FakeCore final:public Core {
 public:
  std::map<std::string,std::map<std::string,std::string>> live;
  std::string generation()override{return "test:1";}
  std::vector<Counter> counters()override{return {};}
  std::map<std::string,std::string> users(const std::string& tag)override{return live[tag];}
  void add_user(const std::string& tag,const User& user)override{live[tag][user.email(tag)]=user.uuid;}
  void restart(const std::string&)override{live.clear();}
};
struct Fixture {
  fs::path path;Options options;std::unique_ptr<Backend> backend;std::string cookie,csrf;
  Fixture(){
    char name[]="/tmp/xg-provision-XXXXXX";path=::mkdtemp(name);
    options.state=path/"state";options.settings=path/"settings.json";options.offline=true;
    options.provision_socket=path/"provision.sock";options.provision_uid=1500;
    std::ofstream(options.settings)<<Json({{"origin","https://testserver"},{"domain","testserver"},{"public_ip","203.0.113.2"},
      {"reality_sni","example.com"},{"reality_public",std::string(43,'p')},{"short_id","aabbccdd"},{"ws_path","/connect/test"}}).dump();
    backend=std::make_unique<Backend>(options,std::make_unique<FakeCore>());
    {Database db(options.state/"gateway.sqlite");db.run("INSERT INTO admin VALUES(1,?)",{password_hash("provision-test-password")});}
    csrf=backend->login({{"username","admin"},{"password","provision-test-password"}},"127.0.0.1",cookie).at("csrf");
  }
  ~Fixture(){backend.reset();fs::remove_all(path);}
};
Json request(const std::string& action,const std::string& account){return {{"action",action},{"account_id",account},{"operation_id",random_id()}};}
}
int main(){try{
  Fixture f;auto& backend=*f.backend;
  const auto original_settings=read_file(f.options.settings);
  for(const auto& invalid:{"http://admin.testserver","https://admin.testserver/","https://user:pass@admin.testserver","https://admin.testserver:0","https://admin.testserver:65536","https://bad..example"}) {
    auto settings=Json::parse(original_settings);settings["admin_origin"]=invalid;std::ofstream(f.options.settings)<<settings.dump();
    bool refused=false;try{Backend candidate(f.options);}catch(const std::runtime_error&){refused=true;}
    check(refused,"Malformed admin_origin accepted");
  }
  std::ofstream(f.options.settings)<<original_settings;
  {auto settings=Json::parse(original_settings);settings["admin_origin"]="https://admin.testserver:0443";std::ofstream(f.options.settings)<<settings.dump();
    Backend normalized(f.options);check(normalized.settings().at("admin_origin")=="https://admin.testserver","Default HTTPS port was not normalized");}
  std::ofstream(f.options.settings)<<original_settings;
  auto legacy=backend.create_user(f.cookie,f.csrf,{{"name","Existing user"}}).at("id").get<std::string>();
  auto old_links=backend.links(f.cookie,legacy);
  auto account=random_id();auto reserve=request("reserve",account);auto held=backend.provision(reserve);
  check(backend.provision(reserve)==held,"Reservation replay changed result");
  auto changed=reserve;changed["account_id"]=random_id();rejected(409,[&]{backend.provision(changed);});
  auto grant=request("grant",account);grant["reservation_id"]=held["reservation_id"];grant["version"]=1;grant["term_seconds"]=30*86400;
  auto bad=grant;bad["user_id"]=legacy;rejected(422,[&]{backend.provision(bad);});
  bad=grant;bad["account_id"]=legacy;rejected(409,[&]{backend.provision(bad);});
  bad=grant;bad["term_seconds"]=0;rejected(422,[&]{backend.provision(bad);});
  bad=grant;bad["term_seconds"]=367*86400;rejected(422,[&]{backend.provision(bad);});
  auto first=backend.provision(grant);check(backend.provision(grant)==first,"Grant replay extended expiry");
  check(first["user_id"]!=legacy,"Portal adopted a legacy user");
  check(backend.links(f.cookie,legacy)==old_links,"Legacy credentials or links changed");
  auto backup=backend.create_backup(f.cookie,f.csrf).at("id");
  rejected(409,[&]{backend.restore_backup(f.cookie,f.csrf,{{"id",backup},{"confirm",backup},{"current_password","provision-test-password"}});});
  auto status=request("status",account);check(!backend.provision(status).at("applied").get<bool>(),"Claimed applied before reconcile");
  backend.poll_once();check(backend.provision(status).at("applied").get<bool>(),"Grant not reconciled into core");
  auto next_hold=backend.provision(request("reserve",account));auto renew=request("grant",account);
  renew["reservation_id"]=next_hold["reservation_id"];renew["term_seconds"]=30*86400;renew["version"]=1;
  rejected(409,[&]{backend.provision(renew);});renew["version"]=2;
  auto second=backend.provision(renew);check(second["expires"].get<Int>()==first["expires"].get<Int>()+30*86400,"Renewal duration wrong");
  check(second["links"]==first["links"],"Renewal rotated credentials");
  check(backend.provision(renew)==second,"Renewal replay changed result");
  backend.update_user(f.cookie,f.csrf,second["user_id"],{{"name","Suspended"},{"enabled",false}});
  rejected(409,[&]{backend.provision(request("reserve",account));});
  rejected(404,[&]{backend.provision(request("status",legacy));});
  auto other=random_id();auto expired=backend.provision(request("reserve",other));
  {Database db(f.options.state/"gateway.sqlite");db.run("UPDATE portal_reservations SET expires=? WHERE account_id=?",{now()-1,other});}
  auto late=request("grant",other);late["reservation_id"]=expired["reservation_id"];late["version"]=1;late["term_seconds"]=86400;
  rejected(409,[&]{backend.provision(late);});
  {Fixture cap;auto& panel=*cap.backend;Database db(cap.options.state/"gateway.sqlite");
    {Transaction tx(db);for(int i=0;i<499;++i)db.run("INSERT INTO users(id,name,uuid,token,created) VALUES(?,?,?,?,?)",{random_id(),"Legacy",random_uuid(),random_token(),now()});tx.commit();}
    const auto a=random_id(),b=random_id();std::atomic<int> successes=0;
    auto reserve_one=[&](const std::string& id){try{panel.provision(request("reserve",id));++successes;}catch(const HttpError& e){check(e.status==409,"Capacity failure status");}};
    std::thread t1(reserve_one,a),t2(reserve_one,b);t1.join();t2.join();check(successes==1,"Concurrent reservations exceeded total capacity");
    rejected(409,[&]{panel.create_user(cap.cookie,cap.csrf,{{"name","Manual creation while slot held"}});});
  }
  std::cout<<"Provisioning idempotency, namespace, reconcile, suspension and shared-capacity tests passed\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
