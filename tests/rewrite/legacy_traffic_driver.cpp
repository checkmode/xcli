// Test-only legacy accounting driver. Use only a disposable state directory.
#include "gateway.hpp"
#include <iostream>

int main(int argc, char** argv) {
  if(argc!=3)return 2;
  try {
    xg::Options options;options.state=argv[1];options.settings=argv[2];options.offline=true;options.automatic_backups=false;
    xg::Backend panel(options);
    xg::Database db(options.state/"gateway.sqlite");
    db.run("INSERT INTO users(id,name,uuid,token,created) VALUES(?,?,?,?,?)",
      {"0123456789abcdef0123456789abcdef","fixture","01234567-89ab-4def-8123-456789abcdef",std::string(43,'x'),xg::Int(1)});
    std::cout<<xg::Json({{"ready",true}}).dump()<<std::endl;
    std::string line;
    while(std::getline(std::cin,line)) {
      try {
        auto input=xg::Json::parse(line);std::vector<xg::Counter> counters;
        for(const auto& value:input.at("counters"))counters.push_back({value.at("name").get<std::string>(),value.at("value").get<xg::Int>()});
        xg::Transaction tx(db);auto result=panel.apply_stats(db,input.at("generation").get<std::string>(),counters);tx.commit();
        auto sample=db.one("SELECT value FROM metadata WHERE key='activity_sample'");
        std::cout<<xg::Json({{"ok",true},{"upload",result.first},{"download",result.second},{"now",std::stoll(sample->at("value").get<std::string>())}}).dump()<<std::endl;
      } catch(const std::exception&) {std::cout<<xg::Json({{"ok",false}}).dump()<<std::endl;}
    }
    return 0;
  } catch(const std::exception&) {return 1;}
}
