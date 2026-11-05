#include "client_policy.hpp"
#include <iostream>
#include <string>

int main() {
  std::string line;
  while (std::getline(std::cin, line)) {
    try {
      auto input = xg::Json::parse(line);
      if (input.value("action", std::string()) == "factory") {
        std::cout << xg::Json{{"ok", true}, {"factory", xg::independent_template_rules()}}.dump() << std::endl;
        continue;
      }
      auto config = input.at("config");
      if (input.value("action", std::string()) == "client-policy") {
        xg::User user;user.id="fixture";
        auto settings=xg::Json{{"client_policies",{{"fixture",{{"ai_outbound",input.at("ai_outbound")}}}}}};
        std::map<std::string,std::string> outbound;
        for (const auto& [key,value] : input.at("outbound").items()) outbound[key]=value.get<std::string>();
        xg::apply_client_policy(config,settings,user,outbound);
      } else if (input.value("action", std::string()) == "google-policy") {
        xg::apply_google_policy(config);
      } else {
        auto spec = xg::validate_rule_template(input.at("spec"));
        xg::apply_template_rules(config, spec, input.at("baseline_dns"));
      }
      std::cout << xg::Json{{"ok", true}, {"value", config}}.dump() << std::endl;
    } catch (const xg::HttpError& error) {
      std::cout << xg::Json{{"ok", false}, {"status", error.status}, {"detail", error.what()}}.dump() << std::endl;
    } catch (const std::exception&) {
      std::cout << xg::Json{{"ok", false}, {"status", 503}}.dump() << std::endl;
    }
  }
}
