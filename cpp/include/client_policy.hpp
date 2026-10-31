#pragma once
#include "gateway.hpp"

namespace xg {
bool client_policy_enabled(const Json& settings,const std::string& user_id);
void apply_client_policy(Json& config,const Json& settings,const User& user,
                         const std::map<std::string,std::string>& outbound_names);
std::string independent_template_rules();
Json validate_rule_template(const Json& input);
void apply_template_rules(Json& config,const Json& spec,const Json& baseline_dns);
}
