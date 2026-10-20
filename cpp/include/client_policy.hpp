#pragma once
#include "gateway.hpp"

namespace xg {
bool client_policy_enabled(const Json& settings,const std::string& user_id);
void apply_client_policy(Json& config,const Json& settings,const User& user,
                         const std::map<std::string,std::string>& outbound_names);
}
