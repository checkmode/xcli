#include "gateway.hpp"
#include "client_policy.hpp"
#include <limits>
#include <regex>
#include <set>

namespace xg {
namespace {
constexpr auto registry_key="rule_templates_v1";

bool is_builtin(const std::string& id) {return id=="standard"||id=="independent";}

Json builtin(const std::string& id) {
  if(id=="standard")return {{"base","standard"},{"ai_outbound","proxy"},{"rules",""}};
  if(id=="independent")return {{"base","independent"},{"ai_outbound","proxy"},{"rules",independent_template_rules()}};
  throw HttpError(404,"模板不存在");
}

Json builtin_default_item(const std::string& id) {
  const auto spec=builtin(id);
  return {{"name",id=="standard"?"标准分流":"独立服务分组"},{"draft",spec},{"revision",1},
    {"published",spec},{"published_revision",1},{"published_at",0}};
}

Json read_registry(Database& database) {
  auto row=database.one("SELECT value FROM metadata WHERE key=?",{std::string(registry_key)});
  if(!row)return {{"version",1},{"templates",Json::object()},{"assignments",Json::object()}};
  try {
    const auto value=row->at("value").get<std::string>();
    if(value.size()>1024*1024)throw std::runtime_error("registry too large");
    auto registry=Json::parse(value);
    if(!registry.is_object()||registry.value("version",0)!=1||!registry.at("templates").is_object()||
       !registry.at("assignments").is_object()||registry.at("templates").size()>64||registry.at("assignments").size()>500)
      throw std::runtime_error("invalid registry");
    if(registry.contains("builtins")) {
      const auto& entries=registry.at("builtins");
      if(!entries.is_object()||entries.size()>2)throw std::runtime_error("invalid builtins");
      for(const auto& [id,item]:entries.items())
        if(!is_builtin(id)||!item.is_object())throw std::runtime_error("invalid builtin");
    }
    return registry;
  } catch(const std::exception&) {throw HttpError(503,"规则模板数据无法读取，现有配置未更改");}
}

void save_registry(Database& database,const Json& registry) {
  auto data=registry.dump();
  if(data.size()>1024*1024)throw HttpError(422,"模板总内容过大");
  database.run("INSERT OR REPLACE INTO metadata(key,value) VALUES(?,?)",{std::string(registry_key),data});
}

void require_fields(const Json& value,const std::set<std::string>& required) {
  if(!value.is_object()||value.size()!=required.size())throw HttpError(422,"请求格式不正确");
  for(const auto& key:required)if(!value.contains(key))throw HttpError(422,"请求格式不正确");
}

Int revision(const Json& input) {
  if(!input.is_number_integer())throw HttpError(422,"模板版本不正确");
  const auto n=input.get<Int>();if(n<1)throw HttpError(422,"模板版本不正确");return n;
}

Json builtin_item(const Json& registry,const std::string& id) {
  if(registry.contains("builtins")&&registry.at("builtins").contains(id))return registry.at("builtins").at(id);
  return builtin_default_item(id);
}

Json& editable_item(Json& registry,const std::string& id) {
  if(is_builtin(id)) {
    if(!registry.contains("builtins"))registry["builtins"]=Json::object();
    auto& entries=registry["builtins"];
    if(!entries.contains(id))entries[id]=builtin_default_item(id);
    return entries[id];
  }
  auto& entries=registry["templates"];
  if(!entries.contains(id))throw HttpError(404,"模板不存在");
  return entries[id];
}

Json selected_spec(const Json& registry,const std::string& id) {
  if(is_builtin(id)) {
    const auto initial=builtin(id);
    if(!registry.contains("builtins")||!registry.at("builtins").contains(id))return initial;
    const auto& published=registry.at("builtins").at(id).at("published");
    return published==initial?initial:validate_rule_template(published);
  }
  if(!std::regex_match(id,std::regex("[0-9a-f]{32}"))||!registry.at("templates").contains(id))
    throw HttpError(404,"模板不存在");
  const auto& item=registry.at("templates").at(id);
  if(!item.contains("published")||item.at("published").is_null())throw HttpError(409,"请先发布模板，再分配给用户");
  return validate_rule_template(item.at("published"));
}

void validate_for_user(const Backend& backend,const User& user,const Json& spec) {
  const auto config=backend.clash_configuration_for(user,spec);
  if(spec.at("base")=="independent"&&spec.at("ai_outbound")!="proxy")
    for(const auto& group:config.at("proxy-groups"))if(group.at("name")=="独立 · AI"&&group.at("proxies").at(0)=="REJECT")
      throw HttpError(422,"AI 默认出口当前不可用");
  if(spec.at("base")=="independent"||!spec.at("rules").get<std::string>().empty()||!spec.value("groups",Json::array()).empty())
    (void)backend.categorized_shadowrocket_profile(user,spec);
}

Int validate_for_assignments(const Backend& backend,Database& database,const Json& registry,const std::string& id,Json spec) {
  spec["managed"]=true;Int affected=0;
  for(const auto& [user_id,choice]:registry.at("assignments").items())if(choice==id) {
    auto row=database.one("SELECT * FROM users WHERE id=? AND deleted=0",{user_id});if(!row)continue;
    validate_for_user(backend,User::from(*row),spec);++affected;
  }
  return affected;
}
}

Json Backend::effective_rule_policy(Database& database,const std::string& user_id) const {
  const auto registry=read_registry(database);const auto& assignments=registry.at("assignments");
  if(assignments.contains(user_id)) {
    if(!assignments.at(user_id).is_string())throw HttpError(503,"用户规则模板配置无效");
    auto spec=selected_spec(registry,assignments.at(user_id).get<std::string>());spec["managed"]=true;return spec;
  }
  const bool independent=client_policy_enabled(settings_,user_id);
  const auto ai=independent?settings_.at("client_policies").at(user_id).at("ai_outbound").get<std::string>():std::string("proxy");
  return {{"base",independent?"independent":"standard"},{"ai_outbound",ai},{"rules",""},{"managed",false}};
}

Json Backend::rule_templates(const std::string& token) {
  session(token);auto database=db();const auto registry=read_registry(database);
  Json templates=Json::array();
  for(const auto* id:{"standard","independent"}) {
    const auto item=builtin_item(registry,id);
    const auto draft=validate_rule_template(item.at("draft")),published=validate_rule_template(item.at("published"));
    templates.push_back({{"id",id},{"name",item.at("name")},{"builtin",true},{"spec",draft},
      {"revision",item.at("revision")},{"published",true},{"published_spec",published},
      {"published_revision",item.at("published_revision")},{"published_at",item.at("published_at")},
      {"factory_spec",builtin(id)},{"can_undo_reset",item.contains("reset_backup")&&item.at("reset_backup").is_object()}});
  }
  for(const auto& [id,item]:registry.at("templates").items()) {
    if(!std::regex_match(id,std::regex("[0-9a-f]{32}")))throw HttpError(503,"规则模板数据无效");
    auto draft=validate_rule_template(item.at("draft"));
    auto published=item.at("published");if(!published.is_null())published=validate_rule_template(published);
    templates.push_back({{"id",id},{"name",item.at("name")},{"builtin",false},{"spec",draft},
      {"revision",item.at("revision")},{"published",!published.is_null()},
      {"published_spec",published},{"published_revision",item.at("published_revision")},
      {"published_at",item.at("published_at")}});
  }
  Json users=Json::array();
  for(const auto& user:database.all("SELECT id,name FROM users WHERE deleted=0 ORDER BY created")) {
    const auto id=user.at("id").get<std::string>();const auto& assignments=registry.at("assignments");
    const auto choice=assignments.contains(id)?assignments.at(id).get<std::string>():std::string("legacy");
    users.push_back({{"id",id},{"name",user.at("name")},{"template_id",choice},
      {"legacy_independent",!assignments.contains(id)&&client_policy_enabled(settings_,id)}});
  }
  return {{"templates",templates},{"users",users}};
}

Json Backend::create_rule_template(const std::string& token,const std::string& csrf,const Json& input) {
  require_fields(input,{"name","spec"});auto name=user_name(input.at("name"));auto spec=validate_rule_template(input.at("spec"));
  std::lock_guard guard(mutation_mutex_);session(token,csrf,true);auto database=db();Transaction transaction(database);
  auto registry=read_registry(database);auto& templates=registry["templates"];
  if(templates.size()>=64)throw HttpError(409,"最多支持 64 个自定义模板");
  auto id=random_id();templates[id]={{"name",name},{"draft",spec},{"revision",1},
    {"published",nullptr},{"published_revision",0},{"published_at",0}};
  save_registry(database,registry);audit(database,"rule_template_created",name);transaction.commit();return {{"id",id},{"revision",1}};
}

Json Backend::validate_rule_template_input(const std::string& token,const std::string& csrf,const Json& input) {
  session(token,csrf,true);require_fields(input,{"name","spec"});
  return {{"name",user_name(input.at("name"))},{"spec",validate_rule_template(input.at("spec"))}};
}

Json Backend::update_rule_template(const std::string& token,const std::string& csrf,const std::string& id,const Json& input) {
  require_fields(input,{"name","spec","expected_revision"});auto name=user_name(input.at("name"));
  auto spec=validate_rule_template(input.at("spec"));auto expected=revision(input.at("expected_revision"));
  std::lock_guard guard(mutation_mutex_);session(token,csrf,true);auto database=db();Transaction transaction(database);
  auto registry=read_registry(database);auto& item=editable_item(registry,id);
  if(item.at("revision").get<Int>()!=expected)throw HttpError(409,"模板已被其他操作修改，请重新读取");
  item["name"]=name;item["draft"]=spec;item["revision"]=expected+1;
  save_registry(database,registry);audit(database,"rule_template_saved",name);transaction.commit();return {{"revision",expected+1}};
}

Json Backend::publish_rule_template(const std::string& token,const std::string& csrf,const std::string& id,const Json& input) {
  require_fields(input,{"expected_revision"});auto expected=revision(input.at("expected_revision"));
  std::lock_guard guard(mutation_mutex_);session(token,csrf,true);auto database=db();Transaction transaction(database);
  auto registry=read_registry(database);auto& item=editable_item(registry,id);
  if(item.at("revision").get<Int>()!=expected)throw HttpError(409,"模板已被其他操作修改，请重新读取");
  const auto spec=validate_rule_template(item.at("draft"));
  const auto affected=validate_for_assignments(*this,database,registry,id,spec);
  item["published"]=spec;item["published_revision"]=expected;item["published_at"]=now();
  save_registry(database,registry);audit(database,"rule_template_published",item.at("name").get<std::string>());transaction.commit();
  return {{"published_revision",expected},{"affected_users",affected}};
}

Json Backend::reset_builtin_rule_template(const std::string& token,const std::string& csrf,const std::string& id,const Json& input) {
  require_fields(input,{"expected_revision"});const auto expected=revision(input.at("expected_revision"));
  std::lock_guard guard(mutation_mutex_);session(token,csrf,true);
  if(!is_builtin(id))throw HttpError(404,"只能恢复内置模板");
  auto database=db();Transaction transaction(database);auto registry=read_registry(database);auto& item=editable_item(registry,id);
  if(item.at("revision").get<Int>()!=expected)throw HttpError(409,"模板已被其他操作修改，请重新读取");
  const auto initial=builtin_default_item(id);
  const bool initial_content=item.at("name")==initial.at("name")&&item.at("draft")==initial.at("draft")&&item.at("published")==initial.at("published");
  if(initial_content&&item.at("revision")==item.at("published_revision"))
    return {{"unchanged",true},{"revision",expected},{"affected_users",0}};
  if(expected==std::numeric_limits<Int>::max())throw HttpError(422,"模板版本已达上限");
  const auto affected=validate_for_assignments(*this,database,registry,id,initial.at("published"));
  const Json backup=initial_content&&item.contains("reset_backup")?item.at("reset_backup"):
    Json{{"name",item.at("name")},{"draft",item.at("draft")},{"published",item.at("published")},
      {"draft_dirty",item.at("revision")!=item.at("published_revision")},{"published_at",item.at("published_at")}};
  item["name"]=initial.at("name");item["draft"]=initial.at("draft");item["published"]=initial.at("published");
  item["revision"]=expected+1;item["published_revision"]=expected+1;item["published_at"]=now();item["reset_backup"]=backup;
  save_registry(database,registry);audit(database,"rule_template_reset",item.at("name").get<std::string>());transaction.commit();
  return {{"unchanged",false},{"revision",expected+1},{"affected_users",affected}};
}

Json Backend::undo_builtin_rule_template_reset(const std::string& token,const std::string& csrf,const std::string& id,const Json& input) {
  require_fields(input,{"expected_revision"});const auto expected=revision(input.at("expected_revision"));
  std::lock_guard guard(mutation_mutex_);session(token,csrf,true);
  if(!is_builtin(id))throw HttpError(404,"只能撤销内置模板的恢复");
  auto database=db();Transaction transaction(database);auto registry=read_registry(database);auto& item=editable_item(registry,id);
  if(item.at("revision").get<Int>()!=expected)throw HttpError(409,"模板已被其他操作修改，请重新读取");
  if(!item.contains("reset_backup")||!item.at("reset_backup").is_object())throw HttpError(409,"没有可撤销的恢复记录");
  if(expected==std::numeric_limits<Int>::max())throw HttpError(422,"模板版本已达上限");
  const auto backup=item.at("reset_backup");
  const auto draft=validate_rule_template(backup.at("draft")),published=validate_rule_template(backup.at("published"));
  const auto affected=validate_for_assignments(*this,database,registry,id,published);
  item["name"]=backup.at("name");item["draft"]=draft;item["published"]=published;item["revision"]=expected+1;
  item["published_revision"]=backup.at("draft_dirty").get<bool>()?expected:expected+1;
  item["published_at"]=backup.at("published_at");item.erase("reset_backup");
  save_registry(database,registry);audit(database,"rule_template_reset_undone",item.at("name").get<std::string>());transaction.commit();
  return {{"revision",expected+1},{"affected_users",affected}};
}

Json Backend::assign_rule_template(const std::string& token,const std::string& csrf,const std::string& id,const Json& input) {
  require_fields(input,{"template_id"});const auto choice=checked_string(input.at("template_id"),1,32);
  std::lock_guard guard(mutation_mutex_);session(token,csrf,true);auto database=db();Transaction transaction(database);
  const auto user=get_user(database,id);auto registry=read_registry(database);
  if(choice=="legacy")registry["assignments"].erase(id);
  else {
    auto spec=selected_spec(registry,choice);spec["managed"]=true;validate_for_user(*this,user,spec);
    registry["assignments"][id]=choice;
  }
  save_registry(database,registry);audit(database,"user_rule_template_changed",user.name);transaction.commit();return {{"ok",true}};
}
}
