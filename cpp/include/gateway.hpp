#pragma once

#include <httplib.h>
#include <nlohmann/json.hpp>
#include <sqlite3.h>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <variant>
#include <vector>

namespace xg {
using Json = nlohmann::ordered_json;
using Int = std::int64_t;
using Value = std::variant<Int, std::string>;
using Params = std::vector<Value>;
namespace fs = std::filesystem;

struct HttpError : std::runtime_error {
  int status;
  HttpError(int code, const std::string& detail) : std::runtime_error(detail), status(code) {}
};

class Database {
 public:
  explicit Database(const fs::path& file, bool read_only = false);
  ~Database();
  Database(const Database&) = delete;
  Database& operator=(const Database&) = delete;
  void exec(std::string_view sql);
  void run(std::string_view sql, const Params& params = {});
  Json all(std::string_view sql, const Params& params = {});
  std::optional<Json> one(std::string_view sql, const Params& params = {});
  void initialize();
  void backup(const fs::path& destination);
  void restore_from(const fs::path& source);
 private:
  sqlite3* db_ = nullptr;
  struct Statement;
};

class Transaction {
 public:
  explicit Transaction(Database& db) : db_(db) { db_.exec("BEGIN IMMEDIATE"); }
  ~Transaction() { if (!committed_) { try { db_.exec("ROLLBACK"); } catch (...) {} } }
  void commit() { db_.exec("COMMIT"); committed_ = true; }
  Transaction(const Transaction&) = delete;
 private:
  Database& db_;
  bool committed_ = false;
};

Int now();
std::string sha256(std::string_view text);
std::string random_token();
std::string random_id();
std::string random_uuid();
std::string password_hash(std::string_view password);
bool password_check(std::string_view password, std::string_view encoded);
bool secure_equal(std::string_view a, std::string_view b);
std::string base64(std::string_view bytes);
std::string unbase64(std::string_view text, std::size_t maximum = 128 * 1024 * 1024);
std::string totp_secret();
std::string totp_code(std::string_view secret, Int timestamp, unsigned digits = 6);
std::optional<Int> verify_totp(std::string_view secret, std::string_view code, Int timestamp, Int last_step = -1);
std::string load_secret_key(const fs::path& path);
std::string seal(std::string_view plaintext, std::string_view key, std::string_view context);
std::string unseal(std::string_view ciphertext, std::string_view key, std::string_view context);
void write_private_file(const fs::path& path, std::string_view content, bool replace = false);
std::string url_quote(std::string_view value, bool plus = false, bool safe_slash = false);
std::string qr_png(std::string_view value);
std::string read_file(const fs::path& path, std::size_t max_size = 1024 * 1024);
std::string checked_string(const Json& value, std::size_t min, std::size_t max);
std::string user_name(const Json& value);

struct Options {
  fs::path state = "/var/lib/xray-gateway";
  fs::path settings = "/etc/xray-gateway/settings.json";
  fs::path static_dir = "/opt/xray-gateway/static";
  fs::path core_binary = "/usr/local/lib/xray-gateway/xray";
  fs::path core_pid_file = "/sys/fs/cgroup/system.slice/xray-gateway-core.service/cgroup.procs";
  fs::path secret_key;
  fs::path monitor_config;
  fs::path monitor_report = "/var/lib/xray-gateway-monitor/report.json";
  std::string api = "127.0.0.1:10085";
  int port = 8080;
  int poll_seconds = 5;
  bool offline = false;
  bool automatic_backups = true;
  int backup_interval = 21600;
  int backup_retention = 28;
};

struct User {
  std::string id, name, uuid, token;
  bool enabled = true, deleted = false;
  Int quota = 0, expires = 0, upload = 0, download = 0, created = 0;
  static User from(const Json& row);
  bool active(Int timestamp = now()) const;
  std::string status(Int timestamp = now()) const;
  Json public_json() const;
  std::string email(std::string_view tag) const;
};
struct Counter { std::string name; Int value; };

struct WebhookResult { int status = 0; std::string error; };
using WebhookSender = std::function<WebhookResult(const Json&, const Json&)>;
std::string validate_webhook_url(const std::string& url);
bool public_webhook_address(const std::string& address);
WebhookResult post_webhook(const Json& configuration, const Json& payload);

class Core {
 public:
  virtual ~Core() = default;
  virtual std::string generation() = 0;
  virtual std::vector<Counter> counters() = 0;
  virtual std::map<std::string, std::string> users(const std::string& tag) = 0;
  virtual void add_user(const std::string& tag, const User& user) = 0;
  virtual void restart(const std::string& expected_generation) = 0;
  virtual Json runtime() { return {{"state","unknown"},{"reason","未提供运行进程信息"}}; }
};
std::unique_ptr<Core> make_core(const Options& options);
Json linux_host_sample(const fs::path& proc, const fs::path& disk);
Json inspect_core_process(const Options& options, const std::string& generation, bool read_version);

class Backend {
 public:
  explicit Backend(Options options, std::unique_ptr<Core> core = nullptr, WebhookSender sender = post_webhook);
  ~Backend();
  Backend(const Backend&) = delete;
  Backend& operator=(const Backend&) = delete;
  const Options& options() const { return options_; }
  const Json& settings() const { return settings_; }
  std::vector<std::string> transports() const;
  void start_worker();
  void stop_worker();
  void poll_once();
  Json preflight();
  Json health();
  Json login(const Json& input, const std::string& ip, std::string& cookie);
  Json session(const std::string& token, const std::string& csrf = "", bool write = false);
  void logout(const std::string& token, const std::string& csrf);
  Json overview(const std::string& token);
  Json runtime(const std::string& token);
  Json diagnostics(const std::string& token);
  void sample_runtime();
  Json create_user(const std::string& token, const std::string& csrf, const Json& input);
  void update_user(const std::string& token, const std::string& csrf, const std::string& id, const Json& input);
  void delete_user(const std::string& token, const std::string& csrf, const std::string& id);
  void rotate_user(const std::string& token, const std::string& csrf, const std::string& id);
  void reset_traffic(const std::string& token, const std::string& csrf, const std::string& id);
  Json links(const std::string& token, const std::string& id);
  Json shadowrocket_links(const std::string& token, const std::string& id);
  std::string shadowrocket_dns() const;
  std::string qr(const std::string& token, const std::string& id, const std::string& kind);
  void change_password(const std::string& token, const std::string& csrf, const Json& input);
  std::pair<std::string, std::string> subscription(const std::string& token);
  Json links_for(const User& user) const;
  Json shadowrocket_links_for(const User& user) const;
  std::pair<Int,Int> apply_stats(Database& db, const std::string& generation, const std::vector<Counter>& counters);
  Json security_status(const std::string& token);
  Json setup_totp(const std::string& token, const std::string& csrf, const Json& input);
  Json enable_totp(const std::string& token, const std::string& csrf, const Json& input);
  void disable_totp(const std::string& token, const std::string& csrf, const Json& input);
  Json regenerate_recovery(const std::string& token, const std::string& csrf, const Json& input);
  Json backup_status(const std::string& token);
  Json create_backup(const std::string& token, const std::string& csrf);
  Json inspect_backup(const std::string& token, const std::string& id);
  std::string download_backup(const std::string& token, const std::string& id);
  void restore_backup(const std::string& token, const std::string& csrf, const Json& input);
  void scheduled_backup();
  Json monitor_status(Int timestamp = now());
  Json activity_status(Database& database);
  Json history(const std::string& token, const std::string& range);
  Json notification_status(const std::string& token);
  void configure_notifications(const std::string& token, const std::string& csrf, const Json& input);
  Json test_notification(const std::string& token, const std::string& csrf);
  void collect_operations(Int timestamp = now());
  void deliver_notifications(Int timestamp = now());
 private:
  Options options_;
  Json settings_;
  std::string secret_key_;
  std::optional<User> probe_user_;
  std::unique_ptr<Core> core_;
  WebhookSender webhook_sender_;
  std::recursive_mutex mutation_mutex_;
  std::mutex health_mutex_, worker_mutex_;
  Json health_ = {{"core",false},{"updated",0},{"attempted",0},{"last_success",0},{"error","等待连接"},{"version",nullptr}};
  Json runtime_ = {{"sampled",0},{"host",Json::object()},{"process",{{"state","unknown"},{"reason","等待采集"}}}};
  Json diagnostic_events_ = Json::array();
  std::mutex runtime_mutex_;
  std::optional<std::pair<Int,Int>> cpu_previous_;
  std::string diagnostic_state_;
  std::chrono::steady_clock::time_point panel_started_ = std::chrono::steady_clock::now();
  Int panel_started_at_ = now();
  std::map<std::string, std::deque<std::chrono::steady_clock::time_point>> rate_;
  std::condition_variable worker_cv_;
  std::thread worker_, operations_worker_;
  bool stop_ = false;
  int lock_fd_ = -1;
  Int backup_retry_after_ = 0;
  Int operations_started_ = now();
  Database db() const { return Database(options_.state / "gateway.sqlite"); }
  User get_user(Database& db, const std::string& id);
  void audit(Database& db, const std::string& action, const std::string& detail = "");
  static Json validated_user(const Json& input);
  bool check_second_factor(Database& database, std::string_view code, bool allow_recovery = true);
  void confirm_admin(Database& database, const std::string& token, const Json& input);
  Json make_recovery(Database& database);
  Json make_backup(const std::string& reason);
  Json open_backup(const std::string& id);
  Json list_backups();
  fs::path backup_path(const std::string& id) const;
  std::vector<User> desired_users(Database& database);
  Json webhook_configuration(Database& database);
  std::string queue_notification(Database& database, const std::string& service,
    const std::string& kind, Int timestamp, Int started);
  void observe_alarm(Database& database, const std::string& service, bool failed,
    Int sample, Int timestamp, int failure_threshold, int recovery_threshold);
};

class HttpServer {
 public:
  explicit HttpServer(Backend& backend);
  bool bind();
  bool listen();
  void stop();
 private:
  Backend& backend_;
  httplib::Server server_;
  using Request = httplib::Request;
  using Response = httplib::Response;
  using Handler = std::function<void(const Request&, Response&)>;
  Handler wrap(Handler handler);
  static void security_headers(Response& response);
  static std::string cookie(const Request& request);
  static std::string client_ip(const Request& request);
  static Json body(const Request& request);
  static void json(Response& response, const Json& value, int status = 200);
};
}
