#include "gateway.hpp"
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace xg {
struct Database::Statement {
  sqlite3_stmt* value = nullptr;
  Statement(sqlite3* db, std::string_view sql, const Params& params) {
    if (sqlite3_prepare_v2(db, sql.data(), static_cast<int>(sql.size()), &value, nullptr) != SQLITE_OK)
      throw std::runtime_error("SQLite prepare failed");
    try {
      for (std::size_t i = 0; i < params.size(); ++i) {
        int result = std::visit([&](const auto& v) -> int {
          using T = std::decay_t<decltype(v)>;
          if constexpr (std::is_same_v<T,Int>) return sqlite3_bind_int64(value, static_cast<int>(i+1), v);
          else return sqlite3_bind_text(value, static_cast<int>(i+1), v.data(), static_cast<int>(v.size()), SQLITE_TRANSIENT);
        }, params[i]);
        if (result != SQLITE_OK) throw std::runtime_error("SQLite bind failed");
      }
    } catch (...) { sqlite3_finalize(value); value = nullptr; throw; }
  }
  ~Statement() { sqlite3_finalize(value); }
};

Database::Database(const fs::path& file, bool read_only) {
  int flags = (read_only ? SQLITE_OPEN_READONLY : SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE) | SQLITE_OPEN_FULLMUTEX;
  if (sqlite3_open_v2(file.c_str(), &db_, flags, nullptr) != SQLITE_OK) {
    sqlite3_close(db_); db_ = nullptr;
    throw std::runtime_error("SQLite open failed");
  }
  try {
    sqlite3_busy_timeout(db_,15000);
    exec("PRAGMA foreign_keys=ON");
    exec("PRAGMA trusted_schema=OFF");
    sqlite3_db_config(db_, SQLITE_DBCONFIG_DEFENSIVE, 1, nullptr);
  } catch (...) { sqlite3_close(db_); db_ = nullptr; throw; }
}
Database::~Database() { if (db_) sqlite3_close(db_); }
void Database::exec(std::string_view sql) {
  std::string owned(sql);
  if (sqlite3_exec(db_, owned.c_str(), nullptr, nullptr, nullptr) != SQLITE_OK)
    throw std::runtime_error("SQLite execution failed");
}
void Database::run(std::string_view sql, const Params& params) {
  Statement stmt(db_,sql,params);
  if (sqlite3_step(stmt.value) != SQLITE_DONE) throw std::runtime_error("SQLite write failed");
}
Json Database::all(std::string_view sql, const Params& params) {
  Statement stmt(db_,sql,params);
  Json result = Json::array(); int state;
  while ((state = sqlite3_step(stmt.value)) == SQLITE_ROW) {
    Json row = Json::object();
    for (int i = 0; i < sqlite3_column_count(stmt.value); ++i) {
      const char* name = sqlite3_column_name(stmt.value,i);
      switch (sqlite3_column_type(stmt.value,i)) {
        case SQLITE_INTEGER: row[name] = sqlite3_column_int64(stmt.value,i); break;
        case SQLITE_FLOAT: row[name] = sqlite3_column_double(stmt.value,i); break;
        case SQLITE_NULL: row[name] = nullptr; break;
        default: {
          auto data = reinterpret_cast<const char*>(sqlite3_column_text(stmt.value,i));
          row[name] = std::string(data,static_cast<std::size_t>(sqlite3_column_bytes(stmt.value,i)));
        }
      }
    }
    result.push_back(std::move(row));
  }
  if (state != SQLITE_DONE) throw std::runtime_error("SQLite read failed");
  return result;
}
std::optional<Json> Database::one(std::string_view sql, const Params& params) {
  auto rows = all(sql,params);
  if (rows.empty()) return std::nullopt;
  return std::optional<Json>(std::in_place,rows.front());
}
void Database::initialize() {
  exec(R"SQL(
    PRAGMA journal_mode=WAL;
    CREATE TABLE IF NOT EXISTS admin(id INTEGER PRIMARY KEY CHECK(id=1), password TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,name TEXT NOT NULL,uuid TEXT NOT NULL UNIQUE,
      token TEXT NOT NULL UNIQUE,enabled INTEGER NOT NULL DEFAULT 1,quota INTEGER NOT NULL DEFAULT 0,
      expires INTEGER NOT NULL DEFAULT 0,upload INTEGER NOT NULL DEFAULT 0,download INTEGER NOT NULL DEFAULT 0,
      created INTEGER NOT NULL,deleted INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE IF NOT EXISTS sessions(hash TEXT PRIMARY KEY,csrf TEXT NOT NULL,expires INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS counters(name TEXT PRIMARY KEY,value INTEGER NOT NULL,generation TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS samples(ts INTEGER NOT NULL,upload INTEGER NOT NULL,download INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,ts INTEGER NOT NULL,action TEXT NOT NULL,detail TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS mfa(id INTEGER PRIMARY KEY CHECK(id=1),enabled INTEGER NOT NULL DEFAULT 0,
      secret TEXT NOT NULL DEFAULT '',last_step INTEGER NOT NULL DEFAULT -1,
      pending TEXT NOT NULL DEFAULT '',pending_expires INTEGER NOT NULL DEFAULT 0,pending_session TEXT NOT NULL DEFAULT '');
    INSERT OR IGNORE INTO mfa(id) VALUES(1);
    CREATE TABLE IF NOT EXISTS mfa_sessions(hash TEXT PRIMARY KEY);
    CREATE TABLE IF NOT EXISTS recovery_codes(hash TEXT PRIMARY KEY,used INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE IF NOT EXISTS device_activity(user_id TEXT NOT NULL,transport TEXT NOT NULL,
      last_seen INTEGER NOT NULL DEFAULT 0,sampled INTEGER NOT NULL DEFAULT 0,
      upload_delta INTEGER NOT NULL DEFAULT 0,download_delta INTEGER NOT NULL DEFAULT 0,
      interval_seconds INTEGER NOT NULL DEFAULT 5,PRIMARY KEY(user_id,transport));
    CREATE INDEX IF NOT EXISTS samples_ts ON samples(ts);
    CREATE TABLE IF NOT EXISTS traffic_history(ts INTEGER PRIMARY KEY,upload INTEGER NOT NULL,download INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS probe_history(ts INTEGER NOT NULL,transport TEXT NOT NULL,status TEXT NOT NULL,
      https_ms REAL,udp_ms REAL,PRIMARY KEY(ts,transport));
    CREATE TABLE IF NOT EXISTS notification_config(id INTEGER PRIMARY KEY CHECK(id=1),enabled INTEGER NOT NULL DEFAULT 0,
      url TEXT NOT NULL DEFAULT '',bearer TEXT NOT NULL DEFAULT '',signing TEXT NOT NULL DEFAULT '',
      generation TEXT NOT NULL DEFAULT '',failures INTEGER NOT NULL DEFAULT 3,recoveries INTEGER NOT NULL DEFAULT 2);
    INSERT OR IGNORE INTO notification_config(id) VALUES(1);
    CREATE TABLE IF NOT EXISTS alarm_state(service TEXT PRIMARY KEY,bad INTEGER NOT NULL DEFAULT 0,
      good INTEGER NOT NULL DEFAULT 0,firing INTEGER NOT NULL DEFAULT 0,since INTEGER NOT NULL DEFAULT 0,
      last_sample INTEGER NOT NULL DEFAULT 0,last_seen INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE IF NOT EXISTS notifications(id TEXT PRIMARY KEY,created INTEGER NOT NULL,service TEXT NOT NULL,
      kind TEXT NOT NULL,payload TEXT NOT NULL,generation TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'pending',
      attempts INTEGER NOT NULL DEFAULT 0,next_attempt INTEGER NOT NULL DEFAULT 0,
      delivered INTEGER NOT NULL DEFAULT 0,last_error TEXT NOT NULL DEFAULT '',http_status INTEGER NOT NULL DEFAULT 0);
    CREATE INDEX IF NOT EXISTS notification_pending ON notifications(status,next_attempt);
    CREATE TABLE IF NOT EXISTS portal_accounts(account_id TEXT PRIMARY KEY,user_id TEXT NOT NULL UNIQUE REFERENCES users(id),version INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS portal_reservations(account_id TEXT PRIMARY KEY,reservation_id TEXT NOT NULL UNIQUE,expires INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS portal_operations(operation_id TEXT PRIMARY KEY,request_hash TEXT NOT NULL,response TEXT NOT NULL,created INTEGER NOT NULL);
  )SQL");
  Transaction migration(*this);
  if(!one("SELECT value FROM metadata WHERE key='operations_history_imported'")) {
    run("INSERT OR IGNORE INTO traffic_history SELECT (ts/60)*60,SUM(upload),SUM(download) FROM samples WHERE ts>=? GROUP BY ts/60",{now()-30*86400});
    run("INSERT INTO metadata VALUES('operations_history_imported','1')");
  }
  migration.commit();
}
void Database::backup(const fs::path& destination) {
  int fd = ::open(destination.c_str(),O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0600);
  if (fd < 0) throw std::runtime_error("Backup destination must be a new file");
  ::close(fd);
  try {
    Database target(destination);
    auto handle = sqlite3_backup_init(target.db_, "main", db_, "main");
    if (!handle) throw std::runtime_error("Backup initialization failed");
    int result = sqlite3_backup_step(handle,-1);
    int finish = sqlite3_backup_finish(handle);
    if (result != SQLITE_DONE || finish != SQLITE_OK) throw std::runtime_error("Backup failed");
  } catch (...) { fs::remove(destination); throw; }
}
void Database::restore_from(const fs::path& source) {
  Database snapshot(source,true);
  auto handle=sqlite3_backup_init(db_,"main",snapshot.db_,"main");
  if(!handle)throw std::runtime_error("Restore initialization failed");
  int result=SQLITE_OK;
  for(int attempt=0;attempt<60;++attempt) {
    result=sqlite3_backup_step(handle,-1);
    if(result!=SQLITE_BUSY&&result!=SQLITE_LOCKED)break;
    sqlite3_sleep(50);
  }
  int finish=sqlite3_backup_finish(handle);
  if(result!=SQLITE_DONE||finish!=SQLITE_OK)throw std::runtime_error("Restore failed");
}
}
