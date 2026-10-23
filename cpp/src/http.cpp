#include "gateway.hpp"
#include "http_queue.hpp"
#include <arpa/inet.h>
#include <array>
#include <charconv>
#include <iostream>
#include <sys/socket.h>

namespace xg {
void HttpServer::json(Response& response,const Json& value,int status) {response.status=status;response.set_content(value.dump(),"application/json");}
void HttpServer::security_headers(Response& response) {
  response.set_header("X-Content-Type-Options","nosniff");
  response.set_header("X-Frame-Options","DENY");
  response.set_header("Referrer-Policy","no-referrer");
  response.set_header("Cache-Control","no-store");
  response.set_header("Content-Security-Policy","default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' blob: data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
}
std::string HttpServer::cookie(const Request& request) {
  auto text=request.get_header_value("Cookie");std::size_t start=0;
  while(start<text.size()) {
    auto end=text.find(';',start);if(end==std::string::npos)end=text.size();
    auto item=std::string_view(text).substr(start,end-start);
    while(!item.empty()&&(item.front()==' '||item.front()=='\t'))item.remove_prefix(1);
    if(item.starts_with("xg_session="))return std::string(item.substr(11));
    start=end+1;
  }
  return {};
}
std::string HttpServer::client_ip(const Request& request) {
  // Only loopback can reach this server. Nginx replaces, rather than appends, XFF.
  if(request.remote_addr=="127.0.0.1"||request.remote_addr=="::1") {
    auto forwarded=request.get_header_value("X-Forwarded-For");std::array<unsigned char,16> buffer{};
    if(::inet_pton(AF_INET,forwarded.c_str(),buffer.data())==1||::inet_pton(AF_INET6,forwarded.c_str(),buffer.data())==1)return forwarded;
  }
  return request.remote_addr;
}
Json HttpServer::body(const Request& request) {
  try {return Json::parse(request.body);}
  catch(const Json::exception&) {throw HttpError(422,"请求 JSON 格式不正确");}
}
HttpServer::Handler HttpServer::wrap(Handler handler) {
  return [handler=std::move(handler)](const Request& request,Response& response) {
    try {handler(request,response);}
    catch(const HttpError& error) {json(response,{{"detail",error.what()}},error.status);}
    catch(const std::exception&) {std::cerr<<"HTTP request failed; internal detail suppressed\n";json(response,{{"detail","服务暂时不可用，请稍后重试"}},503);}
    security_headers(response);
  };
}
HttpServer::HttpServer(Backend& backend) : backend_(backend) {
  server_.new_task_queue=[] {return make_http_queue();};
  server_.set_payload_max_length(16384);
  server_.set_read_timeout(10,0);server_.set_write_timeout(10,0);
  server_.set_keep_alive_timeout(5);server_.set_keep_alive_max_count(100);
  server_.set_socket_options([](socket_t fd){int yes=1;::setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(yes));});
  server_.set_pre_routing_handler([this](const Request& request,Response& response) {
    security_headers(response);
    if(request.body.size()>16384) {json(response,{{"detail","请求过大"}},413);return httplib::Server::HandlerResponse::Handled;}
    if(request.method!="GET"&&request.method!="HEAD"&&request.method!="OPTIONS"&&request.get_header_value("Origin")!=backend_.settings().value("admin_origin",backend_.settings().at("origin").get<std::string>())) {
      json(response,{{"detail","来源校验失败"}},403);return httplib::Server::HandlerResponse::Handled;
    }
    return httplib::Server::HandlerResponse::Unhandled;
  });
  server_.set_error_handler([](const Request&,Response& response) {
    if(response.body.empty())json(response,{{"detail",response.status==413?"请求过大":"Not Found"}},response.status);
    security_headers(response);
  });
  server_.set_post_routing_handler([](const Request&,Response& response){security_headers(response);});
  server_.Get("/healthz",wrap([](const Request&,Response& response){json(response,{{"status","ok"}});}));
  server_.Get("/",wrap([this](const Request&,Response& response){response.set_content(read_file(backend_.options().static_dir/"index.html"),"text/html; charset=utf-8");}));
  server_.Get("/client/shadowrocket",wrap([this](const Request&,Response& response){response.set_content(read_file(backend_.options().static_dir/"shadowrocket.html"),"text/html; charset=utf-8");}));
  server_.Get("/shadowrocket-dns.sgmodule",wrap([this](const Request&,Response& response){response.set_content(backend_.shadowrocket_dns(),"text/plain; charset=utf-8");}));
  for(const auto& [name,type]:std::vector<std::pair<std::string,std::string>>{{"index.html","text/html; charset=utf-8"},{"app.js","text/javascript; charset=utf-8"},{"operations.js","text/javascript; charset=utf-8"},{"webshare.js","text/javascript; charset=utf-8"},{"proxy-import.js","text/javascript; charset=utf-8"},{"runtime.js","text/javascript; charset=utf-8"},{"style.css","text/css; charset=utf-8"},{"shadowrocket.js","text/javascript; charset=utf-8"},{"shadowrocket.css","text/css; charset=utf-8"}})
    server_.Get("/static/"+name,wrap([this,name,type](const Request&,Response& response){response.set_content(read_file(backend_.options().static_dir/name),type);}));
  server_.Post("/api/login",wrap([this](const Request& request,Response& response) {
    std::string token;auto result=backend_.login(body(request),client_ip(request),token);
    response.set_header("Set-Cookie","xg_session="+token+"; HttpOnly; Max-Age=28800; Path=/; SameSite=Strict; Secure");json(response,result);
  }));
  server_.Get("/api/session",wrap([this](const Request& request,Response& response){json(response,backend_.session(cookie(request)));}));
  server_.Post("/api/logout",wrap([this](const Request& request,Response& response) {
    backend_.logout(cookie(request),request.get_header_value("X-CSRF-Token"));
    response.set_header("Set-Cookie","xg_session=; HttpOnly; Max-Age=0; Path=/; SameSite=Strict; Secure");json(response,{{"ok",true}});
  }));
  server_.Get("/api/overview",wrap([this](const Request& request,Response& response){json(response,backend_.overview(cookie(request)));}));
  server_.Get("/api/runtime",wrap([this](const Request& r,Response& s){json(s,backend_.runtime(cookie(r)));}));
  server_.Get("/api/proxy-import",wrap([this](const Request& r,Response& s){json(s,backend_.proxy_import_status(cookie(r)));}));
  server_.Post("/api/proxy-import",wrap([this](const Request& r,Response& s){json(s,backend_.request_proxy_import(cookie(r),r.get_header_value("X-CSRF-Token"),body(r)),202);}));
  server_.Get("/api/webshare",wrap([this](const Request& r,Response& s){json(s,backend_.webshare_status(cookie(r)));}));
  server_.Put("/api/webshare",wrap([this](const Request& r,Response& s){backend_.configure_webshare(cookie(r),r.get_header_value("X-CSRF-Token"),body(r));json(s,{{"ok",true},{"pending",true}});}));
  server_.Post("/api/webshare/action",wrap([this](const Request& r,Response& s){backend_.request_webshare(cookie(r),r.get_header_value("X-CSRF-Token"),body(r));json(s,{{"ok",true},{"pending",true}});}));
  server_.Get("/api/diagnostics",wrap([this](const Request& r,Response& s){json(s,backend_.diagnostics(cookie(r)));}));
  server_.Get("/api/history",wrap([this](const Request& r,Response& s){json(s,backend_.history(cookie(r),r.has_param("range")?r.get_param_value("range"):"24h"));}));
  server_.Get("/api/notifications",wrap([this](const Request& r,Response& s){json(s,backend_.notification_status(cookie(r)));}));
  server_.Put("/api/notifications",wrap([this](const Request& r,Response& s){backend_.configure_notifications(cookie(r),r.get_header_value("X-CSRF-Token"),body(r));json(s,{{"ok",true}});}));
  server_.Post("/api/notifications/test",wrap([this](const Request& r,Response& s){json(s,backend_.test_notification(cookie(r),r.get_header_value("X-CSRF-Token")));}));
  server_.Post("/api/users",wrap([this](const Request& request,Response& response){json(response,backend_.create_user(cookie(request),request.get_header_value("X-CSRF-Token"),body(request)));}));
  server_.Put(R"(/api/users/([^/]+))",wrap([this](const Request& request,Response& response){backend_.update_user(cookie(request),request.get_header_value("X-CSRF-Token"),request.matches[1].str(),body(request));json(response,{{"ok",true}});}));
  server_.Delete(R"(/api/users/([^/]+))",wrap([this](const Request& request,Response& response){backend_.delete_user(cookie(request),request.get_header_value("X-CSRF-Token"),request.matches[1].str());json(response,{{"ok",true}});}));
  server_.Post(R"(/api/users/([^/]+)/rotate)",wrap([this](const Request& request,Response& response){backend_.rotate_user(cookie(request),request.get_header_value("X-CSRF-Token"),request.matches[1].str());json(response,{{"ok",true}});}));
  server_.Post(R"(/api/users/([^/]+)/reset-traffic)",wrap([this](const Request& request,Response& response){backend_.reset_traffic(cookie(request),request.get_header_value("X-CSRF-Token"),request.matches[1].str());json(response,{{"ok",true}});}));
  server_.Get(R"(/api/users/([^/]+)/links)",wrap([this](const Request& request,Response& response){json(response,backend_.links(cookie(request),request.matches[1].str()));}));
  server_.Get(R"(/api/users/([^/]+)/shadowrocket)",wrap([this](const Request& request,Response& response){json(response,backend_.shadowrocket_links(cookie(request),request.matches[1].str()));}));
  server_.Get(R"(/api/users/([^/]+)/qr/([^/]+))",wrap([this](const Request& request,Response& response){response.set_content(backend_.qr(cookie(request),request.matches[1].str(),request.matches[2].str()),"image/png");}));
  server_.Post("/api/password",wrap([this](const Request& request,Response& response) {
    backend_.change_password(cookie(request),request.get_header_value("X-CSRF-Token"),body(request));
    response.set_header("Set-Cookie","xg_session=; HttpOnly; Max-Age=0; Path=/; SameSite=Strict; Secure");json(response,{{"ok",true}});
  }));
  server_.Get("/api/security",wrap([this](const Request& r,Response& s){json(s,backend_.security_status(cookie(r)));}));
  server_.Post("/api/security/setup",wrap([this](const Request& r,Response& s){json(s,backend_.setup_totp(cookie(r),r.get_header_value("X-CSRF-Token"),body(r)));}));
  server_.Post("/api/security/enable",wrap([this](const Request& r,Response& s){json(s,backend_.enable_totp(cookie(r),r.get_header_value("X-CSRF-Token"),body(r)));}));
  server_.Post("/api/security/disable",wrap([this](const Request& r,Response& s){backend_.disable_totp(cookie(r),r.get_header_value("X-CSRF-Token"),body(r));json(s,{{"ok",true}});}));
  server_.Post("/api/security/recovery",wrap([this](const Request& r,Response& s){json(s,backend_.regenerate_recovery(cookie(r),r.get_header_value("X-CSRF-Token"),body(r)));}));
  server_.Get("/api/backups",wrap([this](const Request& r,Response& s){json(s,backend_.backup_status(cookie(r)));}));
  server_.Post("/api/backups",wrap([this](const Request& r,Response& s){json(s,backend_.create_backup(cookie(r),r.get_header_value("X-CSRF-Token")));}));
  server_.Get(R"(/api/backups/([^/]+)/inspect)",wrap([this](const Request& r,Response& s){json(s,backend_.inspect_backup(cookie(r),r.matches[1].str()));}));
  server_.Get(R"(/api/backups/([^/]+)/download)",wrap([this](const Request& r,Response& s){auto id=r.matches[1].str();auto content=backend_.download_backup(cookie(r),id);s.set_header("Content-Disposition","attachment; filename=\""+id+"\"");s.set_content(content,"application/octet-stream");}));
  server_.Post("/api/backups/restore",wrap([this](const Request& r,Response& s){backend_.restore_backup(cookie(r),r.get_header_value("X-CSRF-Token"),body(r));json(s,{{"ok",true}});}));
  server_.Get(R"(/s/([^/]+)/shadowrocket.json)",wrap([this](const Request& request,Response& response) {
    json(response,backend_.shadowrocket_setup(request.matches[1].str()));
  }));
  server_.Get(R"(/s/([^/]+)/shadowrocket\.conf)",wrap([this](const Request& request,Response& response) {
    response.set_content(backend_.shadowrocket_profile(request.matches[1].str()),"text/plain; charset=utf-8");
  }));
  server_.Get(R"(/s/([^/]+)/clash\.yaml)",wrap([this](const Request& request,Response& response) {
    auto [content,info]=backend_.clash_subscription(request.matches[1].str());response.set_content(content,"application/yaml; charset=utf-8");
    response.set_header("subscription-userinfo",info);response.set_header("profile-update-interval","6");response.set_header("Content-Disposition","attachment; filename=\"xdistribute-clash.yaml\"");
  }));
  server_.Get(R"(/s/([^/]+))",wrap([this](const Request& request,Response& response) {
    auto [content,info]=backend_.subscription(request.matches[1].str());response.set_content(content,"text/plain; charset=utf-8");
    response.set_header("subscription-userinfo",info);response.set_header("profile-update-interval","6");response.set_header("Content-Disposition","attachment; filename=\"xdistribute.txt\"");
  }));
}
bool HttpServer::bind() {return server_.bind_to_port("127.0.0.1",backend_.options().port);}
bool HttpServer::listen() {return server_.listen_after_bind();}
void HttpServer::stop() {server_.stop();}
}
