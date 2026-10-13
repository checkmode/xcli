#include "gateway.hpp"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <algorithm>
#include <array>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace xg {
namespace {
std::string random_bytes(std::size_t count) {
  std::string value(count,'\0');
  if(RAND_bytes(reinterpret_cast<unsigned char*>(value.data()),static_cast<int>(count))!=1)throw std::runtime_error("Random generation failed");
  return value;
}
std::string base32_decode(std::string_view value) {
  std::string out;unsigned bits=0,acc=0;
  for(char c:value) {
    unsigned n;if(c>='A'&&c<='Z')n=static_cast<unsigned>(c-'A');else if(c>='2'&&c<='7')n=static_cast<unsigned>(c-'2'+26);else throw std::runtime_error("Invalid TOTP secret");
    acc=(acc<<5)|n;bits+=5;if(bits>=8){bits-=8;out+=static_cast<char>((acc>>bits)&255);}
  }
  return out;
}
}
std::string unbase64(std::string_view text,std::size_t maximum) {
  if(text.empty())return {};
  if(text.size()%4||text.size()>((maximum+2)/3)*4)throw std::runtime_error("Invalid encoded payload");
  std::size_t padding=0;while(padding<2&&text[text.size()-1-padding]=='=')++padding;
  for(std::size_t i=0;i<text.size()-padding;++i)if(!((text[i]>='A'&&text[i]<='Z')||(text[i]>='a'&&text[i]<='z')||(text[i]>='0'&&text[i]<='9')||text[i]=='+'||text[i]=='/'))throw std::runtime_error("Invalid encoded payload");
  std::string out(text.size()/4*3,'\0');int n=EVP_DecodeBlock(reinterpret_cast<unsigned char*>(out.data()),reinterpret_cast<const unsigned char*>(text.data()),static_cast<int>(text.size()));
  if(n<0||static_cast<std::size_t>(n)<padding)throw std::runtime_error("Invalid encoded payload");
  out.resize(static_cast<std::size_t>(n)-padding);if(out.size()>maximum)throw std::runtime_error("Payload too large");return out;
}
std::string totp_secret() {
  auto bytes=random_bytes(20);static constexpr char alphabet[]="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  std::string out;unsigned bits=0,acc=0;
  for(unsigned char c:bytes){acc=(acc<<8)|c;bits+=8;while(bits>=5){bits-=5;out+=alphabet[(acc>>bits)&31];}}
  return out;
}
std::string totp_code(std::string_view secret,Int timestamp,unsigned digits) {
  if(timestamp<0||(digits!=6&&digits!=8))throw std::runtime_error("Invalid TOTP parameters");
  auto key=base32_decode(secret);std::array<unsigned char,8> counter{};auto step=static_cast<std::uint64_t>(timestamp/30);
  for(int i=7;i>=0;--i){counter[static_cast<std::size_t>(i)]=static_cast<unsigned char>(step&255);step>>=8;}
  std::array<unsigned char,EVP_MAX_MD_SIZE> digest{};unsigned length=0;
  if(!HMAC(EVP_sha1(),key.data(),static_cast<int>(key.size()),counter.data(),counter.size(),digest.data(),&length))throw std::runtime_error("TOTP HMAC failed");
  unsigned offset=digest[length-1]&15;std::uint32_t value=((digest[offset]&127U)<<24)|(digest[offset+1]<<16)|(digest[offset+2]<<8)|digest[offset+3];
  value%=digits==6?1000000U:100000000U;auto out=std::to_string(value);return std::string(digits-out.size(),'0')+out;
}
std::optional<Int> verify_totp(std::string_view secret,std::string_view code,Int timestamp,Int last_step) {
  if(code.size()!=6||!std::all_of(code.begin(),code.end(),[](char c){return c>='0'&&c<='9';}))return std::nullopt;
  for(Int shift:{Int(0),Int(-1),Int(1)}) {Int step=timestamp/30+shift;if(step>last_step&&step>=0&&secure_equal(totp_code(secret,step*30),code))return step;}
  return std::nullopt;
}
void write_private_file(const fs::path& path,std::string_view content,bool replace) {
  auto target=replace?fs::path(path.string()+".tmp-"+random_id()):path;
  int fd=::open(target.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);
  if(fd<0)throw std::runtime_error("Cannot create private file");
  try {
    std::size_t offset=0;while(offset<content.size()){ssize_t written=::write(fd,content.data()+offset,content.size()-offset);if(written<0&&errno==EINTR)continue;if(written<=0)throw std::runtime_error("Private file write failed");offset+=static_cast<std::size_t>(written);}
    if(::fsync(fd)<0)throw std::runtime_error("Private file sync failed");
    ::close(fd);fd=-1;
    if(replace)fs::rename(target,path);
  }catch(...){if(fd>=0)::close(fd);fs::remove(target);throw;}
}
std::string load_secret_key(const fs::path& path) {
  if(!fs::exists(path))write_private_file(path,random_bytes(32));
  int fd=::open(path.c_str(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW);struct stat st{};
  if(fd<0)throw std::runtime_error("Cannot open security key");
  if(::fstat(fd,&st)<0||!S_ISREG(st.st_mode)||st.st_size!=32||(st.st_mode&0007)){::close(fd);throw std::runtime_error("Invalid security key file or permissions");}
  std::string key(32,'\0');ssize_t n=::read(fd,key.data(),key.size());::close(fd);if(n!=32)throw std::runtime_error("Cannot read security key");return key;
}
std::string seal(std::string_view plaintext,std::string_view key,std::string_view context) {
  if(key.size()!=32||plaintext.size()>128*1024*1024)throw std::runtime_error("Invalid encryption parameters");
  auto nonce=random_bytes(12);std::string ciphertext(plaintext.size()+16,'\0'),tag(16,'\0');int n=0,total=0;
  std::unique_ptr<EVP_CIPHER_CTX,decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(),EVP_CIPHER_CTX_free);
  if(!ctx||EVP_EncryptInit_ex(ctx.get(),EVP_aes_256_gcm(),nullptr,reinterpret_cast<const unsigned char*>(key.data()),reinterpret_cast<const unsigned char*>(nonce.data()))!=1||
    EVP_EncryptUpdate(ctx.get(),nullptr,&n,reinterpret_cast<const unsigned char*>(context.data()),static_cast<int>(context.size()))!=1||
    EVP_EncryptUpdate(ctx.get(),reinterpret_cast<unsigned char*>(ciphertext.data()),&n,reinterpret_cast<const unsigned char*>(plaintext.data()),static_cast<int>(plaintext.size()))!=1)throw std::runtime_error("Encryption failed");
  total=n;if(EVP_EncryptFinal_ex(ctx.get(),reinterpret_cast<unsigned char*>(ciphertext.data())+total,&n)!=1||EVP_CIPHER_CTX_ctrl(ctx.get(),EVP_CTRL_GCM_GET_TAG,16,tag.data())!=1)throw std::runtime_error("Encryption failed");
  ciphertext.resize(static_cast<std::size_t>(total+n));return "XGB1"+nonce+tag+ciphertext;
}
std::string unseal(std::string_view ciphertext,std::string_view key,std::string_view context) {
  if(key.size()!=32||ciphertext.size()<32||ciphertext.size()>128*1024*1024||ciphertext.substr(0,4)!="XGB1")throw std::runtime_error("Invalid encrypted data");
  std::string plaintext(ciphertext.size()-32+16,'\0'),tag(ciphertext.substr(16,16));int n=0,total=0;
  std::unique_ptr<EVP_CIPHER_CTX,decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(),EVP_CIPHER_CTX_free);
  if(!ctx||EVP_DecryptInit_ex(ctx.get(),EVP_aes_256_gcm(),nullptr,reinterpret_cast<const unsigned char*>(key.data()),reinterpret_cast<const unsigned char*>(ciphertext.data()+4))!=1||
    EVP_DecryptUpdate(ctx.get(),nullptr,&n,reinterpret_cast<const unsigned char*>(context.data()),static_cast<int>(context.size()))!=1||
    EVP_DecryptUpdate(ctx.get(),reinterpret_cast<unsigned char*>(plaintext.data()),&n,reinterpret_cast<const unsigned char*>(ciphertext.data()+32),static_cast<int>(ciphertext.size()-32))!=1)throw std::runtime_error("Decryption failed");
  total=n;if(EVP_CIPHER_CTX_ctrl(ctx.get(),EVP_CTRL_GCM_SET_TAG,16,tag.data())!=1||EVP_DecryptFinal_ex(ctx.get(),reinterpret_cast<unsigned char*>(plaintext.data())+total,&n)!=1)throw std::runtime_error("Encrypted data authentication failed");
  plaintext.resize(static_cast<std::size_t>(total+n));return plaintext;
}

bool Backend::check_second_factor(Database& database,std::string_view code,bool allow_recovery) {
  auto config=database.one("SELECT * FROM mfa WHERE id=1");if(config->at("enabled").get<Int>()==0)return true;
  auto secret=unseal(unbase64(config->at("secret").get<std::string>(),256),secret_key_,"xcli:mfa:v1");
  auto step=verify_totp(secret,code,now(),config->at("last_step").get<Int>());
  if(step){database.run("UPDATE mfa SET last_step=? WHERE id=1",{*step});return true;}
  if(allow_recovery) {
    auto row=database.one("SELECT hash FROM recovery_codes WHERE hash=? AND used=0",{sha256(code)});
    if(row){database.run("UPDATE recovery_codes SET used=1 WHERE hash=?",{sha256(code)});return true;}
  }
  return false;
}
void Backend::confirm_admin(Database& database,const std::string& token,const Json& input) {
  auto stamp=std::chrono::steady_clock::now();auto& attempts=rate_["stepup:"+sha256(token)];
  while(!attempts.empty()&&stamp-attempts.front()>std::chrono::minutes(15))attempts.pop_front();
  if(attempts.size()>=8)throw HttpError(429,"验证尝试过于频繁，请 15 分钟后重试");
  attempts.push_back(stamp);
  auto password=checked_string(input.value("current_password",Json("")),0,256);
  auto code=checked_string(input.value("code",Json("")),0,128);
  auto admin=database.one("SELECT password FROM admin WHERE id=1");
  if(!admin||!password_check(password,admin->at("password").get<std::string>())||!check_second_factor(database,code))throw HttpError(403,"密码或二次验证码错误");
  attempts.clear();
}
Json Backend::make_recovery(Database& database) {
  database.run("DELETE FROM recovery_codes");Json codes=Json::array();
  for(int i=0;i<10;++i){auto raw=random_id();auto code=raw.substr(0,8)+"-"+raw.substr(8,8)+"-"+raw.substr(16,8)+"-"+raw.substr(24);codes.push_back(code);database.run("INSERT INTO recovery_codes(hash) VALUES(?)",{sha256(code)});}
  return codes;
}
Json Backend::security_status(const std::string& token) {
  session(token);auto database=db();auto row=database.one("SELECT enabled FROM mfa WHERE id=1");
  return {{"enabled",row->at("enabled").get<Int>()!=0},{"recovery_remaining",database.one("SELECT COUNT(*) AS n FROM recovery_codes WHERE used=0")->at("n")}};
}
Json Backend::setup_totp(const std::string& token,const std::string& csrf,const Json& input) {
  std::lock_guard guard(mutation_mutex_);session(token,csrf,true);auto database=db();Transaction transaction(database);
  if(database.one("SELECT enabled FROM mfa WHERE id=1")->at("enabled").get<Int>())throw HttpError(409,"二次验证已启用");
  confirm_admin(database,token,input);auto secret=totp_secret();
  database.run("UPDATE mfa SET pending=?,pending_expires=?,pending_session=? WHERE id=1",{base64(seal(secret,secret_key_,"xcli:mfa:v1")),now()+600,sha256(token)});
  audit(database,"mfa_setup");transaction.commit();
  std::string uri="otpauth://totp/"+url_quote(settings_.at("domain").get<std::string>()+":admin")+"?secret="+secret+"&issuer="+url_quote(settings_.at("domain").get<std::string>())+"&algorithm=SHA1&digits=6&period=30";
  return {{"secret",secret},{"qr","data:image/png;base64,"+base64(qr_png(uri))},{"expires",now()+600}};
}
Json Backend::enable_totp(const std::string& token,const std::string& csrf,const Json& input) {
  std::lock_guard guard(mutation_mutex_);session(token,csrf,true);auto database=db();Transaction transaction(database);
  auto stamp=std::chrono::steady_clock::now();auto& enroll=rate_["enroll:"+sha256(token)];
  while(!enroll.empty()&&stamp-enroll.front()>std::chrono::minutes(15))enroll.pop_front();
  if(enroll.size()>=8)throw HttpError(429,"验证尝试过于频繁，请 15 分钟后重试");
  enroll.push_back(stamp);confirm_admin(database,token,input);
  auto row=database.one("SELECT * FROM mfa WHERE id=1");
  if(row->at("enabled").get<Int>()||row->at("pending_expires").get<Int>()<now()||!secure_equal(row->at("pending_session").get<std::string>(),sha256(token)))throw HttpError(409,"绑定已失效，请重新生成二维码");
  auto secret=unseal(unbase64(row->at("pending").get<std::string>(),256),secret_key_,"xcli:mfa:v1");
  auto step=verify_totp(secret,checked_string(input.value("code",Json("")),0,128),now());
  if(!step){rate_["stepup:"+sha256(token)].push_back(std::chrono::steady_clock::now());throw HttpError(403,"二次验证码错误");}
  database.run("UPDATE mfa SET enabled=1,secret=pending,last_step=?,pending='',pending_expires=0,pending_session='' WHERE id=1",{*step});
  database.run("DELETE FROM sessions WHERE hash<>?",{sha256(token)});database.run("DELETE FROM mfa_sessions");database.run("INSERT INTO mfa_sessions VALUES(?)",{sha256(token)});
  enroll.clear();auto codes=make_recovery(database);audit(database,"mfa_enabled");transaction.commit();return {{"recovery_codes",codes}};
}
void Backend::disable_totp(const std::string& token,const std::string& csrf,const Json& input) {
  std::lock_guard guard(mutation_mutex_);session(token,csrf,true);auto database=db();Transaction transaction(database);confirm_admin(database,token,input);
  database.run("UPDATE mfa SET enabled=0,secret='',last_step=-1,pending='',pending_expires=0,pending_session='' WHERE id=1");database.run("DELETE FROM recovery_codes");database.run("DELETE FROM sessions");database.run("DELETE FROM mfa_sessions");audit(database,"mfa_disabled");transaction.commit();
}
Json Backend::regenerate_recovery(const std::string& token,const std::string& csrf,const Json& input) {
  std::lock_guard guard(mutation_mutex_);session(token,csrf,true);auto database=db();Transaction transaction(database);
  if(!database.one("SELECT enabled FROM mfa WHERE id=1")->at("enabled").get<Int>())throw HttpError(409,"请先启用二次验证");
  confirm_admin(database,token,input);auto codes=make_recovery(database);audit(database,"recovery_regenerated");transaction.commit();return {{"recovery_codes",codes}};
}
}
