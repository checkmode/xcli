#include "gateway.hpp"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <png.h>
#include <qrencode.h>
#include <algorithm>
#include <array>
#include <fstream>
#include <limits>

namespace xg {
namespace {
std::vector<unsigned char> random_bytes(std::size_t size) {
  std::vector<unsigned char> bytes(size);
  if (RAND_bytes(bytes.data(),static_cast<int>(bytes.size())) != 1)
    throw std::runtime_error("Secure random generation failed");
  return bytes;
}
std::string hex(const unsigned char* data, std::size_t size) {
  static constexpr char alphabet[] = "0123456789abcdef";
  std::string result; result.reserve(size*2);
  for (std::size_t i=0;i<size;++i) { result += alphabet[data[i]>>4]; result += alphabet[data[i]&15]; }
  return result;
}
std::optional<std::vector<unsigned char>> unhex(std::string_view text) {
  if (text.size()%2) return std::nullopt;
  std::vector<unsigned char> result;
  auto digit=[](char c) { if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return c-'a'+10; if(c>='A'&&c<='F')return c-'A'+10; return -1; };
  for(std::size_t i=0;i<text.size();i+=2) {
    int a=digit(text[i]),b=digit(text[i+1]);
    if(a<0||b<0)return std::nullopt;
    result.push_back(static_cast<unsigned char>(a*16+b));
  }
  return result;
}
std::array<unsigned char,32> derive(std::string_view password, const std::vector<unsigned char>& salt) {
  std::array<unsigned char,32> result{};
  if(EVP_PBE_scrypt(password.data(),password.size(),salt.data(),salt.size(),16384,8,1,64*1024*1024,result.data(),result.size())!=1)
    throw std::runtime_error("Password derivation failed");
  return result;
}
struct Codepoint { std::uint32_t value; std::size_t begin,end; };
std::vector<Codepoint> decode_utf8(std::string_view text) {
  std::vector<Codepoint> values;
  for(std::size_t i=0;i<text.size();) {
    std::size_t start=i; auto c=static_cast<unsigned char>(text[i++]);
    std::uint32_t value=c, minimum=0; unsigned extra=0;
    if(c<0x80){}
    else if(c>=0xc2&&c<=0xdf){value=c&0x1f;extra=1;minimum=0x80;}
    else if(c>=0xe0&&c<=0xef){value=c&0xf;extra=2;minimum=0x800;}
    else if(c>=0xf0&&c<=0xf4){value=c&7;extra=3;minimum=0x10000;}
    else throw HttpError(422,"请输入有效 UTF-8 文本");
    while(extra--) {
      if(i>=text.size())throw HttpError(422,"请输入有效 UTF-8 文本");
      c=static_cast<unsigned char>(text[i++]);
      if((c&0xc0)!=0x80)throw HttpError(422,"请输入有效 UTF-8 文本");
      value=(value<<6)|(c&0x3f);
    }
    if(value<minimum||value>0x10ffff||(value>=0xd800&&value<=0xdfff))throw HttpError(422,"请输入有效 UTF-8 文本");
    values.push_back({value,start,i});
  }
  return values;
}
bool unicode_space(std::uint32_t c) {
  return (c>=9&&c<=13)||(c>=0x1c&&c<=0x20)||c==0x85||c==0xa0||c==0x1680||
    (c>=0x2000&&c<=0x200a)||c==0x2028||c==0x2029||c==0x202f||c==0x205f||c==0x3000;
}
}
Int now() { return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count(); }
std::string sha256(std::string_view text) {
  std::array<unsigned char,EVP_MAX_MD_SIZE> output{}; unsigned int size=0;
  if(EVP_Digest(text.data(),text.size(),output.data(),&size,EVP_sha256(),nullptr)!=1)
    throw std::runtime_error("Digest failed");
  return hex(output.data(),size);
}
std::string base64(std::string_view bytes) {
  if(bytes.size()>static_cast<std::size_t>(std::numeric_limits<int>::max()))throw std::runtime_error("Encoding input too large");
  std::string result(4*((bytes.size()+2)/3)+1,'\0');
  auto length=EVP_EncodeBlock(reinterpret_cast<unsigned char*>(result.data()),reinterpret_cast<const unsigned char*>(bytes.data()),static_cast<int>(bytes.size()));
  result.resize(static_cast<std::size_t>(length));return result;
}
std::string random_token() {
  auto bytes=random_bytes(32);
  std::string result=base64(std::string_view(reinterpret_cast<const char*>(bytes.data()),bytes.size()));
  std::replace(result.begin(),result.end(),'+','-');std::replace(result.begin(),result.end(),'/','_');
  while(!result.empty()&&result.back()=='=')result.pop_back();
  return result;
}
std::string random_id() { auto bytes=random_bytes(16);bytes[6]=(bytes[6]&15)|0x40;bytes[8]=(bytes[8]&63)|0x80;return hex(bytes.data(),bytes.size()); }
std::string random_uuid() { auto id=random_id();return id.substr(0,8)+"-"+id.substr(8,4)+"-"+id.substr(12,4)+"-"+id.substr(16,4)+"-"+id.substr(20); }
std::string password_hash(std::string_view password) { auto salt=random_bytes(16);auto value=derive(password,salt);return hex(salt.data(),salt.size())+":"+hex(value.data(),value.size()); }
bool password_check(std::string_view password,std::string_view encoded) {
  if(encoded.size()!=97||encoded[32]!=':')return false;
  auto salt=unhex(encoded.substr(0,32)),expected=unhex(encoded.substr(33));
  if(!salt||!expected)return false;
  auto actual=derive(password,*salt);
  return CRYPTO_memcmp(actual.data(),expected->data(),actual.size())==0;
}
bool secure_equal(std::string_view a,std::string_view b) { return a.size()==b.size()&&CRYPTO_memcmp(a.data(),b.data(),a.size())==0; }
std::string url_quote(std::string_view value,bool plus,bool safe_slash) {
  static constexpr char chars[]="0123456789ABCDEF";
  std::string out;
  for(unsigned char c:value) {
    if((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='-'||c=='_'||c=='.'||c=='~'||(safe_slash&&c=='/'))out+=static_cast<char>(c);
    else if(plus&&c==' ')out+='+';
    else {out+='%';out+=chars[c>>4];out+=chars[c&15];}
  }
  return out;
}
std::string qr_png(std::string_view text) {
  if(text.size()>4096)throw std::runtime_error("QR input too long");
  static std::mutex mutex;
  std::lock_guard guard(mutex);
  std::unique_ptr<QRcode,decltype(&QRcode_free)> code(QRcode_encodeData(static_cast<int>(text.size()),reinterpret_cast<const unsigned char*>(text.data()),0,QR_ECLEVEL_M),QRcode_free);
  if(!code)throw std::runtime_error("QR generation failed");
  constexpr int scale=10,border=4;
  int width=(code->width+2*border)*scale;
  std::vector<unsigned char> pixels(static_cast<std::size_t>(width)*static_cast<std::size_t>(width),255);
  for(int y=0;y<code->width;++y)for(int x=0;x<code->width;++x)if(code->data[y*code->width+x]&1)
    for(int yy=0;yy<scale;++yy)std::fill_n(pixels.begin()+static_cast<std::ptrdiff_t>(((y+border)*scale+yy)*width+(x+border)*scale),scale,0);
  png_image image{};image.version=PNG_IMAGE_VERSION;image.width=static_cast<png_uint_32>(width);image.height=static_cast<png_uint_32>(width);image.format=PNG_FORMAT_GRAY;
  png_alloc_size_t size=0;
  if(!png_image_write_to_memory(&image,nullptr,&size,0,pixels.data(),0,nullptr))throw std::runtime_error("PNG sizing failed");
  std::string output(size,'\0');
  if(!png_image_write_to_memory(&image,output.data(),&size,0,pixels.data(),0,nullptr))throw std::runtime_error("PNG encoding failed");
  output.resize(size);return output;
}
std::string read_file(const fs::path& path,std::size_t max_size) {
  std::ifstream stream(path,std::ios::binary);
  if(!stream)throw std::runtime_error("Cannot read required file");
  std::string result;std::array<char,8192> chunk{};
  while(stream) {
    stream.read(chunk.data(),chunk.size());auto count=static_cast<std::size_t>(stream.gcount());
    if(result.size()+count>max_size)throw std::runtime_error("Required file exceeds size limit");
    result.append(chunk.data(),count);
  }
  return result;
}
std::string checked_string(const Json& value,std::size_t min,std::size_t max) {
  if(!value.is_string())throw HttpError(422,"字段类型不正确");
  auto text=value.get<std::string>();auto points=decode_utf8(text);
  if(points.size()<min||points.size()>max)throw HttpError(422,"字段长度不符合要求");
  return text;
}
std::string user_name(const Json& value) {
  auto text=checked_string(value,1,60);auto points=decode_utf8(text);
  std::size_t begin=0,end=points.size();
  while(begin<end&&unicode_space(points[begin].value))++begin;
  while(end>begin&&unicode_space(points[end-1].value))--end;
  if(begin==end)throw HttpError(422,"请输入有效名称");
  for(std::size_t i=begin;i<end;++i)if(points[i].value<32)throw HttpError(422,"请输入有效名称");
  return text.substr(points[begin].begin,points[end-1].end-points[begin].begin);
}
}
