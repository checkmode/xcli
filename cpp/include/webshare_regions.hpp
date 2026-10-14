#pragma once
#include <array>
#include <string_view>

namespace xg {
struct WebshareRegion {
  std::string_view country, label, group, tag;
  int port, socks_port;
};
// Existing four paths and ports are stable; new entrances use separate port ranges.
inline constexpr std::array<WebshareRegion,16> webshare_regions{{
  {"US","美国","北美","residential-11",10110,10120},
  {"JP","日本","亚洲","residential-12",10111,10121},
  {"SG","新加坡","亚洲","residential-13",10112,10122},
  {"ZZ","全球","全球","residential-14",10113,10123},
  {"HK","香港","亚洲","residential-15",10200,10300},
  {"TW","台湾","亚洲","residential-16",10201,10301},
  {"KR","韩国","亚洲","residential-17",10202,10302},
  {"TH","泰国","亚洲","residential-18",10203,10303},
  {"MY","马来西亚","亚洲","residential-19",10204,10304},
  {"IN","印度","亚洲","residential-20",10205,10305},
  {"CA","加拿大","北美","residential-21",10206,10306},
  {"GB","英国","欧洲","residential-22",10207,10307},
  {"DE","德国","欧洲","residential-23",10208,10308},
  {"FR","法国","欧洲","residential-24",10209,10309},
  {"NL","荷兰","欧洲","residential-25",10210,10310},
  {"AU","澳大利亚","大洋洲","residential-26",10211,10311}
}};
}
