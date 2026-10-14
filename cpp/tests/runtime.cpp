#include "gateway.hpp"
#include <fstream>
#include <iostream>
#include <sys/stat.h>
#include <unistd.h>
using namespace xg;
int main() {
  auto root=fs::temp_directory_path()/("xcli-runtime-unit-"+random_id());fs::create_directory(root);
  try {
    std::ofstream(root/"uptime")<<"1234.5 600.0\n";
    std::ofstream(root/"loadavg")<<"1.25 2.50 3.75 1/10 123\n";
    std::ofstream(root/"meminfo")<<"MemTotal: 1000 kB\nMemAvailable: 250 kB\nMemFree: 100 kB\nSwapTotal: 500 kB\nSwapFree: 200 kB\n";
    std::ofstream(root/"stat")<<"cpu 100 20 30 500 50 10 20 30 90 10\nbtime 1000\n";
    auto sample=linux_host_sample(root,root);
    if(sample["uptime_seconds"]!=1234.5||sample["memory"]["used"]!=750*1024||sample["swap"]["used"]!=300*1024||sample["cpu_ticks"]!=Json({760,550})||sample["load"][2]!=3.75||sample["disk"]["total"].get<std::uint64_t>()==0)throw std::runtime_error("Host metric sources or guest accounting incorrect");
    fs::remove(root/"meminfo");fs::remove(root/"stat");auto missing=linux_host_sample(root,root);
    if(!missing["memory"].is_null()||!missing["cpu_ticks"].is_null())throw std::runtime_error("Missing host data was reported as zero");
    if(::mkfifo((root/"meminfo").c_str(),0600)!=0)throw std::runtime_error("Cannot create nonregular fixture");
    const auto start=std::chrono::steady_clock::now();auto fifo=linux_host_sample(root,root);
    if(!fifo["memory"].is_null()||std::chrono::steady_clock::now()-start>std::chrono::seconds(1))throw std::runtime_error("Nonregular diagnostic source blocked sampling");
    auto invalid=inspect_core_process(Options(),"invalid",false);
    if(invalid["state"]!="unknown"||invalid.contains("version"))throw std::runtime_error("Unverified process reported a version");
    fs::remove_all(root);std::cout<<"Runtime source, missing-data and CPU accounting checks passed\n";return 0;
  }catch(const std::exception& e){fs::remove_all(root);std::cerr<<e.what()<<'\n';return 1;}
}
