#include "http_queue.hpp"
#include <atomic>
#include <chrono>
#include <future>
#include <iostream>
#include <memory>

int main() {
  using namespace std::chrono_literals;
  xg::BackpressureQueue<httplib::ThreadPool, 2> queue(1);
  std::promise<void> started, release, attempting;
  auto gate = release.get_future().share();
  std::atomic<int> completed = 0;
  queue.enqueue([&] { started.set_value(); gate.wait(); ++completed; });
  started.get_future().wait();
  queue.enqueue([&] { ++completed; });
  queue.enqueue([&] { ++completed; });
  auto fourth = std::async(std::launch::async, [&] {
    attempting.set_value();
    queue.enqueue([&] { ++completed; });
  });
  attempting.get_future().wait();
  bool bounded = fourth.wait_for(100ms) == std::future_status::timeout;
  release.set_value();
  fourth.get();
  queue.shutdown();
  if(!bounded || completed != 4) {
    std::cerr << "Queue did not bound pending work or drain accepted tasks\n";
    return 1;
  }
  std::unique_ptr<httplib::TaskQueue> selected(xg::make_http_queue());
  selected->enqueue([&] { ++completed; });
  selected->shutdown();
  return completed == 5 ? 0 : 1;
}
