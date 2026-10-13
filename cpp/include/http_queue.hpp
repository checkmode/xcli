#pragma once
#include <httplib.h>
#include <cstddef>
#include <functional>
#include <semaphore>
#include <type_traits>
#include <utility>

namespace xg {
// Older distro httplib cannot reject a full queue. Apply backpressure to its
// accept thread, while retaining the same bound on pending connections.
template<class Pool, std::ptrdiff_t Pending = 128>
class BackpressureQueue final : public httplib::TaskQueue {
  using Result = decltype(std::declval<Pool&>().enqueue(std::declval<std::function<void()>>()));
  Pool pool_;
  std::counting_semaphore<Pending> available_{Pending};
 public:
  explicit BackpressureQueue(std::size_t threads = 8) : pool_(threads) {}
  Result enqueue(std::function<void()> function) override {
    available_.acquire();
    auto task = [this, function = std::move(function)] { available_.release(); function(); };
    try {
      if constexpr(std::is_same_v<Result, bool>) {
        if(!pool_.enqueue(std::move(task))) { available_.release(); return false; }
        return true;
      } else {
        pool_.enqueue(std::move(task));
      }
    } catch(...) { available_.release(); throw; }
  }
  void shutdown() override { pool_.shutdown(); }
};

template<class Pool = httplib::ThreadPool>
httplib::TaskQueue* make_http_queue() {
  if constexpr(std::is_constructible_v<Pool, std::size_t, std::size_t>) return new Pool(8, 128);
  else return new BackpressureQueue<Pool>();
}
}
