// Test-only driver: inspect a disposable proc fixture, not production state.
#include "gateway.hpp"
#include <iostream>
int main(int argc, char** argv) {
  if (argc != 3) return 2;
  try { std::cout << xg::linux_host_sample(argv[1], argv[2]).dump() << '\n'; return 0; }
  catch (const std::exception&) { return 1; }
}
