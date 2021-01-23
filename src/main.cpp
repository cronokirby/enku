#include "Key.hpp"
#include <fstream>

int main() {
  auto key = Key::random();
  std::ofstream out{".key.pem"};
  key.write_pem(out);
  return 0;
}
