#include "Key.hpp"
#include <fstream>

int main() {
  std::ifstream in{".key.pem"};
  auto key = Key::read_pem(in);
  std::ofstream out{".key2.pem"};
  key.write_pem(out);
  return 0;
}
