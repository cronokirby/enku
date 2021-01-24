#include "Encryptor.hpp"
#include <fstream>

int main() {
  std::ifstream key_file{".key.pem"};
  auto encryptor = Encryptor::read_pem(key_file);

  std::ifstream in{"hello.txt"};
  std::ofstream out{"hello.bin"};
  encryptor.encrypt(in, out);

  return 0;
}
