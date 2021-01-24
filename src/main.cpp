#include "Encryptor.hpp"
#include <fstream>

int main(int argc, char **argv) {
  if (argc < 2) {
    std::cerr << "insufficient arguments";
    return -1;
  }

  std::string command{argv[1]};
  if (command == "encrypt") {
    if (argc < 4) {
      std::cerr << "insufficient arguments";
      return -1;
    }
    std::ifstream key_file{argv[2]};
    auto encryptor = Encryptor::read_pem(key_file);
    std::ifstream in{argv[3]};

    encryptor.encrypt(in, std::cout);
  } else if (command == "decrypt") {
    if (argc < 4) {
      std::cerr << "insufficient arguments";
      return -1;
    }

    std::ifstream key_file{argv[2]};
    auto encryptor = Encryptor::read_pem(key_file);

    std::ifstream in{argv[3]};

    encryptor.decrypt(in, std::cout);
  } else if (command == "keygen") {
    if (argc < 3) {
      std::cerr << "insuficcient arguments";
      return -1;
    }

    std::ofstream key_file{argv[2]};
    auto encryptor = Encryptor::random();
    encryptor.write_pem(key_file);
  }

  return 0;
}
