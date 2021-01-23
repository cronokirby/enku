#include "Key.hpp"
#include "random.hpp"
#include <assert.h>

// We use 256 bits, since that's the size mandated by ChaCha20
constexpr uint32_t KEY_SIZE = 256;

Key::Key() {
  data = new uint8_t[KEY_SIZE];
}

Key Key::random() {
  Key key;
  random_init(key.data, KEY_SIZE);
  return key;
}

Key::~Key() {
  // Using an opaque pointer here is necessary to avoid compiler optimizations.
  // Without it, the compiler would like to completely remove this zeroing,
  // since it sees that data is going to be deleted afterwards.
  volatile uint8_t *opaque = static_cast<volatile uint8_t *>(data);
  for (uint32_t i = 0; i < KEY_SIZE; ++i) {
    opaque[i] = 0;
  }
  delete[] data;
}

constexpr char BASE64_TABLE[65] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

constexpr char base64(uint8_t c) {
  assert(c < 64);
  return BASE64_TABLE[c];
}

constexpr char *PEM_START = "-----BEGIN ENKU PRIVATE KEY-----\n";
constexpr char *PEM_END = "-----END ENKU PRIVATE KEY-----\n";

void Key::write_pem(std::ostream &stream) {
  stream << PEM_START;
  uint32_t block_size = 1 << 5;
  uint32_t blocks = KEY_SIZE >> 5;
  for (uint32_t block = 0; block < blocks; ++block) {
    for (uint32_t bi = 0; bi < block_size; bi += 3) {
      uint32_t j = (block << 5) | bi;
      uint8_t x1 = data[j];
      uint8_t x2 = data[j + 1];
      uint8_t x3 = data[j + 2];

      stream.put(base64(x1 & 0x3F));
      stream.put(base64((x2 & 0xF) | (x1 >> 6)));
      stream.put(base64((x3 & 0x3) | (x2 >> 4)));
      stream.put(base64(x3 >> 6));
    }
    stream.put('\n');
  }
  stream << PEM_END;
}
