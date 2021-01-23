#include "Key.hpp"
#include "random.hpp"
#include <assert.h>
#include <iostream>

// We use 32 * 8 = 256 bits, since that's the size mandated by ChaCha20
constexpr uint32_t KEY_SIZE = 32;

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

constexpr char PEM_START[] = "-----BEGIN ENKU PRIVATE KEY-----\n";
constexpr char PEM_END[] = "\n-----END ENKU PRIVATE KEY-----\n";

void Key::write_pem(std::ostream &stream) {
  stream << PEM_START;

  for (uint32_t i = 0; i + 2 < KEY_SIZE; i += 3) {
    std::cout << i << '\n';
    uint8_t x1 = data[i];
    uint8_t x2 = data[i + 1];
    uint8_t x3 = data[i + 2];

    stream.put(base64(x1 & 0x3F));
    stream.put(base64((x2 & 0xF) | (x1 >> 6)));
    stream.put(base64((x3 & 0x3) | (x2 >> 4)));
    stream.put(base64(x3 >> 6));
  }
  uint8_t x1 = data[KEY_SIZE - 2];
  uint8_t x2 = data[KEY_SIZE - 1];
  stream.put(base64(x1 & 0x3F));
  stream.put(base64((x2 & 0xF) | (x1 >> 6)));
  stream.put(base64(x2 >> 4));

  stream << PEM_END;
}
