#include "Key.hpp"
#include "random.hpp"
#include <assert.h>
#include <iostream>

Key Key::random() {
  Key key;
  random_init(key.data.bytes, KEY_SIZE);
  return key;
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
    uint8_t x1 = data.bytes[i];
    uint8_t x2 = data.bytes[i + 1];
    uint8_t x3 = data.bytes[i + 2];

    stream.put(base64(x1 & 0x3F));
    stream.put(base64((x2 & 0xF) | (x1 >> 6)));
    stream.put(base64((x3 & 0x3) | (x2 >> 4)));
    stream.put(base64(x3 >> 6));
  }
  uint8_t x1 = data.bytes[KEY_SIZE - 2];
  uint8_t x2 = data.bytes[KEY_SIZE - 1];
  stream.put(base64(x1 & 0x3F));
  stream.put(base64((x2 & 0xF) | (x1 >> 6)));
  stream.put(base64(x2 >> 4));

  stream << PEM_END;
}
