#include "Encryptor.hpp"
#include "random.hpp"
#include <assert.h>
#include <iostream>

Encryptor Encryptor::random() {
  Encryptor enc;
  random_init(enc.key.bytes, KEY_SIZE);
  return enc;
}

constexpr char BASE64_TABLE[65] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

constexpr char base64(uint8_t c) {
  return BASE64_TABLE[c & 0x3F];
}

uint8_t unbase64(uint8_t c) {
  if (c == '=') {
    return 0;
  }
  if (c == '+') {
    return 62;
  }
  if (c == '/') {
    return 63;
  }
  if (c >= 'A' && c <= 'Z') {
    return c - 'A';
  }
  if (c >= 'a' && c <= 'z') {
    return c - 'a' + 26;
  }
  if (c >= '0' && c <= '9') {
    return c - '0' + 52;
  }
  throw std::runtime_error("invalid base64 character");
}

constexpr char PEM_START[] = "-----BEGIN ENKU PRIVATE KEY-----\n";
constexpr char PEM_END[] = "-----END ENKU PRIVATE KEY-----\n";

// How many bytes does it take to encode our key in base 64
constexpr uint32_t BASE64_KEY_SIZE = 44;

Encryptor Encryptor::read_pem(std::istream &stream) {
  for (uint32_t i = 0; i < std::char_traits<char>::length(PEM_START); ++i) {
    if (stream.get() != PEM_START[i]) {
      throw std::runtime_error("Invalid PEM header");
    }
  }

  // We need an extra slot for the '\0'
  SecretData<BASE64_KEY_SIZE + 1> key_line;
  stream.getline((char *)key_line.bytes, BASE64_KEY_SIZE + 1);
  if (stream.gcount() != BASE64_KEY_SIZE + 1) {
    throw std::runtime_error("Invalid key length");
  }

  Encryptor enc;
  uint8_t *cursor = enc.key.bytes;
  for (uint32_t i = 0; i < BASE64_KEY_SIZE; i += 4) {
    uint8_t c1 = unbase64(key_line.bytes[i]);
    uint8_t c2 = unbase64(key_line.bytes[i + 1]);
    uint8_t c3 = unbase64(key_line.bytes[i + 2]);
    uint8_t c4 = unbase64(key_line.bytes[i + 3]);

    *cursor++ = (c2 << 6) | c1;
    *cursor++ = (c3 << 4) | (c2 >> 2);
    *cursor++ = (c4 << 2) | (c3 >> 4);
  }

  for (uint32_t i = 0; i < std::char_traits<char>::length(PEM_END); ++i) {
    if (stream.get() != PEM_END[i]) {
      throw std::runtime_error("Invalid PEM footer");
    }
  }
  return enc;
}

void Encryptor::write_pem(std::ostream &stream) {
  stream << PEM_START;

  for (uint32_t i = 0; i + 2 < KEY_SIZE; i += 3) {
    uint8_t x1 = key.bytes[i];
    uint8_t x2 = key.bytes[i + 1];
    uint8_t x3 = i + 2 >= KEY_SIZE ? 0 : key.bytes[i + 2];

    stream.put(base64(x1));
    stream.put(base64((x2 << 2) | (x1 >> 6)));
    stream.put(base64((x3 << 4) | (x2 >> 4)));
    stream.put(base64(x3 >> 2));
  }

  uint8_t x1 = key.bytes[KEY_SIZE - 2];
  uint8_t x2 = key.bytes[KEY_SIZE - 1];
  stream.put(base64(x1));
  stream.put(base64((x2 << 2) | (x1 >> 6)));
  stream.put(base64(x2 >> 4));
  stream.put('=');

  stream << '\n' << PEM_END;
}

constexpr void chacha_qround(uint32_t &a, uint32_t &b, uint32_t &c,
                             uint32_t &d) {
  a += b;
  d ^= a;
  d <<= 16;

  c += d;
  b ^= c;
  b <<= 12;

  a += b;
  d ^= a;
  d <<= 8;

  c += d;
  b ^= c;
  b <<= 7;
}

constexpr uint32_t NONCE_SIZE = 12;

constexpr uint32_t read_u32_le(uint8_t *bytes) {
  return (bytes[3] << 24) | (bytes[2] << 16) | (bytes[1] << 8) | bytes[0];
}

class ChaChaState {
  constexpr static uint32_t SIZE = 4;

  uint32_t *data;

  void qround(uint32_t a, uint32_t b, uint32_t c, uint32_t d) {
    chacha_qround(data[a], data[b], data[c], data[d]);
  }

public:
  ChaChaState(uint8_t *key, uint8_t *nonce) {
    data = new uint32_t[SIZE * SIZE];

    uint32_t *cursor = data;
    *cursor++ = 0x61707865;
    *cursor++ = 0x3320646e;
    *cursor++ = 0x79622d32;
    *cursor++ = 0x6b206574;

    for (uint32_t i = 0; i < Encryptor::KEY_SIZE; i += 4) {
      *cursor++ = read_u32_le(key + i);
    }

    *cursor++ = 0;

    for (uint32_t i = 0; i < NONCE_SIZE; ++i) {
      *cursor++ = read_u32_le(nonce + i);
    }
  }

  ChaChaState(const ChaChaState &state, uint32_t ctr) {
    data = new uint32_t[SIZE * SIZE];

    for (uint32_t i = 0; i < SIZE * SIZE; ++i) {
      data[i] = state.data[i];
    }
  }

  ~ChaChaState() {
    delete[] data;
  }
};
