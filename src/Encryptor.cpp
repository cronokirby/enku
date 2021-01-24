#include "Encryptor.hpp"
#include "random.hpp"
#include <assert.h>
#include <iostream>

Encryptor Encryptor::random() {
  Encryptor enc;
  random_init(enc.key.data, KEY_SIZE);
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
  stream.getline((char *)key_line.data, BASE64_KEY_SIZE + 1);
  if (stream.gcount() != BASE64_KEY_SIZE + 1) {
    throw std::runtime_error("Invalid key length");
  }

  Encryptor enc;
  uint8_t *cursor = enc.key.data;
  for (uint32_t i = 0; i < BASE64_KEY_SIZE; i += 4) {
    uint8_t c1 = unbase64(key_line[i]);
    uint8_t c2 = unbase64(key_line[i + 1]);
    uint8_t c3 = unbase64(key_line[i + 2]);
    uint8_t c4 = unbase64(key_line[i + 3]);

    *cursor++ = (c2 << 6) | c1;
    *cursor++ = (c3 << 4) | (c2 >> 2);
    if (cursor == enc.key.data + KEY_SIZE) {
      break;
    }
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
    uint8_t x1 = key[i];
    uint8_t x2 = key[i + 1];
    uint8_t x3 = i + 2 >= KEY_SIZE ? 0 : key[i + 2];

    stream.put(base64(x1));
    stream.put(base64((x2 << 2) | (x1 >> 6)));
    stream.put(base64((x3 << 4) | (x2 >> 4)));
    stream.put(base64(x3 >> 2));
  }

  uint8_t x1 = key[KEY_SIZE - 2];
  uint8_t x2 = key[KEY_SIZE - 1];
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
  constexpr static uint32_t SIZE = 16;

  SecretData<SIZE, uint32_t> state;

  void qround(uint32_t a, uint32_t b, uint32_t c, uint32_t d) {
    chacha_qround(state[a], state[b], state[c], state[d]);
  }

  void inner_block() {
    qround(0, 4, 8, 12);
    qround(1, 5, 9, 13);
    qround(2, 6, 10, 14);
    qround(3, 7, 11, 15);
    qround(0, 5, 10, 15);
    qround(1, 6, 11, 12);
    qround(2, 7, 8, 13);
    qround(3, 4, 9, 14);
  }

  ChaChaState(const ChaChaState &that) {
    for (uint32_t i = 0; i < SIZE; ++i) {
      state[i] = that.state[i];
    }
  }

public:
  constexpr static uint32_t BLOCK_SIZE = 64;

  ChaChaState(uint8_t *key, uint8_t *nonce) {
    uint32_t *cursor = state.data;
    *cursor++ = 0x61707865;
    *cursor++ = 0x3320646e;
    *cursor++ = 0x79622d32;
    *cursor++ = 0x6b206574;

    for (uint32_t i = 0; i < Encryptor::KEY_SIZE; i += 4) {
      *cursor++ = read_u32_le(key + i);
    }

    *cursor++ = 0;

    for (uint32_t i = 0; i < NONCE_SIZE; i += 4) {
      *cursor++ = read_u32_le(nonce + i);
    }
  }

  ChaChaState(const ChaChaState &that, uint32_t ctr)
      : ChaChaState{that} {
    state[12] = ctr;
  }

  void shuffle() {
    ChaChaState working{*this};

    for (uint32_t i = 0; i < 10; ++i) {
      working.inner_block();
    }

    for (uint32_t i = 0; i < SIZE; ++i) {
      state[i] += working.state[i];
    }
  }

  void encrypt(uint8_t *bytes, uint32_t n) const {
    uint32_t state_n = n >> 2;
    for (uint32_t i = 0; i < state_n; ++i) {
      *bytes++ = state[i];
      *bytes++ = state[i] >> 8;
      *bytes++ = state[i] >> 16;
      *bytes++ = state[i] >> 24;
    }
    uint32_t remaining = n & 0x3;
    if (remaining == 0) {
      return;
    }
    uint32_t last = state[state_n];
    for (uint32_t i = 0; i < remaining; ++i) {
      *bytes++ = last;
      last >>= 8;
    }
  }
};

void Encryptor::encrypt(std::istream &in, std::ostream &out) {
  uint8_t nonce[NONCE_SIZE];
  random_init(nonce, NONCE_SIZE);

  out << "ENKU";
  out.write((char*)nonce, NONCE_SIZE);

  ChaChaState initial{key.data, nonce};

  uint8_t block[ChaChaState::BLOCK_SIZE];
  for (uint32_t ctr = 1; !in.eof(); ++ctr) {
    in.read((char*)block, ChaChaState::BLOCK_SIZE);
    uint32_t read = in.gcount();

    ChaChaState iter{initial, ctr};
    iter.shuffle();
    iter.encrypt(block, read);

    out.write((char*)block, read);
  }
}
