#include "Key.hpp"

// We use 256 bits, since that's the size mandated by ChaCha20
constexpr uint32_t KEY_SIZE = 256;

Key::Key() {
  data = new uint8_t[KEY_SIZE];
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
