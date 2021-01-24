#pragma once
#include <stdint.h>

/// Represents a piece of managed secret data.
///
/// The point of using this is to create a piece of memory that will
/// automatically be cleared when this object gets destructed
template <uint32_t N, typename T = uint8_t> struct SecretData {
  T *data;

  /// Construct a new instance of this, with uninitialized memory
  SecretData() {
    data = new T[N];
  }

  /// Destroy this object, clearing out the memory it owns
  ~SecretData() {
    // Using an opaque pointer here is necessary to avoid compiler
    // optimizations. Without it, the compiler would like to completely remove
    // this zeroing, since it sees that data is going to be deleted afterwards.
    volatile T *opaque = static_cast<volatile T *>(data);
    for (uint32_t i = 0; i < N; ++i) {
      opaque[i] = 0;
    }
    delete[] data;
  }

  const T &operator[](uint32_t i) const {
    return data[i];
  }

  T &operator[](uint32_t i) {
    return data[i];
  }
};
