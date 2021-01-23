#pragma once

#include <stdint.h>

/// Represents a 256 bit secret key, used for encryption.
///
/// The point of using this class is that it will zero out the memory upon
/// destruction, which can prevent information leakage, in some situations.
class Key final {
  /// The actual bytes
  uint8_t *data;

public:
  /// Create a new key, initialized randomly
  static Key random();
  /// Create a new key, initializing some memory for the key on the heap
  Key();
  /// Delete a key, zeroing out memory, and freeing it
  ~Key();
};
