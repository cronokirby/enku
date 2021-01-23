#pragma once

#include "SecretData.hpp"
#include <ostream>
#include <stdint.h>

/// Represents a 256 bit secret key, used for encryption.
///
/// This aguments SecretData with some utilities for random initialization,
/// as well as utilities for dealing with PEM files.
class Key final {
public:
  constexpr static uint32_t KEY_SIZE = 32;

private:
  // By having this as a member, the data will be cleared correctly upon destruction
  SecretData<Key::KEY_SIZE> data;

public:
  /// Create a new key, initialized randomly
  static Key random();
  /// Write out this key in PEM format to some output stream
  void write_pem(std::ostream &stream);
};
