#pragma once

#include "SecretData.hpp"
#include <iostream>
#include <stdint.h>

/// An Encryptor allows us to encrypt data.
///
/// Internally, the Encryptor has access to some kind of key used for symmetric
/// encryption. We can create a new encryptor with a random key, and serialize
/// an Encryptor by serializing that key.
///
/// We can also create an Encryptor by reading back that key from some data.
class Encryptor final {
public:
  /// The number of bytes composing this key
  constexpr static uint32_t KEY_SIZE = 32;

private:
  // By having this as a member, the data will be cleared correctly upon
  // destruction
  SecretData<Encryptor::KEY_SIZE> key;

public:
  /// Create a new Encryptor, with a random key
  static Encryptor random();

  /// Create an Encryptor by reading a key from a file
  static Encryptor read_pem(std::istream &stream);

  /// Serialize this Encryptor by writing out its key
  void write_pem(std::ostream &stream);

  /// Encrypt all the bytes of the in stream, writing them to the out stream.
  ///
  /// This also adds the necessary header.
  void encrypt(std::istream &in, std::ostream &out);
};
