#pragma once

#include <stdint.h>

/// Initialize some data with random bytes
///
/// @param data the data to initialize
/// @param size the number of bytes to initialize
void random_init(uint8_t *data, uint32_t size);
