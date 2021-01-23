#include <assert.h>
#include "random.hpp"
#include <stdexcept>
#include <sys/random.h>

void random_init(uint8_t *data, uint32_t size) {
  // If we can't initialize all the random data we want then fail
  if (getrandom(data, size, 0) != size) {
    throw std::runtime_error("failed to initialize random data");
  }
}
