#ifndef _OLSR_RANDOM_H
#define _OLSR_RANDOM_H

#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>

#define OLSR_RANDOM_MAX INT32_MAX

static inline long int olsr_random(void) {
#ifdef _WIN32
  return random();
#endif /* _WIN32 */

  int32_t value;
  int randomFile = open("/dev/urandom", O_RDONLY);

  if (randomFile == -1) {
    randomFile = open("/dev/random", O_RDONLY);
  }

  if ((randomFile == -1) || (read(randomFile, &value, sizeof(value)) != sizeof(value))) {
    value = random();
  }

  if (randomFile != -1) {
    close(randomFile);
  }

  return abs(value);
}

static inline void olsr_init_random(void) {
  srandom(time(NULL));
}

#endif /* _OLSR_RANDOM_H */
