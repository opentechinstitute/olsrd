#ifndef _NMEA_RANDOM_H
#define _NMEA_RANDOM_H

#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>

#define NMEA_RANDOM_MAX INT32_MAX

static inline long int nmea_random(const double min, const double max) {
  int32_t value;
  double range = abs(max - min);

#ifdef _WIN32
  value = random();
#else
  int randomFile = open("/dev/urandom", O_RDONLY);
  if (randomFile == -1) {
    randomFile = open("/dev/random", O_RDONLY);
  }

  if ((randomFile == -1) || (read(randomFile, &value, sizeof(value)) != sizeof(value))) {
    value = random();
  }
  close(randomFile);
#endif /* _WIN32 */

  return min + ((abs(value) * range) / NMEA_RANDOM_MAX);
}

static inline void nmea_init_random(void) {
#ifdef _WIN32
  srandom(time(NULL));
  return;
#endif /* _WIN32 */

  srandom(nmea_random(0, NMEA_RANDOM_MAX));
}

#endif /* _NMEA_RANDOM_H */
