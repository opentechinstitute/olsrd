#ifndef _PUD_GPSCONVERSION_H_
#define _PUD_GPSCONVERSION_H_

/* Plugin includes */

/* OLSR includes */
#include "olsr_protocol.h"

/* System includes */
#include <stdbool.h>
#include <nmea/info.h>

/*
 * Version
 */

/** The version of the transmit sentence */
#define PUD_TX_SENTENCE_VERSION		0

/*
 * Functions
 */

void setupCachedValidityTimeMsn(void);

unsigned int gpsToOlsr(nmeaINFO *nmeaInfo, union olsr_message *olsrMessage,
		unsigned int olsrMessageSize, unsigned long long validityTime);

unsigned int gpsFromOlsr(const union olsr_message *olsrMessage,
		unsigned char *olsrMessagePayload, unsigned char * txGpsBuffer,
		unsigned int txGpsBufferSize);

#endif /* _PUD_GPSCONVERSION_H_ */
