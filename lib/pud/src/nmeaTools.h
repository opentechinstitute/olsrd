#ifndef _PUD_NMEATOOLS_H_
#define _PUD_NMEATOOLS_H_

/* Plugin includes */

/* OLSR includes */

/* System includes */
#include <stdbool.h>
#include <nmea/info.h>

/**
 Enumeration for the fields names of a nmeaINFO structure
 */
typedef enum _NmeaInfoFieldName {
	SMASK, UTC, SIG, FIX, PDOP, HDOP, VDOP, LAT, LON, ELV, SPEED, DIRECTION,
	DECLINATION, SATINFO
} NmeaInfoFieldName;

bool nmeaInfoHasField(int smask, NmeaInfoFieldName fieldName);

bool hasInvalidNmeaChars(const char * str, const char * strName);

void nmeaInfoUnitConversion(nmeaINFO * nmeaInfo);

void sanitiseNmeaInfo(nmeaINFO *nmeaInfo);

#endif /* _PUD_NMEATOOLS_H_ */
