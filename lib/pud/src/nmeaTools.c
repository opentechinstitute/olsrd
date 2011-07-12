#include "nmeaTools.h"

/* Plugin includes */

/* OLSR includes */
#include "pud.h"

/* System includes */
#include <nmea/sentence.h>
#include <nmea/gmath.h>
#include <string.h>
#include <assert.h>
#include <stddef.h>
#include <time.h>
#include <sys/timeb.h>
#include <math.h>

/**
 Determine whether a given nmeaINFO structure has a certain field.

 nmeaINFO dependencies:
 field/sentence	GPGGA	GPGSA	GPGSV	GPRMC	GPVTG
 smask:			x		x		x		x		x
 utc:			x						x
 sig:			x						x
 fix:					x				x
 PDOP:					x
 HDOP:			x		x
 VDOP:					x
 lat:			x						x
 lon:			x						x
 elv:			x
 speed:									x		x
 direction: 							x		x
 declination: 									x
 satinfo:				x		x

 @param smask
 the smask of a nmeaINFO structure
 @param fieldName
 the field name

 @return
 - true when the nmeaINFO structure has the field
 - false otherwise
 */
bool nmeaInfoHasField(int smask, NmeaInfoFieldName fieldName) {
	switch (fieldName) {
		case SMASK:
			return true;

		case UTC:
		case SIG:
		case LAT:
		case LON:
			return ((smask & (GPGGA | GPRMC)) != 0);

		case FIX:
			return ((smask & (GPGSA | GPRMC)) != 0);

		case PDOP:
		case VDOP:
			return ((smask & GPGSA) != 0);

		case HDOP:
			return ((smask & (GPGGA | GPGSA)) != 0);

		case ELV:
			return ((smask & GPGGA) != 0);

		case SPEED:
		case DIRECTION:
			return ((smask & (GPRMC | GPVTG)) != 0);

		case DECLINATION:
			return ((smask & GPVTG) != 0);

		case SATINFO:
			return ((smask & (GPGSA | GPGSV)) != 0);

		default:
			return false;
	}
}

/**
 Determine whether the given string contains characters that are not allowed in
 an NMEA string.

 @param str
 The string to check
 @param strName
 The name of the string to report when invalid characters are encountered

 @return
 - true when the string has invalid characters
 - false otherwise
 */
bool hasInvalidNmeaChars(const char * str, const char * strName) {
	static const unsigned char invalidChars[] = { '\n', '\r', '$', '*', ',',
			'!', '\\', '^', '~' };
	static const char * invalidCharsNames[] = { "line feed (\\n)",
			"carriage return (\\r)", "sentence delimiter ($)",
			"checksum field delimiter (*)", "comma (,)",
			"exclamation mark (!)", "backslash (\\)", "^ (^)", "tilde (~)" };

	size_t i;
	size_t j;

	for (i = 0; i < strlen(str); i++) {
		unsigned char c = str[i];

		if ((c < 32) || (c > 126)) {
			pudError(false, "Configured %s (%s) can not contain non-printable"
				" characters (codes [32, 126])", strName, str);
			return true;
		}

		for (j = 0; j < sizeof(invalidChars); j++) {
			if (c == invalidChars[j]) {
				pudError(false,
						"Configured %s (%s) can not contain %s characters",
						strName, str, invalidCharsNames[j]);
				return true;
			}
		}
	}

	return false;
}

/**
 Converts the position entry fields to degrees and DOP entry fields to meters.
 We use only these units internally.

 @param nmeaInfo
 the position entry
 */
void nmeaInfoUnitConversion(nmeaINFO * nmeaInfo) {
	assert (nmeaInfo != NULL);

	/* smask (already in correct format) */

	/* utc (already in correct format) */

	/* sig (already in correct format) */
	/* fix (already in correct format) */

	if (nmeaInfoHasField(nmeaInfo->smask, PDOP)) {
		nmeaInfo->PDOP = nmea_dop2meters(nmeaInfo->PDOP);
	}

	if (nmeaInfoHasField(nmeaInfo->smask, HDOP)) {
		nmeaInfo->HDOP = nmea_dop2meters(nmeaInfo->HDOP);
	}

	if (nmeaInfoHasField(nmeaInfo->smask, VDOP)) {
		nmeaInfo->VDOP = nmea_dop2meters(nmeaInfo->VDOP);
	}

	if (nmeaInfoHasField(nmeaInfo->smask, LAT)) {
		nmeaInfo->lat = nmea_ndeg2degree(nmeaInfo->lat);
	}

	if (nmeaInfoHasField(nmeaInfo->smask, LON)) {
		nmeaInfo->lon = nmea_ndeg2degree(nmeaInfo->lon);
	}

	/* elv (already in correct format) */
	/* speed (already in correct format) */
	/* direction (already in correct format) */
	/* declination (already in correct format) */

	/* satinfo (not used) */
}

/**
 Sanitise the NMEA info: makes sure that latitude is in the range [-90, 90],
 longitude is in the range [-180, 180], speed is positive, direction is in the
 range [0, 360>. The NMEA info must already have undergone unit conversion by
 means of the nmeaInfoUnitConversion function.

 @param nmeaInfo
 the NMEA info structure in which to adjust the latitude and longitude
 */
void sanitiseNmeaInfo(nmeaINFO *nmeaInfo) {
	double lat = 0;
	double lon = 0;
	double speed = 0;
	double direction = 0;
	bool latAdjusted = false;
	bool lonAdjusted = false;
	bool speedAdjusted = false;
	bool directionAdjusted = false;

	if (!nmeaInfoHasField(nmeaInfo->smask, UTC)) {
		/* we ensure that we ALWAYS have utc */
		struct timeb tp;
		struct tm nowStruct;

		(void) ftime(&tp);
		gmtime_r(&tp.time, &nowStruct);

		nmeaInfo->utc.year = nowStruct.tm_year;
		nmeaInfo->utc.mon = nowStruct.tm_mon;
		nmeaInfo->utc.day = nowStruct.tm_mday;
		nmeaInfo->utc.hour = nowStruct.tm_hour;
		nmeaInfo->utc.min = nowStruct.tm_min;
		nmeaInfo->utc.sec = nowStruct.tm_sec;
		nmeaInfo->utc.hsec = (tp.millitm / 10);
	}

	if (!nmeaInfoHasField(nmeaInfo->smask, SIG)) {
		nmeaInfo->sig = NMEA_SIG_BAD;
	}

	if (!nmeaInfoHasField(nmeaInfo->smask, FIX)) {
		nmeaInfo->fix = NMEA_FIX_BAD;
	}

	if (!nmeaInfoHasField(nmeaInfo->smask, PDOP)) {
		nmeaInfo->PDOP = 0;
	} else {
		nmeaInfo->PDOP = fabs(nmeaInfo->PDOP);
	}

	if (!nmeaInfoHasField(nmeaInfo->smask, HDOP)) {
		nmeaInfo->HDOP = 0;
	} else {
		nmeaInfo->HDOP = fabs(nmeaInfo->HDOP);
	}

	if (!nmeaInfoHasField(nmeaInfo->smask, VDOP)) {
		nmeaInfo->VDOP = 0;
	} else {
		nmeaInfo->VDOP = fabs(nmeaInfo->VDOP);
	}

	if (!nmeaInfoHasField(nmeaInfo->smask, LAT)) {
		nmeaInfo->lat = 0;
	}

	if (!nmeaInfoHasField(nmeaInfo->smask, LON)) {
		nmeaInfo->lon = 0;
	}

	if (!nmeaInfoHasField(nmeaInfo->smask, ELV)) {
		nmeaInfo->elv = 0;
	}

	if (!nmeaInfoHasField(nmeaInfo->smask, SPEED)) {
		nmeaInfo->speed = 0;
	}

	if (!nmeaInfoHasField(nmeaInfo->smask, DIRECTION)) {
		nmeaInfo->direction = 0;
	}

	if (!nmeaInfoHasField(nmeaInfo->smask, DECLINATION)) {
		nmeaInfo->declination = 0;
	}

	/* satinfo is not used */

	/*
	 * lat
	 */

	lat = nmeaInfo->lat;
	lon = nmeaInfo->lon;

	/* force lat in [-180, 180] */
	while (unlikely(lat < -180.0)) {
		lat += 360.0;
		latAdjusted = true;
	}
	while (unlikely(lat > 180.0)) {
		lat -= 360.0;
		latAdjusted = true;
	}

	/* lat is now in [-180, 180] */
	assert (lat >= -180.0);
	assert (lat <= 180.0);

	/* force lat from <90, 180] in [90, 0] */
	if (unlikely(lat > 90.0)) {
		lat = 180.0 - lat;
		lon += 180.0;
		latAdjusted = true;
		lonAdjusted = true;
	}

	/* force lat from [-180, -90> in [0, -90] */
	if (unlikely(lat < -90.0)) {
		lat = -180.0 - lat;
		lon += 180.0;
		latAdjusted = true;
		lonAdjusted = true;
	}

	/* lat is now in [-90, 90] */
	assert (lat >= -90.0);
	assert (lat <= 90.0);

	if (latAdjusted) {
		nmeaInfo->lat = lat;
	}

	/*
	 * lon
	 */

	/* force lon in [-180, 180] */
	while (unlikely(lon < -180.0)) {
		lon += 360.0;
		lonAdjusted = true;
	}
	while (unlikely(lon > 180.0)) {
		lon -= 360.0;
		lonAdjusted = true;
	}

	/* lon is now in [-180, 180] */
	assert (lon >= -180.0);
	assert (lon <= 180.0);

	if (lonAdjusted) {
		nmeaInfo->lon = lon;
	}

	/*
	 * speed
	 */

	speed = nmeaInfo->speed;
	direction = nmeaInfo->direction;

	if (unlikely(speed < 0.0)) {
		speed = -speed;
		direction += 180.0;
		speedAdjusted = true;
		directionAdjusted = true;
	}

	/* speed is now in [0, max> */
	assert (speed >= 0.0);

	if (speedAdjusted) {
		nmeaInfo->speed = speed;
	}

	/*
	 * direction
	 */

	/* force direction in [0, 360> */
	while (unlikely(direction < 0.0)) {
		direction += 360.0;
		directionAdjusted = true;
	}
	while (unlikely(direction >= 360.0)) {
		direction -= 360.0;
		directionAdjusted = true;
	}

	/* direction is now in [0, 360> */
	assert (direction >= 0.0);
	assert (direction < 360.0);

	if (directionAdjusted) {
		nmeaInfo->direction = direction;
	}
}
