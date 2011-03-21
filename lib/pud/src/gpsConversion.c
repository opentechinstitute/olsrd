#include "gpsConversion.h"

/* Plugin includes */
#include "wireFormat.h"
#include "pud.h"
#include "configuration.h"
#include "nodeIdConversion.h"
#include "nmeaTools.h"

/* OLSR includes */
#include "olsr.h"

/* System includes */
#include <stdint.h>
#include <nmea/time.h>
#include <time.h>
#include <nmea/gmath.h>
#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <nmea/tok.h>
#include <netinet/in.h>

/*
 * GPS Information Conversion Functions For OLSR GPS Wire Format
 */

/* ************************************************************************
 * TIME
 * ************************************************************************ */

/**
 Convert the time of a nmeaINFO structure to the time for an OLSR message (the
 number of seconds after midnight).

 @param nmeaTime
 The NMEA info containing the time

 @return
 The time converted to the format for the wire format
 */
static unsigned long getTimeForOlsr(nmeaTIME * nmeaTime) {
	return ((nmeaTime->hour * 60 * 60) + (nmeaTime->min * 60) + nmeaTime->sec);
}

/**
 Convert the time of an OLSR message (the number of seconds after midnight) to
 a time structure, based on midnight of the current day.

 @param olsrTime
 The time from the wire format
 @param nowStruct
 A pointer to the time structure into which to put the converted time
 */
static void getTimeFromOlsr(uint32_t olsrTime, struct tm *nowStruct) {
	unsigned int secNow;

	time_t now = time(NULL);
	gmtime_r(&now, nowStruct);

	secNow = ((nowStruct->tm_hour * 60 * 60) + (nowStruct->tm_min * 60)
			+ nowStruct->tm_sec);

	if (secNow <= (12 * 60 * 60)) {
		/* we are now in the first 12h of the day */
		if (unlikely(olsrTime > (secNow + (12 * 60 * 60)))) {
			/* the message was sent more than 12h later in time:
			 the message was sent yesterday: adjust the date by -1 day */
			now -= (24 * 60 * 60);
			gmtime_r(&now, nowStruct);
		}
	} else {
		/* we are now in the last 12h of the day */
		if (unlikely(olsrTime < (secNow - (12 * 60 * 60)))) {
			/* the message was sent more than 12h earlier in time:
			 the message was sent tomorrow: adjust the date by +1 day */
			now += (24 * 60 * 60);
			gmtime_r(&now, nowStruct);
		}
	}

	nowStruct->tm_mon++;
	nowStruct->tm_hour = ((olsrTime % (24 * 60 * 60)) / 3600);
	nowStruct->tm_min = ((olsrTime % (60 * 60)) / 60);
	nowStruct->tm_sec = (olsrTime % 60);
}

/* ************************************************************************
 * LATITUDE
 * ************************************************************************ */

/**
 Convert the latitude of a nmeaINFO structure to the latitude for an OLSR
 message

 @param infoLat
 The latitude as contained in an NMEA info structure (in degrees)

 @return
 The latitude converted to the format for the wire format
 */
static unsigned long getLatitudeForOlsr(double infoLat) {
	double lat = infoLat;

	/* lat is in [-90, 90] */
	assert (lat >= -90.0);
	assert (lat <= 90.0);

	lat /= 180.0;
	/* lat is now in [-0.5, 0.5] */

	lat += 0.5;
	/* lat is now in [0, 1] */

	lat *= (double) (1 << PUD_LATITUDE_BITS);
	/* lat is now in [0, LATITUDE_BITS] */

	/* clip max */
	if (unlikely(lat > (double)((1 << PUD_LATITUDE_BITS) - 1))) {
		lat = (double) ((1 << PUD_LATITUDE_BITS) - 1);
	}
	/* lat is now in [0, 2^LATITUDE_BITS> */

	return lrint(lat);
}

/**
 Convert the latitude of an OLSR message to the latitude for a nmeaINFO
 structure

 @param olsrLat
 The latitude as contained in the wire format

 @return
 The latitude converted to the format for an NMEA info structure (in degrees)
 */
static double getLatitudeFromOlsr(uint32_t olsrLat) {
	double lat = (double) olsrLat;

	/* lat is in [0, 2^LATITUDE_BITS> */

	/* take half of the rounding error */
	lat += 0.5;

	lat /= (double) (1 << PUD_LATITUDE_BITS);
	/* lat is now in [0, 1> */

	lat -= 0.5;
	/* lat is now in [-0.5, 0.5> */

	lat *= 180.0;
	/* lat is now in [-90, 90> */

	return lat;
}

/* ************************************************************************
 * LONGITUDE
 * ************************************************************************ */

/**
 Convert the longitude of a nmeaINFO structure to the longitude for an OLSR
 message

 @param infoLon
 The longitude as contained in an NMEA info structure (in degrees)

 @return
 The longitude converted to the format for the wire format
 */
static unsigned long getLongitudeForOlsr(double infoLon) {
	double lon = infoLon;

	/* lon is in [-180, 180] */
	assert (lon >= -180.0);
	assert (lon <= 180.0);

	lon /= 360.0;
	/* lon is now in [-0.5, 0.5] */

	lon += 0.5;
	/* lon is now in [0, 1] */

	lon *= (double) (1 << PUD_LONGITUDE_BITS);
	/* lon is now in [0, LONGITUDE_BITS] */

	/* clip max */
	if (unlikely(lon > (double)((1 << PUD_LATITUDE_BITS) - 1))) {
		lon = (double) ((1 << PUD_LATITUDE_BITS) - 1);
	}

	/* lon is now in [0, 2^LONGITUDE_BITS> */

	return lrint(lon);
}

/**
 Convert the longitude of an OLSR message to the longitude for a nmeaINFO
 structure

 @param olsrLon
 The longitude as contained in the wire format

 @return
 The longitude converted to the format for an NMEA info structure (in degrees)
 */
static double getLongitudeFromOlsr(uint32_t olsrLon) {
	double lon = (double) olsrLon;

	/* lon is in [0, 2^LONGITUDE_BITS> */

	/* take half of the rounding error */
	lon += 0.5;

	lon /= (1 << PUD_LONGITUDE_BITS);
	/* lon is now in [0, 1> */

	lon -= 0.5;
	/* lon is now in [-0.5, 0.5> */

	lon *= 360.0;
	/* lon is now in [-180, 180> */

	return lon;
}

/* ************************************************************************
 * ALTITIDE
 * ************************************************************************ */

/**
 Convert the altitude of a nmeaINFO structure to the altitude for an OLSR
 message

 @param infoElv
 The altitude as contained in an NMEA info structure

 @return
 The altitude converted to the format for the wire format
 */
static long getAltitudeForOlsr(double infoElv) {
	double elv = infoElv;

	if (unlikely(elv > PUD_ALTITUDE_MAX)) {
		elv = PUD_ALTITUDE_MAX;
	} else if (unlikely(elv < PUD_ALTITUDE_MIN)) {
		elv = PUD_ALTITUDE_MIN;
	}

	elv -= PUD_ALTITUDE_MIN;

	return lrint(elv);
}

/**
 Convert the altitude of an OLSR message to the altitude for a nmeaINFO
 structure

 @param olsrAlt
 The altitude as contained in the wire format

 @return
 The altitude converted to the format for an NMEA info structure
 */
static long getAltitudeFromOlsr(uint32_t olsrAlt) {
	return (olsrAlt + PUD_ALTITUDE_MIN);
}

/* ************************************************************************
 * SPEED
 * ************************************************************************ */

/**
 Convert the speed of a nmeaINFO structure to the speed for an OLSR message

 @param infoSpeed
 The speed as contained in an NMEA info structure

 @return
 The speed converted to the format for the wire format
 */
static long getSpeedForOlsr(double infoSpeed) {
	if (unlikely(infoSpeed < 0)) {
		return 0;
	}
	if (unlikely(infoSpeed > PUD_SPEED_MAX)) {
		return PUD_SPEED_MAX;
	}

	return lrint(infoSpeed);
}

/**
 Convert the speed of an OLSR message to the speed for a nmeaINFO structure

 @param olsrSpeed
 The speed as contained in the wire format

 @return
 The speed converted to the format for an NMEA info structure
 */
static unsigned long getSpeedFromOlsr(uint32_t olsrSpeed) {
	return olsrSpeed;
}

/* ************************************************************************
 * TRACK
 * ************************************************************************ */

/**
 Convert the track angle of a nmeaINFO structure to the track angle for an OLSR
 message

 @param infoTrack
 The track angle as contained in an NMEA info structure

 @return
 The track angle converted to the format for the wire format
 */
static long getTrackForOlsr(double infoTrack) {
	return lrint(infoTrack);
}

/**
 Convert the track angle of an OLSR message to the track angle for a nmeaINFO
 structure

 @param olsrTrack
 The track angle as contained in the wire format

 @return
 The track angle converted to the format for an NMEA info structure
 */
static unsigned long getTrackFromOlsr(uint32_t olsrTrack) {
	return olsrTrack;
}

/* ************************************************************************
 * HDOP
 * ************************************************************************ */

/**
 Convert the HDOP of a nmeaINFO structure to the HDOP for an OLSR message

 @param infoHdop
 The HDOP as contained in an NMEA info structure

 @return
 The HDOP converted to the format for the wire format
 */
static long getHdopForOlsr(double infoHdop) {
	double infoHdopInternal = infoHdop;

	if (unlikely(infoHdopInternal > PUD_HDOP_MAX)) {
		infoHdopInternal = PUD_HDOP_MAX;
	}

	return lrint(infoHdopInternal / PUD_HDOP_RESOLUTION);
}

/**
 Convert the HDOP of an OLSR message to the HDOP for a nmeaINFO structure

 @param olsrHdop
 The HDOP as contained in the wire format

 @return
 The HDOP converted to the format for an NMEA info structure
 */
static double getHdopFromOlsr(uint32_t olsrHdop) {
	return (olsrHdop * PUD_HDOP_RESOLUTION);
}

/* ************************************************************************
 * VALIDITY TIME
 * ************************************************************************ */

/** Determine the validity time in seconds from the OLSR wire format value */
#define PUD_VALIDITY_TIME_FROM_OLSR(msn, lsn) ((((lsn) + 16) * (1 << (msn))) - 16)

unsigned long long cachedValidityTimeMsn[16];

/**
 Setup of cache of calculated most significant nibble results of the validity
 time calculation to speed up run-time calculations.
 */
void setupCachedValidityTimeMsn(void) {
	unsigned int msn;
	for (msn = 0; msn < 16; msn++) {
		cachedValidityTimeMsn[msn] = PUD_VALIDITY_TIME_FROM_OLSR(msn, 0);
	}
}

/**
 Convert the validity time to the validity time for an OLSR message

 @param validityTime
 The validity time (in seconds)

 @return
 The validity time converted to the format for the wire format
 */
static unsigned char getValidityTimeForOlsr(unsigned long long validityTime) {
	unsigned int msn = 1;
	unsigned long long lsn = 0;
	unsigned long long upperBound = cachedValidityTimeMsn[msn];
	while ((msn < 16) && (validityTime >= upperBound)) {
		msn++;
		upperBound = cachedValidityTimeMsn[msn];
	}
	msn--;

	if (unlikely(validityTime >= upperBound)) {
		lsn = 15;
	} else {
		unsigned long lowerBound = PUD_VALIDITY_TIME_FROM_OLSR(msn, 0);
		unsigned long resolution = (1 << msn);
		lsn = ((validityTime - lowerBound + (resolution >> 1)) / resolution);
	}

	assert (msn <= 15);
	assert (lsn <= 15);

	return (msn << 4) | lsn;
}

/**
 Convert the validity time of an OLSR message to the validity time for internal
 use.

 @param internal
 The validity time as contained in the wire format

 @return
 The validity time converted to seconds
 */
static unsigned long getValidityTimeFromOlsr(unsigned char internal) {
	return PUD_VALIDITY_TIME_FROM_OLSR(internal >> 4, internal % 16);
}

/* ************************************************************************
 * OLSR --> External
 * ************************************************************************ */

/**
 Convert an OLSR message into a string to multicast on the LAN

 @param olsrMessage
 A pointer to the OLSR message
 @param olsrMessagePayload
 A pointer to the GPS message in the OLSR message
 @param txGpsBuffer
 A pointer to the buffer in which the transmit string can be written
 @param txGpsBufferSize
 The size of the txGpsBuffer

 @return
 - the length of the transmit string placed in the txGpsBuffer
 - 0 (zero) in case of an error
 */
unsigned int gpsFromOlsr(const union olsr_message *olsrMessage,
		unsigned char *olsrMessagePayload, unsigned char * txGpsBuffer,
		unsigned int txGpsBufferSize) {
	PudOlsrWireFormat *olsrGpsMessage =
			(PudOlsrWireFormat *) olsrMessagePayload;
	const GpsInfo* gpsMessage = &olsrGpsMessage->gpsInfo;

	unsigned long validityTime;

	struct tm timeStruct;
	char latitudeString[PUD_TX_LATITUDE_DIGITS + 1];
	const char * latitudeHemisphere;
	char longitudeString[PUD_TX_LONGITUDE_DIGITS + 1];
	const char * longitudeHemisphere;
	char altitudeString[PUD_TX_ALTITUDE_DIGITS + 1];
	char speedString[PUD_TX_SPEED_DIGITS + 1];
	char trackString[PUD_TX_TRACK_DIGITS + 1];
	char hdopString[PUD_TX_HDOP_DIGITS + 1];

	char nodeIdTypeString[PUD_TX_NODEIDTYPE_DIGITS + 1];
	char nodeIdString[PUD_TX_NODEID_BUFFERSIZE + 1];
	const char * nodeId;

	unsigned int transmitStringLength;

	if (unlikely(olsrGpsMessage->version != PUD_WIRE_FORMAT_VERSION)) {
		/* currently we can only handle our own version */
		pudError(false, "Can not handle version %u OLSR PUD messages"
			" (only version %u): message ignored", olsrGpsMessage->version,
				PUD_WIRE_FORMAT_VERSION);
		return 0;
	}

	validityTime = getValidityTimeFromOlsr(olsrGpsMessage->validityTime);

	/* time is ALWAYS present so we can just use it */
	getTimeFromOlsr(gpsMessage->time, &timeStruct);

	if (likely(nmeaInfoHasField(olsrGpsMessage->smask, LAT))) {
		int chars;
		double latitude = getLatitudeFromOlsr(gpsMessage->lat);

		if (latitude >= 0) {
			latitudeHemisphere = "N";
		} else {
			latitudeHemisphere = "S";
			latitude = -latitude;
		}
		latitude = nmea_degree2ndeg(latitude);

		chars = snprintf(&latitudeString[0], PUD_TX_LATITUDE_DIGITS,
				"%." PUD_TX_LATITUDE_DECIMALS "f", latitude);
		if (likely(chars < PUD_TX_LATITUDE_DIGITS)) {
			latitudeString[chars] = '\0';
		} else {
			latitudeString[PUD_TX_LATITUDE_DIGITS] = '\0';
		}
	} else {
		latitudeHemisphere = "";
		latitudeString[0] = '\0';
	}

	if (likely(nmeaInfoHasField(olsrGpsMessage->smask, LON))) {
		int chars;
		double longitude = getLongitudeFromOlsr(gpsMessage->lon);

		if (longitude >= 0) {
			longitudeHemisphere = "E";
		} else {
			longitudeHemisphere = "W";
			longitude = -longitude;
		}
		longitude = nmea_degree2ndeg(longitude);

		chars = snprintf(&longitudeString[0], PUD_TX_LONGITUDE_DIGITS,
				"%." PUD_TX_LONGITUDE_DECIMALS "f", longitude);
		if (likely(chars < PUD_TX_LONGITUDE_DIGITS)) {
			longitudeString[chars] = '\0';
		} else {
			longitudeString[PUD_TX_LONGITUDE_DIGITS] = '\0';
		}
	} else {
		longitudeHemisphere = "";
		longitudeString[0] = '\0';
	}

	if (likely(nmeaInfoHasField(olsrGpsMessage->smask, ELV))) {
		int chars = snprintf(&altitudeString[0], PUD_TX_ALTITUDE_DIGITS, "%ld",
				getAltitudeFromOlsr(gpsMessage->alt));
		if (likely(chars < PUD_TX_ALTITUDE_DIGITS)) {
			altitudeString[chars] = '\0';
		} else {
			altitudeString[PUD_TX_ALTITUDE_DIGITS] = '\0';
		}
	} else {
		altitudeString[0] = '\0';
	}

	if (likely(nmeaInfoHasField(olsrGpsMessage->smask, SPEED))) {
		int chars = snprintf(&speedString[0], PUD_TX_SPEED_DIGITS, "%lu",
				getSpeedFromOlsr(gpsMessage->speed));
		if (likely(chars < PUD_TX_SPEED_DIGITS)) {
			speedString[chars] = '\0';
		} else {
			speedString[PUD_TX_SPEED_DIGITS] = '\0';
		}
	} else {
		speedString[0] = '\0';
	}

	if (likely(nmeaInfoHasField(olsrGpsMessage->smask, DIRECTION))) {
		int chars = snprintf(&trackString[0], PUD_TX_TRACK_DIGITS, "%lu",
				getTrackFromOlsr(gpsMessage->track));
		if (likely(chars < PUD_TX_TRACK_DIGITS)) {
			trackString[chars] = '\0';
		} else {
			trackString[PUD_TX_TRACK_DIGITS] = '\0';
		}
	} else {
		trackString[0] = '\0';
	}

	if (likely(nmeaInfoHasField(olsrGpsMessage->smask, HDOP))) {
		int chars = snprintf(&hdopString[0], PUD_TX_HDOP_DIGITS,
				"%." PUD_TX_HDOP_DECIMALS "f", nmea_meters2dop(getHdopFromOlsr(
						gpsMessage->hdop)));
		if (likely(chars < PUD_TX_HDOP_DIGITS)) {
			hdopString[chars] = '\0';
		} else {
			hdopString[PUD_TX_HDOP_DIGITS] = '\0';
		}
	} else {
		hdopString[0] = '\0';
	}

	getNodeInfoFromOlsr(olsrMessage, olsrGpsMessage, &nodeIdString[0],
			PUD_TX_NODEID_BUFFERSIZE, &nodeId, &nodeIdTypeString[0]);

	transmitStringLength = nmea_printf((char *) txGpsBuffer, txGpsBufferSize
			- 1, "$P%s," /* prefix (always) */
		"%u," /* sentence version (always) */
		"%s,%s," /* nodeIdType/nodeId (always) */
		"%02u%02u%02u," /* date (always) */
		"%02u%02u%02u," /* time (always) */
		"%lu," /* validity time (always) */
		"%s,%s," /* latitude (optional) */
		"%s,%s," /* longitude (optional) */
		"%s," /* altitude (optional) */
		"%s," /* speed (optional) */
		"%s," /* track (optional) */
		"%s" /* hdop (optional) */
	, getTxNmeaMessagePrefix(), PUD_TX_SENTENCE_VERSION, &nodeIdTypeString[0],
			nodeId, timeStruct.tm_mday, timeStruct.tm_mon, (timeStruct.tm_year
					% 100), timeStruct.tm_hour, timeStruct.tm_min,
			timeStruct.tm_sec, validityTime, &latitudeString[0],
			latitudeHemisphere, &longitudeString[0], longitudeHemisphere,
			&altitudeString[0], &speedString[0], &trackString[0],
			&hdopString[0]);

	if (unlikely(transmitStringLength > (txGpsBufferSize - 1))) {
		pudError(false, "String to transmit on non-OLSR is too large, need"
			" at least %u bytes, skipped", transmitStringLength);
		return 0;
	}

	if (unlikely(transmitStringLength == (txGpsBufferSize - 1))) {
		txGpsBuffer[txGpsBufferSize - 1] = '\0';
	} else {
		txGpsBuffer[transmitStringLength] = '\0';
	}

	return transmitStringLength;
}

/* ************************************************************************
 * External --> OLSR
 * ************************************************************************ */

/**
 Convert a nmeaINFO structure into an OLSR message.

 @param nmeaInfo
 A pointer to a nmeaINFO structure
 @param olsrMessage
 A pointer to an OLSR message in which to place the converted information
 @param olsrMessageSize
 The maximum number of bytes available for the olsrMessage
 @param validityTime
 the validity time of the message

 @return
 - the aligned size of the converted information
 - 0 (zero) in case of an error
 */
unsigned int gpsToOlsr(nmeaINFO *nmeaInfo, union olsr_message *olsrMessage,
		unsigned int olsrMessageSize, unsigned long long validityTime) {
	PudOlsrWireFormat * olsrGpsMessage;
	unsigned int aligned_size;
	unsigned int aligned_size_remainder;
	size_t nodeLength;

	if (olsr_cnf->ip_version == AF_INET) {
		olsrGpsMessage = (PudOlsrWireFormat *) &olsrMessage->v4.message;
	} else {
		olsrGpsMessage = (PudOlsrWireFormat *) &olsrMessage->v6.message;
	}

	/*
	 * Compose message contents
	 */

	olsrGpsMessage->version = PUD_WIRE_FORMAT_VERSION;
	olsrGpsMessage->validityTime = getValidityTimeForOlsr(validityTime);
	olsrGpsMessage->smask = nmeaInfo->smask;

	/* utc is always present, we make sure of that, so just use it */
	olsrGpsMessage->gpsInfo.time = getTimeForOlsr(&nmeaInfo->utc);

	if (likely(nmeaInfoHasField(nmeaInfo->smask, LAT))) {
		olsrGpsMessage->gpsInfo.lat = getLatitudeForOlsr(nmeaInfo->lat);
	} else {
		olsrGpsMessage->gpsInfo.lat = (1 << (PUD_LATITUDE_BITS - 1));
	}

	if (likely(nmeaInfoHasField(nmeaInfo->smask, LON))) {
		olsrGpsMessage->gpsInfo.lon = getLongitudeForOlsr(nmeaInfo->lon);
	} else {
		olsrGpsMessage->gpsInfo.lon = (1 << (PUD_LONGITUDE_BITS - 1));
	}

	if (likely(nmeaInfoHasField(nmeaInfo->smask, ELV))) {
		olsrGpsMessage->gpsInfo.alt = getAltitudeForOlsr(nmeaInfo->elv);
	} else {
		olsrGpsMessage->gpsInfo.alt = -PUD_ALTITUDE_MIN;
	}

	if (likely(nmeaInfoHasField(nmeaInfo->smask, SPEED))) {
		olsrGpsMessage->gpsInfo.speed = getSpeedForOlsr(nmeaInfo->speed);
	} else {
		olsrGpsMessage->gpsInfo.speed = 0;
	}

	if (likely(nmeaInfoHasField(nmeaInfo->smask, DIRECTION))) {
		olsrGpsMessage->gpsInfo.track = getTrackForOlsr(nmeaInfo->direction);
	} else {
		olsrGpsMessage->gpsInfo.track = 0;
	}

	if (likely(nmeaInfoHasField(nmeaInfo->smask, HDOP))) {
		olsrGpsMessage->gpsInfo.hdop = getHdopForOlsr(nmeaInfo->HDOP);
	} else {
		olsrGpsMessage->gpsInfo.hdop = PUD_HDOP_MAX;
	}

	nodeLength = setupNodeInfoForOlsr(olsrGpsMessage, olsrMessageSize);

	/*
	 * Messages in OLSR are 4-byte aligned: align
	 */

	/* size = type, string, string terminator */
	aligned_size = PUD_OLSRWIREFORMATSIZE + nodeLength;
	aligned_size_remainder = (aligned_size % 4);
	if (aligned_size_remainder != 0) {
		aligned_size += (4 - aligned_size_remainder);
	}

	/*
	 * Fill message headers (fill ALL fields, except message)
	 * Note: olsr_vtime is currently unused, we use it for our validity time.
	 */

	if (olsr_cnf->ip_version == AF_INET) {
		/* IPv4 */

		olsrMessage->v4.olsr_msgtype = PUD_OLSR_MSG_TYPE;
		olsrMessage->v4.olsr_vtime = reltime_to_me(validityTime * 1000);
		/* message->v4.olsr_msgsize at the end */
		memcpy(&olsrMessage->v4.originator, &olsr_cnf->main_addr,
				olsr_cnf->ipsize);
		olsrMessage->v4.ttl = getOlsrTtl();
		olsrMessage->v4.hopcnt = 0;
		olsrMessage->v4.seqno = htons(get_msg_seqno());

		/* add length of message->v4 fields */
		aligned_size += (sizeof(olsrMessage->v4)
				- sizeof(olsrMessage->v4.message));
		olsrMessage->v4.olsr_msgsize = htons(aligned_size);
	} else {
		/* IPv6 */

		olsrMessage->v6.olsr_msgtype = PUD_OLSR_MSG_TYPE;
		olsrMessage->v6.olsr_vtime = reltime_to_me(validityTime * 1000);
		/* message->v6.olsr_msgsize at the end */
		memcpy(&olsrMessage->v6.originator, &olsr_cnf->main_addr,
				olsr_cnf->ipsize);
		olsrMessage->v6.ttl = getOlsrTtl();
		olsrMessage->v6.hopcnt = 0;
		olsrMessage->v6.seqno = htons(get_msg_seqno());

		/* add length of message->v6 fields */
		aligned_size += (sizeof(olsrMessage->v6)
				- sizeof(olsrMessage->v6.message));
		olsrMessage->v6.olsr_msgsize = htons(aligned_size);
	}

	/* pad with zeroes */
	if (aligned_size_remainder != 0) {
		memset(&(((char *) &olsrGpsMessage->nodeInfo.nodeIdType)[nodeLength]),
				0, (4 - aligned_size_remainder));
	}

	return aligned_size;
}
