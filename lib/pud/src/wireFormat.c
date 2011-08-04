#include "wireFormat.h"

/* Plugin includes */
#include "compiler.h"

/* System includes */
#include <stdlib.h>
#include <stdbool.h>
#include <math.h>
#include <assert.h>

/*
 * GPS Information Conversion Functions For OLSR GPS Wire Format
 */

/* ************************************************************************
 * OLSR Header
 * ************************************************************************ */

/**
 Determine the originator of an OLSR message

 @param ipVersion
 The IP version
 @param olsrMessage
 A pointer to the OLSR message
 @return
 A pointer to the originator address
 */
inline union olsr_ip_addr * getOlsrMessageOriginator(int ipVersion,
		union olsr_message * olsrMessage) {
	if (ipVersion == AF_INET) {
		return (union olsr_ip_addr *) &olsrMessage->v4.originator;
	}

	return (union olsr_ip_addr *) &olsrMessage->v6.originator;
}

/**
 Determine the size of an OLSR message

 @param ipVersion
 The IP version
 @param olsrMessage
 A pointer to the OLSR message
 @return
 The size of the OLSR message
 */
inline unsigned short getOlsrMessageSize(int ipVersion,
		union olsr_message * olsrMessage) {
	if (ipVersion == AF_INET) {
		return ntohs(olsrMessage->v4.olsr_msgsize);
	}

	return ntohs(olsrMessage->v6.olsr_msgsize);
}

/**
 Determine the address of the position update message in an OLSR message

 @param ipVersion
 The IP version
 @param olsrMessage
 A pointer to the OLSR message
 @return
 A pointer to the position update message
 */
inline PudOlsrWireFormat * getOlsrMessagePayload(int ipVersion,
		union olsr_message * olsrMessage) {
	if (ipVersion == AF_INET) {
		return (PudOlsrWireFormat *) &olsrMessage->v4.message;
	}

	return (PudOlsrWireFormat *) &olsrMessage->v6.message;
}

/* ************************************************************************
 * VALIDITY TIME
 * ************************************************************************ */

/** Determine the validity time in seconds from the OLSR wire format value */
#define PUD_VALIDITY_TIME_FROM_OLSR(msn, lsn) ((((lsn) + 16) * (1 << (msn))) - 16)

static unsigned long long cachedValidityTimeMsn[16];

static bool cachedValidityTimeMsnValid = false;

/**
 Setup of cache of calculated most significant nibble results of the validity
 time calculation to speed up run-time calculations. This method has to be
 called once upon first use of ValidityTime functions.
 */
static void setupCachedValidityTimeMsn(void) {
	unsigned int msn;
	for (msn = 0; msn < 16; msn++) {
		cachedValidityTimeMsn[msn] = PUD_VALIDITY_TIME_FROM_OLSR(msn, 0);
	}
	cachedValidityTimeMsnValid = true;
}

/**
 Convert the validity time to the validity time for an OLSR message

 @param validityTime
 The validity time (in seconds)

 @return
 The validity time converted to the format for the wire format
 */
unsigned char getValidityTimeForOlsr(unsigned long long validityTime) {
	unsigned int msn = 1;
	unsigned long long lsn = 0;
	unsigned long long upperBound;

	if (!cachedValidityTimeMsnValid) {
		setupCachedValidityTimeMsn();
	}
	upperBound = cachedValidityTimeMsn[msn];
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

	assert(msn <= 15);
	assert(lsn <= 15);

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
unsigned long getValidityTimeFromOlsr(unsigned char internal) {
	return PUD_VALIDITY_TIME_FROM_OLSR(internal >> 4, internal % 16);
}

/* ************************************************************************
 * TIME
 * ************************************************************************ */

/**
 Convert the time to the time for an OLSR message (the number of seconds after
 midnight).

 @param hour
 The hours
 @param min
 The minutes
 @param sec
 The seconds

 @return
 The time converted to the format for the wire format
 */
unsigned long getTimeForOlsr(int hour, int min, int sec) {
	return ((hour * 60 * 60) + (min * 60) + sec);
}

/**
 Convert the time of an OLSR message (the number of seconds after midnight) to
 a time structure, based on midnight of the current day.

 @param olsrTime
 The time from the wire format
 @param nowStruct
 A pointer to the time structure into which to put the converted time
 */
void getTimeFromOlsr(uint32_t olsrTime, struct tm *nowStruct) {
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
unsigned long getLatitudeForOlsr(double infoLat) {
	double lat = infoLat;

	/* lat is in [-90, 90] */
	assert(lat >= -90.0);
	assert(lat <= 90.0);

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
double getLatitudeFromOlsr(uint32_t olsrLat) {
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
unsigned long getLongitudeForOlsr(double infoLon) {
	double lon = infoLon;

	/* lon is in [-180, 180] */
	assert(lon >= -180.0);
	assert(lon <= 180.0);

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
double getLongitudeFromOlsr(uint32_t olsrLon) {
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
long getAltitudeForOlsr(double infoElv) {
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
long getAltitudeFromOlsr(uint32_t olsrAlt) {
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
long getSpeedForOlsr(double infoSpeed) {
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
unsigned long getSpeedFromOlsr(uint32_t olsrSpeed) {
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
long getTrackForOlsr(double infoTrack) {
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
unsigned long getTrackFromOlsr(uint32_t olsrTrack) {
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
long getHdopForOlsr(double infoHdop) {
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
double getHdopFromOlsr(uint32_t olsrHdop) {
	return (olsrHdop * PUD_HDOP_RESOLUTION);
}

/* ************************************************************************
 * NodeInfo
 * ************************************************************************ */

/**
 Get the nodeIdType, accounting for nodeId presence

 @param ipVersion
 The ip version, either AF_INET or AF_INET6
 @param olsrMessage
 A pointer to the OLSR message

 @return
 The nodeIdType
 */
NodeIdType getNodeIdType(int ipVersion, union olsr_message * olsrMessage) {
	PudOlsrWireFormat *olsrGpsMessage = getOlsrMessagePayload(ipVersion,
			olsrMessage);

	if (olsrGpsMessage->smask & PUD_FLAGS_ID) {
		return olsrGpsMessage->nodeInfo.nodeIdType;
	}

	return ((ipVersion == AF_INET) ? PUD_NODEIDTYPE_IPV4 : PUD_NODEIDTYPE_IPV6);
}

/**
 Get the nodeId and its size, accounting for nodeId presence

 @param ipVersion
 The ip version, either AF_INET or AF_INET6
 @param olsrMessage
 A pointer to the OLSR message
 @param buffer
 A pointer to the location where a pointer to the nodeId (as contained in the
 olsrMessage) can be stored
 @param bufferSize
 A pointer to the location where the number of bytes in the buffer can be
 stored
 */
void getNodeIdPointers(int ipVersion, union olsr_message * olsrMessage,
		unsigned char ** buffer, unsigned int * bufferSize) {
	PudOlsrWireFormat * olsrGpsMessage = getOlsrMessagePayload(ipVersion, olsrMessage);

	if (olsrGpsMessage->smask & PUD_FLAGS_ID) {
		*buffer = &olsrGpsMessage->nodeInfo.nodeId;

		switch (olsrGpsMessage->nodeInfo.nodeIdType) {
			case PUD_NODEIDTYPE_MAC: /* hardware address */
				*bufferSize = PUD_NODEIDTYPE_MAC_BYTES;
				break;

			case PUD_NODEIDTYPE_MSISDN: /* an MSISDN number */
				*bufferSize = PUD_NODEIDTYPE_MSISDN_BYTES;
				break;

			case PUD_NODEIDTYPE_TETRA: /* a Tetra number */
				*bufferSize = PUD_NODEIDTYPE_TETRA_BYTES;
				break;

			case PUD_NODEIDTYPE_DNS: /* DNS name */
				*buffer = (unsigned char *) &olsrGpsMessage->nodeInfo.nodeId;
				*bufferSize = strlen((char *)*buffer);
				break;

			case PUD_NODEIDTYPE_192:
				*bufferSize = PUD_NODEIDTYPE_192_BYTES;
				break;

			case PUD_NODEIDTYPE_193:
				*bufferSize = PUD_NODEIDTYPE_193_BYTES;
				break;

			case PUD_NODEIDTYPE_194:
				*bufferSize = PUD_NODEIDTYPE_194_BYTES;
				break;

			case PUD_NODEIDTYPE_IPV4: /* IPv4 address */
			case PUD_NODEIDTYPE_IPV6: /* IPv6 address */
			default: /* unsupported */
				olsrGpsMessage->smask &= ~PUD_FLAGS_ID;
				goto noId;
		}

		return;
	}

	/* message has NO nodeId information */
	noId: {
		*buffer = (unsigned char *) getOlsrMessageOriginator(ipVersion,
				olsrMessage);
		*bufferSize = (ipVersion == AF_INET) ? PUD_NODEIDTYPE_IPV4_BYTES :
				PUD_NODEIDTYPE_IPV6_BYTES;
	}

	return;
}
