#include "gpsConversion.h"

/* Plugin includes */
#include "wireFormat.h"
#include "pud.h"
#include "nodeIdConversion.h"
#include "configuration.h"
#include "compiler.h"

/* OLSR includes */
#include "olsr.h"

/* System includes */
#include <nmea/gmath.h>
#include <nmea/tok.h>
#include <nmea/info.h>
#include <netinet/in.h>
#include <stdio.h>

/* ************************************************************************
 * OLSR --> External
 * ************************************************************************ */

/**
 Convert an OLSR message into a string to multicast on the LAN

 @param olsrMessage
 A pointer to the OLSR message
 @param txGpsBuffer
 A pointer to the buffer in which the transmit string can be written
 @param txGpsBufferSize
 The size of the txGpsBuffer

 @return
 - the length of the transmit string placed in the txGpsBuffer
 - 0 (zero) in case of an error
 */
unsigned int gpsFromOlsr(union olsr_message *olsrMessage,
		unsigned char * txGpsBuffer, unsigned int txGpsBufferSize) {
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

	GpsInfo* gpsMessage;
	PudOlsrWireFormat * olsrGpsMessage =
			getOlsrMessagePayload(olsr_cnf->ip_version, olsrMessage);

	if (unlikely(olsrGpsMessage->version != PUD_WIRE_FORMAT_VERSION)) {
		/* currently we can only handle our own version */
		pudError(false, "Can not handle version %u OLSR PUD messages"
			" (only version %u): message ignored", olsrGpsMessage->version,
				PUD_WIRE_FORMAT_VERSION);
		return 0;
	}

	validityTime = getValidityTimeFromOlsr(olsrGpsMessage->validityTime);

	gpsMessage = &olsrGpsMessage->gpsInfo;

	/* time is ALWAYS present so we can just use it */
	getTimeFromOlsr(gpsMessage->time, &timeStruct);

	if (likely(nmea_INFO_has_field(olsrGpsMessage->smask, LAT))) {
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

	if (likely(nmea_INFO_has_field(olsrGpsMessage->smask, LON))) {
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

	if (likely(nmea_INFO_has_field(olsrGpsMessage->smask, ELV))) {
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

	if (likely(nmea_INFO_has_field(olsrGpsMessage->smask, SPEED))) {
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

	if (likely(nmea_INFO_has_field(olsrGpsMessage->smask, DIRECTION))) {
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

	if (likely(nmea_INFO_has_field(olsrGpsMessage->smask, HDOP))) {
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

	getNodeTypeStringFromOlsr(olsr_cnf->ip_version, olsrMessage,
			&nodeIdTypeString[0], sizeof(nodeIdTypeString));
	getNodeIdStringFromOlsr(olsr_cnf->ip_version, olsrMessage, &nodeId,
			&nodeIdString[0], sizeof(nodeIdString));

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
	unsigned int aligned_size;
	unsigned int aligned_size_remainder;
	size_t nodeLength;
	PudOlsrWireFormat * olsrGpsMessage =
			getOlsrMessagePayload(olsr_cnf->ip_version, olsrMessage);

	/*
	 * Compose message contents
	 */

	olsrGpsMessage->version = PUD_WIRE_FORMAT_VERSION;
	olsrGpsMessage->validityTime = getValidityTimeForOlsr(validityTime);
	olsrGpsMessage->smask = nmeaInfo->smask;

	/* utc is always present, we make sure of that, so just use it */
	olsrGpsMessage->gpsInfo.time = getTimeForOlsr(nmeaInfo->utc.hour,
			nmeaInfo->utc.min, nmeaInfo->utc.sec);

	if (likely(nmea_INFO_has_field(nmeaInfo->smask, LAT))) {
		olsrGpsMessage->gpsInfo.lat = getLatitudeForOlsr(nmeaInfo->lat);
	} else {
		olsrGpsMessage->gpsInfo.lat = (1 << (PUD_LATITUDE_BITS - 1));
	}

	if (likely(nmea_INFO_has_field(nmeaInfo->smask, LON))) {
		olsrGpsMessage->gpsInfo.lon = getLongitudeForOlsr(nmeaInfo->lon);
	} else {
		olsrGpsMessage->gpsInfo.lon = (1 << (PUD_LONGITUDE_BITS - 1));
	}

	if (likely(nmea_INFO_has_field(nmeaInfo->smask, ELV))) {
		olsrGpsMessage->gpsInfo.alt = getAltitudeForOlsr(nmeaInfo->elv);
	} else {
		olsrGpsMessage->gpsInfo.alt = -PUD_ALTITUDE_MIN;
	}

	if (likely(nmea_INFO_has_field(nmeaInfo->smask, SPEED))) {
		olsrGpsMessage->gpsInfo.speed = getSpeedForOlsr(nmeaInfo->speed);
	} else {
		olsrGpsMessage->gpsInfo.speed = 0;
	}

	if (likely(nmea_INFO_has_field(nmeaInfo->smask, DIRECTION))) {
		olsrGpsMessage->gpsInfo.track = getTrackForOlsr(nmeaInfo->direction);
	} else {
		olsrGpsMessage->gpsInfo.track = 0;
	}

	if (likely(nmea_INFO_has_field(nmeaInfo->smask, HDOP))) {
		olsrGpsMessage->gpsInfo.hdop = getHdopForOlsr(nmeaInfo->HDOP);
	} else {
		olsrGpsMessage->gpsInfo.hdop = PUD_HDOP_MAX;
	}

	nodeLength = setupNodeInfoForOlsr(olsrGpsMessage, olsrMessageSize,
			getNodeIdTypeNumber());

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
