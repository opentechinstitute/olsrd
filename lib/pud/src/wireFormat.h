#ifndef _PUD_WIREFORMAT_H_
#define _PUD_WIREFORMAT_H_

/* OLSRD includes */
#include "olsr_protocol.h"

/* System includes */
#include <stdint.h>
#include <time.h>

/*
 * Version
 */

/** The version of the wire format */
#define PUD_WIRE_FORMAT_VERSION		0

/*
 * Flags
 * We use the smask of nmeaINFO and the flags below on top of that
 */

/** Flags that the GPS information contains the nodeId */
#define PUD_FLAGS_ID				0x80

/*
 * Time
 */

/** The number of bits for the time field */
#define PUD_TIME_BITS				17

/*
 * Latitude
 */

/** The number of bits for the latitude field */
#define PUD_LATITUDE_BITS			28

/** The maximum size of the string representation of the latitude
 * sign [0,90] [0,59] dot [0,59] [0,999] */
#define PUD_TX_LATITUDE_DIGITS		(1 + 2 + 2 + 1 + 2 + 3)

/** The number of decimals of the latitude in the transmit sentence */
#define PUD_TX_LATITUDE_DECIMALS	"5"

/*
 * Longitude
 */

/** The number of bits for the longitude field */
#define PUD_LONGITUDE_BITS			27

/** The maximum size of the string representation of the longitude
 * sign [0,180] [0,59] dot [0,59] [0,999] */
#define PUD_TX_LONGITUDE_DIGITS		(1 + 3 + 2 + 1 + 2 + 3)

/** The number of decimals of the longitude in the transmit sentence */
#define PUD_TX_LONGITUDE_DECIMALS	"5"

/*
 * Altitude
 */

/** The number of bits for the altitude field */
#define PUD_ALTITUDE_BITS			16

/** The minimum altitude */
#define PUD_ALTITUDE_MIN			(-400)

/** The maximum altitude */
#define PUD_ALTITUDE_MAX	(((1 << PUD_ALTITUDE_BITS) - 1) + PUD_ALTITUDE_MIN)

/** The maximum size of the string representation of the altitude */
#define PUD_TX_ALTITUDE_DIGITS		6

/*
 * Speed
 */

/** The number of bits for the speed field */
#define PUD_SPEED_BITS				12

/** The maximum speed value */
#define PUD_SPEED_MAX				((1 << PUD_SPEED_BITS) - 1)

/** The maximum size of the string representation of the speed */
#define PUD_TX_SPEED_DIGITS			4

/*
 * Track
 */

/** The number of bits for the track angle field */
#define PUD_TRACK_BITS				9

/** The maximum size of the string representation of the track angle */
#define PUD_TX_TRACK_DIGITS			3

/*
 * HDOP
 */

/** The number of bits for the HDOP field */
#define PUD_HDOP_BITS				11

/** The HDOP resolution (in m) */
#define PUD_HDOP_RESOLUTION			(0.1)

/** The maximum HDOP value (in m) */
#define PUD_HDOP_MAX		(((1 << PUD_HDOP_BITS) - 1) * PUD_HDOP_RESOLUTION)

/** The maximum size of the string representation of the HDOP */
#define PUD_TX_HDOP_DIGITS			5

/** The number of decimals of the HDOP in the transmit sentence */
#define PUD_TX_HDOP_DECIMALS		"3"

/*
 * Node ID Type
 */

/** nodeIdType legal values */
typedef enum _NodeIdType {
	/** MAC address, 48 bits, 6 bytes */
	PUD_NODEIDTYPE_MAC = 0,

	/** MSISDN number, 15 digits, 50 bits, 7 bytes */
	PUD_NODEIDTYPE_MSISDN = 1,

	/** TETRA number, 17 digits, 57 bits, 8 bytes */
	PUD_NODEIDTYPE_TETRA = 2,

	/** DNS name, variable length */
	PUD_NODEIDTYPE_DNS = 3,

	/** IPv4 address, 32 bits, 4 bytes */
	PUD_NODEIDTYPE_IPV4 = 4,

	/** IPv6 address, 128 bits, 16 bytes */
	PUD_NODEIDTYPE_IPV6 = 6,

	/** Brandweer number, 7 digits, 24 bits, 3 bytes */
	PUD_NODEIDTYPE_192 = 192,

	/** Ambulance number, 6 digits, 20 bits, 3 bytes */
	PUD_NODEIDTYPE_193 = 193,

	/** Number in the range [1, 8191], 4 digits, 13 bits, 2 bytes */
	PUD_NODEIDTYPE_194 = 194
} NodeIdType;

/** The maximum size of the string representation of the nodeIdType */
#define PUD_TX_NODEIDTYPE_DIGITS	3

/*
 * Node ID
 */

/** The maximum size of the string representation of the nodeId */
#define PUD_TX_NODEID_BUFFERSIZE	1023

/*
 * Wire Format Structures
 */

/** Sub-format GPS information, 120 bits = 15 bytes */
typedef struct _GpsInfo {
		uint32_t time :PUD_TIME_BITS; /**< the number of seconds since midnight, ALWAYS present */
		uint32_t lat :PUD_LATITUDE_BITS; /**< latitude */
		uint32_t lon :PUD_LONGITUDE_BITS; /**< longitude */
		uint32_t alt :PUD_ALTITUDE_BITS; /**< altitude */
		uint32_t speed :PUD_SPEED_BITS; /**< speed */
		uint32_t track :PUD_TRACK_BITS; /**< track angle */
		uint32_t hdop :PUD_HDOP_BITS; /**< HDOP */
}__attribute__((__packed__)) GpsInfo;

/** Sub-format Node information, 8 + variable bits = 1 + variable bytes */
typedef struct _NodeInfo {
		uint8_t nodeIdType; /**< the nodeIdType */
		unsigned char nodeId; /**< placeholder for variable length nodeId string */
}__attribute__((__packed__)) NodeInfo;

/** Complete format, 8+8+8+120+(8+variable) bits =  18+(1+variable) bytes*/
typedef struct _PudOlsrWireFormat {
		uint8_t version; /**< the version of the sentence */
		uint8_t validityTime; /**< the validity time of the sentence */
		uint8_t smask; /**< mask signaling the contents of the sentence */
		GpsInfo gpsInfo; /**< the GPS information (MANDATORY) */
		NodeInfo nodeInfo; /**< placeholder for node information (OPTIONAL) */
}__attribute__((__packed__)) PudOlsrWireFormat;

/** The size of the wire format, minus the size of the node information */
#define PUD_OLSRWIREFORMATSIZE (sizeof(PudOlsrWireFormat) - sizeof(NodeInfo))

/* ************************************************************************
 * FUNCTIONS
 * ************************************************************************ */

/*
 * OLSR header
 */

union olsr_ip_addr * getOlsrMessageOriginator(int ipVersion,
		union olsr_message * olsrMessage);

unsigned short getOlsrMessageSize(int ipVersion,
		union olsr_message * olsrMessage);

PudOlsrWireFormat * getOlsrMessagePayload(int ipVersion,
		union olsr_message * olsrMessage);

/*
 * PudOlsrWireFormat
 */

unsigned char getValidityTimeForOlsr(unsigned long long validityTime);
unsigned long getValidityTimeFromOlsr(unsigned char internal);

/*
 * GpsInfo
 */

unsigned long getTimeForOlsr(int hour, int min, int sec);
void getTimeFromOlsr(uint32_t olsrTime, struct tm *nowStruct);

unsigned long getLatitudeForOlsr(double infoLat);
double getLatitudeFromOlsr(uint32_t olsrLat);

unsigned long getLongitudeForOlsr(double infoLon);
double getLongitudeFromOlsr(uint32_t olsrLon);

long getAltitudeForOlsr(double infoElv);
long getAltitudeFromOlsr(uint32_t olsrAlt);

long getSpeedForOlsr(double infoSpeed);
unsigned long getSpeedFromOlsr(uint32_t olsrSpeed);

long getTrackForOlsr(double infoTrack);
unsigned long getTrackFromOlsr(uint32_t olsrTrack);

long getHdopForOlsr(double infoHdop);
double getHdopFromOlsr(uint32_t olsrHdop);

/*
 * NodeInfo
 */

NodeIdType getNodeIdType(int ipVersion, union olsr_message * olsrMessage);

#endif /* _PUD_WIREFORMAT_H_ */
