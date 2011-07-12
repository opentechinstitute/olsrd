#include "dump.h"

#ifdef PUD_DUMP_GPS_PACKETS

/* Plugin includes */
#include "pud.h"

/* OLSRD includes */
#include "olsr.h"

/* System includes */
#include <string.h>

/** the number of bytes/characters per line */
#define PUD_DUMP_GPS_PACKETS_CHARSPERLINE 16

/**
 Prints a packet in hex/ascii.

 @param packet
 a pointer to the packet
 @param length
 the number of bytes in the packet
 */
void dump_packet(unsigned char* packet, unsigned int length) {
	unsigned int packetPos;
	unsigned int linePos;
	unsigned char line[PUD_DUMP_GPS_PACKETS_CHARSPERLINE + 1];

	for (packetPos = 0; packetPos < length; packetPos
			+= PUD_DUMP_GPS_PACKETS_CHARSPERLINE) {
		unsigned int copyLength = PUD_DUMP_GPS_PACKETS_CHARSPERLINE;
		if ((packetPos + copyLength) > length) {
			copyLength = length - packetPos;
		}

		memcpy(&line[0], &packet[packetPos], copyLength);
		line[copyLength] = '\0';

		olsr_printf(0, "%s: ", PUD_PLUGIN_ABBR);
		for (linePos = 0; linePos < PUD_DUMP_GPS_PACKETS_CHARSPERLINE; linePos++) {
			if (linePos >= copyLength) {
				olsr_printf(0, "   ");
			} else {
				olsr_printf(0, "%2.2X ", packet[packetPos + linePos]);
				if ((line[linePos] < 32) || (line[linePos] > 126)) {
					line[linePos] = '.';
				}
			}
		}
		olsr_printf(0, " %s\n", line);
	}
}

#endif /* PUD_DUMP_GPS_PACKETS */

#ifdef PUD_DUMP_NMEA

/* Plugin includes */

/* OLSRD includes */
#include "olsr.h"

/* System includes */
#include <nmea/info.h>
#include <nmea/sentence.h>

void dump_nmeaInfo(nmeaINFO * nmeaInfo, const char * prefix) {
	olsr_printf(0,
			"%s (%p)\n" /* prefix */
			"  smask = %02x%s%s%s%s%s\n"
			"  utc   = %04u%02u%02u %02u:%02u:%02u.%02u\n"
			"  sig   = %s (%u)\n"
			"  fix   = %s (%u)\n"
			"  PDOP  = %fm\n"
			"  HDOP  = %fm\n"
			"  VDOP  = %fm\n"
			"  lat   = %f\n"
			"  lon   = %f\n"
			"  alt   = %f\n"
			"  speed = %f\n"
			"  track = %f\n"
			"  decl  = %f\n"
			"\n",
			prefix, nmeaInfo,
			nmeaInfo->smask,
			((nmeaInfo->smask & GPGGA) != 0) ? " GPGGA" : "",
			((nmeaInfo->smask & GPGSA) != 0) ? " GPGSA" : "",
			((nmeaInfo->smask & GPGSV) != 0) ? " GPGSV" : "",
			((nmeaInfo->smask & GPRMC) != 0) ? " GPRMC" : "",
			((nmeaInfo->smask & GPVTG) != 0) ? " GPVTG" : "",
			(nmeaInfo->utc.year + 1900), nmeaInfo->utc.mon, nmeaInfo->utc.day,
			nmeaInfo->utc.hour, nmeaInfo->utc.min, nmeaInfo->utc.sec, nmeaInfo->utc.hsec,
			(nmeaInfo->sig == NMEA_SIG_BAD) ? "BAD" : (nmeaInfo->sig == NMEA_SIG_LOW) ? "LOW" : (nmeaInfo->sig == NMEA_SIG_MID) ? "MID" : (nmeaInfo->sig == NMEA_SIG_HIGH) ? "HIGH" : "UNKNOWN", nmeaInfo->sig,
			(nmeaInfo->fix == NMEA_FIX_BAD) ? "BAD" : (nmeaInfo->fix == NMEA_FIX_2D) ? "2D" : (nmeaInfo->fix == NMEA_FIX_3D) ? "3D" : "UNKNOWN", nmeaInfo->fix,
			nmeaInfo->PDOP,
			nmeaInfo->HDOP,
			nmeaInfo->VDOP,
			nmeaInfo->lat,
			nmeaInfo->lon,
			nmeaInfo->elv,
			nmeaInfo->speed,
			nmeaInfo->direction,
			nmeaInfo->declination
	);
}

#endif /* PUD_DUMP_NMEA */
