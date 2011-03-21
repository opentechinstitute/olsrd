#ifndef _PUD_DUMP_H_
#define _PUD_DUMP_H_

#if defined(PUD_DUMP_GPS_PACKETS_RX_NON_OLSR) | \
	defined(PUD_DUMP_GPS_PACKETS_RX_OLSR) | \
	defined(PUD_DUMP_GPS_PACKETS_TX_OLSR) | \
	defined(PUD_DUMP_GPS_PACKETS_TX_NON_OLSR) | \
	defined(PUD_DUMP_GPS_PACKETS)

#ifndef PUD_DUMP_GPS_PACKETS
#define PUD_DUMP_GPS_PACKETS
#endif

void dump_packet(unsigned char* packet, unsigned int length);

#endif /* PUD_DUMP_GPS_PACKETS_* */


#if defined(PUD_DUMP_AVERAGING) | \
	defined(PUD_DUMP_NMEA)

#ifndef PUD_DUMP_NMEA
#define PUD_DUMP_NMEA
#endif

#include <nmea/info.h>

void dump_nmeaInfo(nmeaINFO * nmeaInfo, const char * prefix);

#endif /* PUD_DUMP_AVERAGING */

#endif /* _PUD_DUMP_H_ */
