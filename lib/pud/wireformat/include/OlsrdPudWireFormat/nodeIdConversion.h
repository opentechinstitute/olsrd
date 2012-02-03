#ifndef _PUD_NODEIDCONVERSION_H_
#define _PUD_NODEIDCONVERSION_H_

#include "olsr_protocol.h"

#include <OlsrdPudWireFormat/wireFormat.h>
#include <stddef.h>

void getNodeTypeStringFromOlsr(int ipVersion,
		PudOlsrPositionUpdate * olsrGpsMessage, char * nodeIdTypeBuffer,
		int nodeIdTypeBufferSize);

void getNodeIdStringFromOlsr(int ipVersion, union olsr_message *olsrMessage,
		const char **nodeIdStr, char *nodeIdStrBuffer,
		unsigned int nodeIdStrBufferSize);

bool setupNodeIdBinaryMAC(nodeIdBinaryType * nodeIdBinary,
		size_t * nodeIdBinaryLength, bool * nodeIdBinarySet,
		unsigned char * mac);

bool setupNodeIdBinaryLongLong(nodeIdBinaryType * nodeIdBinary,
		size_t * nodeIdBinaryLength, bool * nodeIdBinarySet,
		unsigned long long longValue, size_t bytes);

bool setupNodeIdBinaryString(nodeIdBinaryType * nodeIdBinary,
		size_t * nodeIdBinaryLength, bool * nodeIdBinarySet,
		char * nodeId, size_t nodeIdLength);

bool setupNodeIdBinaryIp(nodeIdBinaryType * nodeIdBinary,
		size_t * nodeIdBinaryLength, bool * nodeIdBinarySet, void * ip,
		size_t ipLength);

#endif /* _PUD_NODEIDCONVERSION_H_ */
