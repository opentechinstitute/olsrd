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

#endif /* _PUD_NODEIDCONVERSION_H_ */
