#ifndef _PUD_NODEIDCONVERSION_H_
#define _PUD_NODEIDCONVERSION_H_

/* Plugin includes */
#include "wireFormat.h"

/* OLSR includes */
#include "olsr_protocol.h"

/* System includes */
#include <stdbool.h>
#include <stddef.h>

size_t setupNodeInfoForOlsr(PudOlsrWireFormat * olsrGpsMessage,
		unsigned int olsrMessageSize);

void getNodeTypeStringFromOlsr(int ipVersion, union olsr_message * olsrMessage,
		char * nodeIdTypeBuffer, int nodeIdTypeBufferSize);

void getNodeIdStringFromOlsr(int ipVersion, union olsr_message *olsrMessage,
		const char **nodeIdStr, char *nodeIdStrBuffer,
		unsigned int nodeIdStrBufferSize);

#endif /* _PUD_NODEIDCONVERSION_H_ */
