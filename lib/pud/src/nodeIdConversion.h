#ifndef _PUD_NODEIDCONVERSION_H_
#define _PUD_NODEIDCONVERSION_H_

/* Plugin includes */
#include "configuration.h"
#include "wireFormat.h"

/* OLSR includes */
#include "olsr_protocol.h"
#include "interfaces.h"

/* System includes */
#include <stdbool.h>
#include <stddef.h>
#include <unistd.h>

bool validateNodeId(NodeIdType nodeIdTypeNumber);

size_t setupNodeInfoForOlsr(PudOlsrWireFormat * olsrGpsMessage,
		unsigned int olsrMessageSize);

void nodeIdPreTransmitHook(union olsr_message *olsrMessage,
		struct interface *ifn);

void getNodeInfoFromOlsr(const union olsr_message *olsrMessage,
		PudOlsrWireFormat *olsrGpsMessage, char *nodeIdBuffer,
		unsigned int nodeIdBufferSize, const char **nodeId,
		char *nodeIdTypeString);

#endif /* _PUD_NODEIDCONVERSION_H_ */
