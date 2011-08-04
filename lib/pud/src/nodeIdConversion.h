#ifndef _PUD_NODEIDCONVERSION_H_
#define _PUD_NODEIDCONVERSION_H_

/* Plugin includes */
#include "wireFormat.h"

/* OLSR includes */
#include "olsr_protocol.h"

/* System includes */
#include <stddef.h>

void getNodeTypeStringFromOlsr(int ipVersion, union olsr_message * olsrMessage,
		char * nodeIdTypeBuffer, int nodeIdTypeBufferSize);

void getNodeIdStringFromOlsr(int ipVersion, union olsr_message *olsrMessage,
		const char **nodeIdStr, char *nodeIdStrBuffer,
		unsigned int nodeIdStrBufferSize);

#endif /* _PUD_NODEIDCONVERSION_H_ */
