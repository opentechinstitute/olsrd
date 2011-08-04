#include "nodeIdConversion.h"

/* Plugin includes */
#include "pud.h"
#include "configuration.h"
#include "networkInterfaces.h"

/* OLSR includes */

/* System includes */
#include <assert.h>
#include <arpa/inet.h>
#include <nmea/util.h>
#include <net/if.h>

/* ************************************************************************
 * Node Information
 * ************************************************************************ */

/**
 Convert the node information to the node information for an OLSR message and
 put it in the PUD message in the OLSR message. Also updates the PUD message
 smask.

 @param olsrGpsMessage
 A pointer to the PUD message in the OLSR message
 @param olsrMessageSize
 The maximum number of bytes available for the olsrMessage

 @return
 The number of bytes written in the PUD message in the OLSR message (for ALL
 the node information)
 */
size_t setupNodeInfoForOlsr(PudOlsrWireFormat * olsrGpsMessage,
		unsigned int olsrMessageSize) {
	NodeIdType nodeIdTypeNumber = getNodeIdTypeNumber();
	unsigned char * buffer;
	unsigned int length = 0;

	olsrGpsMessage->nodeInfo.nodeIdType = nodeIdTypeNumber;
	switch (nodeIdTypeNumber) {
		case PUD_NODEIDTYPE_MAC: /* hardware address */
			/* handled when the message is actually sent into OLSR, in the
			 * pre-transmit hook */
			length = IFHWADDRLEN;
			break;

		case PUD_NODEIDTYPE_MSISDN: /* an MSISDN number */
		case PUD_NODEIDTYPE_TETRA: /* a Tetra number */
		case PUD_NODEIDTYPE_192:
		case PUD_NODEIDTYPE_193:
		case PUD_NODEIDTYPE_194:
			getNodeIdNumberForOlsrCache(&buffer, &length);
			memcpy(&olsrGpsMessage->nodeInfo.nodeId, buffer, length);
			break;

		case PUD_NODEIDTYPE_DNS: /* DNS name */
		{
			size_t nodeIdLength;
			unsigned char * nodeId = getNodeIdWithLength(&nodeIdLength);
			long charsAvailable = olsrMessageSize - (PUD_OLSRWIREFORMATSIZE
					+ sizeof(NodeInfo)
					- sizeof(olsrGpsMessage->nodeInfo.nodeId)) - 1;

			length = nodeIdLength + 1;
			if (unlikely((long) length > charsAvailable)) {
				length = charsAvailable;
				pudError(false,
						"nodeId too long, truncated after %ld characters",
						charsAvailable);
			}

			memcpy(&olsrGpsMessage->nodeInfo.nodeId, nodeId, length);
			(&olsrGpsMessage->nodeInfo.nodeId)[length] = '\0';
		}
			break;

		case PUD_NODEIDTYPE_IPV4: /* IPv4 address */
		case PUD_NODEIDTYPE_IPV6: /* IPv6 address */
			/* explicit return: no nodeId information in message */
			return 0;

		default: /* unsupported */
			pudError(false, "Configuration of unsupported %s %u, using %u",
					PUD_NODE_ID_TYPE_NAME, nodeIdTypeNumber,
					((olsr_cnf->ip_version == AF_INET) ? PUD_NODEIDTYPE_IPV4
							: PUD_NODEIDTYPE_IPV6));

			/* fallback to IP address */
			olsrGpsMessage->nodeInfo.nodeIdType = (olsr_cnf->ip_version
					== AF_INET) ? PUD_NODEIDTYPE_IPV4 : PUD_NODEIDTYPE_IPV6;

			/* explicit return: no nodeId information in message */
			return 0;
	}

	olsrGpsMessage->smask |= PUD_FLAGS_ID;
	return ((sizeof(NodeInfo)
			- (sizeof(olsrGpsMessage->nodeInfo.nodeId) /* nodeId placeholder */))
			+ length);
}

/**
 Get a nodeId number (in string representation), using a certain number of
 bytes, from the message of an OLSR message.

 @param olsrGpsMessage
 A pointer to the OLSR message
 @param bytes
 The number of bytes used by the number
 @param nodeIdBuffer
 The buffer in which to place the nodeId number in string representation
 @param nodeIdBufferSize
 The size of the buffer

 @return
 A pointer to the nodeId string representation (&nodeIdBuffer[0])
 */
static char *getNodeIdNumberFromOlsr(PudOlsrWireFormat * olsrGpsMessage,
		unsigned int bytes, char *nodeIdBuffer, socklen_t nodeIdBufferSize) {
	unsigned char * nodeId = &(olsrGpsMessage->nodeInfo.nodeId);
	unsigned long long val = 0;
	unsigned int i = 0;
	int chars;

	while (i < bytes) {
		val <<= 8;
		val += nodeId[i];
		i++;
	}

	chars = snprintf(nodeIdBuffer, nodeIdBufferSize, "%llu", val);
	if (likely(chars < (int) nodeIdBufferSize)) {
		nodeIdBuffer[chars] = '\0';
	} else {
		nodeIdBuffer[nodeIdBufferSize] = '\0';
	}
	return &nodeIdBuffer[0];
}

/**
 Convert the nodeId of an OLSR message into a string.

 @param ipVersion
 The ip version, either AF_INET or AF_INET6
 @param olsrMessage
 A pointer to the OLSR message. Used to be able to retrieve the IP address of
 the sender.
 @param nodeId
 A pointer to a variable in which to store the pointer to the buffer in which
 the nodeId string representation is written (the buffer needs to be at least
 PUD_TX_NODEIDTYPE_DIGITS + 1 bytes). Not written to when nodeIdBuffer or
 nodeId is NULL or when nodeIdBufferSize is zero. Can point to nodeIdBuffer
 or straight into the olsrMessage
 @param nodeIdBuffer
 A pointer to the buffer in which the nodeId string representation can be
 written. Not written to when nodeIdBuffer or nodeId is NULL or when
 nodeIdBufferSize is zero.
 @param nodeIdBufferSize
 The size of the nodeIdBuffer. When zero then nodeIdBuffer and nodeId are not
 written to.
 */
void getNodeIdStringFromOlsr(int ipVersion, union olsr_message *olsrMessage,
		const char **nodeId, char *nodeIdBuffer, unsigned int nodeIdBufferSize) {
	PudOlsrWireFormat *olsrGpsMessage;
	int chars;

	if (unlikely(!nodeIdBuffer || (nodeIdBufferSize == 0) || !nodeId)) {
		return;
	}

	assert (nodeIdBufferSize >= (PUD_TX_NODEID_BUFFERSIZE + 1));

	/* determine the originator of the message */
	if (ipVersion == AF_INET) {
		olsrGpsMessage = (PudOlsrWireFormat *) &olsrMessage->v4.message;
	} else {
		olsrGpsMessage = (PudOlsrWireFormat *) &olsrMessage->v6.message;
	}

	if (olsrGpsMessage->smask & PUD_FLAGS_ID) {
		switch (olsrGpsMessage->nodeInfo.nodeIdType) {
			case PUD_NODEIDTYPE_MAC: /* hardware address */
			{
				unsigned char * hwAddr = &olsrGpsMessage->nodeInfo.nodeId;

				assert (IFHWADDRLEN == 6);

				chars = snprintf(nodeIdBuffer, nodeIdBufferSize,
						"%02x:%02x:%02x:%02x:%02x:%02x", hwAddr[0], hwAddr[1],
						hwAddr[2], hwAddr[3], hwAddr[4], hwAddr[5]);
				if (likely(chars < (int) nodeIdBufferSize)) {
					nodeIdBuffer[chars] = '\0';
				} else {
					nodeIdBuffer[nodeIdBufferSize - 1] = '\0';
				}
				*nodeId = &nodeIdBuffer[0];
			}
				break;

			case PUD_NODEIDTYPE_MSISDN: /* an MSISDN number */
				*nodeId = getNodeIdNumberFromOlsr(olsrGpsMessage, 7,
						nodeIdBuffer, nodeIdBufferSize);
				break;

			case PUD_NODEIDTYPE_TETRA: /* a Tetra number */
				*nodeId = getNodeIdNumberFromOlsr(olsrGpsMessage, 8,
						nodeIdBuffer, nodeIdBufferSize);
				break;

			case PUD_NODEIDTYPE_DNS: /* DNS name */
				*nodeId = (char *) &olsrGpsMessage->nodeInfo.nodeId;
				break;

			case PUD_NODEIDTYPE_192:
			case PUD_NODEIDTYPE_193:
				*nodeId = getNodeIdNumberFromOlsr(olsrGpsMessage, 3,
						nodeIdBuffer, nodeIdBufferSize);
				break;

			case PUD_NODEIDTYPE_194:
				*nodeId = getNodeIdNumberFromOlsr(olsrGpsMessage, 2,
						nodeIdBuffer, nodeIdBufferSize);
				break;

			case PUD_NODEIDTYPE_IPV4: /* IPv4 address */
			case PUD_NODEIDTYPE_IPV6: /* IPv6 address */
				goto noId;

			default: /* unsupported */
				pudError(false,
						"Reception of unsupported %s %u, using %u",
						PUD_NODE_ID_TYPE_NAME,
						olsrGpsMessage->nodeInfo.nodeIdType,
						((ipVersion == AF_INET) ? PUD_NODEIDTYPE_IPV4
								: PUD_NODEIDTYPE_IPV6));
				olsrGpsMessage->smask &= ~PUD_FLAGS_ID;
				goto noId;
		}

		return;
	}

	/* message has NO nodeId information */
	noId: {
		const void * addr;

		if (ipVersion == AF_INET) {
			addr = (const void *) &olsrMessage->v4.originator;
		} else {
			addr = (const void *) &olsrMessage->v6.originator;
		}

		*nodeId = inet_ntop(ipVersion, addr, nodeIdBuffer, nodeIdBufferSize);
	}

	return;
}

/**
 Convert the nodeIdType of an OLSR message into a string.

 @param ipVersion
 The ip version, either AF_INET or AF_INET6
 @param olsrMessage
 A pointer to the OLSR message. Used to be able to retrieve the IP address of
 the sender.
 @param nodeIdTypeBuffer
 A pointer to the buffer in which the nodeIdType string representation is
 written (the buffer needs to be at least PUD_TX_NODEIDTYPE_DIGITS + 1 bytes).
 When NULL then the nodeIdType string is not written.
 @param nodeIdTypeBufferSize
 The size of the nodeIdTypeBuffer
 */
void getNodeTypeStringFromOlsr(int ipVersion, union olsr_message * olsrMessage,
		char * nodeIdTypeBuffer, int nodeIdTypeBufferSize) {
	PudOlsrWireFormat *olsrGpsMessage;
	unsigned int type;
	int chars;

	if (unlikely(!nodeIdTypeBuffer || (nodeIdTypeBufferSize == 0))) {
		return;
	}

	assert(nodeIdTypeBufferSize >= (PUD_TX_NODEIDTYPE_DIGITS + 1));

	/* determine the originator of the message */
	if (ipVersion == AF_INET) {
		olsrGpsMessage = (PudOlsrWireFormat *) &olsrMessage->v4.message;
	} else {
		olsrGpsMessage = (PudOlsrWireFormat *) &olsrMessage->v6.message;
	}

	if (olsrGpsMessage->smask & PUD_FLAGS_ID) {
		type = olsrGpsMessage->nodeInfo.nodeIdType;
	} else {
		type = (ipVersion == AF_INET) ? PUD_NODEIDTYPE_IPV4 :
				PUD_NODEIDTYPE_IPV6;
	}

	/* message has NO nodeId information */
	chars = snprintf(&nodeIdTypeBuffer[0], nodeIdTypeBufferSize, "%u", type);
	if (likely(chars < nodeIdTypeBufferSize)) {
		nodeIdTypeBuffer[chars] = '\0';
	} else {
		nodeIdTypeBuffer[nodeIdTypeBufferSize] = '\0';
	}

	return;
}
