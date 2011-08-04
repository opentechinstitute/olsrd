#include "nodeIdConversion.h"

/* Plugin includes */
#include "configuration.h"
#include "networkInterfaces.h"
#include "compiler.h"

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
	int chars;

	if (unlikely(!nodeIdTypeBuffer || (nodeIdTypeBufferSize == 0))) {
		return;
	}

	assert(nodeIdTypeBufferSize >= (PUD_TX_NODEIDTYPE_DIGITS + 1));

	/* message has NO nodeId information */
	chars = snprintf(&nodeIdTypeBuffer[0], nodeIdTypeBufferSize, "%u",
			getNodeIdType(ipVersion, olsrMessage));
	if (likely(chars < nodeIdTypeBufferSize)) {
		nodeIdTypeBuffer[chars] = '\0';
	} else {
		nodeIdTypeBuffer[nodeIdTypeBufferSize] = '\0';
	}

	return;
}

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
			length = PUD_NODEIDTYPE_MAC_BYTES;
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

 @param buffer
 A pointer to the buffer that holds the nodeId
 @param bufferSize
 The number of bytes used by the number in the buffer
 @param nodeIdBuffer
 The buffer in which to place the nodeId number in string representation
 @param nodeIdBufferSize
 The size of the nodeIdbuffer

 @return
 A pointer to the nodeId string representation (&nodeIdBuffer[0])
 */
static char *getNodeIdNumberFromOlsr(unsigned char * buffer,
		unsigned int bufferSize, char *nodeIdBuffer, socklen_t nodeIdBufferSize) {
	unsigned long long val = 0;
	unsigned int i = 0;
	int chars;

	while (i < bufferSize) {
		val <<= 8;
		val += buffer[i];
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
	PudOlsrWireFormat * olsrGpsMessage;
	unsigned char * buffer;
	unsigned int bufferSize;

	if (unlikely(!nodeIdBuffer || (nodeIdBufferSize == 0) || !nodeId)) {
		return;
	}

	assert (nodeIdBufferSize >= (PUD_TX_NODEID_BUFFERSIZE + 1));

	olsrGpsMessage = getOlsrMessagePayload(ipVersion, olsrMessage);

	getNodeIdPointers(ipVersion, olsrMessage, &buffer, &bufferSize);

	if (olsrGpsMessage->smask & PUD_FLAGS_ID) {
		switch (olsrGpsMessage->nodeInfo.nodeIdType) {
			case PUD_NODEIDTYPE_MAC: /* hardware address */
			{
				int chars = snprintf(nodeIdBuffer, nodeIdBufferSize,
						"%02x:%02x:%02x:%02x:%02x:%02x", buffer[0], buffer[1],
						buffer[2], buffer[3], buffer[4], buffer[5]);
				if (likely(chars < (int) nodeIdBufferSize)) {
					nodeIdBuffer[chars] = '\0';
				} else {
					nodeIdBuffer[nodeIdBufferSize - 1] = '\0';
				}
				*nodeId = &nodeIdBuffer[0];
			}
				break;

			case PUD_NODEIDTYPE_DNS: /* DNS name */
				*nodeId = (char *) &olsrGpsMessage->nodeInfo.nodeId;
				break;

			case PUD_NODEIDTYPE_MSISDN: /* an MSISDN number */
			case PUD_NODEIDTYPE_TETRA: /* a Tetra number */
			case PUD_NODEIDTYPE_192:
			case PUD_NODEIDTYPE_193:
			case PUD_NODEIDTYPE_194:
				*nodeId = getNodeIdNumberFromOlsr(buffer, bufferSize,
						nodeIdBuffer, nodeIdBufferSize);
				break;

			case PUD_NODEIDTYPE_IPV4: /* IPv4 address */
			case PUD_NODEIDTYPE_IPV6: /* IPv6 address */
			default: /* unsupported */
				goto noId;
		}

		return;
	}

	/* message has NO nodeId information */
	noId: {
		void * addr = getOlsrMessageOriginator(ipVersion, olsrMessage);
		*nodeId = inet_ntop(ipVersion, addr, nodeIdBuffer, nodeIdBufferSize);
	}

	return;
}
