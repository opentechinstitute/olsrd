#include <OlsrdPudWireFormat/nodeIdConversion.h>
#include <OlsrdPudWireFormat/compiler.h>

#include <assert.h>
#include <arpa/inet.h>
#include <net/if.h>

/* ************************************************************************
 * Node Information
 * ************************************************************************ */

/**
 Convert the nodeIdType of an OLSR message into a string.

 @param ipVersion
 The ip version (AF_INET or AF_INET6)
 @param olsrGpsMessage
 A pointer to the position update message.
 @param nodeIdTypeBuffer
 A pointer to the buffer in which the nodeIdType string representation is
 written (the buffer needs to be at least PUD_TX_NODEIDTYPE_DIGITS + 1 bytes).
 When NULL then the nodeIdType string is not written.
 @param nodeIdTypeBufferSize
 The size of the nodeIdTypeBuffer. When zero then the nodeIdType string is not
 written.
 */
void getNodeTypeStringFromOlsr(int ipVersion,
		PudOlsrPositionUpdate * olsrGpsMessage, char * nodeIdTypeBuffer,
		int nodeIdTypeBufferSize) {
	int chars;

	if (unlikely(!nodeIdTypeBuffer || (nodeIdTypeBufferSize == 0))) {
		return;
	}

	assert(nodeIdTypeBufferSize >= (PUD_TX_NODEIDTYPE_DIGITS + 1));

	/* message has NO nodeId information */
	chars = snprintf(&nodeIdTypeBuffer[0], nodeIdTypeBufferSize, "%u",
			getPositionUpdateNodeIdType(ipVersion, olsrGpsMessage));
	if (likely(chars < nodeIdTypeBufferSize)) {
		nodeIdTypeBuffer[chars] = '\0';
	} else {
		nodeIdTypeBuffer[nodeIdTypeBufferSize] = '\0';
	}

	return;
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
 The ip version (AF_INET or AF_INET6)
 @param olsrMessage
 A pointer to the OLSR message. Used to be able to retrieve the IP address of
 the sender.
 @param nodeIdStr
 A pointer to a variable in which to store the pointer to the buffer in which
 the nodeId string representation is written (the buffer needs to be at least
 PUD_TX_NODEIDTYPE_DIGITS + 1 bytes). Not written to when nodeIdStrBuffer or
 nodeIdStr is NULL or when nodeIdStrBufferSize is zero. Can point to
 nodeIdStrBuffer or straight into the olsrMessage
 @param nodeIdStrBuffer
 A pointer to the buffer in which the nodeId string representation can be
 written. Not written to when nodeIdStrBuffer or nodeIdStr is NULL or when
 nodeIdStrBufferSize is zero.
 @param nodeIdStrBufferSize
 The size of the nodeIdStrBuffer. When zero then nodeIdStrBuffer and nodeIdStr
 are not written to.
 */
void getNodeIdStringFromOlsr(int ipVersion, union olsr_message *olsrMessage,
		const char **nodeIdStr, char *nodeIdStrBuffer,
		unsigned int nodeIdStrBufferSize) {
	PudOlsrPositionUpdate * olsrGpsMessage;
	unsigned char * nodeId;
	unsigned int nodeIdSize;

	if (unlikely(!nodeIdStrBuffer || (nodeIdStrBufferSize == 0) || !nodeIdStr)) {
		return;
	}

	assert(nodeIdStrBufferSize >= (PUD_TX_NODEID_BUFFERSIZE + 1));

	olsrGpsMessage = getOlsrMessagePayload(ipVersion, olsrMessage);

	getPositionUpdateNodeId(ipVersion, olsrMessage, &nodeId, &nodeIdSize);

	switch (getPositionUpdateNodeIdType(ipVersion, olsrGpsMessage)) {
	case PUD_NODEIDTYPE_MAC: /* hardware address */
	{
		int chars;

		assert(nodeIdSize == 6);

		chars = snprintf(nodeIdStrBuffer, nodeIdStrBufferSize,
				"%02x:%02x:%02x:%02x:%02x:%02x", nodeId[0], nodeId[1],
				nodeId[2], nodeId[3], nodeId[4], nodeId[5]);
		if (likely(chars < (int) nodeIdStrBufferSize)) {
			nodeIdStrBuffer[chars] = '\0';
		} else {
			nodeIdStrBuffer[nodeIdStrBufferSize - 1] = '\0';
		}
		*nodeIdStr = &nodeIdStrBuffer[0];
	}
		break;

	case PUD_NODEIDTYPE_DNS: /* DNS name */
		*nodeIdStr = (char *) nodeId;
		break;

	case PUD_NODEIDTYPE_MSISDN: /* an MSISDN number */
	case PUD_NODEIDTYPE_TETRA: /* a Tetra number */
	case PUD_NODEIDTYPE_MMSI: /* an AIS MMSI number */
	case PUD_NODEIDTYPE_192:
	case PUD_NODEIDTYPE_193:
	case PUD_NODEIDTYPE_194:
		*nodeIdStr = getNodeIdNumberFromOlsr(nodeId, nodeIdSize,
				nodeIdStrBuffer, nodeIdStrBufferSize);
		break;

	case PUD_NODEIDTYPE_IPV4: /* IPv4 address */
	case PUD_NODEIDTYPE_IPV6: /* IPv6 address */
	default: /* unsupported */
	{
		void * addr = getOlsrMessageOriginator(ipVersion, olsrMessage);
		*nodeIdStr = inet_ntop(ipVersion, addr, nodeIdStrBuffer,
				nodeIdStrBufferSize);
	}
		break;
	}

	return;
}
