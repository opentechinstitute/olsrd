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

/** The size of the cached nodeId buffer */
#define PUD_CACHED_NODEID_BUFFER_SIZE 16

/** The cached nodeId buffer: contains a pre-processed version of the nodeId
 in order to improve performance. It is currently used for nodeIdTypes
 PUD_NODEIDTYPE_MSISDN, PUD_NODEIDTYPE_TETRA, PUD_NODEIDTYPE_192,
 PUD_NODEIDTYPE_193 (so basically for numbers that will not change) */
static unsigned char cachedNodeIdBuffer[PUD_CACHED_NODEID_BUFFER_SIZE];

/** The number of bytes stored in cachedNodeIdBuffer */
static unsigned char cachedNodeIdBufferLength = 0;

/**
 Check a nodeId number for validity and if valid set it up in the
 cachedNodeIdBuffer. The valid range for the number is [min, max].

 @param min
 The lower bound for a valid number
 @param max
 The upper bound for a valid number
 @param bytes
 The number of bytes used by the number in the wire format

 @return
 - true when the number is valid
 - false otherwise
 */
static bool setupNodeIdNumberForOlsr(unsigned long long min,
		unsigned long long max, unsigned int bytes) {
	unsigned long long val;

	assert (bytes <= PUD_CACHED_NODEID_BUFFER_SIZE);

	if (!getNodeIdAsNumber(&val)) {
		return false;
	}

	if ((val >= min) && (val <= max)) {
		int i = bytes - 1;
		while (i >= 0) {
			cachedNodeIdBuffer[i] = val & 0xff;
			val >>= 8;
			i--;
		}

		assert(val == 0);

		cachedNodeIdBufferLength = bytes;
		return true;
	}

	pudError(false, "%s value %llu is out of range [%llu,%llu]",
			PUD_NODE_ID_NAME, val, min, max);
	return false;
}

/**
 Validate whether the configured nodeId is valid w.r.t. the configured
 nodeIdType

 @return
 - true when ok
 - false on failure
 */
bool validateNodeId(NodeIdType nodeIdTypeNumber) {
	switch (nodeIdTypeNumber) {
		case PUD_NODEIDTYPE_IPV4: /* IPv4 address */
		case PUD_NODEIDTYPE_IPV6: /* IPv6 address */
		case PUD_NODEIDTYPE_MAC: /* hardware address */
			/* explicit return: configured nodeId is not relevant */
			return true;

		case PUD_NODEIDTYPE_MSISDN: /* an MSISDN number */
			return setupNodeIdNumberForOlsr(0LL, 999999999999999LL, 7);

		case PUD_NODEIDTYPE_TETRA: /* a Tetra number */
			return setupNodeIdNumberForOlsr(0LL, 99999999999999999LL, 8);

		case PUD_NODEIDTYPE_DNS: /* DNS name */
		{
			bool invalidChars;
			char report[256];

			invalidChars = nmea_string_has_invalid_chars((char *) getNodeId(),
					PUD_NODE_ID_NAME, &report[0], sizeof(report));
			if (invalidChars) {
				pudError(false, &report[0]);
			}
			return !invalidChars;
		}

		case PUD_NODEIDTYPE_192:
			return setupNodeIdNumberForOlsr(0LL, 9999999LL, 3);

		case PUD_NODEIDTYPE_193:
			return setupNodeIdNumberForOlsr(0LL, 999999LL, 3);

		case PUD_NODEIDTYPE_194:
			return setupNodeIdNumberForOlsr(1LL, 8191LL, 2);

		default: /* unsupported */
			/* explicit return: configured nodeId is not relevant, will
			 * fallback to IP addresses */
			return true;
	}

	return false;
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
	size_t length = 0;

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
			length = cachedNodeIdBufferLength;
			memcpy(&olsrGpsMessage->nodeInfo.nodeId, &cachedNodeIdBuffer[0],
					length);
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
 Convert the node information of an OLSR message to the node information for
 internal use and set it up in the given buffers.

 @param olsrMessage
 A pointer to the OLSR message. Used to be able to retrieve the IP address of
 the sender.
 @param olsrGpsMessage
 A pointer to the GPS message in the OLSR message
 @param nodeId
 A pointer a variable in which to store the pointer to the buffer in which the
 nodeId string representation can be found
 @param nodeIdBuffer
 A pointer to the buffer in which the nodeId string representation can be
 written
 @param nodeIdBufferSize
 The size of the nodeIdBuffer
 @param nodeIdTypeString
 A pointer to the buffer in which the nodeIdType string representation can be
 written
 */
void getNodeInfoFromOlsr(const union olsr_message *olsrMessage,
		PudOlsrWireFormat *olsrGpsMessage, char *nodeIdBuffer,
		unsigned int nodeIdBufferSize, const char **nodeId,
		char *nodeIdTypeString) {
	int chars;

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
						((olsr_cnf->ip_version == AF_INET) ? PUD_NODEIDTYPE_IPV4
								: PUD_NODEIDTYPE_IPV6));
				olsrGpsMessage->smask &= ~PUD_FLAGS_ID;
				goto noId;
		}

		/* nodeIdType */
		chars = snprintf(nodeIdTypeString, PUD_TX_NODEIDTYPE_DIGITS + 1, "%u",
				olsrGpsMessage->nodeInfo.nodeIdType);
		if (likely(chars < PUD_TX_NODEIDTYPE_DIGITS)) {
			nodeIdTypeString[chars] = '\0';
		} else {
			nodeIdTypeString[PUD_TX_NODEIDTYPE_DIGITS] = '\0';
		}

		return;
	}

	/* message has NO nodeId information */
	noId: {
		const void * addr;

		/* nodeIdType */
		chars = snprintf(&nodeIdTypeString[0], PUD_TX_NODEIDTYPE_DIGITS + 1,
				"%u", ((olsr_cnf->ip_version == AF_INET) ? PUD_NODEIDTYPE_IPV4
				: PUD_NODEIDTYPE_IPV6));
		if (likely(chars < PUD_TX_NODEIDTYPE_DIGITS)) {
			nodeIdTypeString[chars] = '\0';
		} else {
			nodeIdTypeString[PUD_TX_NODEIDTYPE_DIGITS] = '\0';
		}

		if (olsr_cnf->ip_version == AF_INET) {
			addr = (const void *) &olsrMessage->v4.originator;
		} else {
			addr = (const void *) &olsrMessage->v6.originator;
		}

		*nodeId = inet_ntop(olsr_cnf->ip_version, addr, nodeIdBuffer,
				nodeIdBufferSize);
	}

	return;
}
