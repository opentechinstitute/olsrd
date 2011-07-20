#include "configuration.h"

/* Plugin includes */
#include "pud.h"
#include "netTools.h"
#include "nodeIdConversion.h"
#include "networkInterfaces.h"

/* OLSR includes */
#include "olsr_types.h"
#include "olsr_cfg.h"

/* System includes */
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <nmea/util.h>

/*
 * Utility functions
 */

/**
 Read an unsigned long long number from a value string

 @param valueName
 the name of the value
 @param value
 the string to convert to a number
 @param valueNumber
 a pointer to the location where to store the number upon successful conversion

 @return
 - true on success
 - false otherwise
 */
static bool readULL(const char * valueName, const char * value,
		unsigned long long * valueNumber) {
	char * endPtr = NULL;
	unsigned long long valueNew;

	errno = 0;
	valueNew = strtoull(value, &endPtr, 10);

	if (!((endPtr != value) && (*value != '\0') && (*endPtr == '\0'))) {
		/* invalid conversion */
		pudError(true, "Configured %s (%s) could not be converted to a number",
				valueName, value);
		return false;
	}

	*valueNumber = valueNew;

	return true;
}

/**
 Read a double number from a value string

 @param valueName
 the name of the value
 @param value
 the string to convert to a number
 @param valueNumber
 a pointer to the location where to store the number upon successful conversion

 @return
 - true on success
 - false otherwise
 */
static bool readDouble(const char * valueName, const char * value,
		double * valueNumber) {
	char * endPtr = NULL;
	double valueNew;

	errno = 0;
	valueNew = strtod(value, &endPtr);

	if (!((endPtr != value) && (*value != '\0') && (*endPtr == '\0'))) {
		/* invalid conversion */
		pudError(true, "Configured %s (%s) could not be converted to a number",
				valueName, value);
		return false;
	}

	*valueNumber = valueNew;

	return true;
}

/*
 * nodeIdType
 */

/** The nodeIdType */
static NodeIdType nodeIdType = PUD_NODE_ID_TYPE_DEFAULT;

/**
 @return
 The node ID type
 */
NodeIdType getNodeIdTypeNumber(void) {
	return nodeIdType;
}

/**
 Set the node ID type.

 @param value
 The value of the node ID type to set (a number in string representation)
 @param data
 Unused
 @param addon
 Unused

 @return
 - true when an error is detected
 - false otherwise
 */
int setNodeIdType(const char *value, void *data __attribute__ ((unused)),
		set_plugin_parameter_addon addon __attribute__ ((unused))) {
	static const char * valueName = PUD_NODE_ID_TYPE_NAME;
	unsigned long long nodeIdTypeNew;

	assert (value != NULL);

	if (!readULL(valueName, value, &nodeIdTypeNew)) {
		return true;
	}

	if (nodeIdTypeNew > PUD_NODE_ID_TYPE_MAX) {
		pudError(false, "Configured %s (%llu) is out of range 0-%u", valueName,
				nodeIdTypeNew, PUD_NODE_ID_TYPE_MAX);
		return true;
	}

	switch (nodeIdTypeNew) {
		case PUD_NODEIDTYPE_MAC:
		case PUD_NODEIDTYPE_MSISDN:
		case PUD_NODEIDTYPE_TETRA:
		case PUD_NODEIDTYPE_DNS:
		case PUD_NODEIDTYPE_IPV4:
		case PUD_NODEIDTYPE_IPV6:
		case PUD_NODEIDTYPE_192:
		case PUD_NODEIDTYPE_193:
		case PUD_NODEIDTYPE_194:
			break;

		default:
			pudError(false, "Configured %s (%llu) is reserved", valueName,
					nodeIdTypeNew);
			return true;
	}

	nodeIdType = nodeIdTypeNew;

	return false;
}

/*
 * nodeId
 */

/** The maximum length of a nodeId */
#define PUD_NODEIDMAXLENGTH 255

/** The nodeId buffer */
static unsigned char nodeId[PUD_NODEIDMAXLENGTH + 1];

/** The length of the string in the nodeId buffer */
static size_t nodeIdLength = 0;

/** True when the nodeId is set */
static bool nodeIdSet = false;

/** The nodeId as a nuber */
static unsigned long long nodeIdNumber = 0;

/** True when the nodeIdNumber is set */
static bool nodeIdNumberSet = false;

/**
 @return
 The node ID
 */
unsigned char * getNodeId(void) {
	return getNodeIdWithLength(NULL);
}

/**
 @param value
 A pointer to the node ID number
 @return
 - true on success
 - false otherwise
 */
bool getNodeIdAsNumber(unsigned long long * value) {
	if (!nodeIdNumberSet) {
		if (!readULL(PUD_NODE_ID_NAME, (char *) &nodeId[0], &nodeIdNumber)) {
			return false;
		}
		nodeIdNumberSet = true;
	}
	*value = nodeIdNumber;
	return true;
}

/**
 Get the nodeId and its length

 @param length
 a pointer to the variable in which to store the nodeId length (allowed to be
 NULL, in which case the length is not stored)

 @return
 The node ID
 */
unsigned char * getNodeIdWithLength(size_t *length) {
	if (!nodeIdSet) {
		setNodeId("", NULL, (set_plugin_parameter_addon) {.pc = NULL});
	}

	if (length != NULL) {
		*length = nodeIdLength;
	}

	return &nodeId[0];
}

/**
 Set the node ID.

 @param value
 The value of the node ID to set (in string representation)
 @param data
 Unused
 @param addon
 Unused

 @return
 - true when an error is detected
 - false otherwise
 */
int setNodeId(const char *value, void *data __attribute__ ((unused)), set_plugin_parameter_addon addon __attribute__ ((unused))) {
	static const char * valueName = PUD_NODE_ID_NAME;
	size_t valueLength;

	assert (value != NULL);

	valueLength = strlen(value);
	if (valueLength > PUD_NODEIDMAXLENGTH) {
		pudError(false, "Configured %s is too long, maximum length is"
			" %u, current length is %lu", valueName, PUD_NODEIDMAXLENGTH,
				(unsigned long) valueLength);
		return true;
	}

	strcpy((char *) &nodeId[0], value);
	nodeIdLength = valueLength;
	nodeIdSet = true;

	return false;
}

/*
 * rxNonOlsrIf
 */

/** The maximum number of RX non-OLSR interfaces */
#define PUD_RX_NON_OLSR_IF_MAX 32

/** Array with RX non-OLSR interface names */
static unsigned char rxNonOlsrInterfaceNames[PUD_RX_NON_OLSR_IF_MAX][IFNAMSIZ + 1];

/** The number of RX non-OLSR interface names in the array */
static unsigned int rxNonOlsrInterfaceCount = 0;

/**
 Determine whether a give interface name is configured as a receive non-OLSR
 interface.

 @param ifName
 The interface name to check

 @return
 - true when the given interface name is configured as a receive non-OLSR
 interface
 - false otherwise
 */
bool isRxNonOlsrInterface(const char *ifName) {
	unsigned int i;

	assert (ifName != NULL);

	for (i = 0; i < rxNonOlsrInterfaceCount; i++) {
		if (strncmp((char *) &rxNonOlsrInterfaceNames[i][0], ifName, IFNAMSIZ
				+ 1) == 0) {
			return true;
		}
	}

	return false;
}

/**
 Add a receive non-OLSR interface

 @param value
 The name of the non-OLSR interface to add
 @param data
 Unused
 @param addon
 Unused

 @return
 - true when an error is detected
 - false otherwise
 */
int addRxNonOlsrInterface(const char *value, void *data __attribute__ ((unused)),
		set_plugin_parameter_addon addon __attribute__ ((unused))) {
	unsigned long valueLength;

	assert (value != NULL);

	valueLength = strlen(value);
	if (valueLength > IFNAMSIZ) {
		pudError(false, "Configured %s (%s) is too long,"
			" maximum length is %u, current length is %lu",
				PUD_RX_NON_OLSR_IF_NAME, value, IFNAMSIZ, valueLength);
		return true;
	}

	if (!isRxNonOlsrInterface(value)) {
		if (rxNonOlsrInterfaceCount >= PUD_RX_NON_OLSR_IF_MAX) {
			pudError(false, "Can't configure more than %u receive interfaces",
					PUD_RX_NON_OLSR_IF_MAX);
			return true;
		}

		strcpy((char *) &rxNonOlsrInterfaceNames[rxNonOlsrInterfaceCount][0],
				value);
		rxNonOlsrInterfaceCount++;
	}

	return false;
}

/*
 * rxAllowedSourceIpAddress
 */

/** The maximum number of RX allowed source IP addresses */
#define PUD_RX_ALLOWED_SOURCE_IP_MAX 32

/** Array with RX allowed source IP addresses */
static struct sockaddr rxAllowedSourceIpAddresses[PUD_RX_ALLOWED_SOURCE_IP_MAX];

/** The number of RX allowed source IP addresses in the array */
static unsigned int rxAllowedSourceIpAddressesCount = 0;

/**
 Determine whether a give IP address is configured as an allowed source IP
 address.

 @param sender
 The IP address to check

 @return
 - true when the given IP address is configured as an allowed source IP
 address
 - false otherwise
 */
bool isRxAllowedSourceIpAddress(struct sockaddr * sender) {
	void * addr;
	unsigned int addrSize;
	unsigned int i;

	if (rxAllowedSourceIpAddressesCount == 0) {
		return true;
	}

	if (sender == NULL) {
		return false;
	}

	if (sender->sa_family == AF_INET) {
		addr = (void *) (&((struct sockaddr_in *) sender)->sin_addr);
		addrSize = sizeof(struct in_addr);
	} else {
		addr = (void *) (&((struct sockaddr_in6 *) sender)->sin6_addr);
		addrSize = sizeof(struct in6_addr);
	}

	for (i = 0; i < rxAllowedSourceIpAddressesCount; i++) {
		if ((rxAllowedSourceIpAddresses[i].sa_family == sender->sa_family)
				&& (memcmp(&rxAllowedSourceIpAddresses[i].sa_data, addr,
						addrSize) == 0)) {
			return true;
		}
	}

	return false;
}

/**
 Set the RX allowed source IP addresses.

 @param value
 The RX allowed source IP address (in string representation)
 @param data
 Unused
 @param addon
 Unused

 @return
 - true when an error is detected
 - false otherwise
 */
int addRxAllowedSourceIpAddress(const char *value, void *data __attribute__ ((unused)),
		set_plugin_parameter_addon addon __attribute__ ((unused))) {
	static const char * valueName = PUD_RX_ALLOWED_SOURCE_IP_NAME;
	const char * valueInternal = value;
	int conversion;
	struct sockaddr addr;

	assert (value != NULL);

	memset(&addr, 0, sizeof(addr));

	addr.sa_family = olsr_cnf->ip_version;
	conversion = inet_pton(olsr_cnf->ip_version, valueInternal, &addr.sa_data);
	if (conversion != 1) {
		pudError((conversion == -1) ? true : false,
				"Configured %s (%s) is not an IP address", valueName,
				valueInternal);
		return true;
	}

	if ((rxAllowedSourceIpAddressesCount == 0) || !isRxAllowedSourceIpAddress(&addr)) {
		if (rxAllowedSourceIpAddressesCount >= PUD_RX_ALLOWED_SOURCE_IP_MAX) {
			pudError(false, "Can't configure more than %u allowed source IP"
				" addresses", PUD_RX_ALLOWED_SOURCE_IP_MAX);
			return true;
		}

		memcpy(&rxAllowedSourceIpAddresses[rxAllowedSourceIpAddressesCount],
				&addr, sizeof(addr));
		rxAllowedSourceIpAddressesCount++;
	}

	return false;
}

/*
 * rxMcAddr
 */

/** The rx multicast address */
static union olsr_sockaddr rxMcAddr;

/** True when the rx multicast address is set */
static bool rxMcAddrSet = false;

/**
 @return
 The receive multicast address (in network byte order). Sets both the address
 and the port to their default values when the address was not yet set.
 */
union olsr_sockaddr * getRxMcAddr(void) {
	if (!rxMcAddrSet) {
		setRxMcAddr(NULL, NULL, ((set_plugin_parameter_addon) {.pc = NULL}));
	}
	return &rxMcAddr;
}

/**
 Set the receive multicast address. Sets the address to its default value when
 the value is NULL. Also sets the port to its default value when the address
 was not yet set.

 @param value
 The receive multicast address (in string representation)
 @param data
 Unused
 @param addon
 Unused

 @return
 - true when an error is detected
 - false otherwise
 */
int setRxMcAddr(const char *value, void *data __attribute__ ((unused)), set_plugin_parameter_addon addon __attribute__ ((unused))) {
	static const char * valueName = PUD_RX_MC_ADDR_NAME;
	void * ipAddress;
	in_port_t * port;
	const char * valueInternal = value;
	int conversion;

	if (olsr_cnf->ip_version == AF_INET) {
		rxMcAddr.in4.sin_family = olsr_cnf->ip_version;
		ipAddress = (void *) &rxMcAddr.in4.sin_addr;
		port = (void *) &rxMcAddr.in4.sin_port;
		if (valueInternal == NULL) {
			valueInternal = PUD_RX_MC_ADDR_4_DEFAULT;
		}
	} else {
		rxMcAddr.in6.sin6_family = olsr_cnf->ip_version;
		ipAddress = (void *) &rxMcAddr.in6.sin6_addr;
		port = (void *) &rxMcAddr.in6.sin6_port;
		if (valueInternal == NULL) {
			valueInternal = PUD_RX_MC_ADDR_6_DEFAULT;
		}
	}

	if (!rxMcAddrSet) {
		*port = htons(PUD_RX_MC_PORT_DEFAULT);
	}

	conversion = inet_pton(olsr_cnf->ip_version, valueInternal, ipAddress);
	if (conversion != 1) {
		pudError((conversion == -1) ? true : false,
				"Configured %s (%s) is not an IP address", valueName,
				valueInternal);
		return true;
	}

	if (!isMulticast(olsr_cnf->ip_version, &rxMcAddr)) {
		pudError(false, "Configured %s (%s) is not a multicast address",
				valueName, valueInternal);
		return true;
	}

	rxMcAddrSet = true;
	return false;
}

/*
 * rxMcPort
 */

/**
 @return
 The receive multicast port (in network byte order)
 */
unsigned short getRxMcPort(void) {
	in_port_t * port;
	union olsr_sockaddr * addr = getRxMcAddr();

	if (olsr_cnf->ip_version == AF_INET) {
		port = (void *) &addr->in4.sin_port;
	} else {
		port = (void *) &addr->in6.sin6_port;
	}

	return *port;
}

/**
 Set the receive multicast port

 @param value
 The receive multicast port (a number in string representation)
 @param data
 Unused
 @param addon
 Unused

 @return
 - true when an error is detected
 - false otherwise
 */
int setRxMcPort(const char *value, void *data __attribute__ ((unused)), set_plugin_parameter_addon addon __attribute__ ((unused))) {
	static const char * valueName = PUD_RX_MC_PORT_NAME;
	unsigned long long rxMcPortNew;
	in_port_t * port;
	union olsr_sockaddr * addr = getRxMcAddr();

	assert (value != NULL);

	if (!readULL(valueName, value, &rxMcPortNew)) {
		return true;
	}

	if ((rxMcPortNew < 1) || (rxMcPortNew > 65535)) {
		pudError(false, "Configured %s (%llu) is outside of"
			" valid range 1-65535", valueName, rxMcPortNew);
		return true;
	}

	if (olsr_cnf->ip_version == AF_INET) {
		port = (void *) &addr->in4.sin_port;
	} else {
		port = (void *) &addr->in6.sin6_port;
	}

	*port = htons((uint16_t) rxMcPortNew);

	return false;
}

/*
 * txNonOlsrIf
 */

/** The maximum number of rx non-olsr interfaces */
#define PUD_TX_NON_OLSR_IF_MAX 32

/** Array with tx non-olsr interface names */
static unsigned char txNonOlsrInterfaceNames[PUD_TX_NON_OLSR_IF_MAX][IFNAMSIZ + 1];

/** The number of tx interface names in the array */
static unsigned int txNonOlsrInterfaceCount = 0;

/**
 Determine whether a give interface name is configured as a transmit non-OLSR
 interface.

 @param ifName
 The interface to check

 @return
 - true when the given interface name is configured as a transmit non-OLSR
 interface
 - false otherwise
 */
bool isTxNonOlsrInterface(const char *ifName) {
	unsigned int i;

	assert (ifName != NULL);

	for (i = 0; i < txNonOlsrInterfaceCount; i++) {
		if (strncmp((char *) &txNonOlsrInterfaceNames[i][0], ifName, IFNAMSIZ
				+ 1) == 0) {
			return true;
		}
	}

	return false;
}

/**
 Add a transmit non-OLSR interface

 @param value
 The name of the non-OLSR interface to add
 @param data
 Unused
 @param addon
 Unused

 @return
 - true when an error is detected
 - false otherwise
 */
int addTxNonOlsrInterface(const char *value, void *data __attribute__ ((unused)),
		set_plugin_parameter_addon addon __attribute__ ((unused))) {
	unsigned long valueLength;

	assert (value != NULL);

	valueLength = strlen(value);
	if (valueLength > IFNAMSIZ) {
		pudError(false, "Configured %s (%s) is too long,"
			" maximum length is %u, current length is %lu",
				PUD_TX_NON_OLSR_IF_NAME, value, IFNAMSIZ, valueLength);
		return true;
	}

	if (!isTxNonOlsrInterface(value)) {
		if (txNonOlsrInterfaceCount >= PUD_TX_NON_OLSR_IF_MAX) {
			pudError(false, "Can not configure more than %u transmit"
				" interfaces", PUD_TX_NON_OLSR_IF_MAX);
			return true;
		}

		strcpy((char *) &txNonOlsrInterfaceNames[txNonOlsrInterfaceCount][0],
				value);
		txNonOlsrInterfaceCount++;
	}

	return false;
}

/*
 * txMcAddr
 */

/** The tx multicast address */
static union olsr_sockaddr txMcAddr;

/** True when the tx multicast address is set */
static bool txMcAddrSet = false;

/**
 @return
 The transmit multicast address (in network byte order). Sets both the address
 and the port to their default values when the address was not yet set.
 */
union olsr_sockaddr * getTxMcAddr(void) {
	if (!txMcAddrSet) {
		setTxMcAddr(NULL, NULL, ((set_plugin_parameter_addon) {.pc = NULL}));
	}
	return &txMcAddr;
}

/**
 Set the transmit multicast address. Sets the address to its default value when
 the value is NULL. Also sets the port to its default value when the address
 was not yet set.

 @param value
 The transmit multicast address (in string representation)
 @param data
 Unused
 @param addon
 Unused

 @return
 - true when an error is detected
 - false otherwise
 */
int setTxMcAddr(const char *value, void *data __attribute__ ((unused)), set_plugin_parameter_addon addon __attribute__ ((unused))) {
	static const char * valueName = PUD_TX_MC_ADDR_NAME;
	void * ipAddress;
	in_port_t * port;
	const char * valueInternal = value;
	int conversion;

	if (olsr_cnf->ip_version == AF_INET) {
		txMcAddr.in4.sin_family = olsr_cnf->ip_version;
		ipAddress = (void *) &txMcAddr.in4.sin_addr;
		port = (void *) &txMcAddr.in4.sin_port;
		if (valueInternal == NULL) {
			valueInternal = PUD_TX_MC_ADDR_4_DEFAULT;
		}
	} else {
		txMcAddr.in6.sin6_family = olsr_cnf->ip_version;
		ipAddress = (void *) &txMcAddr.in6.sin6_addr;
		port = (void *) &txMcAddr.in6.sin6_port;
		if (valueInternal == NULL) {
			valueInternal = PUD_TX_MC_ADDR_6_DEFAULT;
		}
	}

	if (!txMcAddrSet) {
		*port = htons(PUD_TX_MC_PORT_DEFAULT);
	}

	conversion = inet_pton(olsr_cnf->ip_version, valueInternal, ipAddress);
	if (conversion != 1) {
		pudError((conversion == -1) ? true : false,
				"Configured %s (%s) is not an IP address", valueName,
				valueInternal);
		return true;
	}

	if (!isMulticast(olsr_cnf->ip_version, &txMcAddr)) {
		pudError(false, "Configured %s (%s) is not a multicast address",
				valueName, valueInternal);
		return true;
	}

	txMcAddrSet = true;
	return false;
}

/*
 * txMcPort
 */

/**
 @return
 The transmit multicast port (in network byte order)
 */
unsigned short getTxMcPort(void) {
	in_port_t * port;
	union olsr_sockaddr * addr = getTxMcAddr();

	if (olsr_cnf->ip_version == AF_INET) {
		port = (void *) &addr->in4.sin_port;
	} else {
		port = (void *) &addr->in6.sin6_port;
	}

	return *port;
}

/**
 Set the transmit multicast port

 @param value
 The transmit multicast port (a number in string representation)
 @param data
 Unused
 @param addon
 Unused

 @return
 - true when an error is detected
 - false otherwise
 */
int setTxMcPort(const char *value, void *data __attribute__ ((unused)), set_plugin_parameter_addon addon __attribute__ ((unused))) {
	static const char * valueName = PUD_TX_MC_PORT_NAME;
	unsigned long long txMcPortNew;
	in_port_t * port;
	union olsr_sockaddr * addr = getTxMcAddr();

	assert (value != NULL);

	if (!readULL(valueName, value, &txMcPortNew)) {
		return true;
	}

	if ((txMcPortNew < 1) || (txMcPortNew > 65535)) {
		pudError(false, "Configured %s (%llu) is outside of"
			" valid range 1-65535", valueName, txMcPortNew);
		return true;
	}

	if (olsr_cnf->ip_version == AF_INET) {
		port = (void *) &addr->in4.sin_port;
	} else {
		port = (void *) &addr->in6.sin6_port;
	}

	*port = htons((uint16_t) txMcPortNew);

	return false;
}

/*
 * txTtl
 */

/** The tx TTL */
static unsigned char txTtl = PUD_TX_TTL_DEFAULT;

/**
 @return
 The transmit multicast IP packet time-to-live
 */
unsigned char getTxTtl(void) {
	return txTtl;
}

/**
 Set the transmit multicast IP packet time-to-live

 @param value
 The transmit multicast IP packet time-to-live (a number in string representation)
 @param data
 Unused
 @param addon
 Unused

 @return
 - true when an error is detected
 - false otherwise
 */
int setTxTtl(const char *value, void *data __attribute__ ((unused)), set_plugin_parameter_addon addon __attribute__ ((unused))) {
	static const char * valueName = PUD_TX_TTL_NAME;
	unsigned long long txTtlNew;

	assert (value != NULL);

	if (!readULL(valueName, value, &txTtlNew)) {
		return true;
	}

	if ((txTtlNew < 1) || (txTtlNew > MAX_TTL)) {
		pudError(false, "Configured %s (%llu) is outside of"
			" valid range 1-%u", valueName, txTtlNew, MAX_TTL);
		return true;
	}

	txTtl = txTtlNew;

	return false;
}

/*
 * txNmeaMessagePrefix
 */

/** The exact length of the tx NMEA message prefix */
#define PUD_TXNMEAMESSAGEPREFIXLENGTH 4

/** The tx NMEA message prefix buffer */
static unsigned char txNmeaMessagePrefix[PUD_TXNMEAMESSAGEPREFIXLENGTH + 1];

/** True when the tx NMEA message prefix is set */
static bool txNmeaMessagePrefixSet = false;

/**
 @return
 The transmit multicast NMEA message prefix
 */
unsigned char * getTxNmeaMessagePrefix(void) {
	if (!txNmeaMessagePrefixSet) {
		setTxNmeaMessagePrefix(PUD_TX_NMEAMESSAGEPREFIX_DEFAULT, NULL,
				(set_plugin_parameter_addon) {.pc = NULL});
	}
	return &txNmeaMessagePrefix[0];
}

/**
 Set the transmit multicast NMEA message prefix

 @param value
 The transmit multicast NMEA message prefix (in string representation)
 @param data
 Unused
 @param addon
 Unused

 @return
 - true when an error is detected
 - false otherwise
 */
int setTxNmeaMessagePrefix(const char *value, void *data __attribute__ ((unused)),
		set_plugin_parameter_addon addon __attribute__ ((unused))) {
	static const char * valueName = PUD_TX_NMEAMESSAGEPREFIX_NAME;
	size_t valueLength;
	bool invalidChars;
	char report[256];

	assert (value != NULL);

	valueLength = strlen(value);
	if (valueLength != PUD_TXNMEAMESSAGEPREFIXLENGTH) {
		pudError(false, "Configured %s (%s) must be %u exactly characters",
				valueName, value, PUD_TXNMEAMESSAGEPREFIXLENGTH);
		return true;
	}

	invalidChars = nmea_string_has_invalid_chars(value, valueName, &report[0],
			sizeof(report));
	if (invalidChars) {
		pudError(false, &report[0]);
		return true;
	}

	if ((strchr(value, ' ') != NULL) || (strchr(value, '\t') != NULL)) {
		pudError(false, "Configured %s (%s) can not contain whitespace",
				valueName, value);
		return true;
	}

	strcpy((char *) &txNmeaMessagePrefix[0], value);
	txNmeaMessagePrefixSet = true;
	return false;
}

/*
 * olsrTtl
 */

/** The OLSR TTL */
static unsigned char olsrTtl = PUD_OLSR_TTL_DEFAULT;

/**
 @return
 The OLSR multicast IP packet time-to-live
 */
unsigned char getOlsrTtl(void) {
	return olsrTtl;
}

/**
 Set the OLSR multicast IP packet time-to-live

 @param value
 The OLSR multicast IP packet time-to-live (a number in string representation)
 @param data
 Unused
 @param addon
 Unused

 @return
 - true when an error is detected
 - false otherwise
 */
int setOlsrTtl(const char *value, void *data __attribute__ ((unused)), set_plugin_parameter_addon addon __attribute__ ((unused))) {
	static const char * valueName = PUD_OLSR_TTL_NAME;
	unsigned long long olsrTtlNew;

	assert (value != NULL);

	if (!readULL(valueName, value, &olsrTtlNew)) {
		return true;
	}

	if ((olsrTtlNew < 1) || (olsrTtlNew > MAX_TTL)) {
		pudError(false, "Configured %s (%llu) is outside of valid range 1-%u",
				valueName, olsrTtlNew, MAX_TTL);
		return true;
	}

	olsrTtl = olsrTtlNew;

	return false;
}

/*
 * updateIntervalStationary
 */

/** The stationary interval update plugin parameter (in seconds) */
static unsigned long long updateIntervalStationary = PUD_UPDATE_INTERVAL_STATIONARY_DEFAULT;

/**
 @return
 The stationary interval update plugin parameter (in seconds)
 */
unsigned long long getUpdateIntervalStationary(void) {
	return updateIntervalStationary;
}

/**
 Set stationary interval update plugin parameter

 @param value
 The stationary interval update plugin parameter (in seconds)
 @param data
 Unused
 @param addon
 Unused

 @return
 - true when an error is detected
 - false otherwise
 */
int setUpdateIntervalStationary(const char *value, void *data __attribute__ ((unused)),
		set_plugin_parameter_addon addon __attribute__ ((unused))) {
	static const char * valueName = PUD_UPDATE_INTERVAL_STATIONARY_NAME;
	unsigned long long updateIntervalStationaryNew;

	assert (value != NULL);

	if (!readULL(valueName, value, &updateIntervalStationaryNew)) {
		return true;
	}

	if (updateIntervalStationaryNew < 1) {
		pudError(false, "Configured %s must be at least 1", valueName);
		return true;
	}

	updateIntervalStationary = updateIntervalStationaryNew;

	return false;
}

/*
 * updateIntervalMoving
 */

/** The moving interval update plugin parameter (in seconds) */
static unsigned long long updateIntervalMoving = PUD_UPDATE_INTERVAL_MOVING_DEFAULT;

/**
 @return
 The moving interval update plugin parameter (in seconds)
 */
unsigned long long getUpdateIntervalMoving(void) {
	return updateIntervalMoving;
}

/**
 Set moving interval update plugin parameter

 @param value
 The moving interval update plugin parameter (in seconds)
 @param data
 Unused
 @param addon
 Unused

 @return
 - true when an error is detected
 - false otherwise
 */
int setUpdateIntervalMoving(const char *value, void *data __attribute__ ((unused)),
		set_plugin_parameter_addon addon __attribute__ ((unused))) {
	static const char * valueName = PUD_UPDATE_INTERVAL_MOVING_NAME;
	unsigned long long updateIntervalMovingNew;

	assert (value != NULL);

	if (!readULL(valueName, value, &updateIntervalMovingNew)) {
		return true;
	}

	if (updateIntervalMovingNew < 1) {
		pudError(false, "Configured %s must be at least 1", valueName);
		return true;
	}

	updateIntervalMoving = updateIntervalMovingNew;

	return false;
}

/*
 * movingSpeedThreshold
 */

/** The moving speed threshold plugin parameter (in kph) */
static unsigned long long movingSpeedThreshold = PUD_MOVING_SPEED_THRESHOLD_DEFAULT;

/**
 @return
 The moving speed threshold plugin parameter (in kph)
 */
unsigned long long getMovingSpeedThreshold(void) {
	return movingSpeedThreshold;
}

/**
 Set moving speed threshold plugin parameter

 @param value
 The moving speed threshold plugin parameter (in kph)
 @param data
 Unused
 @param addon
 Unused

 @return
 - true when an error is detected
 - false otherwise
 */
int setMovingSpeedThreshold(const char *value, void *data __attribute__ ((unused)),
		set_plugin_parameter_addon addon __attribute__ ((unused))) {
	static const char * valueName = PUD_MOVING_SPEED_THRESHOLD_NAME;
	unsigned long long movingSpeedThresholdNew;

	assert (value != NULL);

	if (!readULL(valueName, value, &movingSpeedThresholdNew)) {
		return true;
	}

	movingSpeedThreshold = movingSpeedThresholdNew;

	return false;
}

/*
 * movingDistanceThreshold
 */

/** The moving distance threshold plugin parameter (in meters) */
static unsigned long long movingDistanceThreshold = PUD_MOVING_DISTANCE_THRESHOLD_DEFAULT;

/**
 @return
 The moving distance threshold plugin parameter (in meters)
 */
unsigned long long getMovingDistanceThreshold(void) {
	return movingDistanceThreshold;
}

/**
 Set moving distance threshold plugin parameter

 @param value
 The moving distance threshold plugin parameter (in meter)
 @param data
 Unused
 @param addon
 Unused

 @return
 - true when an error is detected
 - false otherwise
 */
int setMovingDistanceThreshold(const char *value, void *data __attribute__ ((unused)),
		set_plugin_parameter_addon addon __attribute__ ((unused))) {
	static const char * valueName = PUD_MOVING_DISTANCE_THRESHOLD_NAME;
	unsigned long long movingDistanceThresholdNew;

	assert (value != NULL);

	if (!readULL(valueName, value, &movingDistanceThresholdNew)) {
		return true;
	}

	movingDistanceThreshold = movingDistanceThresholdNew;

	return false;
}

/*
 * dopMultiplier
 */

/* The DOP multiplier plugin parameter */
static double dopMultiplier = PUD_DOP_MULTIPLIER_DEFAULT;

/**
 @return
 The DOP multiplier plugin parameter
 */
double getDopMultiplier(void) {
	return dopMultiplier;
}

/**
 Set DOP multiplier plugin parameter

 @param value
 The DOP multiplier plugin parameter
 @param data
 Unused
 @param addon
 Unused

 @return
 - true when an error is detected
 - false otherwise
 */
int setDopMultiplier(const char *value, void *data __attribute__ ((unused)),
		set_plugin_parameter_addon addon __attribute__ ((unused))) {
	static const char * valueName = PUD_DOP_MULTIPLIER_NAME;
	double dopMultiplierNew;

	assert (value != NULL);

	if (!readDouble(valueName, value, &dopMultiplierNew)) {
		return true;
	}

	dopMultiplier = dopMultiplierNew;

	return false;
}

/*
 * defaultHdop
 */

/** The default HDOP plugin parameter (in meters) */
static unsigned long long defaultHdop = PUD_DEFAULT_HDOP_DEFAULT;

/**
 @return
 The default HDOP plugin parameter (in meters)
 */
unsigned long long getDefaultHdop(void) {
	return defaultHdop;
}

/**
 Set default HDOP plugin parameter

 @param value
 The default HDOP plugin parameter (in meters)
 @param data
 Unused
 @param addon
 Unused

 @return
 - true when an error is detected
 - false otherwise
 */
int setDefaultHdop(const char *value, void *data __attribute__ ((unused)),
		set_plugin_parameter_addon addon __attribute__ ((unused))) {
	static const char * valueName = PUD_MOVING_DISTANCE_THRESHOLD_NAME;
	unsigned long long defaultHdopNew;

	assert (value != NULL);

	if (!readULL(valueName, value, &defaultHdopNew)) {
		return true;
	}

	defaultHdop = defaultHdopNew;

	return false;
}

/*
 * defaultVdop
 */

/** The default VDOP plugin parameter (in meters) */
static unsigned long long defaultVdop = PUD_DEFAULT_VDOP_DEFAULT;

/**
 @return
 The default VDOP plugin parameter (in meters)
 */
unsigned long long getDefaultVdop(void) {
	return defaultVdop;
}

/**
 Set default VDOP plugin parameter

 @param value
 The default VDOP plugin parameter (in meters)
 @param data
 Unused
 @param addon
 Unused

 @return
 - true when an error is detected
 - false otherwise
 */
int setDefaultVdop(const char *value, void *data __attribute__ ((unused)),
		set_plugin_parameter_addon addon __attribute__ ((unused))) {
	static const char * valueName = PUD_MOVING_DISTANCE_THRESHOLD_NAME;
	unsigned long long defaultVdopNew;

	assert (value != NULL);

	if (!readULL(valueName, value, &defaultVdopNew)) {
		return true;
	}

	defaultVdop = defaultVdopNew;

	return false;
}

/*
 * averageDepth
 */

/** The depth of the average list */
static unsigned long long averageDepth = PUD_AVERAGE_DEPTH_DEFAULT;

/**
 @return
 The depth of the average list
 */
unsigned long long getAverageDepth(void) {
	return averageDepth;
}

/**
 Set average depth plugin parameter

 @param value
 The average depth plugin parameter
 @param data
 Unused
 @param addon
 Unused

 @return
 - true when an error is detected
 - false otherwise
 */
int setAverageDepth(const char *value, void *data __attribute__ ((unused)),
		set_plugin_parameter_addon addon __attribute__ ((unused))) {
	static const char * valueName = PUD_AVERAGE_DEPTH_NAME;
	unsigned long long averageDepthNew;

	assert (value != NULL);

	if (!readULL(valueName, value, &averageDepthNew)) {
		return true;
	}

	if (averageDepthNew < 1) {
		pudError(false, "Configured %s must be at least 1", valueName);
		return true;
	}

	averageDepth = averageDepthNew;

	return false;
}

/*
 * hysteresisCountToStationary
 */

/** The hysteresis count for changing state from moving to stationary */
static unsigned long long hysteresisCountToStationary = PUD_HYSTERESIS_COUNT_2STAT_DEFAULT;

/**
 @return
 The hysteresis count for changing state from moving to stationary
 */
unsigned long long getHysteresisCountToStationary(void) {
	return hysteresisCountToStationary;
}

/**
 Set hysteresis count plugin parameter

 @param value
 The hysteresis count plugin parameter
 @param data
 Unused
 @param addon
 Unused

 @return
 - true when an error is detected
 - false otherwise
 */
int setHysteresisCountToStationary(const char *value, void *data __attribute__ ((unused)),
		set_plugin_parameter_addon addon __attribute__ ((unused))) {
	static const char * valueName = PUD_HYSTERESIS_COUNT_2STAT_NAME;
	unsigned long long hysteresisCountNew;

	assert (value != NULL);

	if (!readULL(valueName, value, &hysteresisCountNew)) {
		return true;
	}

	hysteresisCountToStationary = hysteresisCountNew;

	return false;
}

/*
 * hysteresisCountToMoving
 */

/** The hysteresis count for changing state from stationary to moving */
static unsigned long long hysteresisCountToMoving = PUD_HYSTERESIS_COUNT_2MOV_DEFAULT;

/**
 @return
 The hysteresis count for changing state from stationary to moving
 */
unsigned long long getHysteresisCountToMoving(void) {
	return hysteresisCountToMoving;
}

/**
 Set hysteresis count plugin parameter

 @param value
 The hysteresis count plugin parameter
 @param data
 Unused
 @param addon
 Unused

 @return
 - true when an error is detected
 - false otherwise
 */
int setHysteresisCountToMoving(const char *value, void *data __attribute__ ((unused)),
		set_plugin_parameter_addon addon __attribute__ ((unused))) {
	static const char * valueName = PUD_HYSTERESIS_COUNT_2MOV_NAME;
	unsigned long long hysteresisCountNew;

	assert (value != NULL);

	if (!readULL(valueName, value, &hysteresisCountNew)) {
		return true;
	}

	hysteresisCountToMoving = hysteresisCountNew;

	return false;
}

/*
 * useDeDup
 */

/* when true then duplicate message detection is performed */
static bool useDeDup = PUD_USE_DEDUP_DEFAULT;

/**
 @return
 The duplicate message detection setting
 */
bool getUseDeDup(void) {
	return useDeDup;
}

/**
 Set duplicate message detection setting plugin parameter

 @param value
 The duplicate message detection setting plugin parameter
 @param data
 Unused
 @param addon
 Unused

 @return
 - true when an error is detected
 - false otherwise
 */
int setUseDeDup(const char *value, void *data __attribute__ ((unused)),
		set_plugin_parameter_addon addon __attribute__ ((unused))) {
	static const char * valueName = PUD_USE_DEDUP_NAME;
	unsigned long long useDeDupNew;

	assert (value != NULL);

	if (!readULL(valueName, value, &useDeDupNew)) {
		return true;
	}

	if ((useDeDupNew != 0) && (useDeDupNew != 1)) {
		pudError(false, "Configured %s must be 0 (false) or 1 (true)",
				valueName);
		return true;
	}

	useDeDup = (useDeDupNew == 1);

	return false;
}

/*
 * deDupDepth
 */

/** The hysteresis count for changing state from stationary to moving */
static unsigned long long deDupDepth = PUD_DEDUP_DEPTH_DEFAULT;

/**
 @return
 The hysteresis count for changing state from stationary to moving
 */
unsigned long long getDeDupDepth(void) {
	return deDupDepth;
}

/**
 Set de-duplication depth plugin parameter

 @param value
 The de-duplication depth plugin parameter
 @param data
 Unused
 @param addon
 Unused

 @return
 - true when an error is detected
 - false otherwise
 */
int setDeDupDepth(const char *value, void *data __attribute__ ((unused)),
		set_plugin_parameter_addon addon __attribute__ ((unused))) {
	static const char * valueName = PUD_DEDUP_DEPTH_NAME;
	unsigned long long deDupDepthNew;

	assert (value != NULL);

	if (!readULL(valueName, value, &deDupDepthNew)) {
		return true;
	}

	deDupDepth = deDupDepthNew;

	return false;
}

/*
 * useLoopback
 */

/* when true then loopback is performed */
static bool useLoopback = PUD_USE_LOOPBACK_DEFAULT;

/**
 @return
 The loopback usage setting
 */
bool getUseLoopback(void) {
	return useLoopback;
}

/**
 Set loopback usage plugin parameter

 @param value
 The loopback usage plugin parameter
 @param data
 Unused
 @param addon
 Unused

 @return
 - true when an error is detected
 - false otherwise
 */
int setUseLoopback(const char *value, void *data __attribute__ ((unused)),
		set_plugin_parameter_addon addon __attribute__ ((unused))) {
	static const char * valueName = PUD_USE_LOOPBACK_NAME;
	unsigned long long useLoopbackNew;

	assert (value != NULL);

	if (!readULL(valueName, value, &useLoopbackNew)) {
		return true;
	}

	if ((useLoopbackNew != 0) && (useLoopbackNew != 1)) {
		pudError(false, "Configured %s must be 0 (false) or 1 (true)",
				valueName);
		return true;
	}

	useLoopback = (useLoopbackNew == 1);

	return false;
}

/*
 * Check Functions
 */

/**
 Check the configuration for consistency and validity.

 @return
 - true when the configuration is consistent and valid
 - false otherwise
 */
unsigned int checkConfig(void) {
	int retval = true;

	if (rxNonOlsrInterfaceCount == 0) {
		pudError(false, "No receive non-OLSR interfaces configured");
		retval = false;
	}

	if (txNonOlsrInterfaceCount == 0) {
		pudError(false, "No transmit non-OLSR interfaces configured");
		retval = false;
	}

	if (!nodeIdSet) {
		if (nodeIdType == PUD_NODEIDTYPE_DNS) {
			char name[PUD_NODEIDMAXLENGTH + 1];

			errno = 0;
			if (gethostname(&name[0], sizeof(name)) < 0) {
				pudError(true, "Could not get the host name");
				retval = false;
			} else {
				setNodeId(&name[0], NULL,
						(set_plugin_parameter_addon) {.pc = NULL});
			}
		} else if ((nodeIdType != PUD_NODEIDTYPE_MAC) && (nodeIdType
				!= PUD_NODEIDTYPE_IPV4) && (nodeIdType != PUD_NODEIDTYPE_IPV6)) {
			pudError(false, "No node ID set while one is required for"
				" node type %u", nodeIdType);
			retval = false;
		}
	}

	if (!validateNodeId(nodeIdType)) {
		retval = false;
	}

	if (updateIntervalMoving > updateIntervalStationary) {
		pudError(false,"The update interval for moving situations must not be"
		" larger than that for stationary situations");
		retval = false;
	}

	return retval;
}

/**
 Check the configuration for consistency and validity after everything has been
 setup.

 @return
 - true when the configuration is consistent and valid
 - false otherwise
 */
unsigned int checkRunSetup(void) {
	int retval = true;
	unsigned int i;

	/* any receive interface name that is configured but is not the name of an
	 * actual receive interface is not a valid interface name */
	for (i = 0; i < rxNonOlsrInterfaceCount; i++) {
		unsigned char * nonOlsrInterfaceName = &rxNonOlsrInterfaceNames[i][0];

		TRxTxNetworkInterface * interfaceObject = getRxNetworkInterfaces();
		bool found = false;
		while (interfaceObject != NULL) {
			if (strncmp((char *) nonOlsrInterfaceName,
					(char *) &interfaceObject->name[0], IFNAMSIZ + 1) == 0) {
				found = true;
				break;
			}
			interfaceObject = interfaceObject->next;
		}
		if (!found) {
			pudError(false, "Configured receive non-OLSR interface %s is not"
				" a known interface name", nonOlsrInterfaceName);
			retval = false;
		}
	}

	/* any transmit interface name that is configured but is not the name of an
	 * actual transmit interface is not a valid interface name */
	for (i = 0; i < txNonOlsrInterfaceCount; i++) {
		unsigned char * nonOlsrInterfaceName = &txNonOlsrInterfaceNames[i][0];

		TRxTxNetworkInterface * interfaceObject = getTxNetworkInterfaces();
		bool found = false;
		while (interfaceObject != NULL) {
			if (strncmp((char *) nonOlsrInterfaceName,
					(char *) &interfaceObject->name[0], IFNAMSIZ + 1) == 0) {
				found = true;
				break;
			}
			interfaceObject = interfaceObject->next;
		}
		if (!found) {
			pudError(false, "Configured transmit non-OLSR interface %s is not"
				" a known interface name", nonOlsrInterfaceName);
			retval = false;
		}
	}

	return retval;
}
