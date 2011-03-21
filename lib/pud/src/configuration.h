#ifndef _PUD_CONFIGURATION_H_
#define _PUD_CONFIGURATION_H_

/* Plugin includes */

/* OLSR includes */
#include "olsrd_plugin.h"

/* System includes */
#include <stddef.h>
#include <stdbool.h>
#include <sys/socket.h>

/*
 * Utility Functions
 */

bool readULL(const char * valueName, const char * value,
		unsigned long long * valueNumber);

/*
 * Global Parameters
 */

/** nodeIdType legal values */
typedef enum {
	/** MAC address, 48 bits, 6 bytes */
	PUD_NODEIDTYPE_MAC = 0,

	/** MSISDN number, 15 digits, 50 bits, 7 bytes */
	PUD_NODEIDTYPE_MSISDN = 1,

	/** TETRA number, 17 digits, 57 bits, 8 bytes */
	PUD_NODEIDTYPE_TETRA = 2,

	/** DNS name, variable length */
	PUD_NODEIDTYPE_DNS = 3,

	/** IPv4 address, 32 bits, 4 bytes */
	PUD_NODEIDTYPE_IPV4 = 4,

	/** IPv6 address, 128 bits, 16 bytes */
	PUD_NODEIDTYPE_IPV6 = 6,

	/** Brandweer number, 7 digits, 24 bits, 3 bytes */
	PUD_NODEIDTYPE_192 = 192,

	/** Ambulance number, 6 digits, 20 bits, 3 bytes */
	PUD_NODEIDTYPE_193 = 193,

	/** Number in the range [1, 8191], 4 digits, 13 bits, 2 bytes */
	PUD_NODEIDTYPE_194 = 194
} NodeIdType;

/** The name of the nodeIdType plugin parameter */
#define PUD_NODE_ID_TYPE_NAME					"nodeIdType"

/** The default value of the nodeIdType plugin parameter */
#define PUD_NODE_ID_TYPE_DEFAULT				PUD_NODEIDTYPE_IPV4

/** The maximum value of the nodeIdType plugin parameter */
#define PUD_NODE_ID_TYPE_MAX					254

NodeIdType getNodeIdTypeNumber(void);
int setNodeIdType(const char *value, void *data,
		set_plugin_parameter_addon addon);

/** The name of the nodeId plugin parameter */
#define PUD_NODE_ID_NAME						"nodeId"

unsigned char * getNodeId(void);
unsigned char * getNodeIdWithLength(size_t *length);
int setNodeId(const char *value, void *data, set_plugin_parameter_addon addon);

/*
 * RX Parameters
 */

/** The name of the receive non-OLSR interfaces plugin parameter */
#define PUD_RX_NON_OLSR_IF_NAME					"rxNonOlsrIf"

bool isRxNonOlsrInterface(const char *ifName);
int addRxNonOlsrInterface(const char *value, void *data,
		set_plugin_parameter_addon addon);

/** The name of the allowed source IP address plugin parameter */
#define PUD_RX_ALLOWED_SOURCE_IP_NAME			"rxAllowedSourceIpAddress"

bool isRxAllowedSourceIpAddress(struct sockaddr * sender);
int addRxAllowedSourceIpAddress(const char *value, void *data,
		set_plugin_parameter_addon addon);

/** The name of the receive multicast address plugin parameter */
#define PUD_RX_MC_ADDR_NAME						"rxMcAddr"

/** The default value of the receive multicast address plugin parameter for IPv4 */
#define PUD_RX_MC_ADDR_4_DEFAULT				"224.0.0.224"

/** The default value of the receive multicast address plugin parameter for IPv6 */
#define PUD_RX_MC_ADDR_6_DEFAULT				"FF02:0:0:0:0:0:0:1"

union olsr_sockaddr * getRxMcAddr(void);
int
setRxMcAddr(const char *value, void *data, set_plugin_parameter_addon addon);

/** The name of the receive multicast port plugin parameter */
#define PUD_RX_MC_PORT_NAME						"rxMcPort"

/** The default value of the receive multicast port plugin parameter */
#define PUD_RX_MC_PORT_DEFAULT					2240

unsigned short getRxMcPort(void);
int
setRxMcPort(const char *value, void *data, set_plugin_parameter_addon addon);

/*
 * TX Parameters
 */

/** The name of the transmit non-OLSR interfaces plugin parameter */
#define PUD_TX_NON_OLSR_IF_NAME					"txNonOlsrIf"

bool isTxNonOlsrInterface(const char *ifName);
int addTxNonOlsrInterface(const char *value, void *data,
		set_plugin_parameter_addon addon);

/** The name of the transmit multicast address plugin parameter */
#define PUD_TX_MC_ADDR_NAME						"txMcAddr"

/** The default value of the transmit multicast address plugin parameter fro IPv4*/
#define PUD_TX_MC_ADDR_4_DEFAULT				"224.0.0.224"

/** The default value of the transmit multicast address plugin parameter for IPv6 */
#define PUD_TX_MC_ADDR_6_DEFAULT				"FF02:0:0:0:0:0:0:1"

union olsr_sockaddr * getTxMcAddr(void);
int
setTxMcAddr(const char *value, void *data, set_plugin_parameter_addon addon);

/** The name of the transmit multicast port plugin parameter */
#define PUD_TX_MC_PORT_NAME          			"txMcPort"

/** The default value of the transmit multicast port plugin parameter */
#define PUD_TX_MC_PORT_DEFAULT          		2240

unsigned short getTxMcPort(void);
int
setTxMcPort(const char *value, void *data, set_plugin_parameter_addon addon);

/** The name of the transmit multicast time-to-live plugin parameter */
#define PUD_TX_TTL_NAME							"txTtl"

/** The default value of the transmit multicast time-to-live plugin parameter */
#define PUD_TX_TTL_DEFAULT						1

unsigned char getTxTtl(void);
int setTxTtl(const char *value, void *data, set_plugin_parameter_addon addon);

/** The name of the transmit multicast NMEA message prefix plugin parameter */
#define PUD_TX_NMEAMESSAGEPREFIX_NAME			"txNmeaMessagePrefix"

/** The default value of the transmit multicast NMEA message prefix plugin parameter */
#define PUD_TX_NMEAMESSAGEPREFIX_DEFAULT		"NBSX"

unsigned char * getTxNmeaMessagePrefix(void);
int setTxNmeaMessagePrefix(const char *value, void *data,
		set_plugin_parameter_addon addon);

/*
 * OLSR Parameters
 */

/** The name of the OLSR multicast time-to-live plugin parameter */
#define PUD_OLSR_TTL_NAME						"olsrTtl"

/** The default value of the OLSR multicast time-to-live plugin parameter */
#define PUD_OLSR_TTL_DEFAULT					64

unsigned char getOlsrTtl(void);
int setOlsrTtl(const char *value, void *data, set_plugin_parameter_addon addon);

/*
 * Update Parameters
 */

/** The name of the stationary update interval plugin parameter */
#define PUD_UPDATE_INTERVAL_STATIONARY_NAME		"updateIntervalStationary"

/** The default value of the stationary update interval plugin parameter */
#define PUD_UPDATE_INTERVAL_STATIONARY_DEFAULT	60

unsigned long long getUpdateIntervalStationary(void);
int setUpdateIntervalStationary(const char *value, void *data,
		set_plugin_parameter_addon addon);

/** The name of the moving update interval plugin parameter */
#define PUD_UPDATE_INTERVAL_MOVING_NAME			"updateIntervalMoving"

/** The default value of the moving update interval plugin parameter */
#define PUD_UPDATE_INTERVAL_MOVING_DEFAULT		5

unsigned long long getUpdateIntervalMoving(void);
int setUpdateIntervalMoving(const char *value, void *data,
		set_plugin_parameter_addon addon);

/** The name of the moving speed threshold plugin parameter */
#define PUD_MOVING_SPEED_THRESHOLD_NAME			"movingSpeedThreshold"

/** The default value of the moving speed threshold plugin parameter */
#define PUD_MOVING_SPEED_THRESHOLD_DEFAULT		5

unsigned long long getMovingSpeedThreshold(void);
int setMovingSpeedThreshold(const char *value, void *data,
		set_plugin_parameter_addon addon);

/** The name of the moving distance threshold plugin parameter */
#define PUD_MOVING_DISTANCE_THRESHOLD_NAME		"movingDistanceThreshold"

/** The default value of the moving distance threshold plugin parameter */
#define PUD_MOVING_DISTANCE_THRESHOLD_DEFAULT	50

unsigned long long getMovingDistanceThreshold(void);
int setMovingDistanceThreshold(const char *value, void *data,
		set_plugin_parameter_addon addon);

/** The name of the default HDOP plugin parameter */
#define PUD_DEFAULT_HDOP_NAME		"defaultHdop"

/** The default value of the default HDOP plugin parameter */
#define PUD_DEFAULT_HDOP_DEFAULT	50

unsigned long long getDefaultHdop(void);
int setDefaultHdop(const char *value, void *data,
		set_plugin_parameter_addon addon);

/** The name of the default VDOP plugin parameter */
#define PUD_DEFAULT_VDOP_NAME		"defaultVdop"

/** The default value of the default VDOP plugin parameter */
#define PUD_DEFAULT_VDOP_DEFAULT	50

unsigned long long getDefaultVdop(void);
int setDefaultVdop(const char *value, void *data,
		set_plugin_parameter_addon addon);

/** The name of the average depth plugin parameter */
#define PUD_AVERAGE_DEPTH_NAME					"averageDepth"

/** The default value of the average depth plugin parameter */
#define PUD_AVERAGE_DEPTH_DEFAULT				5

unsigned long long getAverageDepth(void);
int setAverageDepth(const char *value, void *data,
		set_plugin_parameter_addon addon);

/** The name of the hysteresis count to stationary plugin parameter */
#define PUD_HYSTERESIS_COUNT_2STAT_NAME			"hysteresisCountToStationary"

/** The default value of the hysteresis count to stationary plugin parameter */
#define PUD_HYSTERESIS_COUNT_2STAT_DEFAULT		17

unsigned long long getHysteresisCountToStationary(void);
int setHysteresisCountToStationary(const char *value, void *data,
		set_plugin_parameter_addon addon);

/** The name of the hysteresis count to moving plugin parameter */
#define PUD_HYSTERESIS_COUNT_2MOV_NAME			"hysteresisCountToMoving"

/** The default value of the hysteresis count to moving plugin parameter */
#define PUD_HYSTERESIS_COUNT_2MOV_DEFAULT		5

unsigned long long getHysteresisCountToMoving(void);
int setHysteresisCountToMoving(const char *value, void *data,
		set_plugin_parameter_addon addon);

/*
 * Other Plugin Settings
 */

/** The name of the deduplication usage plugin parameter */
#define PUD_USE_DEDUP_NAME						"useDeDup"

/** The default value of the deduplication usage plugin parameter */
#define PUD_USE_DEDUP_DEFAULT					true

bool getUseDeDup(void);
int
setUseDeDup(const char *value, void *data, set_plugin_parameter_addon addon);

/** The name of the deduplication depth plugin parameter */
#define PUD_DEDUP_DEPTH_NAME					"deDupDepth"

/** The default value of the deduplication depth plugin parameter */
#define PUD_DEDUP_DEPTH_DEFAULT					56

unsigned long long getDeDupDepth(void);
int
setDeDupDepth(const char *value, void *data, set_plugin_parameter_addon addon);

/** The name of the loopback usage plugin parameter */
#define PUD_USE_LOOPBACK_NAME					"useLoopback"

/** The default value of the loopback usage plugin parameter */
#define PUD_USE_LOOPBACK_DEFAULT				false

bool getUseLoopback(void);
int
setUseLoopback(const char *value, void *data, set_plugin_parameter_addon addon);

/*
 * Check Functions
 */

unsigned int checkConfig(void);

unsigned int checkRunSetup(void);

#endif /* _PUD_CONFIGURATION_H_ */
