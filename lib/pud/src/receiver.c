#include "receiver.h"

/* Plugin includes */
#include "pud.h"
#include "gpsConversion.h"
#include "configuration.h"
#include "dump.h"
#include "timers.h"
#include "posAvg.h"
#include "networkInterfaces.h"
#include "compiler.h"

/* OLSRD includes */
#include "net_olsr.h"

/* System includes */
#include <stddef.h>
#include <nmea/parser.h>
#include <nmea/info.h>
#include <pthread.h>
#include <nmea/info.h>
#include <string.h>
#include <nmea/gmath.h>
#include <nmea/sentence.h>
#include <math.h>
#include <net/if.h>
#include <assert.h>

/* Debug includes */
#if defined(PUD_DUMP_GPS_PACKETS_TX_OLSR) || \
	defined(PUD_DUMP_GPS_PACKETS_TX_UPLINK) || \
	defined(PUD_DUMP_AVERAGING)
#include "olsr.h"
#endif

/*
 * NMEA parser
 */

/** The NMEA string parser */
static nmeaPARSER nmeaParser;

/*
 * State
 */

/** Type describing a tri-state boolean */
typedef enum _TristateBoolean {
	UNKNOWN = 0,
	UNSET = 1,
	SET = 2
} TristateBoolean;

#define TristateBooleanToString(s)	((s == SET) ? "set" : \
									 (s == UNSET) ? "unset" : \
									 "unknown")

/** Type describing movement state */
typedef enum _MovementState {
	STATIONARY = 0,
	MOVING = 1
} MovementState;

#define MovementStateToString(s)	((s == MOVING) ? "moving" : \
									 "stationary")

/** Type describing state */
typedef struct _StateType {
	MovementState internalState; /**< the internal movement state */
	MovementState externalState; /**< the externally visible movement state */
	unsigned long long hysteresisCounter; /**< the hysteresis counter external state changes */
} StateType;

/** The state */
static StateType state = {
		.internalState = MOVING,
		.externalState = MOVING,
		.hysteresisCounter = 0
};

/** Type describing movement calculations */
typedef struct _MovementType {
	TristateBoolean moving; /**< SET: we are moving */

	TristateBoolean overThresholds; /**< SET: at least 1 threshold state is set */
	TristateBoolean speedOverThreshold; /**< SET: speed is over threshold */
	TristateBoolean hDistanceOverThreshold; /**< SET: horizontal distance is outside threshold */
	TristateBoolean vDistanceOverThreshold; /**< SET: vertical distance is outside threshold */

	TristateBoolean outside; /**< SET: at least 1 outside state is SET */
	TristateBoolean outsideHdop; /**< SET: avg is outside lastTx HDOP */
	TristateBoolean outsideVdop; /**< SET: avg is outside lastTx VDOP */

	TristateBoolean inside; /**< SET: all inside states are SET */
	TristateBoolean insideHdop; /**< SET: avg is inside lastTx HDOP */
	TristateBoolean insideVdop; /**< SET: avg is inside lastTx VDOP */
} MovementType;

/*
 * Averaging
 */

/** The average position with its administration */
static PositionAverageList positionAverageList;

/*
 * TX to OLSR
 */

typedef enum _TimedTxInterface {
	OLSR = 1,
	UPLINK = 2
} TimedTxInterface;

/** Structure of the latest GPS information that is transmitted */
typedef struct _TransmitGpsInformation {
	pthread_mutex_t mutex; /**< access mutex */
	bool updated; /**< true when the information was updated */
	PositionUpdateEntry txPosition; /**< The last transmitted position */
} TransmitGpsInformation;

/** The latest position information that is transmitted */
static TransmitGpsInformation transmitGpsInformation;

/** The last transmitted position.
 * The same as transmitGpsInformation.txPosition.
 * We keep this because then we can access the information without locking
 * mutexes. */
static PositionUpdateEntry txPosition;

/** The size of the buffer in which the OLSR and uplink messages are assembled */
#define TX_BUFFER_SIZE_FOR_OLSR 1024

/*
 * Functions
 */

/**
 This function is called every time before a message is sent on a specific
 interface. It can manipulate the outgoing message.
 Note that a change to the outgoing messages is carried over to the message
 that goes out on the next interface when the message is _not_ reset
 before it is sent out on the next interface.

 @param olsrMessage
 A pointer to the outgoing message
 @param ifn
 A pointer to the OLSR interface structure
 */
static void nodeIdPreTransmitHook(union olsr_message *olsrMessage,
		struct interface *ifn) {
	/* set the MAC address in the message when needed */
	if (unlikely(getNodeIdTypeNumber() == PUD_NODEIDTYPE_MAC)) {
		TOLSRNetworkInterface * olsrIf = getOlsrNetworkInterface(ifn);
		PudOlsrPositionUpdate * olsrGpsMessage =
				getOlsrMessagePayload(olsr_cnf->ip_version, olsrMessage);

		if (likely(olsrIf != NULL)) {
			setPositionUpdateNodeId(olsrGpsMessage, &olsrIf->hwAddress[0],
					PUD_NODEIDTYPE_MAC_BYTES, false);
		} else {
			unsigned char buffer[PUD_NODEIDTYPE_MAC_BYTES] = { 0 };
			setPositionUpdateNodeId(olsrGpsMessage, &buffer[0],
					PUD_NODEIDTYPE_MAC_BYTES, false);

			pudError(false, "Could not find OLSR interface %s, cleared its"
				" MAC address in the OLSR message\n", ifn->int_name);
		}
	}
}

/**
 Determine whether s position is valid.

 @param position
 a pointer to a position

 @return
 - true when valid
 - false otherwise
 */
static bool positionValid(PositionUpdateEntry * position) {
	return (nmea_INFO_has_field(position->nmeaInfo.smask, FIX)
			&& (position->nmeaInfo.fix != NMEA_FIX_BAD));
}

/** Send the transmit buffer out over all designated interfaces, called as a
 * timer callback and also immediately on an external state change.

 @param interfaces
 a bitmap defining which interfaces to send over
 */
static void txToAllOlsrInterfaces(TimedTxInterface interfaces) {
	/** buffer used to fill in the OLSR and uplink messages */
	unsigned char txBuffer[TX_BUFFER_SIZE_FOR_OLSR];
	UplinkMessage * message1 = (UplinkMessage *) &txBuffer[0];

	unsigned int txBufferSpaceTaken = 0;
	#define txBufferSpaceFree	(sizeof(txBuffer) - txBufferSpaceTaken)

	/* the first message in the buffer is an OLSR position update */
	union olsr_message * olsrMessage =
			(union olsr_message *) &message1->msg.olsrMessage;
	unsigned int aligned_size = 0;

	/* convert nmeaINFO to wireformat olsr message */
	(void) pthread_mutex_lock(&transmitGpsInformation.mutex);
	if (!transmitGpsInformation.updated
			&& positionValid(&transmitGpsInformation.txPosition)) {
		nmea_time_now(&transmitGpsInformation.txPosition.nmeaInfo.utc);
	}

	txBufferSpaceTaken += sizeof(UplinkHeader);
	aligned_size = gpsToOlsr(&transmitGpsInformation.txPosition.nmeaInfo,
			olsrMessage, txBufferSpaceFree,
			((state.externalState == MOVING) ? getUpdateIntervalMoving()
						: getUpdateIntervalStationary()));
	txBufferSpaceTaken += aligned_size;
	transmitGpsInformation.updated = false;
	(void) pthread_mutex_unlock(&transmitGpsInformation.mutex);

	if (aligned_size > 0) {
		/* push out to all OLSR interfaces */
		if ((interfaces & OLSR) != 0) {
			int r;
			struct interface *ifn;
			for (ifn = ifnet; ifn; ifn = ifn->int_next) {
				nodeIdPreTransmitHook(olsrMessage, ifn);
				r = net_outbuffer_push(ifn, olsrMessage, aligned_size);
				if (r != (int) aligned_size) {
					pudError(
							false,
							"Could not send to OLSR interface %s: %s"
									" (aligned_size=%u, r=%d)",
							ifn->int_name,
							((r == -1) ? "no buffer was found"
							: (r == 0) ? "there was not enough room in the buffer"
							: "unknown reason"), aligned_size, r);
				}
#ifdef PUD_DUMP_GPS_PACKETS_TX_OLSR
				else {
					olsr_printf(0, "%s: packet sent to OLSR interface %s (%d bytes)\n",
							PUD_PLUGIN_ABBR, ifn->int_name, aligned_size);
					dump_packet((unsigned char *)olsrMessage, aligned_size);
				}
#endif
			}

			/* loopback to tx interface when so configured */
			if (getUseLoopback()) {
				(void) packetReceivedFromOlsr(olsrMessage, NULL, NULL);
			}
		}

		/* push out over uplink when an uplink is configured */
		if (((interfaces & UPLINK) != 0) && isUplinkAddrSet()) {
			int fd = getUplinkSocketFd();
			if (fd != -1) {
				/* FIXME until we have gateway selection we just send ourselves
				 * as cluster leader */
				union olsr_ip_addr * gwAddr = &olsr_cnf->main_addr;

				UplinkMessage * message2 =
						(UplinkMessage *) &txBuffer[aligned_size
								+ sizeof(UplinkHeader)];
				UplinkClusterLeader * clusterLeaderMessage =
						&message2->msg.clusterLeader;
				unsigned int message2Size;
				union olsr_ip_addr * clOriginator;
				union olsr_ip_addr * clClusterLeader;

				/*
				 * position update message (message1)
				 */

				union olsr_sockaddr * address = getUplinkAddr();
				PudOlsrPositionUpdate * olsrGpsMessage = getOlsrMessagePayload(
						olsr_cnf->ip_version, olsrMessage);

				/* set header fields */
				setUplinkMessageType(&message1->header, POSITION);
				setUplinkMessageLength(&message1->header, aligned_size);
				setUplinkMessageIPv6(&message1->header,
						(olsr_cnf->ip_version != AF_INET));
				setUplinkMessagePadding(&message1->header, 0);

				/* fixup validity time */
				setValidityTime(&olsrGpsMessage->validityTime,
						(state.externalState == MOVING) ?
						getUplinkUpdateIntervalMoving() :
						getUplinkUpdateIntervalStationary());

				/*
				 * cluster leader message (message2)
				 */

				clOriginator = getClusterLeaderOriginator(olsr_cnf->ip_version,
						clusterLeaderMessage);
				clClusterLeader = getClusterLeaderClusterLeader(
						olsr_cnf->ip_version, clusterLeaderMessage);
				if (olsr_cnf->ip_version == AF_INET) {
					message2Size = sizeof(clusterLeaderMessage->version)
							+ sizeof(clusterLeaderMessage->validityTime)
							+ sizeof(clusterLeaderMessage->leader.v4);
				} else {
					message2Size = sizeof(clusterLeaderMessage->version)
							+ sizeof(clusterLeaderMessage->validityTime)
							+ sizeof(clusterLeaderMessage->leader.v6);
				}

				/* set header fields */
				setUplinkMessageType(&message2->header, CLUSTERLEADER);
				setUplinkMessageLength(&message2->header, message2Size);
				setUplinkMessageIPv6(&message2->header,
						(olsr_cnf->ip_version != AF_INET));
				setUplinkMessagePadding(&message2->header, 0);
				txBufferSpaceTaken += sizeof(UplinkHeader);

				/* setup validity time */
				setClusterLeaderVersion(clusterLeaderMessage, PUD_WIRE_FORMAT_VERSION);
				setValidityTime(&clusterLeaderMessage->validityTime,
						(state.externalState == MOVING) ?
						getUplinkUpdateIntervalMoving() :
						getUplinkUpdateIntervalStationary());

				memcpy(clOriginator, &olsr_cnf->main_addr, olsr_cnf->ipsize);
				memcpy(clClusterLeader, gwAddr, olsr_cnf->ipsize);

				txBufferSpaceTaken += message2Size;

				errno = 0;
				if (sendto(fd, &txBuffer, txBufferSpaceTaken, 0,
					(struct sockaddr *) &address->in, sizeof(address->in)) < 0) {
					pudError(true, "Could not send to uplink"
							" (aligned_size=%u)", txBufferSpaceTaken);
				}
#ifdef PUD_DUMP_GPS_PACKETS_TX_UPLINK
				else {
					olsr_printf(0, "%s: packet sent to uplink (%d bytes)\n",
							PUD_PLUGIN_ABBR, aligned_size);
					dump_packet((unsigned char *)&txBuffer,
							(sizeof(txBuffer) -
							 sizeof(txBuffer.msg)) + aligned_size);
				}
#endif
			}
		}
	}
}

/*
 * Timer Callbacks
 */

/**
 The OLSR tx timer callback

 @param context
 unused
 */
static void pud_olsr_tx_timer_callback(void *context __attribute__ ((unused))) {
	txToAllOlsrInterfaces(OLSR);
}

/**
 The uplink timer callback

 @param context
 unused
 */
static void pud_uplink_timer_callback(void *context __attribute__ ((unused))) {
	txToAllOlsrInterfaces(UPLINK);
}

/**
 Detemine whether we are moving by comparing fields from the average
 position against those of the last transmitted position.

 MUST be called which the position average list locked.

 @param avg
 the average position
 @param lastTx
 the last transmitted position
 @param result
 the results of all movement criteria
 */
static void detemineMoving(PositionUpdateEntry * avg,
		PositionUpdateEntry * lastTx, MovementType * result) {
	/* avg field presence booleans */
	bool avgHasSpeed;
	bool avgHasPos;
	bool avgHasHdop;
	bool avgHasElv;
	bool avgHasVdop;

	/* lastTx field presence booleans */bool lastTxHasPos;
	bool lastTxHasHdop;
	bool lastTxHasElv;
	bool lastTxHasVdop;

	/* these have defaults */
	double dopMultiplier;
	double avgHdop;
	double lastTxHdop;
	double avgVdop;
	double lastTxVdop;

	/* calculated values and their validity booleans */
	double hDistance;
	double vDistance;
	double hdopDistanceForOutside;
	double hdopDistanceForInside;
	double vdopDistanceForOutside;
	double vdopDistanceForInside;
	bool hDistanceValid;
	bool hdopDistanceValid;
	bool vDistanceValid;
	bool vdopDistanceValid;

	/* clear outputs */
	memset(result, UNKNOWN, sizeof(MovementType));

	/*
	 * Validity
	 *
	 * avg  last  movingNow
	 *  0     0   UNKNOWN : can't determine whether we're moving
	 *  0     1   UNKNOWN : can't determine whether we're moving
	 *  1     0   MOVING  : always seen as movement
	 *  1     1   determine via other parameters
	 */

	if (!positionValid(avg)) {
		/* everything is unknown */
		return;
	}

	/* avg is valid here */

	if (!positionValid(lastTx)) {
		result->moving = SET;
		/* the rest is unknown */
		return;
	}

	/* both avg and lastTx are valid here */

	/* avg field presence booleans */
	avgHasSpeed = nmea_INFO_has_field(avg->nmeaInfo.smask, SPEED);
	avgHasPos = nmea_INFO_has_field(avg->nmeaInfo.smask, LAT)
			&& nmea_INFO_has_field(avg->nmeaInfo.smask, LON);
	avgHasHdop = nmea_INFO_has_field(avg->nmeaInfo.smask, HDOP);
	avgHasElv = nmea_INFO_has_field(avg->nmeaInfo.smask, ELV);
	avgHasVdop = nmea_INFO_has_field(avg->nmeaInfo.smask, VDOP);

	/* lastTx field presence booleans */
	lastTxHasPos = nmea_INFO_has_field(lastTx->nmeaInfo.smask, LAT)
			&& nmea_INFO_has_field(lastTx->nmeaInfo.smask, LON);
	lastTxHasHdop = nmea_INFO_has_field(lastTx->nmeaInfo.smask, HDOP);
	lastTxHasElv = nmea_INFO_has_field(lastTx->nmeaInfo.smask, ELV);
	lastTxHasVdop = nmea_INFO_has_field(lastTx->nmeaInfo.smask, VDOP);

	/* fill in some values _or_ defaults */
	dopMultiplier = getDopMultiplier();
	avgHdop = avgHasHdop ? avg->nmeaInfo.HDOP : getDefaultHdop();
	lastTxHdop = lastTxHasHdop ? lastTx->nmeaInfo.HDOP : getDefaultHdop();
	avgVdop = avgHasVdop ? avg->nmeaInfo.VDOP : getDefaultVdop();
	lastTxVdop = lastTxHasVdop ? lastTx->nmeaInfo.VDOP : getDefaultVdop();

	/*
	 * Calculations
	 */

	/* hDistance */
	if (avgHasPos && lastTxHasPos) {
		nmeaPOS avgPos;
		nmeaPOS lastTxPos;

		avgPos.lat = nmea_degree2radian(avg->nmeaInfo.lat);
		avgPos.lon = nmea_degree2radian(avg->nmeaInfo.lon);

		lastTxPos.lat = nmea_degree2radian(lastTx->nmeaInfo.lat);
		lastTxPos.lon = nmea_degree2radian(lastTx->nmeaInfo.lon);

		hDistance = nmea_distance_ellipsoid(&avgPos, &lastTxPos, NULL, NULL);
		hDistanceValid = true;
	} else {
		hDistanceValid = false;
	}

	/* hdopDistance */
	if (avgHasHdop || lastTxHasHdop) {
		hdopDistanceForOutside = dopMultiplier * (lastTxHdop + avgHdop);
		hdopDistanceForInside = dopMultiplier * (lastTxHdop - avgHdop);
		hdopDistanceValid = true;
	} else {
		hdopDistanceValid = false;
	}

	/* vDistance */
	if (avgHasElv && lastTxHasElv) {
		vDistance = fabs(lastTx->nmeaInfo.elv - avg->nmeaInfo.elv);
		vDistanceValid = true;
	} else {
		vDistanceValid = false;
	}

	/* vdopDistance */
	if (avgHasVdop || lastTxHasVdop) {
		vdopDistanceForOutside = dopMultiplier * (lastTxVdop + avgVdop);
		vdopDistanceForInside = dopMultiplier * (lastTxVdop - avgVdop);
		vdopDistanceValid = true;
	} else {
		vdopDistanceValid = false;
	}

	/*
	 * Moving Criteria Evaluation Start
	 * We compare the average position against the last transmitted position.
	 */

	/* Speed */
	if (avgHasSpeed) {
		if (avg->nmeaInfo.speed >= getMovingSpeedThreshold()) {
			result->speedOverThreshold = SET;
		} else {
			result->speedOverThreshold = UNSET;
		}
	}

	/*
	 * Position
	 *
	 * avg  last  hDistanceMoving
	 *  0     0   determine via other parameters
	 *  0     1   determine via other parameters
	 *  1     0   MOVING
	 *  1     1   determine via distance threshold and HDOP
	 */
	if (avgHasPos && !lastTxHasPos) {
		result->hDistanceOverThreshold = SET;
	} else if (hDistanceValid) {
		if (hDistance >= getMovingDistanceThreshold()) {
			result->hDistanceOverThreshold = SET;
		} else {
			result->hDistanceOverThreshold = UNSET;
		}

		/*
		 * Position with HDOP
		 *
		 * avg  last  movingNow
		 *  0     0   determine via other parameters
		 *  0     1   determine via position with HDOP (avg has default HDOP)
		 *  1     0   determine via position with HDOP (lastTx has default HDOP)
		 *  1     1   determine via position with HDOP
		 */
		if (hdopDistanceValid) {
			/* we are outside the HDOP when the HDOPs no longer overlap */
			if (hDistance > hdopDistanceForOutside) {
				result->outsideHdop = SET;
			} else {
				result->outsideHdop = UNSET;
			}

			/* we are inside the HDOP when the HDOPs fully overlap */
			if (hDistance <= hdopDistanceForInside) {
				result->insideHdop = SET;
			} else {
				result->insideHdop = UNSET;
			}
		}
	}

	/*
	 * Elevation
	 *
	 * avg  last  movingNow
	 *  0     0   determine via other parameters
	 *  0     1   determine via other parameters
	 *  1     0   MOVING
	 *  1     1   determine via distance threshold and VDOP
	 */
	if (avgHasElv && !lastTxHasElv) {
		result->vDistanceOverThreshold = SET;
	} else if (vDistanceValid) {
		if (vDistance >= getMovingDistanceThreshold()) {
			result->vDistanceOverThreshold = SET;
		} else {
			result->vDistanceOverThreshold = UNSET;
		}

		/*
		 * Elevation with VDOP
		 *
		 * avg  last  movingNow
		 *  0     0   determine via other parameters
		 *  0     1   determine via elevation with VDOP (avg has default VDOP)
		 *  1     0   determine via elevation with VDOP (lastTx has default VDOP)
		 *  1     1   determine via elevation with VDOP
		 */
		if (vdopDistanceValid) {
			/* we are outside the VDOP when the VDOPs no longer overlap */
			if (vDistance > vdopDistanceForOutside) {
				result->outsideVdop = SET;
			} else {
				result->outsideVdop = UNSET;
			}

			/* we are inside the VDOP when the VDOPs fully overlap */
			if (vDistance <= vdopDistanceForInside) {
				result->insideVdop = SET;
			} else {
				result->insideVdop = UNSET;
			}
		}
	}

	/*
	 * Moving Criteria Evaluation End
	 */

	/* accumulate inside criteria */
	if ((result->insideHdop == SET) && (result->insideVdop == SET)) {
		result->inside = SET;
	} else if ((result->insideHdop == UNSET) || (result->insideVdop == UNSET)) {
		result->inside = UNSET;
	}

	/* accumulate outside criteria */
	if ((result->outsideHdop == SET) || (result->outsideVdop == SET)) {
		result->outside = SET;
	} else if ((result->outsideHdop == UNSET)
			|| (result->outsideVdop == UNSET)) {
		result->outside = UNSET;
	}

	/* accumulate threshold criteria */
	if ((result->speedOverThreshold == SET)
			|| (result->hDistanceOverThreshold == SET)
			|| (result->vDistanceOverThreshold == SET)) {
		result->overThresholds = SET;
	} else if ((result->speedOverThreshold == UNSET)
			|| (result->hDistanceOverThreshold == UNSET)
			|| (result->vDistanceOverThreshold == UNSET)) {
		result->overThresholds = UNSET;
	}

	/* accumulate moving criteria */
	if ((result->overThresholds == SET) || (result->outside == SET)) {
		result->moving = SET;
	} else if ((result->overThresholds == UNSET)
			&& (result->outside == UNSET)) {
		result->moving = UNSET;
	}

	return;
}

/**
 Update the latest GPS information. This function is called when a packet is
 received from a rxNonOlsr interface, containing one or more NMEA strings with
 GPS information.

 @param rxBuffer
 the receive buffer with the received NMEA string(s)
 @param rxCount
 the number of bytes in the receive buffer

 @return
 - false on failure
 - true otherwise
 */
bool receiverUpdateGpsInformation(unsigned char * rxBuffer, size_t rxCount) {
	static const char * rxBufferPrefix = "$GP";
	static const size_t rxBufferPrefixLength = 3;

	bool retval = false;
	PositionUpdateEntry * incomingEntry;
	MovementState newState = MOVING;
	PositionUpdateEntry * posAvgEntry;
	MovementType movementResult;
	TristateBoolean movingNow;
	bool internalStateChange = false;
	bool externalStateChange = false;
	bool updateTransmitGpsInformation = false;

	/* do not process when the message does not start with $GP */
	if ((rxCount < rxBufferPrefixLength) || (strncmp((char *) rxBuffer,
			rxBufferPrefix, rxBufferPrefixLength) != 0)) {
		return true;
	}

	(void) pthread_mutex_lock(&positionAverageList.mutex);

	/* parse all NMEA strings in the rxBuffer into the incoming entry */
	incomingEntry = getPositionAverageEntry(&positionAverageList, INCOMING);
	nmea_zero_INFO(&incomingEntry->nmeaInfo);
	nmea_parse(&nmeaParser, (char *) rxBuffer, rxCount,
			&incomingEntry->nmeaInfo);

#if defined(PUD_DUMP_AVERAGING)
	dump_nmeaInfo(&incomingEntry->nmeaInfo,
			"receiverUpdateGpsInformation: incoming entry");
#endif /* PUD_DUMP_AVERAGING */

	/* ignore when no useful information */
	if (incomingEntry->nmeaInfo.smask == GPNON) {
		retval = true;
		goto end;
	}

	nmea_INFO_sanitise(&incomingEntry->nmeaInfo);

#if defined(PUD_DUMP_AVERAGING)
	dump_nmeaInfo(&incomingEntry->nmeaInfo,
			"receiverUpdateGpsInformation: incoming entry after sanitise");
#endif /* PUD_DUMP_AVERAGING */

	/* we always work with latitude, longitude in degrees and DOPs in meters */
	nmea_INFO_unit_conversion(&incomingEntry->nmeaInfo);

#if defined(PUD_DUMP_AVERAGING)
	dump_nmeaInfo(&incomingEntry->nmeaInfo,
			"receiverUpdateGpsInformation: incoming entry after unit conversion");
#endif /* PUD_DUMP_AVERAGING */

	/*
	 * Averageing
	 */

	if (state.internalState == MOVING) {
		/* flush average: keep only the incoming entry */
		flushPositionAverageList(&positionAverageList);
	}
	addNewPositionToAverage(&positionAverageList, incomingEntry);
	posAvgEntry = getPositionAverageEntry(&positionAverageList, AVERAGE);

	/*
	 * Movement detection
	 */

	detemineMoving(posAvgEntry, &txPosition, &movementResult);
	movingNow = movementResult.moving;

#if defined(PUD_DUMP_AVERAGING)
	olsr_printf(0, "receiverUpdateGpsInformation: internalState = %s\n",
			MovementStateToString(state.internalState));
	olsr_printf(0, "receiverUpdateGpsInformation: movingNow     = %s\n",
			TristateBooleanToString(movingNow));
#endif /* PUD_DUMP_AVERAGING */

	/*
	 * Internal State
	 */

	if (movingNow == SET) {
		newState = MOVING;
	} else if (movingNow == UNSET) {
		newState = STATIONARY;
	}
	internalStateChange = (state.internalState != newState);
	state.internalState = newState;

	/*
	 * External State (+ hysteresis)
	 */

	if (internalStateChange) {
		/* restart hysteresis for external state change when we have an internal
		 * state change */
		state.hysteresisCounter = 0;
	}

	/* when internal state and external state are not the same we need to
	 * perform hysteresis before we can propagate the internal state to the
	 * external state */
	newState = state.externalState;
	if (state.internalState != state.externalState) {
		switch (state.internalState) {
			case STATIONARY:
				/* external state is MOVING */

				/* delay going to stationary a bit */
				state.hysteresisCounter++;

				if (state.hysteresisCounter
						>= getHysteresisCountToStationary()) {
					/* outside the hysteresis range, go to stationary */
					newState = STATIONARY;
				}
				break;

			case MOVING:
				/* external state is STATIONARY */

				/* delay going to moving a bit */
				state.hysteresisCounter++;

				if (state.hysteresisCounter >= getHysteresisCountToMoving()) {
					/* outside the hysteresis range, go to moving */
					newState = MOVING;
				}
				break;

			default:
				/* when unknown do just as if we transition into moving */
				newState = MOVING;
				break;
		}
	}
	externalStateChange = (state.externalState != newState);
	state.externalState = newState;

#if defined(PUD_DUMP_AVERAGING)
	olsr_printf(0, "receiverUpdateGpsInformation: newState = %s\n",
			MovementStateToString(newState));
	dump_nmeaInfo(&posAvgEntry->nmeaInfo,
			"receiverUpdateGpsInformation: posAvgEntry");
#endif /* PUD_DUMP_AVERAGING */

	/*
	 * Update transmitGpsInformation
	 */

	updateTransmitGpsInformation = externalStateChange
			|| (positionValid(posAvgEntry) && !positionValid(&txPosition))
			|| (movementResult.inside == SET);

	if ((state.externalState == MOVING) || updateTransmitGpsInformation) {
		memcpy(&txPosition.nmeaInfo, &posAvgEntry->nmeaInfo, sizeof(nmeaINFO));
		(void) pthread_mutex_lock(&transmitGpsInformation.mutex);
		memcpy(&transmitGpsInformation.txPosition.nmeaInfo,
				&posAvgEntry->nmeaInfo, sizeof(nmeaINFO));
		transmitGpsInformation.updated = true;

#if defined(PUD_DUMP_AVERAGING)
		dump_nmeaInfo(&transmitGpsInformation.txPosition.nmeaInfo,
			"receiverUpdateGpsInformation: transmitGpsInformation");
#endif /* PUD_DUMP_AVERAGING */

		(void) pthread_mutex_unlock(&transmitGpsInformation.mutex);
	}

	if (updateTransmitGpsInformation) {
		TimedTxInterface interfaces = OLSR; /* always send over olsr */
		if (!restartOlsrTxTimer(
				(state.externalState == STATIONARY) ? getUpdateIntervalStationary()
				: getUpdateIntervalMoving(), &pud_olsr_tx_timer_callback)) {
			pudError(0, "Could not restart OLSR tx timer, no periodic"
					" position updates will be sent to the OLSR network");
		}

		if (isUplinkAddrSet()) {
			interfaces |= UPLINK;
			if (!restartUplinkTxTimer(
					(state.externalState == STATIONARY) ? getUplinkUpdateIntervalStationary()
					: getUplinkUpdateIntervalMoving(), &pud_uplink_timer_callback)
					) {
				pudError(0, "Could not restart uplink timer, no periodic"
						" position updates will be uplinked");
			}
		}

		/* do an immediate transmit */
		txToAllOlsrInterfaces(interfaces);
	}

	retval = true;

	end: (void) pthread_mutex_unlock(&positionAverageList.mutex);
	return retval;
}

/*
 * Receiver start/stop
 */

/**
 Start the receiver

 @return
 - false on failure
 - true otherwise
 */
bool startReceiver(void) {
	pthread_mutexattr_t attr;
	if (pthread_mutexattr_init(&attr)) {
		return false;
	}
	if (pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE_NP)) {
		return false;
	}
	if (pthread_mutex_init(&transmitGpsInformation.mutex, &attr)) {
		return false;
	}

	if (!nmea_parser_init(&nmeaParser)) {
		pudError(false, "Could not initialise NMEA parser");
		return false;
	}

	nmea_zero_INFO(&transmitGpsInformation.txPosition.nmeaInfo);
	transmitGpsInformation.updated = false;

	nmea_zero_INFO(&txPosition.nmeaInfo);

	state.internalState = MOVING;
	state.externalState = MOVING;
	state.hysteresisCounter = 0;

	initPositionAverageList(&positionAverageList, getAverageDepth());

	if (!initOlsrTxTimer()) {
		stopReceiver();
		return false;
	}

	if (!initUplinkTxTimer()) {
		stopReceiver();
		return false;
	}

	return true;
}

/**
 Stop the receiver
 */
void stopReceiver(void) {
	destroyUplinkTxTimer();
	destroyOlsrTxTimer();

	destroyPositionAverageList(&positionAverageList);

	state.hysteresisCounter = 0;
	state.externalState = MOVING;
	state.internalState = MOVING;

	nmea_zero_INFO(&txPosition.nmeaInfo);

	transmitGpsInformation.updated = false;
	nmea_zero_INFO(&transmitGpsInformation.txPosition.nmeaInfo);

	nmea_parser_destroy(&nmeaParser);

	(void) pthread_mutex_destroy(&transmitGpsInformation.mutex);
}
