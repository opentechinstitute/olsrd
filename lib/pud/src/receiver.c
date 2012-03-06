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
#include "uplinkGateway.h"

/* OLSRD includes */
#include "net_olsr.h"
#include "ipcalc.h"

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

	TristateBoolean differentGateway; /**< SET: the gateway is different */

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
	union olsr_ip_addr txGateway; /**< the best gateway at the time the transmitted position was determined */
} TransmitGpsInformation;

/** The latest position information that is transmitted */
static TransmitGpsInformation transmitGpsInformation;

/** The size of the buffer in which the OLSR and uplink messages are assembled */
#define TX_BUFFER_SIZE_FOR_OLSR 1024

/*
 * Functions
 */

/**
 Clear the MovementType
 * @param result a pointer to the MovementType
 */
static void clearMovementType(MovementType * result) {
	/* clear outputs */
	result->moving = UNKNOWN;
	result->differentGateway = UNSET;
	result->overThresholds = UNKNOWN;
	result->speedOverThreshold = UNKNOWN;
	result->hDistanceOverThreshold = UNKNOWN;
	result->vDistanceOverThreshold = UNKNOWN;
	result->outside = UNKNOWN;
	result->outsideHdop = UNKNOWN;
	result->outsideVdop = UNKNOWN;
	result->inside = UNKNOWN;
	result->insideHdop = UNKNOWN;
	result->insideVdop = UNKNOWN;
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

/**
 Send the transmit buffer out over all designated interfaces, called as a
 timer callback and also immediately on an external state change.

 @param interfaces
 a bitmap defining which interfaces to send over
 */
static void txToAllOlsrInterfaces(TimedTxInterface interfaces) {
	/** txBuffer is used to concatenate the position update and cluster leader messages in */
	unsigned char txBuffer[TX_BUFFER_SIZE_FOR_OLSR];
	unsigned int txBufferBytesUsed = 0;
	#define txBufferBytesFree	(sizeof(txBuffer) - txBufferBytesUsed)

	/*
	 * The first message in txBuffer is an OLSR position update.
	 *
	 * The position update is not present when the position is not valid.
	 * Otherwise it is always present: when we transmit onto the OLSR network
	 * and/or when we transmit onto the uplink.
	 *
	 * The second message is the cluster leader message, but only when uplink
	 * was requested and correctly configured.
	 */

	UplinkMessage * pu_uplink = (UplinkMessage *) &txBuffer[0];
	union olsr_message * pu = &pu_uplink->msg.olsrMessage;
	unsigned int pu_size = 0;
	union olsr_ip_addr gateway;

	(void) pthread_mutex_lock(&transmitGpsInformation.mutex);

	/* only fixup timestamp when the position is valid _and_ when the position was not updated */
	if (positionValid(&transmitGpsInformation.txPosition) && !transmitGpsInformation.updated) {
		nmea_time_now(&transmitGpsInformation.txPosition.nmeaInfo.utc);
	}

	/* convert nmeaINFO to wireformat olsr message */
	txBufferBytesUsed += sizeof(UplinkHeader); /* keep before txBufferSpaceFree usage */
	pu_size = gpsToOlsr(&transmitGpsInformation.txPosition.nmeaInfo, pu, txBufferBytesFree,
			((state.externalState == MOVING) ? getUpdateIntervalMoving() : getUpdateIntervalStationary()));
	txBufferBytesUsed += pu_size;
	gateway = transmitGpsInformation.txGateway;

	transmitGpsInformation.updated = false;
	(void) pthread_mutex_unlock(&transmitGpsInformation.mutex);

	/*
	 * push out to all OLSR interfaces
	 */
	if (((interfaces & OLSR) != 0) && (pu_size > 0)) {
		int r;
		struct interface *ifn;
		for (ifn = ifnet; ifn; ifn = ifn->int_next) {
			r = net_outbuffer_push(ifn, pu, pu_size);
			if (r != (int) pu_size) {
				pudError(
						false,
						"Could not send to OLSR interface %s: %s (size=%u, r=%d)",
						ifn->int_name,
						((r == -1) ? "no buffer was found" :
							(r == 0) ? "there was not enough room in the buffer" : "unknown reason"), pu_size, r);
			}
#ifdef PUD_DUMP_GPS_PACKETS_TX_OLSR
			else {
				olsr_printf(0, "%s: packet sent to OLSR interface %s (%d bytes)\n",
						PUD_PLUGIN_ABBR, ifn->int_name, pu_size);
				dump_packet((unsigned char *)pu, pu_size);
			}
#endif
		}

		/* loopback to tx interface when so configured */
		if (getUseLoopback()) {
			(void) packetReceivedFromOlsr(pu, NULL, NULL);
		}
	}

	/* push out over uplink when an uplink is configured */
	if (((interfaces & UPLINK) != 0) && isUplinkAddrSet()) {
		int fd = getDownlinkSocketFd();
		if (fd != -1) {
			union olsr_sockaddr * uplink_addr = getUplinkAddr();

			UplinkMessage * cl_uplink = (UplinkMessage *) &txBuffer[txBufferBytesUsed];
			UplinkClusterLeader * cl = &cl_uplink->msg.clusterLeader;
			union olsr_ip_addr * cl_originator = getClusterLeaderOriginator(olsr_cnf->ip_version, cl);
			union olsr_ip_addr * cl_clusterLeader = getClusterLeaderClusterLeader(olsr_cnf->ip_version, cl);
			unsigned int cl_size =
					sizeof(UplinkClusterLeader) - sizeof(cl->leader)
							+ ((olsr_cnf->ip_version == AF_INET) ? sizeof(cl->leader.v4) :
									sizeof(cl->leader.v6));

			/*
			 * position update message (pu)
			 */

			/* set header fields in position update uplink message and adjust
			 * the validity time to the uplink validity time */
			if (pu_size > 0) {
				PudOlsrPositionUpdate * pu_gpsMessage = getOlsrMessagePayload(olsr_cnf->ip_version, pu);

				setUplinkMessageType(&pu_uplink->header, POSITION);
				setUplinkMessageLength(&pu_uplink->header, pu_size);
				setUplinkMessageIPv6(&pu_uplink->header, (olsr_cnf->ip_version != AF_INET));
				setUplinkMessagePadding(&pu_uplink->header, 0);

				/* fixup validity time */
				setValidityTime(
						&pu_gpsMessage->validityTime,
						(state.externalState == MOVING) ?
								getUplinkUpdateIntervalMoving() : getUplinkUpdateIntervalStationary());
			}

			/*
			 * cluster leader message (cl)
			 */

			/* set cl_uplink header fields */
			setUplinkMessageType(&cl_uplink->header, CLUSTERLEADER);
			setUplinkMessageLength(&cl_uplink->header, cl_size);
			setUplinkMessageIPv6(&cl_uplink->header, (olsr_cnf->ip_version != AF_INET));
			setUplinkMessagePadding(&cl_uplink->header, 0);

			/* setup cl */
			setClusterLeaderVersion(cl, PUD_WIRE_FORMAT_VERSION);
			setValidityTime(
					&cl->validityTime,
					(state.externalState == MOVING) ?
							getUplinkUpdateIntervalMoving() : getUplinkUpdateIntervalStationary());

			/* really need 2 memcpy's here because of olsr_cnf->ipsize */
			memcpy(cl_originator, &olsr_cnf->main_addr, olsr_cnf->ipsize);
			memcpy(cl_clusterLeader, &gateway, olsr_cnf->ipsize);

			txBufferBytesUsed += sizeof(UplinkHeader);
			txBufferBytesUsed += cl_size;

			errno = 0;
			if (sendto(fd, &txBuffer, txBufferBytesUsed, 0, (struct sockaddr *) &uplink_addr->in,
					sizeof(uplink_addr->in)) < 0) {
				pudError(true, "Could not send to uplink (size=%u)", txBufferBytesUsed);
			}
#ifdef PUD_DUMP_GPS_PACKETS_TX_UPLINK
			else {
				olsr_printf(0, "%s: packet sent to uplink (%d bytes)\n",
						PUD_PLUGIN_ABBR, pu_size);
				dump_packet((unsigned char *)&txBuffer, txBufferBytesUsed);
			}
#endif
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
 Detemine whether we are moving from the gateway.

 MUST be called which the position average list locked.

 @param gateway
 the current best gateway
 @param lastGateway
 the last best gateway
 @param result
 the results of all movement criteria
 */
static void detemineMovingFromGateway(union olsr_ip_addr * gateway, union olsr_ip_addr * lastGateway,
		MovementType * result) {
	/*
	 * When the gateway is different from the gateway during last transmit, then
	 * we force MOVING
	 */
	if (!ipequal(gateway, lastGateway)) {
		result->moving = SET;
		result->differentGateway = SET;
		return;
	}

	result->differentGateway = UNSET;
}

/**
 Detemine whether we are moving from the position, by comparing fields from the
 average position against those of the last transmitted position.

 MUST be called which the position average list locked.

 @param avg
 the average position
 @param lastTx
 the last transmitted position
 @param result
 the results of all movement criteria
 */
static void detemineMovingFromPosition(PositionUpdateEntry * avg, PositionUpdateEntry * lastTx, MovementType * result) {
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

	/*
	 * Validity
	 *
	 * avg  last  movingNow
	 *  0     0   UNKNOWN : can't determine whether we're moving
	 *  0     1   UNKNOWN : can't determine whether we're moving
	 *  1     0   UNKNOWN : can't determine whether we're moving
	 *  1     1   determine via other parameters
	 */

	if (!positionValid(avg)) {
		result->moving = UNKNOWN;
		return;
	}

	/* avg is valid here */

	if (!positionValid(lastTx)) {
		result->moving = UNKNOWN;
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
 Restart the OLSR tx timer
 */
static void restartOlsrTimer(void) {
	if (!restartOlsrTxTimer(
			(state.externalState == STATIONARY) ? getUpdateIntervalStationary() :
					getUpdateIntervalMoving(), &pud_olsr_tx_timer_callback)) {
		pudError(0, "Could not restart OLSR tx timer, no periodic"
				" position updates will be sent to the OLSR network");
	}
}

/**
 Restart the uplink tx timer
 */
static void restartUplinkTimer(void) {
	if (!restartUplinkTxTimer(
			(state.externalState == STATIONARY) ? getUplinkUpdateIntervalStationary() :
					getUplinkUpdateIntervalMoving(),
			&pud_uplink_timer_callback)) {
		pudError(0, "Could not restart uplink timer, no periodic"
				" position updates will be uplinked");
	}
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
	MovementState newState;
	PositionUpdateEntry * posAvgEntry;
	MovementType movementResult;
	TristateBoolean movingNow;
	bool internalStateChange = false;
	bool externalStateChange = false;
	bool updateTransmitGpsInformation = false;
	union olsr_ip_addr bestGateway;
	PositionUpdateEntry txPosition;
	union olsr_ip_addr txGateway;

	/* do not process when the message does not start with $GP */
	if ((rxCount < rxBufferPrefixLength) || (strncmp((char *) rxBuffer,
			rxBufferPrefix, rxBufferPrefixLength) != 0)) {
		return true;
	}

	(void) pthread_mutex_lock(&transmitGpsInformation.mutex);
	txPosition = transmitGpsInformation.txPosition;
	txGateway = transmitGpsInformation.txGateway;
	(void) pthread_mutex_unlock(&transmitGpsInformation.mutex);

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

	getBestUplinkGateway(&bestGateway);
	clearMovementType(&movementResult);
	detemineMovingFromGateway(&bestGateway, &txGateway, &movementResult);
	if (movementResult.moving != SET) {
		detemineMovingFromPosition(posAvgEntry, &txPosition, &movementResult);
	}
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
	} else {
		/* force back to stationary for unknown movement */
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
				/* when unknown do just as if we transition into stationary */
				newState = STATIONARY;
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
		(void) pthread_mutex_lock(&transmitGpsInformation.mutex);
		transmitGpsInformation.txPosition.nmeaInfo = posAvgEntry->nmeaInfo;
		transmitGpsInformation.txGateway = bestGateway;
		transmitGpsInformation.updated = true;
		(void) pthread_mutex_unlock(&transmitGpsInformation.mutex);

#if defined(PUD_DUMP_AVERAGING)
		dump_nmeaInfo(&posAvgEntry->nmeaInfo,
			"receiverUpdateGpsInformation: transmitGpsInformation");
#endif /* PUD_DUMP_AVERAGING */
	}

	if (externalStateChange) {
		TimedTxInterface interfaces = OLSR; /* always send over olsr */
		restartOlsrTimer();

		if (isUplinkAddrSet()) {
			interfaces |= UPLINK;
			restartUplinkTimer();
		}

		/* do an immediate transmit */
		txToAllOlsrInterfaces(interfaces);
	}

	retval = true;

	end:
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
	transmitGpsInformation.txGateway = olsr_cnf->main_addr;
	transmitGpsInformation.updated = false;

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

	restartOlsrTimer();
	restartUplinkTimer();

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

	(void) pthread_mutex_lock(&transmitGpsInformation.mutex);
	transmitGpsInformation.updated = false;
	nmea_zero_INFO(&transmitGpsInformation.txPosition.nmeaInfo);
	transmitGpsInformation.txGateway = olsr_cnf->main_addr;
	(void) pthread_mutex_unlock(&transmitGpsInformation.mutex);

	nmea_parser_destroy(&nmeaParser);

	(void) pthread_mutex_destroy(&transmitGpsInformation.mutex);
}
