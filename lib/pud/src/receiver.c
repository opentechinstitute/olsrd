#include "receiver.h"

/* Plugin includes */
#include "pud.h"
#include "gpsConversion.h"
#include "configuration.h"
#include "nodeIdConversion.h"
#include "dump.h"
#include "nmeaTools.h"
#include "posAvg.h"

/* OLSRD includes */
#include "olsr_protocol.h"
#include "interfaces.h"
#include "net_olsr.h"
#include "olsr_cookie.h"
#include "scheduler.h"
#include "olsr.h"

/* System includes */
#include <nmea/parser.h>
#include <nmea/gmath.h>
#include <nmea/sentence.h>
#include <assert.h>
#include <stddef.h>
#include <time.h>
#include <sys/timeb.h>
#include <math.h>

/* Forward declaration */
static int restartTimer(unsigned long long interval);

/*
 * NMEA parser
 */

/** The NMEA string parser */
nmeaPARSER nmeaParser;

/*
 * State
 */

/** Type describing a tri-state boolean */
typedef enum _TristateBoolean {
	UNKNOWN, UNSET, SET
} TristateBoolean;

#define TristateBooleanToString(s)	((s == SET) ? "set" : \
									 (s == UNSET) ? "unset" : \
									 "unknown")

/** Type describing movement state */
typedef enum _MovementState {
	STATIONARY, MOVING
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
StateType state = { .internalState = MOVING, .externalState = MOVING, .hysteresisCounter = 0 };

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
PositionAverageList positionAverageList;

/*
 * TX to OLSR
 */

/** Structure of the latest GPS information that is transmitted */
typedef struct _TransmitGpsInformation {
	pthread_mutex_t mutex; /**< access mutex */
	bool updated; /**< true when the information was updated */
	PositionUpdateEntry txPosition; /**< The last transmitted position */
} TransmitGpsInformation;

/** The latest position information that is transmitted */
TransmitGpsInformation transmitGpsInformation;

/** The last transmitted position.
 * The same as transmitGpsInformation.txPosition.
 * We keep this because then we can access the information without locking
 * mutexes. */
PositionUpdateEntry txPosition;

/** The size of the buffer in which the OLSR message is assembled */
#define TX_BUFFER_SIZE_FOR_OLSR 512

/*
 * Functions
 */

/**
 Determine whether s position is valid.

 @param position
 a pointer to a position

 @return
 - true when valid
 - false otherwise
 */
static bool positionValid(PositionUpdateEntry * position){
	return (nmeaInfoHasField(position->nmeaInfo.smask, FIX)
			&& (position->nmeaInfo.fix != NMEA_FIX_BAD));
}

/** Send the transmit buffer out over all OLSR interfaces, called as a timer
 * callback and also immediately on an external state change */
static void txToAllOlsrInterfaces(void) {
	unsigned char txBuffer[TX_BUFFER_SIZE_FOR_OLSR];
	unsigned int aligned_size = 0;

	(void) pthread_mutex_lock(&transmitGpsInformation.mutex);

	if (!transmitGpsInformation.updated
			&& positionValid(&transmitGpsInformation.txPosition)) {
		struct timeb tp;
		struct tm nowStruct;

		(void) ftime(&tp);
		gmtime_r(&tp.time, &nowStruct);

		transmitGpsInformation.txPosition.nmeaInfo.utc.year = nowStruct.tm_year;
		transmitGpsInformation.txPosition.nmeaInfo.utc.mon = nowStruct.tm_mon;
		transmitGpsInformation.txPosition.nmeaInfo.utc.day = nowStruct.tm_mday;
		transmitGpsInformation.txPosition.nmeaInfo.utc.hour = nowStruct.tm_hour;
		transmitGpsInformation.txPosition.nmeaInfo.utc.min = nowStruct.tm_min;
		transmitGpsInformation.txPosition.nmeaInfo.utc.sec = nowStruct.tm_sec;
		transmitGpsInformation.txPosition.nmeaInfo.utc.hsec = (tp.millitm / 10);
	}
	aligned_size = gpsToOlsr(&transmitGpsInformation.txPosition.nmeaInfo,
			(union olsr_message *) &txBuffer[0], sizeof(txBuffer),
			((state.externalState == MOVING) ? getUpdateIntervalMoving()
					: getUpdateIntervalStationary()));
	transmitGpsInformation.updated = false;
	(void) pthread_mutex_unlock(&transmitGpsInformation.mutex);

	/* push out to all OLSR interfaces */
	if (aligned_size > 0) {
		int r;
		struct interface *ifn;
		for (ifn = ifnet; ifn; ifn = ifn->int_next) {
			nodeIdPreTransmitHook((union olsr_message *) txBuffer, ifn);

			/* loopback to tx interface when so configured */
			if (getUseLoopback()) {
				(void) packetReceivedFromOlsr(
						(union olsr_message *) &txBuffer[0], NULL, NULL);
			}

#ifdef PUD_DUMP_GPS_PACKETS_TX_OLSR
			olsr_printf(0, "%s: packet sent to OLSR interface %s (%d bytes)\n",
					PUD_PLUGIN_ABBR, ifn->int_name, aligned_size);
			dump_packet(&txBuffer[0], aligned_size);
#endif

			r = net_outbuffer_push(ifn, &txBuffer[0], aligned_size);
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
		}
	}
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
	result->moving = UNKNOWN;

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
	avgHasSpeed = nmeaInfoHasField(avg->nmeaInfo.smask, SPEED);
	avgHasPos = nmeaInfoHasField(avg->nmeaInfo.smask, LAT)
			&& nmeaInfoHasField(avg->nmeaInfo.smask, LON);
	avgHasHdop = nmeaInfoHasField(avg->nmeaInfo.smask, HDOP);
	avgHasElv = nmeaInfoHasField(avg->nmeaInfo.smask, ELV);
	avgHasVdop = nmeaInfoHasField(avg->nmeaInfo.smask, VDOP);

	/* lastTx field presence booleans */
	lastTxHasPos = nmeaInfoHasField(lastTx->nmeaInfo.smask, LAT)
			&& nmeaInfoHasField(lastTx->nmeaInfo.smask, LON);
	lastTxHasHdop = nmeaInfoHasField(lastTx->nmeaInfo.smask, HDOP);
	lastTxHasElv = nmeaInfoHasField(lastTx->nmeaInfo.smask, ELV);
	lastTxHasVdop = nmeaInfoHasField(lastTx->nmeaInfo.smask, VDOP);

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
 receiver from a rxNonOlsr interface, containing one or more NMEA strings with
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

	/* we always work with latitude, longitude in degrees and DOPs in meters */
	nmeaInfoUnitConversion(&incomingEntry->nmeaInfo);

#if defined(PUD_DUMP_AVERAGING)
	dump_nmeaInfo(&incomingEntry->nmeaInfo,
			"receiverUpdateGpsInformation: incoming entry after unit conversion");
#endif /* PUD_DUMP_AVERAGING */

	sanitiseNmeaInfo(&incomingEntry->nmeaInfo);

#if defined(PUD_DUMP_AVERAGING)
	dump_nmeaInfo(&incomingEntry->nmeaInfo,
			"receiverUpdateGpsInformation: incoming entry after sanitise");
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
		(void) pthread_mutex_unlock(&transmitGpsInformation.mutex);
	}

#if defined(PUD_DUMP_AVERAGING)
	dump_nmeaInfo(&transmitGpsInformation.txPosition.nmeaInfo,
			"receiverUpdateGpsInformation: transmitGpsInformation");
#endif /* PUD_DUMP_AVERAGING */

	if (updateTransmitGpsInformation) {
		if (!restartTimer(
				(state.externalState == STATIONARY) ? getUpdateIntervalStationary()
				: getUpdateIntervalMoving())) {
			pudError(0, "Could not restart receiver timer, no position"
					" updates will be sent to the OLSR network");
			goto end;
		}

		/* do an immediate transmit */
		txToAllOlsrInterfaces();
	}

	retval = true;

	end: (void) pthread_mutex_unlock(&positionAverageList.mutex);
	return retval;
}

/*
 * Timer
 */

/** The timer cookie, used to trace back the originator in debug */
struct olsr_cookie_info *pud_receiver_timer_cookie = NULL;

/** The timer */
struct timer_entry * pud_receiver_timer = NULL;

/**
 The timer callback

 @param context
 unused
 */
static void pud_receiver_timer_callback(void *context __attribute__ ((unused))) {
	txToAllOlsrInterfaces();
}

/**
 Start the receiver timer. Does nothing when the timer is already running.

 @param interval
 The interval in seconds

 @return
 - false on failure
 - true otherwise
 */
static int startTimer(unsigned long long interval) {
	if (pud_receiver_timer == NULL) {
		pud_receiver_timer = olsr_start_timer(interval * MSEC_PER_SEC, 0,
				OLSR_TIMER_PERIODIC, &pud_receiver_timer_callback, NULL,
				pud_receiver_timer_cookie);
		if (pud_receiver_timer == NULL) {
			stopReceiver();
			return false;
		}
	}

	return true;
}

/**
 Stop the receiver timer
 */
static void stopTimer(void) {
	if (pud_receiver_timer != NULL) {
		olsr_stop_timer(pud_receiver_timer);
		pud_receiver_timer = NULL;
	}
}

/**
 Restart the receiver timer

 @param interval
 The interval in seconds

 @return
 - false on failure
 - true otherwise
 */
static int restartTimer(unsigned long long interval) {
	stopTimer();
	return startTimer(interval);
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

	if (pud_receiver_timer_cookie == NULL) {
		pud_receiver_timer_cookie = olsr_alloc_cookie(
				PUD_PLUGIN_ABBR ": receiver", OLSR_COOKIE_TYPE_TIMER);
		if (pud_receiver_timer_cookie == NULL) {
			stopReceiver();
			return false;
		}
	}

	return true;
}

/**
 Stop the receiver
 */
void stopReceiver(void) {
	stopTimer();

	if (pud_receiver_timer_cookie != NULL) {
		olsr_free_cookie(pud_receiver_timer_cookie);
		pud_receiver_timer_cookie = NULL;
	}

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
