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
typedef enum {
	UNKNOWN, UNSET, SET
} TristateBoolean;

#define TristateBooleanToString(s)	((s == SET) ? "set" : \
									 (s == UNSET) ? "unset" : \
									 "unknown")

/** Type describing movement state */
typedef enum {
	STATIONARY, MOVING
} MovementState;

#define MovementStateToString(s)	((s == MOVING) ? "moving" : \
									 "stationary")

/** Type describing state */
typedef struct {
	MovementState state; /**< the movement state */
	unsigned long long hysteresisCounter; /**< the hysteresis counter for moving --> stationary */
} StateType;

/** The state */
StateType state = { .state = MOVING, .hysteresisCounter = 0 };

/*
 * Averaging
 */

/** The average position with its administration */
PositionAverageList positionAverageList;

/*
 * TX to OLSR
 */

/** Structure of the latest GPS information that is transmitted */
typedef struct {
	pthread_mutex_t mutex; /**< access mutex */
	bool updated; /**< true when the information was updated */
	bool invalid; /**< true when invalid (bad fix or bad sig) */
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

/** Send the transmit buffer out over all OLSR interfaces, called as a timer
 * callback and also immediately on a state change */
static void txToAllOlsrInterfaces(void) {
	unsigned char txBuffer[TX_BUFFER_SIZE_FOR_OLSR];
	unsigned int aligned_size = 0;

	(void) pthread_mutex_lock(&transmitGpsInformation.mutex);
	if (!transmitGpsInformation.updated && !transmitGpsInformation.invalid) {
		/* fix the timestamp when the transmitGpsInformation was not updated
		 * while it is valid */
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
			((state.state == MOVING) ? getUpdateIntervalMoving()
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
 * Detemines whether we are moving by comparing fields from the average
 * position against those of the last transmitted position.
 *
 * MUST be called which the position average list locked.
 *
 * @param posAvgEntry
 * the average position
 * @param lastTxEntry
 * the last transmitted position
 */
static TristateBoolean detemineMoving(PositionUpdateEntry * posAvgEntry,
		PositionUpdateEntry * lastTxEntry) {
	TristateBoolean speedMoving = UNKNOWN;
	TristateBoolean outsideHdopOrDistance = UNKNOWN;
	TristateBoolean elvMoving = UNKNOWN;

	/*
	 * Moving Criteria Evaluation Start
	 * We compare the average position against the last transmitted position.
	 *
	 * Note: when the current state is not STATIONARY then the average position
	 * is the same as the incoming position.
	 */

	/*
	 * Fix
	 *
	 * avg  last  movingNow
	 *  0     0   UNKNOWN
	 *  0     1   UNKNOWN
	 *  1     0   MOVING
	 *  1     1   determine via other parameters
	 */

	/* when avg has no valid fix then can't determine whether we're moving */
	if (!(nmeaInfoHasField(posAvgEntry->nmeaInfo.smask, FIX)
			&& (posAvgEntry->nmeaInfo.fix != NMEA_FIX_BAD))) {
		return UNKNOWN;
	}

	/* avg has a valid fix here */

	/* when lastTx has no valid fix, then we are moving */
	if (!(nmeaInfoHasField(lastTxEntry->nmeaInfo.smask, FIX)
			&& (lastTxEntry->nmeaInfo.fix != NMEA_FIX_BAD))) {
		return SET;
	}

	/* both avg and lastTx have a valid fix here */

	/*
	 * Speed
	 */

	if (nmeaInfoHasField(posAvgEntry->nmeaInfo.smask, SPEED)) {
		if (posAvgEntry->nmeaInfo.speed >= getMovingSpeedThreshold()) {
			return SET;
		}

		/* speed is below threshold */
		speedMoving = UNSET;
	}

	/*
	 * Position
	 *
	 * avg  last  movingNow
	 *  0     0   determine via other parameters
	 *  0     1   determine via other parameters
	 *  1     0   MOVING
	 *  1     1   determine via distance threshold and HDOP
	 */
	if ((nmeaInfoHasField(posAvgEntry->nmeaInfo.smask, LAT))
			&& (nmeaInfoHasField(posAvgEntry->nmeaInfo.smask, LON))) {
		nmeaPOS avgPos;
		nmeaPOS lastTxPos;
		double distance;

		/* when avg has valid position while lastTx does not, then we are
		 * moving */
		if (!((nmeaInfoHasField(lastTxEntry->nmeaInfo.smask, LAT))
				&& (nmeaInfoHasField(lastTxEntry->nmeaInfo.smask, LON)))) {
			return SET;
		}

		/* both avg and lastTx have a valid position here */

		avgPos.lat = nmea_degree2radian(posAvgEntry->nmeaInfo.lat);
		avgPos.lon = nmea_degree2radian(posAvgEntry->nmeaInfo.lon);

		lastTxPos.lat = nmea_degree2radian(lastTxEntry->nmeaInfo.lat);
		lastTxPos.lon = nmea_degree2radian(lastTxEntry->nmeaInfo.lon);

		distance = nmea_distance_ellipsoid(&avgPos, &lastTxPos, 0, 0);

		/* determine whether we are moving according to the distance threshold */
		if (distance >= getMovingDistanceThreshold()) {
			return SET;
		}

		/* distance is below threshold */
		outsideHdopOrDistance = UNSET;

		/*
		 * Position with HDOP
		 *
		 * avg  last  movingNow
		 *  0     0   determine via other parameters
		 *  0     1   determine via position with HDOP (avg has default HDOP)
		 *  1     0   determine via position with HDOP (lastTx has default HDOP)
		 *  1     1   determine via position with HDOP
		 */
		{
			bool avgHasHdop = nmeaInfoHasField(posAvgEntry->nmeaInfo.smask,
					HDOP);
			bool lastTxHasHdop = nmeaInfoHasField(lastTxEntry->nmeaInfo.smask,
					HDOP);

			if (avgHasHdop || lastTxHasHdop) {
				double avgHdop;
				double lastTxHdop;

				if (avgHasHdop) {
					avgHdop = posAvgEntry->nmeaInfo.HDOP;
				} else {
					avgHdop = getDefaultHdop();
				}
				if (lastTxHasHdop) {
					lastTxHdop = lastTxEntry->nmeaInfo.HDOP;
				} else {
					lastTxHdop = getDefaultHdop();
				}

				/* we are outside the HDOP when the HDOPs no longer overlap */
				if (distance > (getDopMultiplier() * (avgHdop + lastTxHdop))) {
					return SET;
				}

				/* the HDOPs overlap */
				outsideHdopOrDistance = UNSET;
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
	if (nmeaInfoHasField(posAvgEntry->nmeaInfo.smask, ELV)) {
		double avgElv;
		double lastTxElv;
		double distance;

		/* when avg has valid elevation while lastTx does not, then we are
		 * moving */
		if (!nmeaInfoHasField(lastTxEntry->nmeaInfo.smask, ELV)) {
			return SET;
		}

		/* both avg and lastTx have a valid elevation here */

		avgElv = posAvgEntry->nmeaInfo.elv;
		lastTxElv = lastTxEntry->nmeaInfo.elv;

		distance = fabs(lastTxElv - avgElv);

		/* determine whether we are moving according to the distance threshold */
		if (distance >= getMovingDistanceThreshold()) {
			return SET;
		}

		/* distance is below threshold */
		elvMoving = UNSET;

		/*
		 * Elevation with VDOP
		 *
		 * avg  last  movingNow
		 *  0     0   determine via other parameters
		 *  0     1   determine via elevation with VDOP (avg has default VDOP)
		 *  1     0   determine via elevation with VDOP (lastTx has default VDOP)
		 *  1     1   determine via elevation with VDOP
		 */
		{
			bool avgHasVdop = nmeaInfoHasField(posAvgEntry->nmeaInfo.smask,
					VDOP);
			bool lastTxHasVdop = nmeaInfoHasField(lastTxEntry->nmeaInfo.smask,
					VDOP);

			if (avgHasVdop || lastTxHasVdop) {
				double avgVdop;
				double lastTxVdop;

				if (avgHasVdop) {
					avgVdop = posAvgEntry->nmeaInfo.VDOP;
				} else {
					avgVdop = getDefaultVdop();
				}
				if (lastTxHasVdop) {
					lastTxVdop = lastTxEntry->nmeaInfo.VDOP;
				} else {
					lastTxVdop = getDefaultVdop();
				}

				/* we are outside the VDOP when the VDOPs no longer overlap */
				if (distance > (getDopMultiplier() * (avgVdop + lastTxVdop))) {
					return SET;
				}

				/* the VDOPs don't overlap */
				elvMoving = UNSET;
			}
		}
	}

	assert (speedMoving != SET);
	assert (outsideHdopOrDistance != SET);
	assert (elvMoving != SET);

	/* accumulate moving criteria */

	if ((speedMoving == UNSET) || (outsideHdopOrDistance == UNSET)
			|| (elvMoving == UNSET)) {
		return UNSET;
	}

	/*
	 * Moving Criteria Evaluation End
	 */

	return UNKNOWN;
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
	MovementState currentState = state.state;
	MovementState newState = MOVING;
	PositionUpdateEntry * posAvgEntry;
	TristateBoolean movingNow;

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

	/* flush on MOVING */
	if (currentState == MOVING) {
		flushPositionAverageList(&positionAverageList);
	}

	/* add to average */
	addNewPositionToAverage(&positionAverageList, incomingEntry);

	posAvgEntry = getPositionAverageEntry(&positionAverageList, AVERAGE);

	movingNow = detemineMoving(posAvgEntry, &txPosition);

#if defined(PUD_DUMP_AVERAGING)
	olsr_printf(0, "receiverUpdateGpsInformation: currentState = %s\n",
			MovementStateToString(currentState));
	olsr_printf(0, "receiverUpdateGpsInformation: movingNow    = %s\n",
			TristateBooleanToString(movingNow));
#endif /* PUD_DUMP_AVERAGING */

	/* determine the new state */
	switch (currentState) {
		case STATIONARY:
			if (movingNow == SET) {
				/* delay going to moving a bit */
				state.hysteresisCounter++;

				if (state.hysteresisCounter >= getHysteresisCountToMoving()) {
					/* outside the hysteresis range, go to moving */
					newState = MOVING;
				} else {
					/* within the hysteresis range, stay in stationary */
					newState = STATIONARY;
				}
			} else { /* unset and unknown */
				newState = STATIONARY;
			}
			break;

		case MOVING:
			if (movingNow == UNSET) {
				/* delay going to stationary a bit */
				state.hysteresisCounter++;

				if (state.hysteresisCounter >= getHysteresisCountToStationary()) {
					/* outside the hysteresis range, go to stationary */
					newState = STATIONARY;
				} else {
					/* within the hysteresis range, stay in moving */
					newState = MOVING;
				}
			} else { /* set and unknown */
				newState = MOVING;
			}
			break;

		default:
			/* when unknown do just as if we transition into moving */
			newState = MOVING;
			break;
	}

#if defined(PUD_DUMP_AVERAGING)
	olsr_printf(0, "receiverUpdateGpsInformation: newState = %s\n",
			MovementStateToString(newState));
#endif /* PUD_DUMP_AVERAGING */

	/* perform state change actions */
	if (currentState != newState) {
		/* reset the hysteresis counter upon state change */
		state.hysteresisCounter = 0;

		/* set the new state */
		state.state = newState;

		/* restart the timer for the new state */
		if (!restartTimer(
				(newState == STATIONARY) ? getUpdateIntervalStationary()
						: getUpdateIntervalMoving())) {
			pudError(0, "Could not restart receiver timer, no position"
				" updates will be sent to the OLSR network");
			goto end;
		}
	}

#if defined(PUD_DUMP_AVERAGING)
	dump_nmeaInfo(&posAvgEntry->nmeaInfo,
			"receiverUpdateGpsInformation: posAvgEntry");
#endif /* PUD_DUMP_AVERAGING */

	/*
	 * Update transmitGpsInformation
	 */

	(void) pthread_mutex_lock(&transmitGpsInformation.mutex);
	transmitGpsInformation.invalid
			= (posAvgEntry->nmeaInfo.fix == NMEA_FIX_BAD);

	/* Only when not invalid we update the transmitGpsInformation */
	if (!transmitGpsInformation.invalid) {
		if ((movingNow == SET) || (state.state == MOVING)) {
			/* Copy posAvgEntry into txPosition and transmitGpsInformation
			 * when we consider ourselves as moving (independent of the state)
			 * or when we are in the MOVING state */
			memcpy(&txPosition.nmeaInfo,
					&posAvgEntry->nmeaInfo,	sizeof(nmeaINFO));
			memcpy(&transmitGpsInformation.txPosition.nmeaInfo, &posAvgEntry->nmeaInfo,
					sizeof(nmeaINFO));
			transmitGpsInformation.updated = true;
		} else /* (movingNow != SET) && (state.state == STATIONARY) */{
			/* no nothing */
		}
	}
	(void) pthread_mutex_unlock(&transmitGpsInformation.mutex);

#if defined(PUD_DUMP_AVERAGING)
	dump_nmeaInfo(&transmitGpsInformation.txPosition.nmeaInfo,
			"receiverUpdateGpsInformation: transmitGpsInformation");
#endif /* PUD_DUMP_AVERAGING */

	/* on a state change do an immediate transmit */
	if (currentState != newState) {
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
	transmitGpsInformation.invalid = true;

	nmea_zero_INFO(&txPosition.nmeaInfo);

	state.state = MOVING;
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
	state.state = MOVING;

	nmea_zero_INFO(&txPosition.nmeaInfo);

	nmea_zero_INFO(&transmitGpsInformation.txPosition.nmeaInfo);
	transmitGpsInformation.updated = false;
	transmitGpsInformation.invalid = true;

	nmea_parser_destroy(&nmeaParser);

	(void) pthread_mutex_destroy(&transmitGpsInformation.mutex);
}
