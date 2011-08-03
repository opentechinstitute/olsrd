#include "pud.h"

/* Plugin includes */
#include "configuration.h"
#include "networkInterfaces.h"
#include "dump.h"
#include "gpsConversion.h"
#include "receiver.h"
#include "dedup.h"

/* OLSRD includes */
#include "ipcalc.h"
#include "parser.h"
#include "olsr.h"

/* System includes */
#include <assert.h>

/** The size of the buffer in which the received NMEA string is stored */
#define BUFFER_SIZE_FOR_OLSR	2048

/** The size of the buffer in which the transmit NMEA string is assembled */
#define BUFFER_SIZE_FROM_OLSR 	512

/** The transmit socket address */
static union olsr_sockaddr * txAddress;

/** The de-duplication list */
static DeDupList deDupList;

/**
 Report a plugin error.

 @param useErrno
 when true then errno is used in the error message; the error reason is also
 reported.
 @param format
 a pointer to the format string
 @param ...
 arguments to the format string
 */
void pudError(bool useErrno, const char *format, ...) {
	char strDesc[256];
	char *stringErr = NULL;

	if (useErrno) {
		stringErr = strerror(errno);
	}

	if ((format == NULL) || (*format == '\0')) {
		if (useErrno) {
			olsr_printf(0, "%s: %s\n", PUD_PLUGIN_ABBR, stringErr);
		} else {
			olsr_printf(0, "%s: Unknown error\n", PUD_PLUGIN_ABBR);
		}
	} else {
		va_list arglist;

		va_start(arglist, format);
		vsnprintf(strDesc, sizeof(strDesc), format, arglist);
		va_end(arglist);

		strDesc[sizeof(strDesc) - 1] = '\0'; /* Ensures null termination */

		if (useErrno) {
			olsr_printf(0, "%s: %s: %s\n", PUD_PLUGIN_ABBR, strDesc, stringErr);
		} else {
			olsr_printf(0, "%s: %s\n", PUD_PLUGIN_ABBR, strDesc);
		}
	}
}

/**
 Sends a buffer out on all transmit interfaces

 @param buffer
 the buffer
 @param bufferLength
 the number of bytes in the buffer
 */
static void sendToAllTxInterfaces(unsigned char *buffer,
		unsigned int bufferLength) {
	TRxTxNetworkInterface *txNetworkInterfaces = getTxNetworkInterfaces();
	while (txNetworkInterfaces != NULL) {
		TRxTxNetworkInterface *networkInterface = txNetworkInterfaces;

#ifdef PUD_DUMP_GPS_PACKETS_TX_NON_OLSR
		olsr_printf(0, "%s: packet sent to non-OLSR interface %s (%u bytes)\n",
				PUD_PLUGIN_ABBR, &networkInterface->name[0], bufferLength);
		dump_packet(&buffer[0], bufferLength);
#endif

		errno = 0;
		if (sendto(networkInterface->socketFd, buffer, bufferLength, 0,
				(struct sockaddr *) &txAddress->in, sizeof(txAddress->in)) < 0) {
			pudError(true, "Transmit error on interface %s",
					(char *) &networkInterface->name);
		}
		txNetworkInterfaces = networkInterface->next;
	}
}

/**
 Called by OLSR core when a packet for the plugin is received from the OLSR
 network. It converts the packet into an NMEA string and transmits it over all
 transmit non-OLSR network interfaces.

 @param olsrMessage
 a pointer to the received OLSR message
 @param in_if
 a pointer to the OLSR network interface on which the packet was received
 @param ipaddr
 a pointer to the IP address of the sender

 @return
 - true when the packet was processed
 - false otherwise
 */
bool packetReceivedFromOlsr(union olsr_message *olsrMessage,
		struct interface *in_if __attribute__ ((unused)), union olsr_ip_addr *ipaddr __attribute__ ((unused))) {
	const union olsr_ip_addr * originator;
	unsigned int transmitStringLength;
	unsigned char buffer[BUFFER_SIZE_FROM_OLSR];

#ifdef PUD_DUMP_GPS_PACKETS_RX_OLSR
	unsigned int olsrMessageSize;
#endif

	/* determine the originator of the messsage */
	if (olsr_cnf->ip_version == AF_INET) {
		originator = (const union olsr_ip_addr *) &olsrMessage->v4.originator;
#ifdef PUD_DUMP_GPS_PACKETS_RX_OLSR
		olsrMessageSize = ntohs(olsrMessage->v4.olsr_msgsize);
#endif
	} else {
		originator = (const union olsr_ip_addr *) &olsrMessage->v6.originator;
#ifdef PUD_DUMP_GPS_PACKETS_RX_OLSR
		olsrMessageSize = ntohs(olsrMessage->v6.olsr_msgsize);
#endif
	}

	/* when we do not loopback then check if the message originated from this
	 * node: back off */
	if (!getUseLoopback() && ipequal(originator, &olsr_cnf->main_addr)) {
		return false;
	}

	/* do deduplication: when we have already seen this message from the same
	 * originator then just back off */
	if (likely(getUseDeDup())) {
		if (isInDeDupList(&deDupList, olsrMessage)) {
			return false;
		}

		addToDeDup(&deDupList, olsrMessage);
	}

#ifdef PUD_DUMP_GPS_PACKETS_RX_OLSR
	olsr_printf(0, "\n%s: packet received from OLSR interface %s (%u bytes)\n",
			PUD_PLUGIN_ABBR, in_if->int_name, olsrMessageSize);
	dump_packet((unsigned char *) olsrMessage, olsrMessageSize);
#endif

	transmitStringLength = gpsFromOlsr(olsrMessage, &buffer[0], sizeof(buffer));
	if (unlikely(transmitStringLength == 0)) {
		return false;
	}

	sendToAllTxInterfaces(&buffer[0], transmitStringLength);

	return true;
}

/**
 Called by OLSR core when a packet for the plugin is received from the non-OLSR
 network. It converts the packet into the internal OLSR wire format for a
 position update and transmits it over all OLSR network interfaces.

 @param skfd
 the socket file descriptor on which the packet is received
 @param data
 a pointer to the network interface structure on which the packet was received
 @param flags
 unused
 */
#ifdef PUD_DUMP_GPS_PACKETS_RX_NON_OLSR
static void packetReceivedForOlsr(int skfd, void *data, unsigned int flags __attribute__ ((unused))) {
#else
static void packetReceivedForOlsr(int skfd, void *data __attribute__ ((unused)), unsigned int flags __attribute__ ((unused))) {
#endif
	if (skfd >= 0) {
		unsigned char rxBuffer[BUFFER_SIZE_FOR_OLSR];
		ssize_t rxCount;
		struct sockaddr sender;
		socklen_t senderSize = sizeof(sender);

		assert(data != NULL);

		/* Receive the captured Ethernet frame */
		memset(&sender, 0, senderSize);
		errno = 0;
		rxCount = recvfrom(skfd, &rxBuffer[0], (sizeof(rxBuffer) - 1), 0,
				&sender, &senderSize);
		if (rxCount < 0) {
			pudError(true, "Receive error in %s, ignoring message.", __func__);
			return;
		}

		/* make sure the string is null-terminated */
		rxBuffer[rxCount] = '\0';

		/* only accept messages from configured IP addresses */
		if (!isRxAllowedSourceIpAddress(&sender)) {
			return;
		}

#ifdef PUD_DUMP_GPS_PACKETS_RX_NON_OLSR
		{
			TRxTxNetworkInterface * networkInterface = data;
			void * src;
			in_port_t port;
			char fromAddr[64];

			if (olsr_cnf->ip_version == AF_INET) {
				src = &((struct sockaddr_in*) &sender)->sin_addr;
				port = ntohs(((struct sockaddr_in*) &sender)->sin_port);
			} else {
				src = &((struct sockaddr_in6*) &sender)->sin6_addr;
				port = ntohs(((struct sockaddr_in6*) &sender)->sin6_port);
			}

			inet_ntop(olsr_cnf->ip_version, src, &fromAddr[0], sizeof(fromAddr));
			olsr_printf(0, "\n%s: packet received from %s, port %u on non-OLSR"
					" interface %s (%lu bytes)\n", PUD_PLUGIN_ABBR, &fromAddr[0],
					port, &networkInterface->name[0], (size_t) rxCount);

			dump_packet(&rxBuffer[0], (size_t)rxCount);
		}
#endif

		/* we have the received string in the rxBuffer now */

		/* hand the NMEA information to the receiver */
		(void) receiverUpdateGpsInformation(&rxBuffer[0], rxCount);
	}
}

/**
 Initialise the plugin: check the configuration, initialise the NMEA parser,
 create network interface sockets, hookup the plugin to OLSR and setup data
 that can be setup in advance.

 @return
 - false upon failure
 - true otherwise
 */
bool initPud(void) {
	if (!checkConfig()) {
		pudError(false, "Invalid configuration");
		goto error;
	}

	initDeDupList(&deDupList, getDeDupDepth());

	/* set global transmit socket config */
	txAddress = getTxMcAddr();

	if (!startReceiver()) {
		pudError(false, "Could not start receiver");
		goto error;
	}

	/*
	 * Creates receive and transmit sockets and register the receive sockets
	 * with the OLSR stack
	 */
	if (!createNetworkInterfaces(&packetReceivedForOlsr)) {
		pudError(false, "Could not create require network interfaces");
		goto error;
	}

	if (!checkRunSetup()) {
		pudError(false, "Invalid configuration");
		goto error;
	}

	/*
	 * Tell OLSR to launch olsr_parser when the packets for this plugin
	 * arrive from the OLSR network
	 */
	olsr_parser_add_function(&packetReceivedFromOlsr, PUD_OLSR_MSG_TYPE);

	return true;

	error: closePud();
	return false;
}

/**
 Stop the plugin: shut down all created network interface sockets and destroy
 the NMEA parser.
 */
void closePud(void) {
	closeNetworkInterfaces();
	stopReceiver();
	destroyDeDupList(&deDupList);
}
