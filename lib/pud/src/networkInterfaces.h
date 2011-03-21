#ifndef _PUD_NETWORKINTERFACES_H
#define _PUD_NETWORKINTERFACES_H

/* Plugin includes */

/* OLSR includes */
#include "olsr_types.h"
#include "interfaces.h"
#include "scheduler.h"

/* System includes */
#include <stdbool.h>
#include <net/if.h>

/** The size of the hardware address */
#define PUD_HWADDR_SIZE IFHWADDRLEN

/** A list of TRxTxNetworkInterface objects, used for non-OLSR interfaces */
typedef struct _TRxTxNetworkInterface {
		/** The socket file descriptor for the non-OLSR interface*/
		int socketFd;

		/** The name of the interface */
		unsigned char name[IFNAMSIZ + 1];

		/** The IP address of the interface */
		union olsr_sockaddr ipAddress;

		/** The hardware address of the interface */
		unsigned char hwAddress[PUD_HWADDR_SIZE];

		/** The next TRxTxNetworkInterface in the list */
		struct _TRxTxNetworkInterface * next;
} TRxTxNetworkInterface;

/** A list of TOLSRNetworkInterface objects, used for OLSR interfaces */
typedef struct _TOLSRNetworkInterface {
		/** A pointer to the OLSR interface */
		struct interface * olsrIntf;

		/** The hardware address of the interface */
		unsigned char hwAddress[PUD_HWADDR_SIZE];

		/** The next TOLSRNetworkInterface in the list */
		struct _TOLSRNetworkInterface * next;
} TOLSRNetworkInterface;

bool createNetworkInterfaces(socket_handler_func rxSocketHandlerFunction);
void closeNetworkInterfaces(void);

TRxTxNetworkInterface * getRxNetworkInterfaces(void);
TRxTxNetworkInterface * getTxNetworkInterfaces(void);
TOLSRNetworkInterface * getOlsrNetworkInterface(struct interface * olsrIntf);

#endif /* _PUD_NETWORKINTERFACES_H */
