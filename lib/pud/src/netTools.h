#ifndef _PUD_NETTOOLS_H_
#define _PUD_NETTOOLS_H_

/* Plugin includes */

/* OLSR includes */
#include "olsr_types.h"

/* System includes */
#include <assert.h>
#include <unistd.h>
#include <stdbool.h>
#include <net/if.h>

/**
 Get the port in an OLSR socket address

 @param addr
 A pointer to OLSR socket address
 @return
 The port (in network byte order)
 */
static inline in_port_t getOlsrSockaddrPort(union olsr_sockaddr * addr) {
	if (addr->in.sa_family == AF_INET) {
		return addr->in4.sin_port;
	} else {
		return addr->in6.sin6_port;
	}
}

/**
 Set the port in an OLSR socket address

 @param addr
 A pointer to OLSR socket address
 @param port
 The port (in network byte order)
 */
static inline void setOlsrSockaddrPort(union olsr_sockaddr * addr, in_port_t port) {
	if (addr->in.sa_family == AF_INET) {
		addr->in4.sin_port = port;
	} else {
		addr->in6.sin6_port = port;
	}
}

/**
 Determine whether an IP address (v4 or v6) is a multicast address.

 @param addr
 An IP address (v4 or v6)

 @return
 - true when the address is a multicast address
 - false otherwise
 */
static inline bool isMulticast(union olsr_sockaddr *addr) {
	assert(addr != NULL);

	if (addr->in.sa_family == AF_INET) {
		return IN_MULTICAST(ntohl(addr->in4.sin_addr.s_addr));
	}

	return IN6_IS_ADDR_MULTICAST(&addr->in6.sin6_addr);
}


unsigned char * getHardwareAddress(const char * ifName, int family,
		struct ifreq *ifr);

#endif /* _PUD_NETTOOLS_H_ */
