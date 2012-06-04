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
 Determine the address of the port in an OLSR socket address

 @param addr
 A pointer to OLSR socket address
 @param port
 A pointer to the location where the pointer to the port will be stored
 */
static inline void getOlsrSockaddrPortAddress(union olsr_sockaddr * addr, in_port_t ** port) {
	if (addr->in.sa_family == AF_INET) {
		*port = &addr->in4.sin_port;
	} else {
		*port = &addr->in6.sin6_port;
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
