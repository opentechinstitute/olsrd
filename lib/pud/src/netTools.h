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
