#include "uplinkGateway.h"

/* Plugin includes */

/* OLSRD includes */
#include "gateway.h"
#include "tc_set.h"
#include "ipcalc.h"
#include "olsr_types.h"

/* System includes */
#include <stddef.h>
#include <stdbool.h>
#include <sys/socket.h>

/**
 * Determine the speed on which a gateway is chosen
 * @param uplink the uplink speed of the gateway
 * @param downlink the downlink speed of the gateway
 * @return the speed
 */
static inline unsigned long long gw_speed(struct gateway_entry *gw) {
	return (gw->uplink + gw->downlink);
}

/**
 * Determine the best gateway for uplink: this is the cluster leader.
 *
 * Loop over all gateways to find the best one and return it.
 * When no best gateway is found then we return ourselves so that the behaviour
 * degrades gracefully.
 *
 * A gateway is better when the sum of its uplink and downlink are greater than
 * the previous best gateway. In case of a tie, the lowest IP address wins.
 *
 * This code is copied from lib/txtinfo/src/olsrd_txtinfo.c, function ipc_print_gateway.
 * It adjusted for best gateway selection but otherwise kept the same as much
 * as possible.
 *
 * @return
 * a pointer to the IP address of the best gateway
 */
union olsr_ip_addr * getBestUplinkGateway(void) {
	struct gateway_entry me;
	struct gateway_entry *gw_best = NULL;
	unsigned long long gw_best_value = 0;
	struct gateway_entry *gw;

	/* First we start with ourselves as best gateway and then determine whether there is a better one.
	 *
	 * The usage of the uplink and downlink speed is the same as in gateway.c,
	 * function refresh_smartgw_netmask. If that should change, then this must change as well.
	 * Might be better to obtain a pointer to the last HNA that was sent and then to deserialize
	 * that HNA. Or when the olsr_cnf->smart_gw_uplink/downlink fields are modified directly then
	 * obtaining such a pointer is not needed */
	me.originator = olsr_cnf->main_addr;
	me.uplink = olsr_cnf->smart_gw_uplink;
	me.downlink = olsr_cnf->smart_gw_downlink;
	gw_best = &me;
	gw_best_value = gw_speed(&me);

	OLSR_FOR_ALL_GATEWAY_ENTRIES(gw) {
		bool eval4 = false;
		bool eval6 = false;

		struct tc_entry * tc = olsr_lookup_tc_entry(&gw->originator);
		if (tc == NULL) {
			continue;
		}

		if (gw == olsr_get_ipv4_inet_gateway(NULL)) {
			eval4 = true;
		} else if (gw->ipv4
				&& (olsr_cnf->ip_version == AF_INET || olsr_cnf->use_niit)
				&& (olsr_cnf->smart_gw_allow_nat || !gw->ipv4nat)) {
			eval4 = true;
		}

		if (gw == olsr_get_ipv6_inet_gateway(NULL)) {
			eval6 = true;
		} else if (gw->ipv6 && olsr_cnf->ip_version == AF_INET6) {
			eval6 = true;
		}

		if (eval4 || eval6) {
			unsigned long long gw_value = gw_speed(gw);
			if (gw_value > gw_best_value) {
				gw_best = gw;
				gw_best_value = gw_value;
			} else if (gw_value == gw_best_value) {
				bool gwHaslowerIpAddress = false;
				if (eval4) {
					gwHaslowerIpAddress = (ip4cmp(&gw->originator.v4,
							&gw_best->originator.v4) < 0);
				} else /* eval6 */{
					gwHaslowerIpAddress = (ip6cmp(&gw->originator.v6,
							&gw_best->originator.v6) < 0);
				}
				if (gwHaslowerIpAddress) {
					gw_best = gw;
					gw_best_value = gw_value;
				}
			}
		}
	} OLSR_FOR_ALL_GATEWAY_ENTRIES_END(gw)

	if (gw_best == &me) {
		/* I'm the chosen gateway */
		return &olsr_cnf->main_addr;
	}

	/* the chosen gateway is better */
	return &gw_best->originator;
}
