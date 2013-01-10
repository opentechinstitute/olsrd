#include "uplinkGateway.h"

/* Plugin includes */

/* OLSRD includes */
#include "gateway.h"
#include "tc_set.h"
#include "lq_plugin.h"

/* System includes */

/**
 * Determine the best gateway for uplink: this is the cluster leader.
 *
 * We simply use the current gateway that the smart gateway system determined.
 * When no best gateway is found then we return ourselves so that the behaviour
 * degrades gracefully.
 *
 * @param bestGateway
 * a pointer to the variable in which to store the best gateway
 */
void getBestUplinkGateway(union olsr_ip_addr * bestGateway) {
  struct gateway_entry *gw_best = olsr_get_inet_gateway(olsr_cnf->ip_version != AF_INET);
  if (!gw_best) {
    /* degrade gracefully */
    *bestGateway = olsr_cnf->main_addr;
    return;
  }

  *bestGateway = gw_best->originator;
}
