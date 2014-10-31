#ifndef EGRESSTYPES_H
#define EGRESSTYPES_H

#ifdef __linux__

/* Plugin includes */

/* OLSRD includes */

/* System includes */

struct sgw_egress_if {
  char *name;

  /* configured through the SmartGatewayTablesOffset and SmartGatewayRulesOffset configuration parameters */
  uint8_t tableNr; /**< routing table number */
  uint8_t ruleNr; /**< IP rule number */
  uint8_t bypassRuleNr; /**< bypass IP rule number */

  struct sgw_egress_if *next;
};

#endif /* __linux__ */

#endif /* EGRESSTYPES_H */
