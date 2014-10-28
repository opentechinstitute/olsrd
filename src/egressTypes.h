#ifndef EGRESSTYPES_H
#define EGRESSTYPES_H

#ifdef __linux__

/* Plugin includes */

/* OLSRD includes */

/* System includes */

struct sgw_egress_if {
  char *name;
  struct sgw_egress_if *next;
};

#endif /* __linux__ */

#endif /* EGRESSTYPES_H */
