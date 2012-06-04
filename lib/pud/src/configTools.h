#ifndef _PUD_CONFIGTOOLS_H_
#define _PUD_CONFIGTOOLS_H_

/* Plugin includes */

/* OLSR includes */

/* System includes */
#include <stdbool.h>

bool readULL(const char * valueName, const char * value, unsigned long long * valueNumber);

bool readDouble(const char * valueName, const char * value, double * valueNumber);

#endif /* PUD_CONFIGTOOLS_H_ */
