#ifndef _PUD_CONFIGTOOLS_H_
#define _PUD_CONFIGTOOLS_H_

/* Plugin includes */

/* OLSR includes */

/* System includes */
#include <stdbool.h>

bool readULL(const char * parameterName, const char * str, unsigned long long * dst);

bool readDouble(const char * parameterName, const char * str, double * dst);

#endif /* PUD_CONFIGTOOLS_H_ */
