#include "configTools.h"

/* Plugin includes */
#include "pud.h"

/* OLSR includes */

/* System includes */
#include <stdlib.h>
#include <errno.h>
#include <assert.h>

/**
 Read an unsigned long long number from a string

 @param parameterName
 The name of the parameter, used when reporting errors
 @param str
 The string to convert to a number
 @param dst
 A pointer to the location where to store the number upon successful conversion
 Not touched when errors are reported.

 @return
 - true on success
 - false otherwise
 */
bool readULL(const char * parameterName, const char * str, unsigned long long * dst) {
	char * endPtr = NULL;
	unsigned long long value;

	assert(parameterName != NULL);
	assert(str != NULL);
	assert(dst != NULL);

	errno = 0;
	value = strtoull(str, &endPtr, 10);

	if (!((endPtr != str) && (*str != '\0') && (*endPtr == '\0'))) {
		/* invalid conversion */
		pudError(false, "Value of parameter %s (%s) could not be converted to a number", parameterName, str);
		return false;
	}

	*dst = value;
	return true;
}

/**
 Read a double number from a string

 @param parameterName
 The name of the parameter, used when reporting errors
 @param str
 The string to convert to a number
 @param dst
 A pointer to the location where to store the number upon successful conversion
 Not touched when errors are reported.

 @return
 - true on success
 - false otherwise
 */
 bool readDouble(const char * parameterName, const char * str, double * dst) {
	char * endPtr = NULL;
	double value;

	assert(parameterName != NULL);
	assert(str != NULL);
	assert(dst != NULL);

	errno = 0;
	value = strtod(str, &endPtr);

	if (!((endPtr != str) && (*str != '\0') && (*endPtr == '\0'))) {
		/* invalid conversion */
		pudError(false, "Value of parameter %s (%s) could not be converted to a number", parameterName, str);
		return false;
	}

	*dst = value;
	return true;
}
