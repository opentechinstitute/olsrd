#include "configTools.h"

/* Plugin includes */
#include "pud.h"

/* OLSR includes */

/* System includes */
#include <stdlib.h>
#include <errno.h>

/**
 Read an unsigned long long number from a value string

 @param valueName
 the name of the value
 @param value
 the string to convert to a number
 @param valueNumber
 a pointer to the location where to store the number upon successful conversion

 @return
 - true on success
 - false otherwise
 */
bool readULL(const char * valueName, const char * value, unsigned long long * valueNumber) {
	char * endPtr = NULL;
	unsigned long long valueNew;

	errno = 0;
	valueNew = strtoull(value, &endPtr, 10);

	if (!((endPtr != value) && (*value != '\0') && (*endPtr == '\0'))) {
		/* invalid conversion */
		pudError(true, "Configured %s (%s) could not be converted to a number", valueName, value);
		return false;
	}

	*valueNumber = valueNew;

	return true;
}

/**
 Read a double number from a value string

 @param valueName
 the name of the value
 @param value
 the string to convert to a number
 @param valueNumber
 a pointer to the location where to store the number upon successful conversion

 @return
 - true on success
 - false otherwise
 */
bool readDouble(const char * valueName, const char * value, double * valueNumber) {
	char * endPtr = NULL;
	double valueNew;

	errno = 0;
	valueNew = strtod(value, &endPtr);

	if (!((endPtr != value) && (*value != '\0') && (*endPtr == '\0'))) {
		/* invalid conversion */
		pudError(true, "Configured %s (%s) could not be converted to a number", valueName, value);
		return false;
	}

	*valueNumber = valueNew;

	return true;
}
