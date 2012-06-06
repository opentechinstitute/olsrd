#include "posFile.h"

/* Plugin includes */
#include "pud.h"
#include "configTools.h"

/* OLSR includes */

/* System includes */
#include <stdio.h>
#include <string.h>
#include <regex.h>
#include <sys/stat.h>

/** the maximal length of a line that is read from the file */
#define LINE_LENGTH 256

/** regular expression describing a comment */
static const char * regexCommentString = "^([[:space:]]*|[[:space:]#]+.*)$";

/** regular expression describing a key/value pair */
static const char * regexNameValueString =
		"^[[:space:]]*([^[:space:]]+)[[:space:]]*=[[:space:]]*([^[:space:]]+)[[:space:]]*$";

/** the number of matches in regexNameValueString */
static const size_t regexNameValuematchCount = 3;

/** the compiled regular expression describing a comment */
static regex_t regexComment;

/** the compiled regular expression describing a key/value pair */
static regex_t regexNameValue;

/** true when the plugin has been started */
static bool started = false;

/** type to hold the cached stat result */
typedef struct _CachedStat {
	time_t timeStamp; /* Time of last modification (second resolution) */
} CachedStat;

/** the cached stat result */
static CachedStat cachedStat;

/**
 * Initialises the positionFile reader.
 * @return true upon success, false otherwise
 */
bool startPositionFile(void) {
	if (started) {
		return true;
	}

	if (regcomp(&regexComment, regexCommentString, REG_EXTENDED | REG_ICASE)) {
		pudError(false, "Could not compile regex \"%s\"", regexCommentString);
		return false;
	}

	if (regcomp(&regexNameValue, regexNameValueString, REG_EXTENDED | REG_ICASE)) {
		pudError(false, "Could not compile regex \"%s\"", regexNameValueString);
		regfree(&regexComment);
		return false;
	}

	cachedStat.timeStamp = -1;

	started = true;
	return true;
}

/**
 * Cleans up the positionFile reader.
 */
void stopPositionFile(void) {
	if (started) {
		regfree(&regexNameValue);
		regfree(&regexComment);
		started = false;
	}
}

/**
 * Performs a regex match
 * @param regex the compiled regex to match against
 * @param line the line to match
 * @param nmatch the number of matches to produce
 * @param pmatch the array with match information
 * @return true upon success, false otherwise
 */
static bool regexMatch(regex_t * regex, char * line, size_t nmatch, regmatch_t pmatch[]) {
	int result = regexec(regex, line, nmatch, pmatch, 0);
	if (!result) {
		return true;
	}

	if (result == REG_NOMATCH) {
		return false;
	}

	{
		char msgbuf[256];
		regerror(result, regex, msgbuf, sizeof(msgbuf));
		pudError(false, "Regex match failed: %s", msgbuf);
	}

	return false;
}

/** the buffer in which to store a line read from the file */
static char line[LINE_LENGTH];

/**
 * Read the position file
 * @param fileName the filename
 */
bool readPositionFile(char * fileName, nmeaINFO * nmeaInfo) {
	bool retval = false;
	struct stat statBuf;
	nmeaINFO result;
	FILE * fd = NULL;
	unsigned int lineNumber = 0;
	char * name = NULL;
	char * value = NULL;

	if (stat(fileName, &statBuf)) {
		/* could not access the file */
		goto out;
	}

	if (!memcmp(&cachedStat.timeStamp, &statBuf.st_mtime, sizeof(cachedStat.timeStamp))) {
		/* file did not change since last read */
		goto out;
	}

	fd = fopen(fileName, "r");
	if (!fd) {
		goto out;
	}

	nmea_zero_INFO(&result);
	result.sig = POSFILE_DEFAULT_SIG;
	result.fix = POSFILE_DEFAULT_FIX;
	result.HDOP = POSFILE_DEFAULT_HDOP;
	result.VDOP = POSFILE_CALCULATED_VDOP(result.HDOP);
	result.PDOP = POSFILE_CALCULATED_PDOP(result.HDOP);
	result.lat = POSFILE_DEFAULT_LAT;
	result.lon = POSFILE_DEFAULT_LON;
	result.elv = POSFILE_DEFAULT_ELV;
	result.speed = POSFILE_DEFAULT_SPEED;
	result.direction = POSFILE_DEFAULT_DIRECTION;

	memcpy(&cachedStat.timeStamp, &statBuf.st_mtime, sizeof(cachedStat.timeStamp));

	while (fgets(line, LINE_LENGTH, fd)) {
		regmatch_t pmatch[regexNameValuematchCount];

		lineNumber++;

		if (regexMatch(&regexComment, line, 0, NULL)) {
			continue;
		}

		if (!regexMatch(&regexNameValue, line, regexNameValuematchCount, pmatch)) {
			pudError(false, "Position file \"%s\", line %d uses invalid syntax: %s", fileName, lineNumber, line);
			goto out;
		}

		/* determine name/value */
		name = &line[pmatch[1].rm_so];
		line[pmatch[1].rm_eo] = '\0';
		value = &line[pmatch[2].rm_so];
		line[pmatch[2].rm_eo] = '\0';

		if (!strncasecmp(POSFILE_NAME_SIG, name, sizeof(line))) {
			if (!strncasecmp(POSFILE_VALUE_SIG_BAD, value, sizeof(line))) {
				result.sig = NMEA_SIG_BAD;
			} else if (!strncasecmp(POSFILE_VALUE_SIG_LOW, value, sizeof(line))) {
				result.sig = NMEA_SIG_LOW;
			} else if (!strncasecmp(POSFILE_VALUE_SIG_MID, value, sizeof(line))) {
				result.sig = NMEA_SIG_MID;
			} else if (!strncasecmp(POSFILE_VALUE_SIG_HIGH, value, sizeof(line))) {
				result.sig = NMEA_SIG_HIGH;
			} else {
				pudError(false, "Position file \"%s\", line %d uses an invalid value for \"%s\","
						" valid values are [%s|%s\%s|%s]", fileName, lineNumber, POSFILE_NAME_SIG,
						POSFILE_VALUE_SIG_BAD, POSFILE_VALUE_SIG_LOW, POSFILE_VALUE_SIG_MID, POSFILE_VALUE_SIG_HIGH);
				goto out;
			}
		} else if (!strncasecmp(POSFILE_NAME_FIX, name, sizeof(line))) {
			if (!strncasecmp(POSFILE_VALUE_FIX_BAD, value, sizeof(line))) {
				result.fix = NMEA_FIX_BAD;
			} else if (!strncasecmp(POSFILE_VALUE_FIX_2D, value, sizeof(line))) {
				result.fix = NMEA_FIX_2D;
			} else if (!strncasecmp(POSFILE_VALUE_FIX_3D, value, sizeof(line))) {
				result.fix = NMEA_FIX_3D;
			} else {
				pudError(false, "Position file \"%s\", line %d uses an invalid value for \"%s\","
						" valid values are [%s\%s|%s]", fileName, lineNumber, POSFILE_NAME_FIX, POSFILE_VALUE_FIX_BAD,
						POSFILE_VALUE_FIX_2D, POSFILE_VALUE_FIX_3D);
				goto out;
			}
		} else if (!strncasecmp(POSFILE_NAME_HDOP, name, sizeof(line))) {
			double val;
			if (!readDouble(POSFILE_NAME_HDOP, value, &val)) {
				goto out;
			}

			result.HDOP = val;
			result.VDOP = POSFILE_CALCULATED_VDOP(result.HDOP);
			result.PDOP = POSFILE_CALCULATED_PDOP(result.HDOP);
		} else if (!strncasecmp(POSFILE_NAME_LAT, name, sizeof(line))) {
			double val;
			if (!readDouble(POSFILE_NAME_LAT, value, &val)) {
				goto out;
			}

			result.lat = val;
		} else if (!strncasecmp(POSFILE_NAME_LON, name, sizeof(line))) {
			double val;
			if (!readDouble(POSFILE_NAME_LON, value, &val)) {
				goto out;
			}

			result.lon = val;
		} else if (!strncasecmp(POSFILE_NAME_ELV, name, sizeof(line))) {
			double val;
			if (!readDouble(POSFILE_NAME_ELV, value, &val)) {
				goto out;
			}

			result.elv = val;
		} else if (!strncasecmp(POSFILE_NAME_SPEED, name, sizeof(line))) {
			double val;
			if (!readDouble(POSFILE_NAME_SPEED, value, &val)) {
				goto out;
			}

			result.speed = val;
		} else if (!strncasecmp(POSFILE_NAME_DIRECTION, name, sizeof(line))) {
			double val;
			if (!readDouble(POSFILE_NAME_DIRECTION, value, &val)) {
				goto out;
			}

			result.direction = val;
		} else {
			pudError(false, "Position file \"%s\", line %d uses an invalid option \"%s\","
					" valid options are [%s|%s|%s|%s|%s|%s|%s|%s]", fileName, lineNumber, name, POSFILE_NAME_SIG,
					POSFILE_NAME_FIX, POSFILE_NAME_HDOP, POSFILE_NAME_LAT, POSFILE_NAME_LON, POSFILE_NAME_ELV,
					POSFILE_NAME_SPEED, POSFILE_NAME_DIRECTION);
			goto out;
		}
	}

	fclose(fd);

	result.smask = POSFILE_SANITISE_SMASK;
	nmea_INFO_sanitise(&result);
	nmea_INFO_unit_conversion(&result);
	if (result.fix == NMEA_FIX_BAD) {
		result.smask = 0;
	} else {
		result.smask = POSFILE_DEFAULT_SMASK;
	}

	memcpy(nmeaInfo, &result, sizeof(result));
	retval = true;

	out: return retval;
}
