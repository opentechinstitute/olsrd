#include "gatewaySpeedFile.h"

#include "log.h"
#include <regex.h>
#include <sys/stat.h>

#define LINE_LENGTH 256

static const char * regexCommentString = "^([[:space:]]*|[[:space:]#]+.*)$";
static const char * regexNameValueString =
		"^[[:space:]]*([^[:space:]]+)[[:space:]]*=[[:space:]]*([[:digit:]]+)[[:space:]]*$";
static const size_t regexNameValuematchCount = 3;

static regex_t regexComment;
static regex_t regexNameValue;
static bool started = false;

typedef struct _CachedStat {
	struct timespec st_mtim; /* Time of last modification.  */
} CachedStat;

static CachedStat cachedStat;

/**
 Read an unsigned long number from a value string

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
static bool readUL(const char * valueName, const char * value, unsigned long * valueNumber) {
	char * endPtr = NULL;
	unsigned long valueNew;

	errno = 0;
	valueNew = strtoul(value, &endPtr, 10);

	if (!((endPtr != value) && (*value != '\0') && (*endPtr == '\0'))) {
		/* invalid conversion */
		olsr_syslog(OLSR_LOG_ERR, "Configured %s (%s) could not be converted to a number: %s\n", valueName, value,
				strerror(errno));
		return false;
	}

	*valueNumber = valueNew;

	return true;
}

bool startGatewaySpeedFile(void) {
	if (started) {
		return true;
	}

	if (regcomp(&regexComment, regexCommentString, REG_EXTENDED)) {
		olsr_printf(0, "Could not compile regex \"%s\"\n", regexCommentString);
		return false;
	}

	if (regcomp(&regexNameValue, regexNameValueString, REG_EXTENDED)) {
		olsr_printf(0, "Could not compile regex \"%s\"\n", regexNameValueString);
		return false;
	}

	cachedStat.st_mtim.tv_sec = -1;
	cachedStat.st_mtim.tv_nsec = -1;

	started = true;
	return true;
}

void stopGatewaySpeedFile(void) {
	if (started) {
		regfree(&regexNameValue);
		regfree(&regexComment);
		started = false;
	}
}

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
		olsr_syslog(OLSR_LOG_ERR, "Regex match failed: %s\n", msgbuf);
	}

	return false;
}

static char line[LINE_LENGTH];

void readGatewaySpeedFile(char * fileName) {
	struct stat statBuf;
	FILE * fd = NULL;
	unsigned int lineNumber = 0;
	char * name = NULL;
	char * value = NULL;
	unsigned long uplink = DEF_UPLINK_SPEED;
	unsigned long downlink = DEF_DOWNLINK_SPEED;
	bool uplinkSet = false;
	bool downlinkSet = false;

	if (stat(fileName, &statBuf)) {
		/* could not access the file */
		goto out;
	}

	if (!memcmp(&cachedStat.st_mtim, &statBuf.st_mtim, sizeof(cachedStat.st_mtim))) {
		/* file did not change since last read */
		goto out;
	}

	fd = fopen(fileName, "r");
	if (!fd) {
		goto out;
	}

	memcpy(&cachedStat.st_mtim, &statBuf.st_mtim, sizeof(cachedStat.st_mtim));

	while (fgets(line, LINE_LENGTH, fd)) {
		regmatch_t pmatch[regexNameValuematchCount];

		lineNumber++;

		if (regexMatch(&regexComment, line, 0, NULL)) {
			continue;
		}

		if (!regexMatch(&regexNameValue, line, regexNameValuematchCount, pmatch)) {
			olsr_syslog(OLSR_LOG_ERR, "Gateway speed file \"%s\", line %d uses invalid syntax: %s\n", fileName, lineNumber,
					line);
			goto out;
		}

		/* copy name/value */
		name = &line[pmatch[1].rm_so];
		line[pmatch[1].rm_eo] = '\0';
		value = &line[pmatch[2].rm_so];
		line[pmatch[2].rm_eo] = '\0';

		if (!strncasecmp(GATEWAY_SPEED_UPLINK, name, sizeof(line))) {
			if (!readUL(GATEWAY_SPEED_UPLINK, value, &uplink)) {
				goto out;
			}
			uplinkSet = true;
		} else if (!strncasecmp(GATEWAY_SPEED_DOWNLINK, name, sizeof(line))) {
			if (!readUL(GATEWAY_SPEED_DOWNLINK, value, &downlink)) {
				goto out;
			}
			downlinkSet = true;
		} else {
			olsr_syslog(OLSR_LOG_ERR, "Gateway speed file \"%s\", line %d uses an invalid option \"%s\","
					" valid options are [%s|%s]\n", fileName, lineNumber, name, GATEWAY_SPEED_UPLINK,
					GATEWAY_SPEED_DOWNLINK);
			goto out;
		}
	}

	fclose(fd);

	if (uplinkSet) {
		olsr_cnf->smart_gw_uplink = uplink;
	}
	if (downlinkSet) {
		olsr_cnf->smart_gw_downlink = downlink;
	}

	out: return;
}
