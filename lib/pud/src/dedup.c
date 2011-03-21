#include "dedup.h"

/* Plugin includes */

/* OLSR includes */
#include "olsr.h"

/* System includes */
#include <assert.h>
#include <stddef.h>
#include <string.h>

#ifdef PUD_DUMP_DEDUP
#include <arpa/inet.h>
#endif

/* Defines */

#define LISTSIZE(x)			((x)->entriesMaxCount) /* always valid */
#define NEWESTINDEX(x)		((x)->newestEntryIndex) /* always valid */
#define WRAPINDEX(x, i)		((i) % LISTSIZE(x)) /* always valid for i>=0 */
#define INCOMINGINDEX(x)	WRAPINDEX(x, (NEWESTINDEX(x) + LISTSIZE(x) - 1)) /* always valid */

/**
 Initialise the de-duplication list: allocate memory for the entries and
 reset fields.

 @param deDupList
 The de-duplication list
 @param maxEntries
 The maximum number of entries in the list (the number of messages that should
 be tracked)

 @return
 - false on failure
 - true otherwise
 */
bool initDeDupList(DeDupList * deDupList, unsigned long long maxEntries) {
	void * p;

	if (deDupList == NULL) {
		return false;
	}
	if (maxEntries < 1) {
		return false;
	}

	p = olsr_malloc(maxEntries * sizeof(DeDupEntry),
			"DeDupEntry entries for DeDupList (PUD)");
	if (p == NULL) {
		return false;
	}

	deDupList->entriesMaxCount = maxEntries;
	deDupList->entries = p;

	deDupList->entriesCount = 0;
	deDupList->newestEntryIndex = 0;

	return true;
}

/**
 Clean up the de-duplication list: free memory and reset fields.

 @param deDupList
 The de-duplication list
 */
void destroyDeDupList(DeDupList * deDupList) {
	assert (deDupList != NULL);

	if (deDupList->entries != NULL) {
		free(deDupList->entries);
		deDupList->entries = NULL;
	}

	deDupList->entriesMaxCount = 0;

	deDupList->entriesCount = 0;
	deDupList->newestEntryIndex = 0;
}

/**
 Add a new (incoming) message to the de-duplication list

 @param deDupList
 The de-duplication list
 @param olsrMessage
 The message
 */
void addToDeDup(DeDupList * deDupList, union olsr_message *olsrMessage) {
	unsigned long long incomingIndex;
	DeDupEntry * newEntry;

	assert (deDupList != NULL);

	incomingIndex = INCOMINGINDEX(deDupList);
	newEntry = &deDupList->entries[incomingIndex];

#ifdef PUD_DUMP_DEDUP
	olsr_printf(0, "addToDeDup: entriesCount=%llu, newestEntryIndex=%llu,"
			" incomingIndex=%llu (before)\n", deDupList->entriesCount,
			deDupList->newestEntryIndex, INCOMINGINDEX(deDupList));
#endif

	memset(newEntry, 0, sizeof(DeDupEntry));
	if (olsr_cnf->ip_version == AF_INET) {
		newEntry->seqno = olsrMessage->v4.seqno;
		memcpy(&newEntry->originator.v4, &olsrMessage->v4.originator,
				sizeof(newEntry->originator.v4));
	} else {
		newEntry->seqno = olsrMessage->v6.seqno;
		memcpy(&newEntry->originator.v6, &olsrMessage->v6.originator,
				sizeof(newEntry->originator.v6));
	}

	deDupList->newestEntryIndex = incomingIndex;
	if (deDupList->entriesCount < deDupList->entriesMaxCount) {
		deDupList ->entriesCount++;
	}

#ifdef PUD_DUMP_DEDUP
	{
		char addr[64];
		olsr_printf(0, "addToDeDup: added seqno %u from %s\n", newEntry->seqno,
				inet_ntop(olsr_cnf->ip_version,
						&newEntry->originator,
						&addr[0],sizeof(addr)));
		olsr_printf(0, "addToDeDup: entriesCount=%llu, newestEntryIndex=%llu,"
				" incomingIndex=%llu (after)\n\n", deDupList->entriesCount,
				deDupList->newestEntryIndex, INCOMINGINDEX(deDupList));
	}
#endif
}

/**
 Determines whether a new (incoming) message is already in the de-duplication
 list

 @param deDupList
 The de-duplication list
 @param olsrMessage
 The message

 @return
 - true when the message is already in the list
 - false otherwise
 */
bool isInDeDupList(DeDupList * deDupList, union olsr_message *olsrMessage) {
	bool retval = false;
	unsigned long long iteratedIndex = NEWESTINDEX(deDupList);
	unsigned long long count = deDupList->entriesCount;

#ifdef PUD_DUMP_DEDUP
	olsr_printf(0, "isInDeDupList: count=%llu, iteratedIndex=%llu"
			" maxCount=%llu (iteration start)\n", count, iteratedIndex,
			deDupList->entriesMaxCount);
#endif

	/* we iterate from newest until oldest: we have a higher probability to
	 * match on the newest entries */

	while (count > 0) {
		DeDupEntry * iteratedEntry = &deDupList->entries[iteratedIndex];

#ifdef PUD_DUMP_DEDUP
		olsr_printf(0, "isInDeDupList: count=%llu, iteratedIndex=%llu"
				" (iteration)\n", count, iteratedIndex);
#endif

		if (olsr_cnf->ip_version == AF_INET) {
#ifdef PUD_DUMP_DEDUP
			{
				char iteratedAddr[64];
				char olsrMessageAddr[64];

				olsr_printf(0, "isInDeDupList: iterated.seqno %u ==?"
						" olsrMessage.seqno %u\n", iteratedEntry->seqno,
						olsrMessage->v4.seqno);
				olsr_printf(0, "isInDeDupList: iterated.addr %s ==?"
						" olsrMessage.addr %s\n", inet_ntop(olsr_cnf->ip_version,
								&iteratedEntry->originator.v4,
								&iteratedAddr[0],sizeof(iteratedAddr)),
								inet_ntop(olsr_cnf->ip_version,
								&olsrMessage->v4.originator,
								&olsrMessageAddr[0],sizeof(olsrMessageAddr)));
			}
#endif
			if ((iteratedEntry->seqno == olsrMessage->v4.seqno) && (memcmp(
					&iteratedEntry->originator.v4, &olsrMessage->v4.originator,
					sizeof(iteratedEntry->originator.v4))) == 0) {
				retval = true;
				break;
			}
		} else {
#ifdef PUD_DUMP_DEDUP
			{
				char iteratedAddr[64];
				char olsrMessageAddr[64];

				olsr_printf(0, "isInDeDupList: iterated.seqno %u ==?"
						" olsrMessage.seqno %u\n", iteratedEntry->seqno,
						olsrMessage->v6.seqno);
				olsr_printf(0, "isInDeDupList: iterated.addr %s ==?"
						" olsrMessage.addr %s\n", inet_ntop(olsr_cnf->ip_version,
								&iteratedEntry->originator.v6,
								&iteratedAddr[0],sizeof(iteratedAddr)),
								inet_ntop(olsr_cnf->ip_version,
								&olsrMessage->v6.originator,
								&olsrMessageAddr[0],sizeof(olsrMessageAddr)));
			}
#endif
			if ((iteratedEntry->seqno == olsrMessage->v6.seqno) && (memcmp(
					&iteratedEntry->originator.v6, &olsrMessage->v6.originator,
					sizeof(iteratedEntry->originator.v6)) == 0)) {
				retval = true;
				break;
			}
		}

		iteratedIndex = WRAPINDEX(deDupList, iteratedIndex + 1); /* go the the next older entry */
		count--;
	}

#ifdef PUD_DUMP_DEDUP
	olsr_printf(0,"isInDeDupList: result = %s\n\n", retval ? "true" : "false");
#endif

	return retval;
}
