#ifndef _PUD_RECEIVER_H_
#define _PUD_RECEIVER_H_

/* Plugin includes */

/* OLSRD includes */

/* System includes */
#include <stdbool.h>
#include <sys/types.h>

bool startReceiver(void);
void stopReceiver(void);

bool receiverUpdateGpsInformation(unsigned char * rxBuffer, size_t rxCount);

#endif /* _PUD_RECEIVER_H_ */
