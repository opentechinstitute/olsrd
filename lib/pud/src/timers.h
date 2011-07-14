#ifndef _PUD_TIMERS_H_
#define _PUD_TIMERS_H_

/* Plugin includes */

/* OLSRD includes */
#include "scheduler.h"

/* System includes */

int initOlsrTxTimer(void);
void destroyOlsrTxTimer(void);
int restartOlsrTxTimer(unsigned long long interval, timer_cb_func cb_func);

#endif /* _PUD_TIMERS_H_ */
