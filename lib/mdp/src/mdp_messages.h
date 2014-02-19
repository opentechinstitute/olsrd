
/*
 * Serval MDP Secure OLSR plugin
 *
 * Copyright (c) 2012, Open Technology Institute
 * Copyright (c) 2004, Andreas Tonnesen(andreto@olsr.org)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or
 * without modification, are permitted provided that the following
 * conditions are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 * * Neither the name of olsrd, olsr.org nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

/*
 * olsr.org olsr daemon security plugin
 */

#ifndef _OLSRD_SECURE_MSG
#define _OLSRD_SECURE_MSG

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <limits.h>
#include <time.h>
#include <math.h>
#include <stdio.h>

#define HAVE_ARPA_INET_H

#include "olsr_types.h"
#include "interfaces.h"

/* The type of message you will use */
#define MESSAGE_TYPE 10

/* The type of messages we will receive - can be set to promiscuous */
#define PARSER_TYPE MESSAGE_TYPE

#define TYPE_CHALLENGE 11
#define TYPE_CRESPONSE 12
#define TYPE_RRESPONSE 13

#define SID_STRLEN (SID_SIZE*2)
#define SID_SIZE 32
#define SAS_SIZE 32
#define SIGNATURE_BYTES 64

extern char config_sid[SID_STRLEN + 1];
extern char config_keyringpath[PATH_MAX + 1];
extern char config_commotionsock[PATH_MAX + 1];

#define SIGSIZE SIGNATURE_BYTES

/****************************************************************************
 *                            PACKET SECTION                                *
 ****************************************************************************/

#define PACK __attribute__ ((__packed__))
//#define PACK  
#define TIME_TYPE time_t
struct PACK sig_msg {
  uint8_t type;
  uint8_t algorithm;
  uint16_t reserved;

  TIME_TYPE timestamp;
  uint8_t signature[SIGSIZE];
};

/*
 * OLSR message (several can exist in one OLSR packet)
 */

struct PACK s_olsrmsg {
  uint8_t olsr_msgtype;
  uint8_t olsr_vtime;
  uint16_t olsr_msgsize;
  uint32_t originator;
  uint8_t ttl;
  uint8_t hopcnt;
  uint16_t seqno;

  /* YOUR PACKET GOES HERE */
  struct sig_msg sig;

};

/*
 * Challenge response messages
 */

struct PACK challengemsg {
  uint8_t olsr_msgtype;
  uint8_t olsr_vtime;
  uint16_t olsr_msgsize;
  uint32_t originator;
  uint8_t ttl;
  uint8_t hopcnt;
  uint16_t seqno;

  uint32_t destination;
  uint32_t challenge;

  uint8_t signature[SIGSIZE];

};

struct PACK c_respmsg {
  uint8_t olsr_msgtype;
  uint8_t olsr_vtime;
  uint16_t olsr_msgsize;
  uint32_t originator;
  uint8_t ttl;
  uint8_t hopcnt;
  uint16_t seqno;

  uint32_t destination;
  uint32_t challenge;
  TIME_TYPE timestamp;

  uint8_t res_sig[SIGSIZE];

  uint8_t signature[SIGSIZE];
};

struct PACK r_respmsg {
  uint8_t olsr_msgtype;
  uint8_t olsr_vtime;
  uint16_t olsr_msgsize;
  uint32_t originator;
  uint8_t ttl;
  uint8_t hopcnt;
  uint16_t seqno;

  uint32_t destination;
  TIME_TYPE timestamp;

  uint8_t res_sig[SIGSIZE];

  uint8_t signature[SIGSIZE];
};

/*
 *IPv6
 */

struct PACK s_olsrmsg6 {
  uint8_t olsr_msgtype;
  uint8_t olsr_vtime;
  uint16_t olsr_msgsize;
  struct in6_addr originator;
  uint8_t ttl;
  uint8_t hopcnt;
  uint16_t seqno;

  /* YOUR PACKET GOES HERE */
  struct sig_msg sig;
};

/*
 * Generic OLSR packet - DO NOT ALTER
 */

struct s_olsr {
  uint16_t olsr_packlen;             /* packet length */
  uint16_t olsr_seqno;
  struct s_olsrmsg olsr_msg[1];        /* variable messages */
};

struct s_olsr6 {
  uint16_t olsr_packlen;             /* packet length */
  uint16_t olsr_seqno;
  struct s_olsrmsg6 olsr_msg[1];       /* variable messages */
};

#endif /* _OLSRD_SECURE_MSG */

/*
 * Local Variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
