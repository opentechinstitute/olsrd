
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

/* Adjustments made to ensure data going out is converted to network
 * byte ordering.  Also, to ensure incoming data is converted before
 * it is used and before checksums are calculated as well.
 * Rusty Haddock AE5AE -- for the HSMM-MESH project.
 */

/*
 * Dynamic linked library for the olsr.org olsr daemon
 */

#include "olsrd_mdp.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <assert.h>

#include "defs.h"
#include "ipcalc.h"
#include "olsr.h"
#include "parser.h"
#include "scheduler.h"
#include "net_olsr.h"

#include <commotion.h>

#define CHECKSUM mdp_checksum
#define SCHEME   MDP_INCLUDING_KEY

#ifdef OS
#undef OS
#endif /* OS */

#ifdef _WIN32
#define close(x) closesocket(x)
#undef EWOULDBLOCK
#define EWOULDBLOCK WSAEWOULDBLOCK
#define OS "Windows"
#endif /* _WIN32 */
#ifdef __linux__
#define OS "GNU/Linux"
#endif /* __linux__ */
#if defined __FreeBSD__ || defined __FreeBSD_kernel__
#define OS "FreeBSD"
#endif /* defined __FreeBSD__ || defined __FreeBSD_kernel__ */

#ifndef OS
#define OS "Undefined"
#endif /* OS */

#define CLEAN_ERRNO() (errno == 0 ? "None" : strerror(errno))
#define ERROR(M, ...) olsr_printf(1, "(%s:%d: errno: %s) " M "\n", __FILE__, __LINE__, CLEAN_ERRNO(), ##__VA_ARGS__)
#define CHECK(A, M, ...) if(!(A)) { ERROR(M, ##__VA_ARGS__); errno=0; goto error; }
#define CHECKF(A, M, ...) if(!(A)) { ERROR(M, ##__VA_ARGS__); exit(1); }
#define CHECK_MEM(A) CHECK((A), "Out of memory.")
#define CHECKF_MEM(A) CHECKF((A), "Out of memory.")
#define CO_APPEND_STR(R,S) CHECKF(co_request_append_str(co_req,S,strlen(S)+1),"Failed to append to request")
#define CO_APPEND_BIN(R,S,L) CHECK(co_request_append_bin(co_req,(char*)S,L),"Failed to append to request")

static struct timeval now;
co_obj_t *co_req = NULL, *co_resp = NULL;

/* Timestamp node */
struct stamp {
  union olsr_ip_addr addr;
  /* Timestamp difference */
  int diff;
  uint32_t challenge;
  uint8_t validated;
  uint32_t valtime;                     /* Validity time */
  uint32_t conftime;                    /* Reconfiguration time */
  struct stamp *prev;
  struct stamp *next;
};

/* Seconds to cache a valid timestamp entry */
#define TIMESTAMP_HOLD_TIME 30

/* Seconds to cache a not verified timestamp entry */
#define EXCHANGE_HOLD_TIME 5

static struct stamp timestamps[HASHSIZE];

char config_keyringpath[PATH_MAX + 1] = {0};
char config_sid[SID_STRLEN + 1] = {0};
char config_commotionsock[PATH_MAX + 1] = {0};
unsigned char *servald_key;
int servald_key_len;

/* Event function to register with the sceduler */
static int send_challenge(struct interface *olsr_if, const union olsr_ip_addr *);
static int send_cres(struct interface *olsr_if, union olsr_ip_addr *, union olsr_ip_addr *, uint32_t, struct stamp *);
static int send_rres(struct interface *olsr_if, union olsr_ip_addr *, union olsr_ip_addr *, uint32_t);
static int parse_challenge(struct interface *olsr_if, char *);
static int parse_cres(struct interface *olsr_if, char *);
static int parse_rres(char *);
static int check_auth(struct interface *olsr_if, char *, int *);
static int add_signature(struct interface *, uint8_t *, int *);
static int validate_packet(struct interface *olsr_if, const char *, int *);
static char *secure_preprocessor(char *packet, struct interface *olsr_if, union olsr_ip_addr *from_addr, int *length);
static void timeout_timestamps(void *);
static int check_timestamp(struct interface *olsr_if, const union olsr_ip_addr *, TIME_TYPE);
static struct stamp *lookup_timestamp_entry(const union olsr_ip_addr *);
static int read_key_from_servald(co_obj_t *, const char *, const char *);

static void
print_data(const char *label, const uint8_t *data, size_t len)
{
  unsigned int j = 0, i = 0;
  olsr_printf(3, "%s:\n", label);

  for (; i < len; i++) {
    olsr_printf(3, "  %3i", data[i]);
    j++;
    if (j == 4) {
      olsr_printf(3, "\n");
      j = 0;
    }
  }
}

static void
mdp_checksum(uint8_t *data, const uint16_t data_len, 
             uint8_t *sigbuf, const uint16_t sigbuf_len)
{
  unsigned char *sig = NULL;
  size_t sig_len = 0;
  co_obj_t *co_conn = NULL;

  CHECKF((co_conn = co_connect(config_commotionsock,strlen(config_commotionsock)+1)),"Failed to connect to Commotion socket\n\n");

  CHECK_MEM((co_req = co_request_create()));
  CO_APPEND_BIN(co_req,servald_key,servald_key_len);
  CO_APPEND_BIN(co_req,data,data_len);
  int call_ret = co_call(co_conn,&co_resp,"mdp-sign",sizeof("mdp-sign"),co_req);
  CHECK(call_ret, "Failed to receive signature from commotiond");
  sig_len = co_response_get_bin(co_resp,(char**)&sig,"sig",sizeof("sig"));
  CHECK(sig_len, "Received invalid signature from commotiond");

  if (sig_len <= sigbuf_len) {
    CHECK_MEM(memcpy(sigbuf,sig,sig_len));
  } else {
    olsr_printf(1, "Signature too big for signature buffer!\n");
  }

  co_free(co_req);
  co_free(co_resp);
  
  print_data("signature", sigbuf, sig_len);

error:
  /*
   * We can't be sure that we need to disconnect. But 
   * we need to if there is a connection.
   */
  if (co_conn) {
    if (!co_disconnect(co_conn)) {
      olsr_printf(1,"Failed to disconnect from commotiond.");
    }
  }
  return;
}

/**
 *Do initialization here
 *
 *This function is called by the my_init
 *function in uolsrd_plugin.c
 */

int
mdp_plugin_init(void)
{
  int i;
  co_obj_t *co_conn = NULL;
  struct interface *ifn = NULL;

  /* Initialize the timestamp database */
  for (i = 0; i < HASHSIZE; i++) {
    timestamps[i].next = &timestamps[i];
    timestamps[i].prev = &timestamps[i];
  }
  olsr_printf(3, "Timestamp database initialized\n");

  CHECKF(strlen(config_sid),"[MDP] Must set a SID (sid) for this plugin to work.\n\n");

  CHECKF(strlen(config_keyringpath),"[MDP] Must set a Serval keyring path (keyringpath) for this plugin to work.\n\n");
  
  CHECKF(co_init() == 1,"Failed to initialize Commotion client\n\n");
  
  if (!strlen(config_commotionsock))
    strcpy(config_commotionsock,DEFAULT_CO_SOCK);
  
  CHECKF((co_conn = co_connect(config_commotionsock,strlen(config_commotionsock)+1)),"Failed to connect to Commotion socket\n\n");

  CHECKF(read_key_from_servald(co_conn, config_keyringpath, config_sid) == 0,"[MDP] Could not read key from servald sid!\nExiting!\n\n");

  /* loop through interfaces, reserving buffer space for signatures */
  for (ifn = ifnet; ifn; ifn = ifn->int_next) {
    CHECKF(net_reserve_bufspace(ifn, sizeof(struct s_olsrmsg)) == 0, "Error reserving buffer space for signatures");
  }
  
  /* Register the packet transform function */
  add_ptf(&add_signature);

  olsr_preprocessor_add_function(&secure_preprocessor);

  /* Register timeout - poll every 2 seconds */
  olsr_start_timer(2 * MSEC_PER_SEC, 0, OLSR_TIMER_PERIODIC, &timeout_timestamps, NULL, 0);

  CHECK(co_disconnect(co_conn),"Failed to disconnect from commotiond.");
error:
  return 1;
}

int
plugin_ipc_init(void)
{
  return 1;
}

/*
 * destructor - called at unload
 */
void
mdp_plugin_exit(void)
{
  co_shutdown();
  olsr_preprocessor_remove_function(&secure_preprocessor);
}

static char *
secure_preprocessor(char *packet, struct interface *olsr_if, union olsr_ip_addr *from_addr, int *length)
{
  struct olsr *olsr = (struct olsr *)packet;
  struct ipaddr_str buf;

  /*
   * Check for challenge/response messages
   */
  check_auth(olsr_if, packet, length);

  /*
   * Check signature
   */

  if (!validate_packet(olsr_if, packet, length)) {
    olsr_printf(1, "[MDP] Rejecting packet from %s\n", olsr_ip_to_string(&buf, from_addr));
    return NULL;
  }

  olsr_printf(3, "[MDP] Packet from %s OK size %d\n", olsr_ip_to_string(&buf, from_addr), *length);

  /* Fix OLSR packet header */
  olsr->olsr_packlen = htons(*length);
  return packet;
}

/**
 * Check a incoming OLSR packet for
 * challenge/responses.
 * They need not be verified as they
 * are signed in the message.
 *
 */
static int
check_auth(struct interface *olsr_if, char *pck, int *size __attribute__ ((unused)))
{

  olsr_printf(3, "[MDP] Checking packet for challenge response message...\n");

  switch (pck[4]) {
  case (TYPE_CHALLENGE):
    parse_challenge(olsr_if, &pck[4]);
    break;

  case (TYPE_CRESPONSE):
    parse_cres(olsr_if, &pck[4]);
    break;

  case (TYPE_RRESPONSE):
    parse_rres(&pck[4]);
    break;

  default:
    return 0;
  }

  return 1;
}

/**
 * Packet transform function
 * Build a SHA-1/MD5 hash of the original message
 * + the signature message(-digest) + key
 *
 * Then add the signature message to the packet and
 * increase the size
 */
int
add_signature(struct interface *olsr_if, uint8_t * pck, int *size)
{
  struct s_olsrmsg *msg;
  olsr_printf(2, "[MDP] Adding signature for packet size %d\n", *size);
  fflush(stdout);

  msg = (struct s_olsrmsg *)ARM_NOWARN_ALIGN(&pck[*size]);
  /* Update size */
  ((struct olsr *)pck)->olsr_packlen = htons(*size + sizeof(struct s_olsrmsg));

  /* Fill packet header */
  msg->olsr_msgtype = MESSAGE_TYPE;
  msg->olsr_vtime = 0;
  msg->olsr_msgsize = htons(sizeof(struct s_olsrmsg));
  memcpy(&msg->originator, &olsr_if->ip_addr, sizeof(uint32_t));
  msg->ttl = 1;
  msg->hopcnt = 0;
  msg->seqno = htons(get_msg_seqno());

  /* Fill subheader */
  msg->sig.type = ONE_CHECKSUM;
  msg->sig.algorithm = SCHEME;
  memset(&msg->sig.reserved, 0, 2);

  /* Add timestamp */
  msg->sig.timestamp = htonl(now.tv_sec);
#ifndef _WIN32
  olsr_printf(3, "[MDP] timestamp: %lld\n", (long long)now.tv_sec);
#endif /* _WIN32 */
  /* Set the new size */
  *size += sizeof(struct s_olsrmsg);

  {
    uint8_t *checksum_cache = NULL; 
    checksum_cache = (uint8_t*)calloc(1512 + servald_key_len, sizeof(uint8_t));
    /* Create packet + key cache */
    /* First the OLSR packet + signature message - digest */
    memcpy(checksum_cache, pck, *size - SIGNATURE_SIZE);
    /* Then the key */
    memcpy(&checksum_cache[*size - SIGNATURE_SIZE], servald_key, servald_key_len);

    /* Create the hash */
    CHECKSUM(checksum_cache, (*size - SIGNATURE_SIZE) + servald_key_len, &pck[*size - SIGNATURE_SIZE], SIGNATURE_SIZE);
    free(checksum_cache);
  }

  print_data("Signature message", (uint8_t*)msg, sizeof(struct s_olsrmsg));

  olsr_printf(3, "[MDP] Message signed\n");

  if (validate_packet(NULL, (const char*)pck, size))
  {
    olsr_printf(3, "Packet internally validated\n");
  }

  return 1;
}

static int
validate_packet(struct interface *olsr_if, const char *pck, int *size)
{
  int packetsize;
  uint8_t sha1_hash[SIGNATURE_SIZE];
  const struct s_olsrmsg *sig;
  uint32_t rec_time;

  /* Find size - signature message */
  packetsize = *size - sizeof(struct s_olsrmsg);

  if (packetsize < 4)
    return 0;

  sig = (const struct s_olsrmsg *)CONST_ARM_NOWARN_ALIGN(&pck[packetsize]);

  print_data("Input message", (const uint8_t*)sig, sizeof(struct s_olsrmsg));

  /* Sanity check first */
  if ((sig->olsr_msgtype != MESSAGE_TYPE) || (sig->olsr_vtime != 0)
      || (sig->olsr_msgsize != ntohs(sizeof(struct s_olsrmsg))) || (sig->ttl != 1) || (sig->hopcnt != 0)) {
    olsr_printf(1, "[MDP] Packet not sane!\n");
    return 0;
  }

  /* Check scheme and type */
  switch (sig->sig.type) {
  case (ONE_CHECKSUM):
    switch (sig->sig.algorithm) {
    case (SCHEME):
      goto one_checksum_SHA;    /* Ahhh... fix this */
      break;
    default:
    	break;
    }
    break;

  default:
    olsr_printf(3, "[MDP] Unsupported scheme: %d enc: %d!\n", sig->sig.type, sig->sig.algorithm);
    return 0;
  }
  //olsr_printf(1, "Packet sane...\n");

one_checksum_SHA:

  {
    uint8_t *checksum_cache = NULL; 
    checksum_cache = (uint8_t*)calloc(1512 + servald_key_len, sizeof(uint8_t));
    /* Create packet + key cache */
    /* First the OLSR packet + signature message - digest */
    memcpy(checksum_cache, pck, *size - SIGNATURE_SIZE);
    /* Then the key */
    memcpy(&checksum_cache[*size - SIGNATURE_SIZE], servald_key, servald_key_len);

    /* generate SHA-1 */
    CHECKSUM(checksum_cache, (*size - SIGNATURE_SIZE) + servald_key_len, sha1_hash, SIGNATURE_SIZE);
    free(checksum_cache);
  }

  print_data("Received hash", (const uint8_t*)sig->sig.signature, SIGNATURE_SIZE);
  print_data("Calculated hash", sha1_hash, SIGNATURE_SIZE);
  
  if (memcmp(sha1_hash, sig->sig.signature, SIGNATURE_SIZE) != 0) {
    olsr_printf(1, "[MDP] Signature mismatch\n");
    return 0;
  }

  if (!olsr_if)
    return 1;

  /* Check timestamp */
  rec_time = ntohl(sig->sig.timestamp);

  if (!check_timestamp(olsr_if, (const union olsr_ip_addr *)&sig->originator, rec_time)) {
    struct ipaddr_str buf;
    olsr_printf(1, "[MDP] Timestamp mismatch in packet from %s!\n",
                olsr_ip_to_string(&buf, (const union olsr_ip_addr *)&sig->originator));
    return 0;
  }
#ifndef _WIN32
  olsr_printf(3, "[MDP] Received timestamp %lld diff: %lld\n", (long long)rec_time, (long long)now.tv_sec - (long long)rec_time);
#endif /* _WIN32 */
  /* Remove signature message */
  *size = packetsize;
  return 1;
}

int
check_timestamp(struct interface *olsr_if, const union olsr_ip_addr *originator, TIME_TYPE tstamp)
{
  struct stamp *entry;
  int diff;

  entry = lookup_timestamp_entry(originator);

  if (!entry) {
    /* Initiate timestamp negotiation */

    send_challenge(olsr_if, originator);

    return 0;
  }

  if (!entry->validated) {
    olsr_printf(1, "[MDP] Message from non-validated host!\n");
    return 0;
  }

  diff = entry->diff - (now.tv_sec - tstamp);

  olsr_printf(3, "[MDP] Timestamp slack: %d\n", diff);

  if ((diff > UPPER_DIFF) || (diff < LOWER_DIFF)) {
    olsr_printf(1, "[MDP] Timestamp scew detected!!\n");
    return 0;
  }

  /* ok - update diff */
  entry->diff = ((now.tv_sec - tstamp) + entry->diff) ? ((now.tv_sec - tstamp) + entry->diff) / 2 : 0;

  olsr_printf(3, "[MDP] Diff set to : %d\n", entry->diff);

  /* update validtime */

  entry->valtime = GET_TIMESTAMP(TIMESTAMP_HOLD_TIME * 1000);

  return 1;
}

/**
 * Create and send a timestamp
 * challenge message to new_host
 *
 * The host is registered in the timestamps
 * repository with valid=0
 */

int
send_challenge(struct interface *olsr_if, const union olsr_ip_addr *new_host)
{
  struct challengemsg cmsg;
  struct stamp *entry;
  uint32_t challenge, hash;
  struct ipaddr_str buf;

  olsr_printf(3, "[MDP] Building CHALLENGE message\n");

  /* Set the size including OLSR packet size */

  challenge = rand() << 16;
  challenge |= rand();

  /* initialise rrmsg */
  memset(&cmsg, 0, sizeof(cmsg));

  /* Fill challengemessage */
  cmsg.olsr_msgtype = TYPE_CHALLENGE;
  cmsg.olsr_msgsize = htons(sizeof(struct challengemsg));
  memcpy(&cmsg.originator, &olsr_if->ip_addr, sizeof(uint32_t));
  cmsg.ttl = 1;
  cmsg.seqno = htons(get_msg_seqno());

  /* Fill subheader */
  assert(olsr_cnf->ipsize == sizeof(cmsg.destination));
  memcpy(&cmsg.destination, new_host, olsr_cnf->ipsize);
  cmsg.challenge = htonl(challenge);

  olsr_printf(3, "[MDP] Size: %lu\n", (unsigned long)sizeof(struct challengemsg));

  {
    uint8_t *checksum_cache = NULL; 
    checksum_cache = (uint8_t*)calloc((sizeof(cmsg) - sizeof(cmsg.signature)) + servald_key_len, sizeof(uint8_t));
    /* Create packet + key cache */
    /* First the OLSR packet + signature message - digest */
    memcpy(checksum_cache, &cmsg, sizeof(cmsg) - sizeof(cmsg.signature));
    /* Then the key */
    memcpy(&checksum_cache[sizeof(cmsg) - sizeof(cmsg.signature)], servald_key, servald_key_len);

    /* Create the hash */
    CHECKSUM(checksum_cache, (sizeof(cmsg) - sizeof(cmsg.signature)) + servald_key_len, cmsg.signature, SIGNATURE_SIZE);
    free(checksum_cache);
  }
  olsr_printf(3, "[MDP] Sending timestamp request to %s challenge 0x%x\n",
	      olsr_ip_to_string(&buf, new_host), challenge);

  net_output(olsr_if);

  /* Add to buffer */
  net_outbuffer_push(olsr_if, &cmsg, sizeof(struct challengemsg));

  /* Send the request */
  net_output(olsr_if);

  /* Create new entry */
  entry = malloc(sizeof(struct stamp));
  memset(entry, 0, sizeof(struct stamp));

  entry->diff = 0;
  entry->validated = 0;
  entry->challenge = challenge;

  memcpy(&entry->addr, new_host, olsr_cnf->ipsize);

  /* update validtime - not validated */
  entry->conftime = GET_TIMESTAMP(EXCHANGE_HOLD_TIME * 1000);

  hash = olsr_ip_hashing(new_host);

  /* Queue */
  timestamps[hash].next->prev = entry;
  entry->next = timestamps[hash].next;
  timestamps[hash].next = entry;
  entry->prev = &timestamps[hash];

  return 1;

}

int
parse_cres(struct interface *olsr_if, char *in_msg)
{
  struct c_respmsg *msg;
  uint8_t sha1_hash[SIGNATURE_SIZE];
  struct stamp *entry;
  struct ipaddr_str buf;

  msg = (struct c_respmsg *)ARM_NOWARN_ALIGN(in_msg);

  olsr_printf(1, "[MDP] Challenge-response message received\n");
  olsr_printf(3, "[MDP] To: %s\n", olsr_ip_to_string(&buf, (union olsr_ip_addr *)&msg->destination));

  if (if_ifwithaddr((union olsr_ip_addr *)&msg->destination) == NULL) {
    olsr_printf(3, "[MDP] Not for us...\n");
    return 0;
  }

  olsr_printf(3, "[MDP] Challenge: 0x%lx\n", (unsigned long)ntohl(msg->challenge));      /* ntohl() returns a unsignedlong onwin32 */

  /* Check signature */

  {
    uint8_t *checksum_cache = NULL; 
    checksum_cache = (uint8_t*)calloc(1512 + servald_key_len, sizeof(uint8_t));
    /* Create packet + key cache */
    /* First the OLSR packet + signature message - digest */
    memcpy(checksum_cache, msg, sizeof(struct c_respmsg) - SIGNATURE_SIZE);
    /* Then the key */
    memcpy(&checksum_cache[sizeof(struct c_respmsg) - SIGNATURE_SIZE], servald_key, servald_key_len);

    /* Create the hash */
    CHECKSUM(checksum_cache, (sizeof(struct c_respmsg) - SIGNATURE_SIZE) + servald_key_len, sha1_hash, SIGNATURE_SIZE);
    free(checksum_cache);
  }

  if (memcmp(sha1_hash, &msg->signature, SIGNATURE_SIZE) != 0) {
    olsr_printf(1, "[MDP] Signature mismatch in challenge-response!\n");
    return 0;
  }

  olsr_printf(3, "[MDP] Signature verified\n");

  /* Now to check the digest from the emitted challenge */
  if ((entry = lookup_timestamp_entry((const union olsr_ip_addr *)&msg->originator)) == NULL) {
    olsr_printf(1, "[MDP] Received challenge-response from non-registered node %s!\n",
                olsr_ip_to_string(&buf, (union olsr_ip_addr *)&msg->originator));
    return 0;
  }

  /* Generate the digest */
  olsr_printf(3, "[MDP] Entry-challenge 0x%x\n", entry->challenge);

  {
    uint8_t *checksum_cache = NULL; 
    uint32_t netorder_challenge;
    checksum_cache = (uint8_t*)calloc(1512 + servald_key_len, sizeof(uint8_t));

    /* First the challenge received */
    /* But we have to calculate our hash with the challenge in
     * network order just like the remote host did!  6-Jun-2011 AE5AE */
    netorder_challenge = htonl(entry->challenge);
    memcpy(checksum_cache, &netorder_challenge, sizeof(uint32_t));
/*     memcpy(checksum_cache, &entry->challenge, 4); */

    /* Then the local IP */
    memcpy(&checksum_cache[sizeof(uint32_t)], &msg->originator, olsr_cnf->ipsize);

    /* Create the hash */
    CHECKSUM(checksum_cache, sizeof(uint32_t) + olsr_cnf->ipsize, sha1_hash, SIGNATURE_SIZE);
    free(checksum_cache);
  }

  if (memcmp(msg->res_sig, sha1_hash, SIGNATURE_SIZE) != 0) {
    olsr_printf(1, "[MDP] Error in challenge signature from %s!\n",
		olsr_ip_to_string(&buf, (union olsr_ip_addr *)&msg->originator));

    return 0;
  }

  olsr_printf(3, "[MDP] Challenge-response signature ok\n");

  /* Update entry! */

  entry->challenge = 0;
  entry->validated = 1;

  /* Bring timestamp to host order before arith. 2011/05/31 AE5AE */
  entry->diff = now.tv_sec - ntohl(msg->timestamp);

  /* update validtime - validated entry */
  entry->valtime = GET_TIMESTAMP(TIMESTAMP_HOLD_TIME * 1000);

  olsr_printf(1, "[MDP] %s registered with diff %d!\n",
	      olsr_ip_to_string(&buf, (union olsr_ip_addr *)&msg->originator),
              entry->diff);

  /* Send response-response */
  send_rres(olsr_if, (union olsr_ip_addr *)&msg->originator,
	    (union olsr_ip_addr *)&msg->destination, msg->challenge);
/* 	    (union olsr_ip_addr *)&msg->destination, ntohl(msg->challenge)); */
/* Don't give send_rres() the challenge in host order, as the checksum needs to
 * be calculated in network order.   06-Jun-2011  AE5AE */

  return 1;
}

int
parse_rres(char *in_msg)
{
  struct r_respmsg *msg;
  uint8_t sha1_hash[SIGNATURE_SIZE];
  struct stamp *entry;
  struct ipaddr_str buf;

  msg = (struct r_respmsg *)ARM_NOWARN_ALIGN(in_msg);

  olsr_printf(1, "[MDP] Response-response message received\n");
  olsr_printf(3, "[MDP] To: %s\n", olsr_ip_to_string(&buf, (union olsr_ip_addr *)&msg->destination));

  if (if_ifwithaddr((union olsr_ip_addr *)&msg->destination) == NULL) {
    olsr_printf(1, "[MDP] Not for us...\n");
    return 0;
  }

  /* Check signature */

  {
    uint8_t *checksum_cache = NULL; 
    checksum_cache = (uint8_t*)calloc(1512 + servald_key_len, sizeof(uint8_t));
    /* Create packet + key cache */
    /* First the OLSR packet + signature message - digest */
    memcpy(checksum_cache, msg, sizeof(struct r_respmsg) - SIGNATURE_SIZE);
    /* Then the key */
    memcpy(&checksum_cache[sizeof(struct r_respmsg) - SIGNATURE_SIZE], servald_key, servald_key_len);

    /* Create the hash */
    CHECKSUM(checksum_cache, (sizeof(struct r_respmsg) - SIGNATURE_SIZE) + servald_key_len, sha1_hash, SIGNATURE_SIZE);
    free(checksum_cache);
  }

  if (memcmp(sha1_hash, &msg->signature, SIGNATURE_SIZE) != 0) {
    olsr_printf(1, "[MDP] Signature mismatch in response-response!\n");
    return 0;
  }

  olsr_printf(3, "[MDP] Signature verified\n");

  /* Now to check the digest from the emitted challenge */
  if ((entry = lookup_timestamp_entry((const union olsr_ip_addr *)&msg->originator)) == NULL) {
    olsr_printf(1, "[MDP] Received response-response from non-registered node %s!\n",
                olsr_ip_to_string(&buf, (union olsr_ip_addr *)&msg->originator));
    return 0;
  }

  /* Generate the digest */
  olsr_printf(3, "[MDP] Entry-challenge 0x%x\n", entry->challenge);

  {
    uint8_t *checksum_cache = NULL; 
    uint32_t netorder_challenge;
    checksum_cache = (uint8_t*)calloc(1512 + servald_key_len, sizeof(uint8_t));

    /* First the challenge received */
    /* But we have to calculate our hash with the challenge in network order!  6-Jun-2011 AE5AE */
    netorder_challenge = htonl(entry->challenge);
    memcpy(checksum_cache, &netorder_challenge, sizeof(uint32_t));
/*     memcpy(checksum_cache, &entry->challenge, 4); */

    /* Then the local IP */
    memcpy(&checksum_cache[sizeof(uint32_t)], &msg->originator, olsr_cnf->ipsize);

    /* Create the hash */
    CHECKSUM(checksum_cache, sizeof(uint32_t) + olsr_cnf->ipsize, sha1_hash, SIGNATURE_SIZE);
    free(checksum_cache);
  }

  if (memcmp(msg->res_sig, sha1_hash, SIGNATURE_SIZE) != 0) {
    olsr_printf(1, "[MDP] Error in response signature from %s!\n", olsr_ip_to_string(&buf, (union olsr_ip_addr *)&msg->originator));

    return 0;
  }

  olsr_printf(3, "[MDP] Challenge-response signature ok\n");

  /* Update entry! */

  entry->challenge = 0;
  entry->validated = 1;

  /* Bring timestamp to host order before arith. 2011/05/31 AE5AE */
  entry->diff = now.tv_sec - ntohl(msg->timestamp);


  /* update validtime - validated entry */
  entry->valtime = GET_TIMESTAMP(TIMESTAMP_HOLD_TIME * 1000);

  olsr_printf(1, "[MDP] %s registered with diff %d!\n", olsr_ip_to_string(&buf, (union olsr_ip_addr *)&msg->originator),
              entry->diff);

  return 1;
}

int
parse_challenge(struct interface *olsr_if, char *in_msg)
{
  struct challengemsg *msg;
  uint8_t sha1_hash[SIGNATURE_SIZE];
  struct stamp *entry;
  uint32_t hash;
  struct ipaddr_str buf;

  msg = (struct challengemsg *)ARM_NOWARN_ALIGN(in_msg);

  olsr_printf(1, "[MDP] Challenge message received\n");
  olsr_printf(3, "[MDP] To: %s\n", olsr_ip_to_string(&buf, (union olsr_ip_addr *)&msg->destination));

  if (if_ifwithaddr((union olsr_ip_addr *)&msg->destination) == NULL) {
    olsr_printf(1, "[MDP] Not for us...\n");
    return 0;
  }

  /* Create entry if not registered */
  if ((entry = lookup_timestamp_entry((const union olsr_ip_addr *)&msg->originator)) == NULL) {
    entry = malloc(sizeof(struct stamp));
    memset(entry, 0, sizeof(struct stamp));
    memcpy(&entry->addr, &msg->originator, olsr_cnf->ipsize);

    hash = olsr_ip_hashing((union olsr_ip_addr *)&msg->originator);

    /* Queue */
    timestamps[hash].next->prev = entry;
    entry->next = timestamps[hash].next;
    timestamps[hash].next = entry;
    entry->prev = &timestamps[hash];
  } else {
    /* Check configuration timeout */
    if (!TIMED_OUT(entry->conftime)) {
      /* If registered - do not accept! */
      olsr_printf(1, "[MDP] Challenge from registered node...dropping!\n");
      return 0;
    } else {
      olsr_printf(1, "[MDP] Challenge from registered node...accepted!\n");
    }
  }

  olsr_printf(3, "[MDP] Challenge: 0x%lx\n", (unsigned long)ntohl(msg->challenge));      /* ntohl() returns a unsignedlong onwin32 */

  /* Check signature */

  {
    uint8_t *checksum_cache = NULL; 
    checksum_cache = (uint8_t*)calloc(1512 + servald_key_len, sizeof(uint8_t));
    /* Create packet + key cache */
    /* First the OLSR packet + signature message - digest */
    memcpy(checksum_cache, msg, sizeof(struct challengemsg) - SIGNATURE_SIZE);
    /* Then the key */
    memcpy(&checksum_cache[sizeof(struct challengemsg) - SIGNATURE_SIZE], servald_key, servald_key_len);

    /* Create the hash */
    CHECKSUM(checksum_cache, (sizeof(struct challengemsg) - SIGNATURE_SIZE) + servald_key_len, sha1_hash, SIGNATURE_SIZE);
    free(checksum_cache);
  }
  if (memcmp(sha1_hash, &msg->signature, SIGNATURE_SIZE) != 0) {
    olsr_printf(1, "[MDP] Signature mismatch in challenge!\n");
    return 0;
  }

  olsr_printf(3, "[MDP] Signature verified\n");

  entry->diff = 0;
  entry->validated = 0;

  /* update validtime - not validated */
  entry->conftime = GET_TIMESTAMP(EXCHANGE_HOLD_TIME * 1000);

  /* Build and send response */

  send_cres(olsr_if, (union olsr_ip_addr *)&msg->originator,
	    (union olsr_ip_addr *)&msg->destination, msg->challenge, entry);
/* 	    (union olsr_ip_addr *)&msg->destination, ntohl(msg->challenge), entry); */
/* Don't give send_cres() the challenge in host order, as the checksum needs to
 * be calculated with network order.   06-Jun-2011  AE5AE */

  return 1;
}

/**
 * Build and transmit a challenge response
 * message.
 *
 */
int
send_cres(struct interface *olsr_if, union olsr_ip_addr *to, union olsr_ip_addr *from, uint32_t chal_in, struct stamp *entry)
{
  struct c_respmsg crmsg;
  uint32_t challenge;
  struct ipaddr_str buf;

  olsr_printf(3, "[MDP] Building CRESPONSE message\n");

  challenge = rand() << 16;
  challenge |= rand();

  entry->challenge = challenge;

  olsr_printf(3, "[MDP] Challenge-response: 0x%x\n", challenge);

  /* initialise rrmsg */
  memset(&crmsg, 0, sizeof(crmsg));

  /* Fill challengemessage */
  crmsg.olsr_msgtype = TYPE_CRESPONSE;
  crmsg.olsr_msgsize = htons(sizeof(struct c_respmsg));
  memcpy(&crmsg.originator, from, sizeof(uint32_t));
  crmsg.ttl = 1;
  crmsg.seqno = htons(get_msg_seqno());

  /* set timestamp */
  /* but swap the byte order to the network order before sending!  2011/05/28 AE5AE */
  crmsg.timestamp = htonl(now.tv_sec);
#ifndef _WIN32
  /* Don't print htonl()'d time, use now.tv_sec 2011/05/31 AE5AE */
/*   olsr_printf(3, "[MDP] Timestamp %lld\n", (long long)crmsg.timestamp); */
  olsr_printf(3, "[MDP] Timestamp %lld\n", (long long)now.tv_sec);
#endif /* _WIN32 */

  /* Fill subheader */
  assert(olsr_cnf->ipsize == sizeof(crmsg.destination));
  memcpy(&crmsg.destination, to, olsr_cnf->ipsize);
  crmsg.challenge = htonl(challenge);

  /* Create digest of received challenge + IP */

  {
    uint8_t checksum_cache[sizeof(chal_in) + olsr_cnf->ipsize];
    /* Create packet + key cache */
    /* First the challenge received */
    memcpy(checksum_cache, &chal_in, sizeof(chal_in));
    /* Then the local IP */
    memcpy(&checksum_cache[sizeof(chal_in)], from, olsr_cnf->ipsize);

    /* Create the hash */
    CHECKSUM(checksum_cache, sizeof(chal_in) + olsr_cnf->ipsize, crmsg.res_sig, SIGNATURE_SIZE);
  }

  /* Now create the digest of the message and the key */

  {
    uint8_t *checksum_cache = NULL; 
    checksum_cache = (uint8_t*)calloc((sizeof(crmsg) - sizeof(crmsg.signature)) + servald_key_len, sizeof(uint8_t));
    /* Create packet + key cache */
    /* First the OLSR packet + signature message - digest */
    memcpy(checksum_cache, &crmsg, sizeof(crmsg) - sizeof(crmsg.signature));
    /* Then the key */
    memcpy(&checksum_cache[sizeof(crmsg) - sizeof(crmsg.signature)], servald_key, servald_key_len);

    /* Create the hash */
    CHECKSUM(checksum_cache, (sizeof(crmsg) - sizeof(crmsg.signature)) + servald_key_len, crmsg.signature, SIGNATURE_SIZE);
    free(checksum_cache);
  }

  olsr_printf(3, "[MDP] Sending challenge response to %s challenge 0x%x\n", olsr_ip_to_string(&buf, to), challenge);

  net_output(olsr_if);

  /* Add to buffer */
  net_outbuffer_push(olsr_if, &crmsg, sizeof(struct c_respmsg));
  /* Send the request */
  net_output(olsr_if);

  return 1;
}

/**
 * Build and transmit a response response
 * message.
 *
 */
static int
send_rres(struct interface *olsr_if, union olsr_ip_addr *to, union olsr_ip_addr *from, uint32_t chal_in)
{
  struct r_respmsg rrmsg;
  struct ipaddr_str buf;

  olsr_printf(3, "[MDP] Building RRESPONSE message\n");

  /* initialise rrmsg */
  memset(&rrmsg, 0, sizeof(rrmsg));

  /* Fill challengemessage */
  rrmsg.olsr_msgtype = TYPE_RRESPONSE;
  rrmsg.olsr_msgsize = htons(sizeof(struct r_respmsg));
  memcpy(&rrmsg.originator, from, sizeof(uint32_t));
  rrmsg.ttl = 1;
  rrmsg.seqno = htons(get_msg_seqno());

  /* set timestamp */
  /* But swap the byte order to the network order!  2011/05/28 AE5AE */
  rrmsg.timestamp = htonl(now.tv_sec);

#ifndef _WIN32
  /* olsr_printf(3, "[MDP] Timestamp %lld\n", (long long)rrmsg.timestamp); */
  /* don't print htonl()'d time, use now. 2011/05/31 AE5AE */
  olsr_printf(3, "[MDP] Timestamp %lld\n", (long long)now.tv_sec);
#endif /* _WIN32 */
  /* Fill subheader */
  assert(olsr_cnf->ipsize == sizeof(rrmsg.destination));
  memcpy(&rrmsg.destination, to, olsr_cnf->ipsize);

  /* Create digest of received challenge + IP */

  {
    uint8_t checksum_cache[sizeof(chal_in) + sizeof(union olsr_ip_addr)];
    /* Create packet + key cache */
    /* First the challenge received */
    memcpy(checksum_cache, &chal_in, sizeof(chal_in));
    /* Then the local IP */
    memcpy(&checksum_cache[sizeof(chal_in)], from, olsr_cnf->ipsize);

    /* Create the hash */
    CHECKSUM(checksum_cache, sizeof(chal_in) + olsr_cnf->ipsize, rrmsg.res_sig, SIGNATURE_SIZE);
  }

  /* Now create the digest of the message and the key */

  {
    uint8_t *checksum_cache = NULL; 
    checksum_cache = (uint8_t*)calloc((sizeof(rrmsg) - sizeof(rrmsg.signature)) + servald_key_len, sizeof(uint8_t));
    /* Create packet + key cache */
    /* First the OLSR packet + signature message - digest */
    memcpy(checksum_cache, &rrmsg, sizeof(rrmsg) - sizeof(rrmsg.signature));
    /* Then the key */
    memcpy(&checksum_cache[sizeof(rrmsg) - sizeof(rrmsg.signature)], servald_key, servald_key_len);

    /* Create the hash */
    CHECKSUM(checksum_cache, (sizeof(rrmsg) - sizeof(rrmsg.signature)) + servald_key_len, rrmsg.signature, SIGNATURE_SIZE);
    free(checksum_cache);
  }

  olsr_printf(3, "[MDP] Sending response response to %s\n", olsr_ip_to_string(&buf, to));

  net_output(olsr_if);

  /* add to buffer */
  net_outbuffer_push(olsr_if, &rrmsg, sizeof(struct r_respmsg));

  /* Send the request */
  net_output(olsr_if);

  return 1;
}

static struct stamp *
lookup_timestamp_entry(const union olsr_ip_addr *adr)
{
  uint32_t hash;
  struct stamp *entry;
  struct ipaddr_str buf;

  hash = olsr_ip_hashing(adr);

  for (entry = timestamps[hash].next; entry != &timestamps[hash]; entry = entry->next) {
    if (memcmp(&entry->addr, adr, olsr_cnf->ipsize) == 0) {
      olsr_printf(3, "[MDP] Match for %s\n", olsr_ip_to_string(&buf, adr));
      return entry;
    }
  }

  olsr_printf(1, "[MDP] No match for %s\n", olsr_ip_to_string(&buf, adr));

  return NULL;
}

/**
 *Find timed out entries and delete them
 *
 *@return nada
 */
void
timeout_timestamps(void *foo __attribute__ ((unused)))
{
  struct stamp *tmp_list;
  struct stamp *entry_to_delete;
  int idx;

  /* Update our local timestamp */
  gettimeofday(&now, NULL);

  for (idx = 0; idx < HASHSIZE; idx++) {
    tmp_list = timestamps[idx].next;
    /*Traverse MID list */
    while (tmp_list != &timestamps[idx]) {
      /*Check if the entry is timed out */
      if ((TIMED_OUT(tmp_list->valtime)) && (TIMED_OUT(tmp_list->conftime))) {
        struct ipaddr_str buf;
        entry_to_delete = tmp_list;
        tmp_list = tmp_list->next;

        olsr_printf(1, "[MDP] timestamp info for %s timed out.. deleting it\n",
		    olsr_ip_to_string(&buf, &entry_to_delete->addr));

        /*Delete it */
        entry_to_delete->next->prev = entry_to_delete->prev;
        entry_to_delete->prev->next = entry_to_delete->next;

        free(entry_to_delete);
      } else
        tmp_list = tmp_list->next;
    }
  }

  return;
}

static int 
read_key_from_servald(co_obj_t *co_conn, const char *keyring_path, const char *sid)
{
  char *output = NULL;
  
  assert(co_conn);
  CHECKF_MEM((co_req = co_request_create()));
  CO_APPEND_STR(co_req,keyring_path);
  CO_APPEND_STR(co_req,sid);
  CHECKF(co_call(co_conn,&co_resp,"mdp-init",sizeof("mdp-init"),co_req) && 
  (servald_key_len = co_response_get_bin(co_resp,&output,"key",sizeof("key"))),"Failed to receive signing key from commotiond");
  servald_key = (unsigned char *)calloc(servald_key_len, sizeof(unsigned char));
  memcpy(servald_key, output, servald_key_len);
  co_free(co_req);
  co_free(co_resp);
  
  olsr_printf(3, "[MDP] servald_key_len: %d\n", servald_key_len);
  print_data("servald_key", servald_key, servald_key_len);

  return 0;
}

/*
 * Local Variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
