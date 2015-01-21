/*
 * The olsr.org Optimized Link-State Routing daemon(olsrd)
 * Copyright (c) 2004-2009, the olsr.org team - see HISTORY file
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 * * Neither the name of olsr.org, olsrd nor the names of its
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
 * Visit http://www.olsr.org for more information.
 *
 * If you find this software useful feel free to make a donation
 * to the project. For more information see the website or contact
 * the copyright holders.
 *
 */


#ifndef _DNSSD_H
#define _DNSSD_H

#define REMOVE_LOG_DEBUG

#include "olsrd_plugin.h"             /* union set_plugin_parameter_addon */
#include "duplicate_set.h"
//#include "socket_parser.h"
#include "dllist.h"
#include "uthash.h"
#include "ipcalc.h"
#include "lq_packet.h"
#include <ldns/ldns.h>

#define P2PD_MESSAGE_TYPE         132
#define PARSER_TYPE               P2PD_MESSAGE_TYPE
#define P2PD_VALID_TIME           180		/* seconds */

/* DNSSD plugin data */
#define PLUGIN_NAME               "OLSRD DNSSD plugin"
#define PLUGIN_NAME_SHORT         "OLSRD DNSSD"
#define PLUGIN_VERSION            "0.1.0 (" __DATE__ " " __TIME__ ")"
#define MOD_DESC PLUGIN_NAME      " " PLUGIN_VERSION
#define PLUGIN_INTERFACE_VERSION  5
#define IPHDR_FRAGMENT_MASK       0xC000

#define FINGERPRINT_LEN           64
#define UUID_LEN                  52      /* Length of UUID (which is base32 encoding of Serval ID) */
#define MAX_FILE_LEN              72
#define MAX_DIR_LEN               200
#define MAX_FIELD_LEN             100
#define MAX_DOMAIN_LEN            100
#define BUFFER_LENGTH             1024
#define IPV6_HEADER_LENGTH        40
#define UDP_HEADER_LENGTH         8
#define HOSTNAME_LEN              64
#define SERVICE_UPDATE_INTERVAL   300
#define EMISSION_JITTER           25      /* percent */

/* Forward declaration of OLSR interface type */
struct interface;

struct DupFilterEntry {
  int                            ip_version;
  union olsr_ip_addr             address;
  uint16_t                       seqno;
  uint8_t                        msgtype;
  time_t                         creationtime;
};

struct UdpDestPort {
  int                            ip_version;
  union olsr_ip_addr             address;
  uint16_t                       port;
  struct UdpDestPort *           next;
};

struct RrListByTtl {
  int                            ttl;
  ldns_rr_list *                 rr_list[3];
  uint16_t                       rr_count[3];
  UT_hash_handle                 hh;
};

struct MdnsService {
  char                           id[UUID_LEN + 16 + 1];    /* sizeof("._commotion._tcp") == 16 */
  int                            ttl;
  int                            uptodate;
  UT_hash_handle                 hh;
};

struct pseudo_header {
  struct in_addr source_address;
  struct in_addr dest_address;
  u_int8_t placeholder;
  u_int8_t protocol;
  u_int16_t udp_length;
};

struct pseudo_header6 {
  struct in6_addr ip6_src;
  struct in6_addr ip6_dst;
  u_int32_t udp_length;
  u_int16_t zeros1;
  u_int8_t zeros2;
  u_int8_t protocol;
};

typedef enum { IPv4, IPv6 } PKT_TYPE;
extern int ServiceUpdateInterval;

extern int P2pdTtl;
extern int P2pdDuplicateTimeout;
extern int HighestSkfd;
extern fd_set InputSet;
extern struct UdpDestPort * UdpDestPortList;
extern struct DuplicateFilterEntry * FilterList;

void DoP2pd(int sd, void *x, unsigned int y);
void P2pdPError(const char *format, ...) __attribute__ ((format(printf, 1, 2)));
int InitP2pd(struct interface *skipThisIntf);
void CloseP2pd(void);
int AddUdpDestPort(const char *value, void *data __attribute__ ((unused)), set_plugin_parameter_addon addon __attribute__ ((unused)));
bool InUdpDestPortList(int ip_version, union olsr_ip_addr *addr, uint16_t port);
int SetP2pdTtl(const char *value, void *data __attribute__ ((unused)), set_plugin_parameter_addon addon __attribute__ ((unused)));
int SetP2pdUseHashFilter(const char *value, void *data __attribute__ ((unused)), set_plugin_parameter_addon addon __attribute__ ((unused)));
bool p2pd_message_seen(struct node **head, struct node **tail, union olsr_message *m);
void p2pd_store_message(struct node **head, struct node **tail, union olsr_message *m);
bool p2pd_is_duplicate_message(union olsr_message *msg);

void olsr_p2pd_gen(unsigned char *packet, int len, int ttl);

/* Parser function to register with the scheduler */
bool olsr_parser(union olsr_message *, struct interface *, union olsr_ip_addr *);

int SetupServiceList(const char *value, void *data __attribute__ ((unused)), set_plugin_parameter_addon addon __attribute__ ((unused)));
int SetDomain(const char *value, void *data __attribute__ ((unused)), set_plugin_parameter_addon addon __attribute__ ((unused)));
void UpdateServices(void *context);

void AddToRrBuffer(struct RrListByTtl **buf, int ttl, ldns_rr *entry, int section);
struct RrListByTtl *GetRrListByTtl(const struct RrListByTtl **buf, int ttl);
void AddToServiceList(char *name, int ttl);
struct MdnsService *GetServiceById(char *id);
void DeleteListByTtl(struct RrListByTtl **buf, int ttl);
void DeleteList(struct RrListByTtl **buf, struct RrListByTtl *list);
void DeleteListArray(struct RrListByTtl **buf);
void DeleteAllServices(void);
void DeleteService(struct MdnsService *service);
void RemoveStaleServices(void);
void DnssdSendPacket(ldns_pkt *pkt, PKT_TYPE pkt_type, unsigned char *encapsulationUdpData, int nBytes, int ttl);
int IsRrLocal(ldns_rr *rr, int *ttl);
size_t UnescapeStr(char *str, size_t nBytes);
char *ReplaceHostname(char *str, size_t nBytes, char *hostname, size_t hostname_len);
unsigned short CheckSum(unsigned short *ptr,int nbytes);
void removeChar(char *str, size_t *str_len, char garbage);

#endif /* _DNSSD_H */

/*
 * Local Variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
