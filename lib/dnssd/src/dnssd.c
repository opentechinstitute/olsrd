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

#define _GNU_SOURCE

#include "dnssd.h"

/* System includes */
#include <stddef.h>             /* NULL */
#include <sys/types.h>          /* ssize_t */
#include <string.h>             /* strerror() */
#include <stdarg.h>             /* va_list, va_start, va_end */
#include <errno.h>              /* errno */
#include <assert.h>             /* assert() */
#include <unistd.h>
#include <fcntl.h>
#include <linux/if_ether.h>     /* ETH_P_IP */
#include <linux/if_packet.h>    /* struct sockaddr_ll, PACKET_MULTICAST */
//#include <pthread.h> /* pthread_t, pthread_create() */
#include <signal.h>             /* sigset_t, sigfillset(), sigdelset(), SIGINT */
#include <netinet/ip.h>         /* struct ip */
#include <netinet/udp.h>        /* struct udphdr */
#include <unistd.h>             /* close() */

#include <netinet/in.h>
#include <netinet/ip6.h>

#include <time.h>

#include <dirent.h>
#include <regex.h>

#include <stdio.h>

/* OLSRD includes */
#include "plugin_util.h"        /* set_plugin_int */
#include "defs.h"               /* olsr_cnf, //OLSR_PRINTF */
#include "ipcalc.h"
#include "olsr.h"               /* //OLSR_PRINTF */
#include "mid_set.h"            /* mid_lookup_main_addr() */
#include "link_set.h"           /* get_best_link_to_neighbor() */
#include "net_olsr.h"           /* ipequal */
#include "parser.h"

/* plugin includes */
#include "NetworkInterfaces.h"  /* NonOlsrInterface,
                                   CreateBmfNetworkInterfaces(),
                                   CloseBmfNetworkInterfaces() */
//#include "Address.h"          /* IsMulticast() */
#include "Packet.h"             /* ENCAP_HDR_LEN,
                                   BMF_ENCAP_TYPE,
                                   BMF_ENCAP_LEN etc. */
#include "PacketHistory.h"
#include "dllist.h"

struct timer_entry *service_update_timer = NULL;
struct timer_entry *service_query_timer = NULL;
struct MdnsService *ServiceList    = NULL;
char ServiceDomain[MAX_DOMAIN_LEN];
size_t ServiceDomainLength;
char *ServiceFileDir;
int ServiceUpdateInterval          = 300;

int P2pdTtl                        = 0;
int P2pdUseHash                    = 0;  /* Switch off hash filter by default */
int P2pdDuplicateTimeout           = P2PD_VALID_TIME;

/* List of UDP destination address and port information */
struct UdpDestPort *                 UdpDestPortList = NULL;

/* List of filter entries to check for duplicate messages
 */
struct node *                        dupFilterHead = NULL;
struct node *                        dupFilterTail = NULL;

bool is_broadcast(const struct sockaddr_in addr);
bool is_multicast(const struct sockaddr_in addr);
char * get_ipv4_str(uint32_t address, char *s, size_t maxlen);
char * get_ipv6_str(unsigned char* address, char *s, size_t maxlen);
#ifdef INCLUDE_DEBUG_OUTPUT
void dump_packet(unsigned char* packet, int length);
#endif
bool check_and_mark_recent_packet(unsigned char *data, int len);

/* -------------------------------------------------------------------------
 * Function   : PacketReceivedFromOLSR
 * Description: Handle a received packet from a OLSR message
 * Input      : ipPacket into an unsigned char and the lenght of the packet
 * Output     : none
 * Return     : none
 * Data Used  : BmfInterfaces
 * ------------------------------------------------------------------------- */
static void
PacketReceivedFromOLSR(unsigned char *encapsulationUdpData, int len)
{
  struct ip *ipHeader = NULL;       /* IP header inside the encapsulated 
                                     * IP packet */
  struct ip6_hdr *ip6Header = NULL; /* IP header inside the encapsulated 
                                     * IP6 packet */
  struct udphdr *udpHeader = NULL;
  struct NonOlsrInterface *walker = NULL;
  struct sockaddr_in addr;
  int stripped_len = 0;
  union olsr_ip_addr destAddr;
  int destPort;
  bool isInList = false;

  ipHeader = (struct ip *) ARM_NOWARN_ALIGN(encapsulationUdpData);
  ip6Header = (struct ip6_hdr *) ARM_NOWARN_ALIGN(encapsulationUdpData);
  //OLSR_DEBUG(LOG_PLUGINS, "P2PD PLUGIN got packet from OLSR message\n");

  if (check_and_mark_recent_packet(encapsulationUdpData, len))
    return;
  
  if ((encapsulationUdpData[0] & 0xf0) == 0x40)
    stripped_len = ntohs(ipHeader->ip_len);
  
  if ((encapsulationUdpData[0] & 0xf0) == 0x60) {
    stripped_len = 40 + ntohs(ip6Header->ip6_plen); // IPv6 Header size (40)
    // + payload_len
  }
  
  // Sven-Ola: Don't know how to handle the "stripped_len is uninitialized"
  // condition, maybe exit(1) is better...?
  if (0 == stripped_len)
    return;
  
  //TODO: if packet is not IP die here
  
  if (stripped_len > len) {
  }
  
  if (olsr_cnf->ip_version == AF_INET) {
    // Determine the IP address and the port from the header information
    if (ipHeader->ip_p == SOL_UDP && !IsIpv4Fragment(ipHeader)) {
      udpHeader = (struct udphdr*) ARM_NOWARN_ALIGN((encapsulationUdpData +
                                   GetIpHeaderLength(encapsulationUdpData)));
      destAddr.v4.s_addr = ipHeader->ip_dst.s_addr;
      destPort = htons(udpHeader->dest);
      isInList = InUdpDestPortList(AF_INET, &destAddr, destPort);
#ifdef INCLUDE_DEBUG_OUTPUT
      if (!isInList) {
	char tmp[32];
	OLSR_PRINTF(1,
		    "%s: Not in dest/port list: %s:%d\n",
	            PLUGIN_NAME_SHORT,
	            get_ipv4_str(destAddr.v4.s_addr,
		    tmp,
		    sizeof(tmp)),
		    destPort);
      }
#endif
    }
  } else /* (olsr_cnf->ip_version == AF_INET6) */ {
    if (ip6Header->ip6_nxt == SOL_UDP && !IsIpv6Fragment(ip6Header)) {
      udpHeader = (struct udphdr*) ARM_NOWARN_ALIGN((encapsulationUdpData + 40));
      memcpy(&destAddr.v6, &ip6Header->ip6_dst, sizeof(struct in6_addr));
      destPort = htons(udpHeader->dest);
      isInList = InUdpDestPortList(AF_INET6, &destAddr, destPort);
#ifdef INCLUDE_DEBUG_OUTPUT
      if (!isInList) {
	char tmp[64];
	OLSR_PRINTF(1,
		    "%s: Not in dest/port list: %s:%d\n",
	            PLUGIN_NAME_SHORT,
	            get_ipv6_str(destAddr.v6.s6_addr,
	            tmp,
		    sizeof(tmp)),
		    destPort);
      }
#endif
    }
  }
  
  if (!isInList) {
    /* Address/port combination of this packet is not in the UDP dest/port
     * list and will therefore be suppressed. I.e. just continue with the
     * next interface to emit on.
     */
    return;
  }
  
  memset(&addr, 0, sizeof(struct sockaddr_in));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = destAddr.v4.s_addr;
  
  /* Check with each network interface what needs to be done on it */
  for (walker = nonOlsrInterfaces; walker != NULL; walker = walker->next) {
    /* To a non-OLSR interface: unpack encapsulated IP packet and forward it */
    if (walker->olsrIntf == NULL) {
      int nBytesWritten;
      
      nBytesWritten = sendto(walker->encapsulatingSkfd,
			     encapsulationUdpData,
			     stripped_len,
			     0,
			     (struct sockaddr *) &addr,
			     sizeof(struct sockaddr));
      
      if (nBytesWritten != stripped_len) {
        P2pdPError("sendto() error forwarding unpacked encapsulated pkt on \"%s\"",
                   walker->ifName);
      } else {
#ifdef INCLUDE_DEBUG_OUTPUT
        OLSR_PRINTF(
         2,
         "%s: --> unpacked and forwarded on \"%s\"\n",
         PLUGIN_NAME_SHORT,
         walker->ifName);
#endif
      }
    }                           /* if (walker->olsrIntf == NULL) */
  }
}                               /* PacketReceivedFromOLSR */

/* Highest-numbered open socket file descriptor. To be used as first
 * parameter in calls to select(...).
 */
int HighestSkfd = -1;

/* Set of socket file descriptors */
fd_set InputSet;

/* -------------------------------------------------------------------------
 * Function   : p2pd_message_seen
 * Description: Check whether the current message has been seen before
 * Input      : head - start of the list to check for the message
 *              tail - end of the list to check for the message
 *              m    - message to check for in the list
 * Output     : none
 * Return     : true if message was found, false otherwise
 * Data Used  : P2pdDuplicateTimeout
 * ------------------------------------------------------------------------- */
bool
p2pd_message_seen(struct node **head, struct node **tail, union olsr_message *m)
{
  struct node *curr = NULL;
  time_t now;

  now = time(NULL);

  // Check whether any entries have aged
  curr = *head;
  while (curr) {
    struct DupFilterEntry *filter = NULL;
    struct node * next = curr->next; // Save the current pointer since curr may
                                     // be destroyed

    filter = (struct DupFilterEntry*)curr->data;

    if ((filter->creationtime + P2pdDuplicateTimeout) < now)
      remove_node(head, tail, curr, true);

    // Skip to the next element
    curr = next;
  }

  // Now check whether there are any duplicates
  for (curr = *head; curr; curr = curr->next) {
    struct DupFilterEntry *filter = (struct DupFilterEntry*)curr->data;

    if (olsr_cnf->ip_version == AF_INET) {
      if (filter->address.v4.s_addr == m->v4.originator &&
          filter->msgtype == m->v4.olsr_msgtype &&
          filter->seqno == m->v4.seqno) {
          return true;
      }
    } else /* if (olsr_cnf->ip_version == AF_INET6) */ {
      if (memcmp(filter->address.v6.s6_addr,
                 m->v6.originator.s6_addr,
                 sizeof(m->v6.originator.s6_addr)) == 0 &&
          filter->msgtype == m->v6.olsr_msgtype &&
          filter->seqno == m->v6.seqno) {
          return true;
      }
    }
  }

  return false;
}

/* -------------------------------------------------------------------------
 * Function   : p2pd_store_message
 * Description: Store a new message in the duplicate message check list
 * Input      : head - start of the list to add the message to
 *              tail - end of the list to add the message to
 *              m    - message to add to the list
 * Output     : none
 * Return     : nothing
 * Data Used  : none
 * ------------------------------------------------------------------------- */
void
p2pd_store_message(struct node **head, struct node **tail, union olsr_message *m)
{
  time_t now;

  // Store a message into the database
  struct DupFilterEntry *new_dup = calloc(1, sizeof(struct DupFilterEntry));
  if (new_dup == NULL) {
    OLSR_PRINTF(1, "%s: Out of memory\n", PLUGIN_NAME_SHORT);
    return;
  }

  now = time(NULL);

  new_dup->creationtime = now;
  if (olsr_cnf->ip_version == AF_INET) {
    new_dup->address.v4.s_addr = m->v4.originator;
    new_dup->msgtype           = m->v4.olsr_msgtype;
    new_dup->seqno             = m->v4.seqno;
  } else /* if (olsr_cnf->ip_version == AF_INET6) */ {
    memcpy(new_dup->address.v6.s6_addr,
           m->v6.originator.s6_addr,
           sizeof(m->v6.originator.s6_addr));
    new_dup->msgtype           = m->v6.olsr_msgtype;
    new_dup->seqno             = m->v6.seqno;
  }

  // Add the element to the head of the list
  append_node(head, tail, new_dup);
}

/* -------------------------------------------------------------------------
 * Function   : p2pd_is_duplicate_message
 * Description: Check whether the specified message is a duplicate
 * Input      : msg - message to check for in the list of duplicate messages
 * Output     : none
 * Return     : true if message was found, false otherwise
 * Data Used  : none
 * ------------------------------------------------------------------------- */
bool
p2pd_is_duplicate_message(union olsr_message *msg)
{
  if(p2pd_message_seen(&dupFilterHead, &dupFilterTail, msg)) {
    return true;
  }

  p2pd_store_message(&dupFilterHead, &dupFilterTail, msg);

  return false;
}

/* -------------------------------------------------------------------------
 * Function   : olsr_parser
 * Description: Function to be passed to the parser engine. This function
 *              processes the incoming message and passes it on if necessary.
 * Input      : m      - message to parse
 *              in_if  - interface to use (unused in this application)
 *              ipaddr - IP-address to use (unused in this application)
 * Output     : none
 * Return     : false if message should be supressed, true otherwise
 * Data Used  : none
 * ------------------------------------------------------------------------- */
bool
olsr_parser(union olsr_message *m,
            struct interface *in_if __attribute__ ((unused)),
            union olsr_ip_addr *ipaddr __attribute__ ((unused)))
{
  union olsr_ip_addr originator;
  int size;

  //OLSR_DEBUG(LOG_PLUGINS, "P2PD PLUGIN: Received msg in parser\n");

	/* Fetch the originator of the messsage */
  if (olsr_cnf->ip_version == AF_INET) {
    memcpy(&originator, &m->v4.originator, olsr_cnf->ipsize);
    size = ntohs(m->v4.olsr_msgsize);
  } else {
    memcpy(&originator, &m->v6.originator, olsr_cnf->ipsize);
    size = ntohs(m->v6.olsr_msgsize);
  }

  /* Check if message originated from this node.
   *         If so - back off */
  if (ipequal(&originator, &olsr_cnf->main_addr))
    return false;          /* Don't forward either */

  /* Check for duplicate messages for processing */
  if (p2pd_is_duplicate_message(m))
    return true;  /* Don't process but allow to be forwarded */

  if (olsr_cnf->ip_version == AF_INET) {
    PacketReceivedFromOLSR((unsigned char *)&m->v4.message, size - 12);
  } else {
    PacketReceivedFromOLSR((unsigned char *)&m->v6.message, size - 12 - 96);
  }

	return true;
}

/* -------------------------------------------------------------------------
 * Function   : olsr_p2pd_gen
 * Description: Sends a packet in the OLSR network
 * Input      : packet - packet to send in the OLSR network
 *              len    - length of the packet to send
 * Output     : none
 * Return     : nothing
 * Data Used  : none
 * ------------------------------------------------------------------------- */
void
olsr_p2pd_gen(unsigned char *packet, int len, int ttl)
{
  /* send buffer: huge */
  char buffer[10240] = {'\0',};
  int aligned_size, pkt_ttl;
  union olsr_message *message = (union olsr_message *)buffer;
  struct interface *ifn = NULL;

  aligned_size=len;

  if ((aligned_size % 4) != 0) {
    aligned_size = (aligned_size - (aligned_size % 4)) + 4;
  }

  if (ttl)
    pkt_ttl = ttl;
  else if (P2pdTtl)
    pkt_ttl = P2pdTtl;
  else
    pkt_ttl = MAX_TTL;
  
  /* fill message */
  if (olsr_cnf->ip_version == AF_INET) {
    /* IPv4 */
    message->v4.olsr_msgtype  = P2PD_MESSAGE_TYPE;
    message->v4.olsr_vtime    = reltime_to_me(P2PD_VALID_TIME * MSEC_PER_SEC);
    memcpy(&message->v4.originator, &olsr_cnf->main_addr, olsr_cnf->ipsize);
    message->v4.ttl           = pkt_ttl;
    message->v4.hopcnt        = 0;
    message->v4.seqno         = htons(get_msg_seqno());
    message->v4.olsr_msgsize  = htons(aligned_size + 12);
    memset(&message->v4.message, 0, aligned_size);
    memcpy(&message->v4.message, packet, len);
    aligned_size = aligned_size + 12;
  } else /* if (olsr_cnf->ip_version == AF_INET6) */ {
    /* IPv6 */
    message->v6.olsr_msgtype  = P2PD_MESSAGE_TYPE;
    message->v6.olsr_vtime    = reltime_to_me(P2PD_VALID_TIME * MSEC_PER_SEC);
    memcpy(&message->v6.originator, &olsr_cnf->main_addr, olsr_cnf->ipsize);
    message->v6.ttl           = pkt_ttl;
    message->v6.hopcnt        = 0;
    message->v6.seqno         = htons(get_msg_seqno());
    message->v6.olsr_msgsize  = htons(aligned_size + 12 + 96);
    memset(&message->v6.message, 0, aligned_size);
    memcpy(&message->v6.message, packet, len);
    aligned_size = aligned_size + 12 + 96;
  }

  /* looping through interfaces */
  for (ifn = ifnet; ifn; ifn = ifn->int_next) {
    //OLSR_PRINTF(1, "%s: Generating packet - [%s]\n", PLUGIN_NAME_SHORT, ifn->int_name);

    if (net_outbuffer_push(ifn, message, aligned_size) != aligned_size) {
      /* send data and try again */
      net_output(ifn);
      if (net_outbuffer_push(ifn, message, aligned_size) != aligned_size) {
        //OLSR_PRINTF(1, "%s: could not send on interface: %s\n", PLUGIN_NAME_SHORT, ifn->int_name);
      }
    } else
      net_output(ifn);
  }
}

/* -------------------------------------------------------------------------
 * Function   : P2pdPError
 * Description: Prints an error message at OLSR debug level 1.
 *              First the plug-in name is printed. Then (if format is not NULL
 *              and *format is not empty) the arguments are printed, followed
 *              by a colon and a blank. Then the message and a new-line.
 * Input      : format, arguments
 * Output     : none
 * Return     : none
 * Data Used  : none
 * ------------------------------------------------------------------------- */
void
P2pdPError(const char *format, ...)
{
#define MAX_STR_DESC 255
  char strDesc[MAX_STR_DESC];

  char *stringErr = strerror(errno);

  /* Rely on short-circuit boolean evaluation */
  if (format == NULL || *format == '\0') {
    //OLSR_DEBUG(LOG_PLUGINS, "%s: %s\n", PLUGIN_NAME, stringErr);
  } else {
    va_list arglist;

    va_start(arglist, format);
    vsnprintf(strDesc, MAX_STR_DESC, format, arglist);
    va_end(arglist);

    strDesc[MAX_STR_DESC - 1] = '\0';   /* Ensures null termination */

    OLSR_PRINTF(1, "%s: %s: %s\n", PLUGIN_NAME_SHORT, strDesc, stringErr);
  }
}                               /* P2pdPError */

/* -------------------------------------------------------------------------
 * Function   : MainAddressOf
 * Description: Lookup the main address of a node
 * Input      : ip - IP address of the node
 * Output     : none
 * Return     : The main IP address of the node
 * Data Used  : none
 * ------------------------------------------------------------------------- */
union olsr_ip_addr *
MainAddressOf(union olsr_ip_addr *ip)
{
  union olsr_ip_addr *result = NULL;

  /* TODO: mid_lookup_main_addr() is not thread-safe! */
  result = mid_lookup_main_addr(ip);
  if (result == NULL) {
    result = ip;
  }
  return result;
}                               /* MainAddressOf */


/* -------------------------------------------------------------------------
 * Function   : InUdpDestPortList
 * Description: Check whether the specified address and port is in the list of
 *              configured UDP destination/port entries
 * Input      : ip_version  - IP version to use for this check
 *              addr        - address to check for in the list
 *              port        - port to check for in the list
 * Output     : none
 * Return     : true if destination/port combination was found, false otherwise
 * Data Used  : UdpDestPortList
 * ------------------------------------------------------------------------- */
bool
InUdpDestPortList(int ip_version, union olsr_ip_addr *addr, uint16_t port)
{
  struct UdpDestPort *walker = NULL;

  for (walker = UdpDestPortList; walker; walker = walker->next) {
    if (walker->ip_version == ip_version) {
      if (ip_version == AF_INET) {
        if (addr->v4.s_addr == walker->address.v4.s_addr &&
            walker->port == port)
          return true;  // Found so we can stop here
      } else /* ip_version == AF_INET6 */ {
        if ((memcmp(addr->v6.s6_addr,
                   walker->address.v6.s6_addr,
                   sizeof(addr->v6.s6_addr)) == 0) &&
            (walker->port == port))
          return true;  // Found so we can stop here
      }
    }
  }
  return false;
}

/* -------------------------------------------------------------------------
 * Function   : P2pdPacketCaptured
 * Description: Handle a captured IP packet. Parses mDNS packets and sends
 *              new packets containing local service records with custom
 *              TTL values.
 * Input      : encapsulationUdpData - space for the encapsulation header,
 *              followed by the captured IP packet
 *              nBytes - The number of bytes in the data packet
 * Output     : none
 * Return     : none
 * Data Used  : P2pdInterfaces
 * Notes      : The IP packet is assumed to be captured on a socket of family
 *              PF_PACKET and type SOCK_DGRAM (cooked).
 * ------------------------------------------------------------------------- */
static void
P2pdPacketCaptured(unsigned char *encapsulationUdpData, int nBytes)
{
  union olsr_ip_addr src;      /* Destination IP address in captured packet */
  union olsr_ip_addr dst;      /* Destination IP address in captured packet */
  struct ip *ipHeader = NULL;         /* The IP header inside the captured IP packet */
  struct ip6_hdr *ipHeader6 = NULL;   /* The IP header inside the captured IP packet */
  struct udphdr *udpHeader = NULL;
  struct NonOlsrInterface *walker;
  u_int16_t destPort;
  ldns_pkt *p = NULL, *p2 = NULL;
  int p_size, ttl, nonlocal_list_count[3] = {0, 0, 0};
  int found = 0;
  unsigned int i, j;
  ldns_status s;
  ldns_rr_list *full_list = NULL, *nonlocal_list[3];
  ldns_rr *rr = NULL;
  struct RrListByTtl *ttl_bucket = NULL, *rr_buf = NULL;
  PKT_TYPE pkt_type;

  if ((encapsulationUdpData[0] & 0xf0) == 0x40) {       //IPV4
    pkt_type = IPv4;
    
    ipHeader = (struct ip *) ARM_NOWARN_ALIGN(encapsulationUdpData);

    src.v4 = ipHeader->ip_src;
    dst.v4 = ipHeader->ip_dst;
    
    for (walker = nonOlsrInterfaces; walker != NULL; walker = walker->next) {
      if (walker->intAddr.v4.s_addr == src.v4.s_addr) {
	found = 1;
      }
    }
    if (!found) {
#ifdef INCLUDE_DEBUG_OUTPUT
      OLSR_PRINTF(1,"%s: NON SOURCE PACKET\n", PLUGIN_NAME_SHORT);
#endif
      return;
    }

    if (ipHeader->ip_p != SOL_UDP) {
      /* Not UDP */
#ifdef INCLUDE_DEBUG_OUTPUT
      OLSR_PRINTF(1,"%s: NON UDP PACKET\n", PLUGIN_NAME_SHORT);
#endif
      return;                   /* for */
    }

    // If we're dealing with a fragment we bail out here since there's no valid
    // UDP header in this message
    if (IsIpv4Fragment(ipHeader)) {
#ifdef INCLUDE_DEBUG_OUTPUT
      OLSR_PRINTF(1, "%s: Is IPv4 fragment\n", PLUGIN_NAME_SHORT);
#endif
      return;
    }

    if (check_and_mark_recent_packet(encapsulationUdpData, nBytes)) {
#ifdef INCLUDE_DEBUG_OUTPUT
      OLSR_PRINTF(1, "%s: Recent packet\n", PLUGIN_NAME_SHORT);
#endif 
      return;
    }

    udpHeader = (struct udphdr *) ARM_NOWARN_ALIGN((encapsulationUdpData +
                                  GetIpHeaderLength(encapsulationUdpData)));
    destPort = ntohs(udpHeader->dest);

    if (!InUdpDestPortList(AF_INET, &dst, destPort)) {
#ifdef INCLUDE_DEBUG_OUTPUT
      char tmp[32];
      OLSR_PRINTF(1, "%s: Not in dest/port list: %s:%d\n", PLUGIN_NAME_SHORT,
                  get_ipv4_str(dst.v4.s_addr, tmp, sizeof(tmp)), destPort);
#endif
       return;
    }
    
    p_size = nBytes - GetIpHeaderLength(encapsulationUdpData) - UDP_HEADER_LENGTH;
    s = ldns_wire2pkt(&p, ARM_NOWARN_ALIGN(encapsulationUdpData + GetIpHeaderLength(encapsulationUdpData) + UDP_HEADER_LENGTH), p_size);
    if (s != LDNS_STATUS_OK) {
#ifdef INCLUDE_DEBUG_OUTPUT
      OLSR_PRINTF(1, "%s: Error getting ipv4 dns packet\n", PLUGIN_NAME_SHORT);
#endif
      ldns_pkt_free(p);
      return;
    }
    
    
  }                            //END IPV4
  else if ((encapsulationUdpData[0] & 0xf0) == 0x60) {  //IPv6
    pkt_type = IPv6;

    ipHeader6 = (struct ip6_hdr *) ARM_NOWARN_ALIGN(encapsulationUdpData);

    memcpy(&src.v6, &ipHeader6->ip6_src, sizeof(struct in6_addr));
    memcpy(&dst.v6, &ipHeader6->ip6_dst, sizeof(struct in6_addr));
    
    for (walker = nonOlsrInterfaces; walker != NULL; walker = walker->next) {
      if (walker->intAddr.v6.s6_addr == src.v6.s6_addr) {
	found = 1;
      }
    }
    if (!found) {
#ifdef INCLUDE_DEBUG_OUTPUT
      OLSR_PRINTF(1,"%s: NON SOURCE PACKET\n", PLUGIN_NAME_SHORT);
#endif
      return;
    }

    if (ipHeader6->ip6_dst.s6_addr[0] == 0xff)  //Multicast
    {
      //Continue
    } else {
#ifdef INCLUDE_DEBUG_OUTPUT
      OLSR_PRINTF(1, "%s: IPv4 non-multicast\n", PLUGIN_NAME_SHORT);
#endif
      return;                   //not multicast
    }
    if (ipHeader6->ip6_nxt != SOL_UDP) {
      /* Not UDP */
#ifdef INCLUDE_DEBUG_OUTPUT
      OLSR_PRINTF(1,"%s: NON UDP PACKET\n", PLUGIN_NAME_SHORT);
#endif
      return;                   /* for */
    }

    // Check whether this is a IPv6 fragment
    if (IsIpv6Fragment(ipHeader6)) {
#ifdef INCLUDE_DEBUG_OUTPUT
      OLSR_PRINTF(1, "%s: Is IPv6 fragment\n", PLUGIN_NAME_SHORT);
#endif
      return;
    }

    if (check_and_mark_recent_packet(encapsulationUdpData, nBytes)) {
#ifdef INCLUDE_DEBUG_OUTPUT
      OLSR_PRINTF(1, "%s: Recent packet\n", PLUGIN_NAME_SHORT);
#endif 
      return;
    }

    udpHeader = (struct udphdr *) ARM_NOWARN_ALIGN((encapsulationUdpData + IPV6_HEADER_LENGTH));
    destPort = ntohs(udpHeader->dest);

    if (!InUdpDestPortList(AF_INET6, &dst, destPort)) {
#ifdef INCLUDE_DEBUG_OUTPUT
      char tmp[64];
      OLSR_PRINTF(1, "%s: Not in dest/port list: %s:%d\n", PLUGIN_NAME_SHORT,
                  get_ipv6_str(dst.v6.s6_addr, tmp, sizeof(tmp)), destPort);
#endif
      return;
    }
    
    p_size = nBytes - IPV6_HEADER_LENGTH - UDP_HEADER_LENGTH;
    s = ldns_wire2pkt(&p, ARM_NOWARN_ALIGN(encapsulationUdpData + IPV6_HEADER_LENGTH + UDP_HEADER_LENGTH), p_size);
    if (s != LDNS_STATUS_OK) {
#ifdef INCLUDE_DEBUG_OUTPUT
      OLSR_PRINTF(1, "%s: Error getting ipv6 dns packet\n", PLUGIN_NAME_SHORT);
#endif
      ldns_pkt_free(p);
      return;
    }
    
  }                             //END IPV6
  else {
#ifdef INCLUDE_DEBUG_OUTPUT
      OLSR_PRINTF(1, "%s: Not IPv4 or IPv6\n", PLUGIN_NAME_SHORT);
#endif 
    return;                     //Is not IP packet
  }
  
  // do the magic here:
  
  // go through RR sections of mDNS packets, and yank out ones that represent local services
  for (i = 0; i < 3; ++i) {
    if (ldns_pkt_section_count(p, i + 1) != 0) {
      full_list = ldns_pkt_get_section_clone(p, i + 1);
      if (!full_list) {
	ldns_pkt_free(p);
	OLSR_PRINTF(1, "%s: Error cloning rr_list\n", PLUGIN_NAME_SHORT);
	return;
      }
      nonlocal_list[i] = ldns_rr_list_new();
      if (!nonlocal_list[i]) {
	ldns_rr_list_deep_free(full_list);
	ldns_pkt_free(p);
	OLSR_PRINTF(1, "%s: Error allocating rr_list\n", PLUGIN_NAME_SHORT);
	return;
      }
      for(j = 0; j < ldns_rr_list_rr_count(full_list); ++j) {
        rr = ldns_rr_list_rr(full_list, j);
        // check if RR is local service
        if (IsRrLocal(rr, &ttl)) {
          // if so, add to list
          AddToRrBuffer(&rr_buf, ttl, rr, i);
        } else {
	  // if not, add to non-local RR list
	  ldns_rr_list_push_rr(nonlocal_list[i], rr);
	  nonlocal_list_count[i] += 1;
        }
      }
      ldns_rr_list_free(full_list);
    }
  }
  
  // Send packet with non-local RR list (this will include any question RRs)
  p2 = ldns_pkt_clone(p);  // create new mDNS packet p2 cloned from original packet
  ldns_rr_list_deep_free(p2->_answer);
  ldns_rr_list_deep_free(p2->_additional);
  ldns_rr_list_deep_free(p2->_authority);
  ldns_pkt_set_answer(p2, (nonlocal_list_count[0]) ? nonlocal_list[0] : NULL);
  ldns_pkt_set_authority(p2, (nonlocal_list_count[1]) ? nonlocal_list[1] : NULL);
  ldns_pkt_set_additional(p2, (nonlocal_list_count[2]) ? nonlocal_list[2] : NULL);
  for (i = 0; i < 3; ++i)
    ldns_pkt_set_section_count(p2, i + 1, nonlocal_list_count[i]);
  DnssdSendPacket(p2, pkt_type, encapsulationUdpData, nBytes, 0);
  ldns_pkt_free(p2);
  
  // For each batch of RRs grouped by TTL, populate new mDNS packet to encapsulate in an OLSR packet and send to mesh
  for (ttl_bucket = rr_buf; ttl_bucket != NULL; ttl_bucket=ttl_bucket->hh.next) {
    if (ttl_bucket->ttl > 0) {
      p2 = ldns_pkt_clone(p);
      ldns_rr_list_deep_free(p2->_answer);
      ldns_rr_list_deep_free(p2->_additional);
      ldns_rr_list_deep_free(p2->_authority);
      ldns_rr_list_deep_free(p2->_question);
      ldns_pkt_set_question(p2, NULL);
      ldns_pkt_set_qdcount(p2, 0);
      ldns_pkt_set_answer(p2, (ttl_bucket->rr_count[0]) ? ttl_bucket->rr_list[0] : NULL);
      ldns_pkt_set_authority(p2, (ttl_bucket->rr_count[1]) ? ttl_bucket->rr_list[1] : NULL);
      ldns_pkt_set_additional(p2, (ttl_bucket->rr_count[2]) ? ttl_bucket->rr_list[2] : NULL);
      for (i = 0; i < 3; ++i)
        ldns_pkt_set_section_count(p2, i + 1, ttl_bucket->rr_count[i]);
      DnssdSendPacket(p2, pkt_type, encapsulationUdpData, nBytes, ttl_bucket->ttl);
      ldns_pkt_free(p2);
    }
  }

  DeleteListArray(&rr_buf);
  ldns_pkt_free(p);
}                               /* P2pdPacketCaptured */

/* -------------------------------------------------------------------------
 * Function   : DnssdSendPacket
 * Description: Encapsulate mDNS packet into OLSR packet with given TTL and
 *              send to OLSR forwarding mechanism
 * Input      : pkt - ldns packet to be converted and sent
 *              pkt_type - either IPv4 or IPv6
 *              encapsulationUdpData - raw packet buffer that includes
 *                                     original IP and UDP headers
 *              nBytes - size of encapsulationUdpData in bytes
 *              ttl - max # of hops away packet should be sent
 * Output     : none
 * Return     : none
 * Data Used  :
 * ------------------------------------------------------------------------- */
void DnssdSendPacket(ldns_pkt *pkt, PKT_TYPE pkt_type, unsigned char *encapsulationUdpData, int nBytes __attribute__((unused)), int ttl) {
  uint8_t *buf_ptr = NULL;
  size_t buf_size;
  int packet_size, full_header_len, ip_header_len;
  struct ip *ipHeader = NULL;
  struct ip6_hdr *ipHeader6 = NULL;
  struct udphdr *udpHeader = NULL;
  unsigned char *pseudogram = NULL, *new_pkt = NULL;
  size_t pgram_size;
  union {
    struct pseudo_header psh;
    struct pseudo_header6 psh6;
  } pshdr;

  // convert packet to wire format buffer
  if (ldns_pkt2wire(&buf_ptr, pkt, &buf_size) != LDNS_STATUS_OK) {
    OLSR_PRINTF(1, "%s: Error converting dns packet to wire format\n", PLUGIN_NAME_SHORT);
    return;
  }
  
  // Set up packet headers
  if (pkt_type == IPv4) {
    ip_header_len = GetIpHeaderLength(encapsulationUdpData);
    full_header_len = ip_header_len + UDP_HEADER_LENGTH;
    new_pkt = calloc(full_header_len + buf_size, sizeof(unsigned char));
    memcpy(new_pkt, encapsulationUdpData, full_header_len);
    ipHeader = (struct ip *) ARM_NOWARN_ALIGN(new_pkt);
    udpHeader = (struct udphdr *) ARM_NOWARN_ALIGN((new_pkt + ip_header_len));
  } else if (pkt_type == IPv6) {
    ip_header_len = IPV6_HEADER_LENGTH;
    full_header_len = ip_header_len + UDP_HEADER_LENGTH;
    new_pkt = calloc(full_header_len + buf_size, sizeof(unsigned char));
    memcpy(new_pkt, encapsulationUdpData, full_header_len);
    ipHeader6 = (struct ip6_hdr *) ARM_NOWARN_ALIGN(new_pkt);
    udpHeader = (struct udphdr *) ARM_NOWARN_ALIGN((new_pkt + ip_header_len));
  } else
    return;
  
  packet_size = full_header_len + buf_size;
  
  // time to do some raw packet-fu
  memcpy(new_pkt + full_header_len, buf_ptr, buf_size);
  
  udpHeader->len = htons(UDP_HEADER_LENGTH + buf_size);
  udpHeader->check = 0;
  
  // calculate new IP header:
  // for IPv4, packet length ((u_short)ipHeader->ip_len) and header checksum ((u_short)ipHeader->ip_sum)
  // for IPv6, payload length ((u_int16_t)ipHeader6->ip6_ctlun.ip6_un1.ip6_un1_plen)
  if (pkt_type == IPv4) {       //IPV4
      ipHeader->ip_len = htons(packet_size);
      ipHeader->ip_sum = 0;
      ipHeader->ip_sum = CheckSum((unsigned short *)new_pkt, ip_header_len);
      
      // calculate new UDP checksum using IP pseudoheader
      pshdr.psh.source_address = ipHeader->ip_src;
      pshdr.psh.dest_address = ipHeader->ip_dst;
      pshdr.psh.placeholder = 0;
      pshdr.psh.protocol = IPPROTO_UDP;
      pshdr.psh.udp_length = htons(sizeof(struct udphdr) + buf_size);
      pgram_size = sizeof(struct pseudo_header) + sizeof(struct udphdr) + buf_size;
      pseudogram = malloc(pgram_size);
      memcpy(pseudogram, (unsigned char *) &pshdr.psh, sizeof (struct pseudo_header));
      memcpy(pseudogram + sizeof(struct pseudo_header), udpHeader, sizeof(struct udphdr) + buf_size);
      udpHeader->check = CheckSum((unsigned short *)pseudogram, pgram_size);
      free(pseudogram);
      
  } else if (pkt_type == IPv6) {  //IPv6  
      ipHeader6->ip6_ctlun.ip6_un1.ip6_un1_plen = htons(packet_size);
      
      // calculate new UDP checksum using IP pseudoheader
      pshdr.psh6.ip6_src = ipHeader6->ip6_src;
      pshdr.psh6.ip6_dst = ipHeader6->ip6_dst;
      pshdr.psh6.udp_length = UDP_HEADER_LENGTH + buf_size;
      pshdr.psh6.zeros1 = 0;
      pshdr.psh6.zeros2 = 0;
      pgram_size = sizeof(struct pseudo_header6) + sizeof(struct udphdr) + buf_size;
      pshdr.psh6.protocol = IPPROTO_UDP;
      pseudogram = malloc(pgram_size);
      memcpy(pseudogram, (unsigned char *) &pshdr.psh6, sizeof (struct pseudo_header6));
      memcpy(pseudogram + sizeof(struct pseudo_header6), udpHeader, sizeof(struct udphdr) + buf_size);
      udpHeader->check = CheckSum((unsigned short *)pseudogram, pgram_size);
      free(pseudogram);
  }
  
  // send the packet to OLSR forward mechanism
  olsr_p2pd_gen(new_pkt, packet_size, ttl);
  free(buf_ptr);
  free(new_pkt);
}

/* -------------------------------------------------------------------------
 * Function   : CheckSum
 * Description: Simple packet header checksum calculator, taken from
 *              http://www.binarytides.com/raw-udp-sockets-c-linux/
 * Input      : ptr - pointer to data buffer over which to calculate sum
 *              nbytes - length of buffer in bytes
 * Output     : none
 * Return     : returns checksum
 * Data Used  :
 * ------------------------------------------------------------------------- */
unsigned short CheckSum(unsigned short *ptr,int nbytes)
{
    register long sum;
    unsigned short oddbyte;
    register short answer;
 
    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }
 
    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;
     
    return(answer);
}

/* -------------------------------------------------------------------------
 * Function   : IsRrLocal
 * Description: This function checks whether a DNS resource record
 *              represents a service local to this device
 * Input      : rr - resource record to check
 *              ttl - int to store TTL of local service if found
 * Output     : stores TTL of local service in &ttl
 * Return     : 1 if RR represents local service, 0 otherwise
 * Data Used  :
 * ------------------------------------------------------------------------- */
int IsRrLocal(ldns_rr *rr, int *ttl) {
  struct MdnsService *s = NULL;
  ldns_rdf *owner = NULL;
  char *id, *owner_str, *rdata_str;
  
  // if owner == <service name>.<type>.<domain>.
  owner = ldns_rr_owner(rr);
  owner_str = ldns_rdf2str(owner);
  UnescapeStr(owner_str, strlen(owner_str));
  if (strlen(owner_str) <= (strlen(ServiceDomain) + 2)) {
    free(owner_str);
    return 0;
  }
  id = malloc(sizeof(char)*(strlen(owner_str) - strlen(ServiceDomain) - 1));
  strncpy(id, owner_str, strlen(owner_str) - strlen(ServiceDomain) - 2);
  id[strlen(owner_str) - strlen(ServiceDomain) - 2] = '\0';
  
  s = GetServiceById(id);
  free(owner_str);
  free(id);
  // if owner minus .<domain> in ServiceList then add RR to list
  if (s) {
    *ttl = s->ttl;
    return 1;
  }

  // if type == PTR && RDATA == <service name>.<type>.<domain>.
  if (rr->_rr_type == LDNS_RR_TYPE_PTR && rr->_rd_count == 1) {
    // check RDATA
    rdata_str = ldns_rdf2str(rr->_rdata_fields[0]);
    UnescapeStr(rdata_str, strlen(rdata_str));
    if (strlen(rdata_str) <= (strlen(ServiceDomain) + 2)) {
      free(rdata_str);
      return 0;
    }
    id = malloc(sizeof(char)*(strlen(rdata_str) - strlen(ServiceDomain) - 1));
    strncpy(id, rdata_str, strlen(rdata_str) - strlen(ServiceDomain) - 2);
    id[strlen(rdata_str) - strlen(ServiceDomain) - 2] = '\0';
    
    s = GetServiceById(id);
    free(rdata_str);
    free(id);
    if (s) {
      *ttl = s->ttl;
      return 1;
    }
  }
  
  return 0;
}

/* -------------------------------------------------------------------------
 * Function   : UnescapeStr
 * Description: This function removes backslash escaping in DNS resource
 *              record strings.
 * Input      : str - string to unescape
 *              nBytes - length of string in bytes
 * Output     : none
 * Return     : length of unescaped string in bytes
 * Data Used  :
 * ------------------------------------------------------------------------- */
size_t UnescapeStr(char *str, size_t nBytes) {
  char octal[4], tmp[nBytes];
  unsigned int i;
  int converted = 0;
  
  for (i = 0; i < (nBytes - 1); i++) {
    converted = 0;
    if (str[i] == '\\') {
      if ((nBytes - i) > 3) {
        strncpy(octal, str + i + 1, 3);
        octal[3] = '\0';
        if (!strcmp(octal, "032")) {
	  // replace \032 with space
	  str[i] = ' ';
	  strncpy(tmp,str + i + 4, nBytes - i - 4);
	  strncpy(str + i + 1, tmp, nBytes - i - 4);
	  nBytes -= 3;
	  str[nBytes] = '\0';
	  converted = 1;
	}
      }
      if (!converted) {
	// remove escaping backslash
	strncpy(tmp, str + i + 1, nBytes - i - 1);
	strncpy(str + i, tmp, nBytes - i - 1);
	nBytes--;
	str[nBytes] = '\0';
      }
    }
  }

  // return new length
  return nBytes;
}

/* -------------------------------------------------------------------------
 * Function   : DoP2pd
 * Description: This function is registered with the OLSR scheduler and called
 *              when something is captured
 * Input      : none
 * Output     : none
 * Return     : none
 * Data Used  :
 * ------------------------------------------------------------------------- */
void
DoP2pd(int skfd,
       void *data __attribute__ ((unused)),
       unsigned int flags __attribute__ ((unused)))
{
  unsigned char rxBuffer[P2PD_BUFFER_SIZE];
  if (skfd >= 0) {
    struct sockaddr_ll pktAddr;
    socklen_t addrLen = sizeof(pktAddr);
    int nBytes;
    unsigned char *ipPacket = NULL;

    /* Receive the captured Ethernet frame, leaving space for the BMF
     * encapsulation header */
    ipPacket = GetIpPacket(rxBuffer);
    nBytes = recvfrom(skfd, ipPacket, P2PD_BUFFER_SIZE,
                      0, (struct sockaddr *)&pktAddr, &addrLen);
#ifdef INCLUDE_DEBUG_OUTPUT
    OLSR_PRINTF(1, "%s: Received %d bytes\n", PLUGIN_NAME_SHORT, nBytes);
#endif

    if (nBytes < 0) {
      return;                   /* for */
    }

    /* if (nBytes < 0) */
    /* Check if the number of received bytes is large enough for an IP
     * packet which contains at least a minimum-size IP header.
     * Note: There is an apparent bug in the packet socket implementation in
     * combination with VLAN interfaces. On a VLAN interface, the value returned
     * by 'recvfrom' may (but need not) be 4 (bytes) larger than the value
     * returned on a non-VLAN interface, for the same ethernet frame. */
    if (nBytes < (int)sizeof(struct ip)) {
      ////OLSR_PRINTF(
      //              1,
      //              "%s: captured frame too short (%d bytes) on \"%s\"\n",
      //              PLUGIN_NAME_SHORT,
      //              nBytes,
      return;                   /* for */
    }

    if (pktAddr.sll_pkttype == PACKET_OUTGOING) {
#ifdef INCLUDE_DEBUG_OUTPUT
      OLSR_PRINTF(1, "%s: Multicast packet was captured.\n",
                  PLUGIN_NAME_SHORT);
      dump_packet(ipPacket, nBytes);
#endif
      /* A multicast or broadcast packet was captured */
      P2pdPacketCaptured(ipPacket, nBytes);

    }                           /* if (pktAddr.sll_pkttype == ...) */
  }                             /* if (skfd >= 0 && (FD_ISSET...)) */
}                               /* DoP2pd */

static void
DnssdSigHandler(int sig)
{
  if (sig == SIGUSR1) {
    OLSR_PRINTF(1, "%s: Received USR1 signal, updating services\n", PLUGIN_NAME_SHORT);
    UpdateServices(NULL);
  }
}

/* -------------------------------------------------------------------------
 * Function   : InitP2pd
 * Description: Initialize the P2pd plugin
 * Input      : skipThisInterface - pointer to interface to skip
 * Output     : none
 * Return     : Always 0
 * Data Used  : none
 * ------------------------------------------------------------------------- */
int
InitP2pd(struct interface *skipThisIntf)
{
  struct sigaction sa;
  
  if (P2pdUseHash) {
    // Initialize hash table for hash based duplicate IP packet check
    InitPacketHistory();
  }

  //Tells OLSR to launch olsr_parser when the packets for this plugin arrive
  //olsr_parser_add_function(&olsr_parser, PARSER_TYPE,1);
  olsr_parser_add_function(&olsr_parser, PARSER_TYPE);

  //Creates captures sockets and register them to the OLSR scheduler
  CreateNonOlsrNetworkInterfaces(skipThisIntf);

  memset(&sa, 0, sizeof(struct sigaction));
  sa.sa_handler = DnssdSigHandler;
  if (sigaction(SIGUSR1,&sa,NULL) == -1)
    P2pdPError("Failed to set signal handler");
  
  return 0;
}                               /* InitP2pd */

/* -------------------------------------------------------------------------
 * Function   : CloseP2pd
 * Description: Close the P2pd plugin and clean up
 * Input      : none
 * Output     : none
 * Return     : none
 * Data Used  :
 * ------------------------------------------------------------------------- */
void
CloseP2pd(void)
{
  CloseNonOlsrNetworkInterfaces();
  olsr_stop_timer(service_update_timer);
  olsr_stop_timer(service_query_timer);
  free(ServiceFileDir);
  DeleteAllServices();
}

/* -------------------------------------------------------------------------
 * Function   : SetP2pdTtl
 * Description: Set the TTL for message from this plugin
 * Input      : value - parameter value to evaluate
 * Output     : none
 * Return     : Always 0
 * Data Used  : P2pdTtl
 * ------------------------------------------------------------------------- */
int
SetP2pdTtl(const char *value,
           void *data __attribute__ ((unused)),
           set_plugin_parameter_addon addon __attribute__ ((unused)))
{
  assert(value != NULL);
  P2pdTtl = atoi(value);

  return 0;
}

/* -------------------------------------------------------------------------
 * Function   : SetP2pdUseHashFilter
 * Description: Set the Hash filter flag for this plug-in
 * Input      : value - parameter value to evaluate
 *              data  - data associated with this parameter (unused in this app)
 *              addon - additional parameter data
 * Output     : none
 * Return     : Always 0
 * Data Used  : P2pdUseHash
 * ------------------------------------------------------------------------- */
int
SetP2pdUseHashFilter(const char *value,
                     void *data __attribute__ ((unused)),
                     set_plugin_parameter_addon addon __attribute__ ((unused)))
{
  assert(value != NULL);
  P2pdUseHash = atoi(value);
  
  return 0;
}

/* -------------------------------------------------------------------------
 * Function   : AddUdpDestPort
 * Description: Set the UDP destination/port combination as an entry in the
 *              UdpDestPortList
 * Input      : value - parameter value to evaluate
 * Output     : none
 * Return     : -1 on error condition, 0 if all is ok
 * Data Used  : UdpDestPortList
 * ------------------------------------------------------------------------- */
int
AddUdpDestPort(const char *value,
               void *data __attribute__ ((unused)),
               set_plugin_parameter_addon addon __attribute__ ((unused)))
{
  char destAddr[INET6_ADDRSTRLEN];
  uint16_t destPort;
  int num;
  struct UdpDestPort *    new;
  struct sockaddr_in      addr4;
  struct sockaddr_in6     addr6;
  int                     ip_version	= AF_INET;
  int                     res;

  assert(value != NULL);

  // Retrieve the data from the argument string passed
  memset(destAddr, 0, sizeof(destAddr));
  num = sscanf(value, "%45s %hd", destAddr, &destPort);
  if (num != 2) {
    OLSR_PRINTF(1, "%s: Invalid argument for \"UdpDestPort\"",
                PLUGIN_NAME_SHORT);
    return -1;
  }

  // Check whether we're dealing with an IPv4 or IPv6 address
  // When the string contains a ':' we can assume we're dealing with IPv6
  if (strchr(destAddr, (int)':')) {
    ip_version = AF_INET6;
  }

  // Check whether the specified address was either IPv4 multicast,
  // IPv4 broadcast or IPv6 multicast.

  switch (ip_version) {
  case AF_INET6:
    res = inet_pton(AF_INET6, destAddr, &addr6.sin6_addr);
    if (addr6.sin6_addr.s6_addr[0] != 0xFF) {
      OLSR_PRINTF(1,"WARNING: IPv6 address must be multicast... ");
      return -1;
    }
    break;
  case AF_INET:
  default:
    res = inet_pton(AF_INET, destAddr, &addr4.sin_addr);
    if (!is_broadcast(addr4) && !is_multicast(addr4)) {
      OLSR_PRINTF(1,"WARNING: IPv4 address must be multicast or broadcast... ");
    }
    break;
  }
  // Determine whether it is a valid IP address
  if (res == 0) {
    OLSR_PRINTF(1, "Invalid address specified for \"UdpDestPort\"");
    return -1;
  }

  // Create a new entry and link it into the chain
  new = calloc(1, sizeof(struct UdpDestPort));
  if (new == NULL) {
    OLSR_PRINTF(1, "%s: Out of memory", PLUGIN_NAME_SHORT);
    return -1;
  }

  new->ip_version = ip_version;
  switch (ip_version) {
  case AF_INET6:
    memcpy(&new->address.v6.s6_addr,
           &addr6.sin6_addr.s6_addr,
           sizeof(addr6.sin6_addr.s6_addr));
    break;
  default:
  case AF_INET:
    new->address.v4.s_addr = addr4.sin_addr.s_addr;
    break;
  }
  new->port = destPort;
  new->next = UdpDestPortList;
  UdpDestPortList = new;

  // And then we're done
  return 0;
}

/* -------------------------------------------------------------------------
 * Function   : get_ipv4_str
 * Description: Convert the specified address to an IPv4 compatible string
 * Input      : address - IPv4 address to convert to string
 *              s       - string buffer to contain the resulting string
 *              maxlen  - maximum length of the string buffer
 * Output     : none
 * Return     : Pointer to the string buffer containing the result
 * Data Used  : none
 * ------------------------------------------------------------------------- */
char *
get_ipv4_str(uint32_t address, char *s, size_t maxlen)
{
  struct sockaddr_in v4;

  v4.sin_addr.s_addr = address;
  inet_ntop(AF_INET, &v4.sin_addr, s, maxlen);

  return s;
}

/* -------------------------------------------------------------------------
 * Function   : get_ipv6_str
 * Description: Convert the specified address to an IPv4 compatible string
 * Input      : address - IPv6 address to convert to string
 *              s       - string buffer to contain the resulting string
 *              maxlen  - maximum length of the string buffer
 * Output     : none
 * Return     : Pointer to the string buffer containing the result
 * Data Used  : none
 * ------------------------------------------------------------------------- */
char *
get_ipv6_str(unsigned char* address, char *s, size_t maxlen)
{
  struct sockaddr_in6 v6;

  memcpy(v6.sin6_addr.s6_addr, address, sizeof(v6.sin6_addr.s6_addr));
  inet_ntop(AF_INET6, &v6.sin6_addr, s, maxlen);

  return s;
}

/* -------------------------------------------------------------------------
 * Function   : is_broadcast
 * Description: Check whether the address represents a broadcast address
 * Input      : addr - IPv4 address to check
 * Output     : none
 * Return     : true if broadcast address, false otherwise
 * Data Used  : none
 * ------------------------------------------------------------------------- */
bool
is_broadcast(const struct sockaddr_in addr)
{
  if (addr.sin_addr.s_addr == 0xFFFFFFFF)
    return true;

  return false;
}

/* -------------------------------------------------------------------------
 * Function   : is_multicast
 * Description: Check whether the address represents a multicast address
 * Input      : addr - IPv4 address to check
 * Output     : none
 * Return     : true if broadcast address, false otherwise
 * Data Used  : none
 * ------------------------------------------------------------------------- */
bool
is_multicast(const struct sockaddr_in addr)
{
  if ((htonl(addr.sin_addr.s_addr) & 0xE0000000) == 0xE0000000)
    return true;

  return false;
}

#ifdef INCLUDE_DEBUG_OUTPUT
/* -------------------------------------------------------------------------
 * Function   : dump_packet
 * Description: Dump the specified data as hex output
 * Input      : packet - packet to dump to output
 *              length - length of the data in the packet
 * Output     : none
 * Return     : nothing
 * Data Used  : none
 * ------------------------------------------------------------------------- */
void
dump_packet(unsigned char* packet, int length)
{
  int idx;

  OLSR_PRINTF(1, "%s: ", PLUGIN_NAME_SHORT);
  for (idx = 0; idx < length; idx++) {
    if (idx > 0 && ((idx % 16) == 0))
      OLSR_PRINTF(1, "\n%s: ", PLUGIN_NAME_SHORT);
    OLSR_PRINTF(1, "%2.2X ", packet[idx]);
  }
  OLSR_PRINTF(1, "\n");
}
#endif

/* -------------------------------------------------------------------------
 * Function   : check_and_mark_recent_packet
 * Description: Wrapper function for the Hash based duplicate check
 * Input      : data - pointer to a packet of data to be checked
 * Output     : none
 * Return     : true if duplicate packet, false otherwise
 * Data Used  : P2pdUseHash
 * ------------------------------------------------------------------------- */
bool
check_and_mark_recent_packet(unsigned char *data,
                             int len __attribute__ ((unused)))
{
  unsigned char * ipPacket;
  uint16_t ipPacketLen;
  uint32_t crc32;

  /* If we don't use this filter bail out here */
  if (!P2pdUseHash)
    return false;
    
  /* Clean up the hash table each time before we check it */
  PrunePacketHistory(NULL);

  /* Check for duplicate IP packets now based on a hash */
  ipPacket = GetIpPacket(data);
  ipPacketLen = GetIpTotalLength(ipPacket);

  /* Calculate packet fingerprint */
  crc32 = PacketCrc32(ipPacket, ipPacketLen);

  /* Check if this packet was seen recently */
  if (CheckAndMarkRecentPacket(crc32))
  {
    OLSR_PRINTF(
      8,
      "%s: --> discarding: packet is duplicate\n",
      PLUGIN_NAME_SHORT);
    return true;
  }

  return false;
}

/* -------------------------------------------------------------------------
 * Function   : SetupServiceList
 * Description: Validates PmParam 'ServiceFileDir' and populates list of
 *              local services
 * Input      : value - comes from PlParam 'ServiceFileDir'
 * Output     : none
 * Return     : 0 on success, -1 on error
 * Data Used  : none
 * ------------------------------------------------------------------------- */
int SetupServiceList(const char *value, void *data __attribute__ ((unused)), set_plugin_parameter_addon addon __attribute__ ((unused))) {
  size_t value_len;
  
  assert(value != NULL);
  value_len = strlen(value);
  
  if (!value_len || value_len > MAX_FILE_LEN) {
    OLSR_PRINTF(1, "%s: Invalid argument for \"ServiceFileDir\"", PLUGIN_NAME_SHORT);
    return -1;
  }
  
  ServiceFileDir = malloc(sizeof(char)*(value_len + 1));
  strncpy(ServiceFileDir, value, value_len);
  ServiceFileDir[value_len] = '\0';
  
  // do initial ServiceList population
  UpdateServices(NULL);
  
  // set timer for period ServiceList updating
  service_update_timer = olsr_start_timer(ServiceUpdateInterval * MSEC_PER_SEC, EMISSION_JITTER, OLSR_TIMER_PERIODIC, UpdateServices, NULL, 0);
  
  // set timer for periodically prompting service announcements
  service_query_timer = olsr_start_timer(SERVICE_QUERY_INTERVAL * MSEC_PER_SEC, EMISSION_JITTER, OLSR_TIMER_PERIODIC, PromptAnnouncements, NULL, 0);
    
  return 0;
}

void PromptAnnouncements(void *context __attribute__((unused))) {
  int ret;
  const char dnssd_type[] = "_services._dns-sd._udp";
  uint8_t *pkt_buf = NULL;
  size_t buf_size = 0;
  struct MdnsService *service = NULL;
  ldns_rdf *rdf = NULL;
  ldns_rr *question_rr = NULL;
  ldns_rr_list *rr_list = NULL;
  ldns_pkt *pkt = NULL;
  struct NonOlsrInterface *ifwalker = NULL;
  struct UdpDestPort *walker = NULL;
  union olsr_sockaddr addr;
  
  ret = ldns_pkt_query_new_frm_str(&pkt, dnssd_type, LDNS_RR_TYPE_ANY, LDNS_RR_CLASS_IN, 0);
  if (ret != LDNS_STATUS_OK) {
    P2pdPError("Failed to create ldns packet: %s\n", ldns_get_errorstr_by_id(ret));
    return;
  }
  
  for (service = ServiceList; service != NULL; service=service->hh.next) {
    
    ret = ldns_str2rdf_dname(&rdf, service->service_type);
    if (ret != LDNS_STATUS_OK) {
      P2pdPError("Failed to create rdf: %s\n", ldns_get_errorstr_by_id(ret));
      ldns_pkt_free(pkt);
      return;
    }
    
    // Don't add duplicate RRs
    if ((rr_list = ldns_pkt_rr_list_by_name(pkt, rdf, LDNS_SECTION_QUESTION))) {
      ldns_rr_list_free(rr_list);
      break;
    }
    
    question_rr = ldns_rr_new();
    if (!question_rr) {
      P2pdPError("Failed to create rr");
      ldns_rdf_free(rdf);
      ldns_pkt_free(pkt);
      return;
    }
    ldns_rr_set_owner(question_rr, rdf);
    ldns_rr_set_type(question_rr, LDNS_RR_TYPE_ANY);
    ldns_rr_set_class(question_rr, LDNS_RR_CLASS_IN);
    ldns_rr_set_question(question_rr, 1);
    ldns_pkt_push_rr(pkt, LDNS_SECTION_QUESTION, question_rr);
  }
  
  // Convert packet to wire format
  ret = ldns_pkt2wire(&pkt_buf, pkt, &buf_size);
  if (ret != LDNS_STATUS_OK) {
    P2pdPError("Error converting dns packet to wire format: %s\n", ldns_get_errorstr_by_id(ret));
    ldns_pkt_free(pkt);
    return;
  }
  
  // Send packet to local interface(s) and UDP destination addresses
  for (ifwalker = nonOlsrInterfaces; ifwalker != NULL; ifwalker = ifwalker->next) {
    if (ifwalker->olsrIntf == NULL) {
      
      for (walker = UdpDestPortList; walker; walker = walker->next) {
	int nBytesWritten;
	
	memset(&addr, 0, sizeof(union olsr_sockaddr));
	
// 	if (walker->ip_version == AF_INET) {
	  addr.in4.sin_family = AF_INET;
	  addr.in4.sin_port = htons(walker->port);
	  addr.in4.sin_addr.s_addr = walker->address.v4.s_addr;
	  
	  nBytesWritten = sendto(ifwalker->ipSkfd,
			       pkt_buf,
			       buf_size,
			       0,
			       (struct sockaddr *) &addr.in4,
			       sizeof(struct sockaddr));
	  
// 	} else /* ip_version == AF_INET6 */ {
// 	  addr.in6.sin6_family = AF_INET;
// 	  addr.in6.sin6_port = walker->port;
// 	  memcpy(&addr.in6.sin6_addr.s6_addr, walker->address.v6.s6_addr, 16);
// 	  
// 	  nBytesWritten = sendto(ifwalker->ipSkfd,
// 			       pkt_buf,
// 			       buf_size,
// 			       0,
// 			       (struct sockaddr *) &addr.in6,
// 			       sizeof(struct sockaddr));
	  
// 	}
	
	if (nBytesWritten != buf_size) {
	  P2pdPError("sendto() error forwarding unpacked encapsulated pkt on \"%s\"",
		     ifwalker->ifName);
	} else {
#ifdef INCLUDE_DEBUG_OUTPUT
	  OLSR_PRINTF(
	    2,
	    "%s: Sent mDNS queries on \"%s\" to %s:%d\n",
	    PLUGIN_NAME_SHORT,
	    ifwalker->ifName,
	    inet_ntoa(addr.in4.sin_addr),
	    addr.in4.sin_port);
#endif
	}
      }
    }
  }
  
  ldns_pkt_free(pkt);
}

/* -------------------------------------------------------------------------
 * Function   : UpdateServices
 * Description: Fetches local Avahi service files with a TTL txt-record and
 *              the target domain, and adds them to a list of local services
 * Input      : context (currently unused)
 * Output     : none
 * Return     : none
 * Data Used  : ServiceFileDir
 * ------------------------------------------------------------------------- */
void UpdateServices(void *context __attribute__((unused))) {
  char file_suffix[9], line[BUFFER_LENGTH + 1], *ttl_string, *service_name, *service_type, *dirpath, *fullpath, hostname[HOSTNAME_LEN + 1];
  DIR *dp = NULL;
  FILE *fp = NULL;
  struct dirent *ep = NULL;
  const char ttl_pattern[] = "^[[:space:]]*<txt-record>ttl=([[:digit:]]+)</txt-record>[[:space:]]*$";
  int domain_pattern_size = 0;
  char *domain_pattern = NULL;
  const char name_pattern[] = "^[[:space:]]*<name( replace-wildcards=\"yes\")?>(.*)</name>[[:space:]]*$";
  const char type_pattern[] = "^[[:space:]]*<type>(.*)</type>[[:space:]]*$";
  regex_t ttl_regex, domain_regex, name_regex, type_regex;
  const int n_matches = 3;
  regmatch_t match[n_matches];
  unsigned int found_domain, ttl, match_string_len;
  size_t dname_len, service_name_len, service_type_len, service_file_dir_len;
  int ret;
  struct MdnsService *service = NULL;
  
  dp = opendir(ServiceFileDir);
  if (dp == NULL) {
    OLSR_PRINTF(1, "%s: Unable to open directory given by \"ServiceFileDir\"", PLUGIN_NAME_SHORT);
    return;
  }
  
  // check for trailing backslash
  service_file_dir_len = strlen(ServiceFileDir);
  if (ServiceFileDir[service_file_dir_len - 1] == '/') {
    dirpath = malloc(sizeof(char)*(service_file_dir_len + 1));
    strncpy(dirpath,ServiceFileDir,service_file_dir_len);
    dirpath[service_file_dir_len] = '\0';
  } else {
    dirpath = malloc(sizeof(char)*(service_file_dir_len + 2));
    strncpy(dirpath,ServiceFileDir,service_file_dir_len);
    dirpath[service_file_dir_len] = '/';
    dirpath[service_file_dir_len + 1] = '\0';
  }

  domain_pattern_size = strlen("^[[:space:]]*<domain-name>") + 
                   strlen(ServiceDomain) +
		   strlen("</domain-name>[[:space:]]*$") + 1;
  domain_pattern = (char*)calloc(domain_pattern_size, sizeof(char)); 

  strcpy(domain_pattern, "^[[:space:]]*<domain-name>");
  strcat(domain_pattern, ServiceDomain);
  strcat(domain_pattern, "</domain-name>[[:space:]]*$");

  if (regcomp(&ttl_regex, ttl_pattern, REG_NEWLINE | REG_EXTENDED) || 
		regcomp(&domain_regex, domain_pattern, REG_NOSUB | REG_NEWLINE | REG_EXTENDED) ||
		regcomp(&name_regex, name_pattern, REG_NEWLINE | REG_EXTENDED) || 
     		regcomp(&type_regex, type_pattern, REG_NEWLINE | REG_EXTENDED)) {
#ifdef INCLUDE_DEBUG_OUTPUT
    OLSR_PRINTF(1, "%s: Unable to compile regex", PLUGIN_NAME_SHORT);
#endif
    return;
  }
  
  // set uptodate = 0 for all Services
  for (service = ServiceList; service != NULL; service=service->hh.next)
    service->uptodate = 0;
  
  // iterate through files in ServiceFileDir and check against our regex objects
  while ((ep = readdir(dp))) {
    dname_len = strlen(ep->d_name);
    if (dname_len > 8 && dname_len < MAX_DIR_LEN) {
      strncpy(file_suffix, ep->d_name + dname_len - 8, 8);
      file_suffix[8] = '\0';
      if (!strcmp(file_suffix,".service")) {   // if ep->d_name ends in .service, open it
        found_domain = 0;
	ttl = 0;
	service_name = NULL;
	service_type = NULL;
	fullpath = malloc(sizeof(char)*(strlen(dirpath) + dname_len + 1));
	strcpy(fullpath,dirpath);
	strcat(fullpath,ep->d_name);
        fp = fopen(fullpath, "rt");
	if (fp == NULL) {
#ifdef INCLUDE_DEBUG_OUTPUT
	  OLSR_PRINTF(1, "%s: Error opening file %s: %s\n", PLUGIN_NAME_SHORT, fullpath, strerror(errno));
#endif
	  return;
	}
	free(fullpath);
        while (fgets(line, BUFFER_LENGTH, fp)) {
	  if (!found_domain && !regexec(&domain_regex, line, 0, NULL, 0)) {  // check for target domain
	    found_domain = 1;
	  }
	  else if (!ttl  && !regexec(&ttl_regex, line, n_matches, match, 0)) {  // check for u_int TTL value
	    // parse match and store ttl
	    if (match[1].rm_so != -1) {
	      match_string_len = match[1].rm_eo - match[1].rm_so;
	      ttl_string = malloc(sizeof(char)*(match_string_len + 1));
	      strncpy(ttl_string, line + match[1].rm_so, match_string_len);
	      ttl_string[match_string_len] = '\0';
	      ttl = atoi(ttl_string);
	      free(ttl_string);
	      ttl = (ttl < 255 && ttl > 0) ? ttl : 0;
	    }
	  } else if (!service_name && !regexec(&name_regex, line, n_matches, match, 0)) {  // check for valid service name
	    if (match[2].rm_so != -1) {
	      service_name_len = match[2].rm_eo - match[2].rm_so;
	      service_name = malloc(sizeof(char)*(service_name_len + 1));
	      strncpy(service_name, line + match[2].rm_so, service_name_len);
	      service_name[service_name_len] = '\0';
	      if (match[1].rm_so != -1) {
		// replace %h with hostname
		ret = gethostname(hostname, HOSTNAME_LEN + 1);
		if (ret == -1) {
#ifdef INCLUDE_DEBUG_OUTPUT
		  OLSR_PRINTF(1, "%s: Error fetching hostname\n", PLUGIN_NAME_SHORT);
#endif
		  return;
		}
		hostname[HOSTNAME_LEN] = '\0';
		if ((service_name = ReplaceHostname(service_name, service_name_len, hostname, strlen(hostname))) == NULL) {
		  OLSR_PRINTF(1, "%s: Error replacing hostname in servicename\n", PLUGIN_NAME_SHORT);
		  return;
		}
		service_name_len = strlen(service_name);
	      }
	    }
	  } else if (!service_type && !regexec(&type_regex, line, n_matches, match, 0)) {  // check for valid service type
	    if (match[1].rm_so != -1) {
	      service_type_len = match[1].rm_eo - match[1].rm_so;
	      service_type = malloc(sizeof(char)*(service_type_len + 1));
	      strncpy(service_type, line + match[1].rm_so, service_type_len);
	      service_type[service_type_len] = '\0';
	    }
	  }
	}
        fclose(fp);
	// If all the matches succeeded, add service to ServiceList (sets uptodate = 1)
	if (service_name && service_type && found_domain && ttl) {
	  OLSR_PRINTF(1, "%s: Adding local service: %s\n", PLUGIN_NAME_SHORT, ep->d_name);
	  AddToServiceList(service_name, service_name_len, service_type, service_type_len, ep->d_name, dname_len, ttl);
	}
	if (service_name)
	  free(service_name);
	if (service_type)
	  free(service_type);
      }
    }
  }
  (void)closedir(dp);
  
  if (ServiceList == NULL) {
    OLSR_PRINTF(1, "%s: No valid service files found!\n", PLUGIN_NAME_SHORT);
  } else {
    // remove all services with uptodate == 0
    RemoveStaleServices();
  }
  
  regfree(&domain_regex);
  regfree(&ttl_regex);
  regfree(&name_regex);
  regfree(&type_regex);
  free(domain_pattern);
  free(dirpath);
}

/* -------------------------------------------------------------------------
 * Function   : ReplaceHostname
 * Description: Replaces %h in string with provided hostname
 * Input      : str - pointer to dynamically allocated buffer containing 
 *                    target string to manipulate
 *              nBytes - size of str in bytes, not including null ptr
 *              hostname - hostname to replace %h with
 *              hostname_len - size of hostname not including null ptr
 * Output     : none
 * Return     : pointer to new str buffer (caller must remember to free)
 * Data Used  : none
 * ------------------------------------------------------------------------- */
char *ReplaceHostname(char *str, size_t nBytes, char *hostname, size_t hostname_len) {
  char *ptr, str_beginning[nBytes], str_end[nBytes];
  size_t beginning_len, end_len;
  
  if (hostname[hostname_len] != '\0')
    return NULL;
  
  // mDNS strips out underscores from hostname, so let's just take care of that now.
  removeChar(hostname, &hostname_len, '_');
  
  while ((ptr = strstr(str, "%h")) != NULL) {
    beginning_len = ptr - str;
    end_len = nBytes - (ptr - str) - 2;
    strncpy(str_beginning, str, beginning_len);
    strncpy(str_end, ptr + 2, end_len);
    free(str);
    str = malloc(sizeof(char)*(nBytes + hostname_len - 1));
    strncpy(str, str_beginning, beginning_len);
    strncpy(str + beginning_len, hostname, hostname_len);
    strncpy(str + beginning_len + hostname_len, str_end, end_len);
    nBytes = nBytes + hostname_len - 2;
    str[nBytes] = '\0';
  }
  
  return str;
}

/* -------------------------------------------------------------------------
 * Function   : SetDomain
 * Description: Sets target domain using PlParam 'Domain'
 * Input      : value - comes from PlParam 'Domain'
 * Output     : none
 * Return     : 0 on success, -1 on error
 * Data Used  : ServiceDomain
 * ------------------------------------------------------------------------- */
int SetDomain(const char *value, void *data __attribute__ ((unused)), set_plugin_parameter_addon addon __attribute__ ((unused))) {
  assert(value != NULL);
  
  if (strlen(value) >= MAX_DOMAIN_LEN) {
    OLSR_PRINTF(1, "Invalid argument for \"Domain\"\n");
    return -1;
  }
  
  strncpy(ServiceDomain, value, MAX_DOMAIN_LEN - 1);
  ServiceDomain[MAX_DOMAIN_LEN - 1] = '\0';
  ServiceDomainLength = strlen(ServiceDomain);
  
  OLSR_PRINTF(1, "Set domain: %s\n", value);
  
  return 0;
}

/* -------------------------------------------------------------------------
 * Function   : AddToRrBuffer
 * Description: Adds an RR list to an RrListByTtl array based on TTL
 * Input      : buf - pointer to array of RrListByTtl struct the passed RR
 *                    list will be added to (caller must remember to free)
 *              ttl - TTL value of the RrListByTtl to add the RR list to
 *              entry - RR list to be added to buf
 *              section - type of DNS section the RR list came from
 * Output     : none
 * Return     : none
 * Data Used  : none
 * ------------------------------------------------------------------------- */
void AddToRrBuffer(struct RrListByTtl **buf, int ttl, ldns_rr *entry, int section) {
  struct RrListByTtl *s = NULL;
  int i;
  
  HASH_FIND_INT(*buf, &ttl, s);
  if (s==NULL) {
    s = malloc(sizeof(struct RrListByTtl));
    s->ttl = ttl;
    // create ldns_rr_list
    s->rr_list[section] = ldns_rr_list_new();
    for (i = 0; i < 3; ++i)
      s->rr_count[i] = 0;
    HASH_ADD_INT(*buf, ttl, s);
  }
  //check if entry already in s->rr_list
  if (!ldns_rr_list_contains_rr(s->rr_list[section], entry)) {
    //if not, add entry to s->rr_list
    ldns_rr_list_push_rr(s->rr_list[section], entry);
    s->rr_count[section] += 1;
  }
}

/* -------------------------------------------------------------------------
 * Function   : AddToServiceList
 * Description: Add a local service to ServiceList
 * Input      : name - the name of the service
 *              name_len - length of service name
 *              type - the type of the service (i.e. _http._tcp)
 *              type_len - length of type string
 *              path - file name of service (i.e. example.service)
 *              path_len - length of path string
 *              ttl - the service's TTL value (i.e. max number of hops away
 *                    the service should be advertised)
 * Output     : none
 * Return     : none
 * Data Used  : ServiceList
 * ------------------------------------------------------------------------- */
void AddToServiceList(char *name, size_t name_len, char *type, size_t type_len, char *path, size_t path_len, int ttl) {
  struct MdnsService *s = NULL;
  char *id = NULL;
  
  if (name_len > MAX_FIELD_LEN || type_len > MAX_FIELD_LEN || path_len > MAX_FILE_LEN)
    return;
  
  id = malloc(sizeof(char)*(name_len + type_len + 2));
  strncpy(id,name,name_len);
  id[name_len] = '.';
  strncpy(id + name_len + 1,type,type_len);
  id[name_len + 1 + type_len] = '\0';

  HASH_FIND_STR(ServiceList, id, s);
  if (s==NULL) {  // if entry doesn't exist, add it
    s = malloc(sizeof(struct MdnsService));
    strcpy(s->id, id);
    HASH_ADD_STR(ServiceList, id, s);
  }
  strcpy(s->service_name, name);
  strcpy(s->service_type, type);
  strcpy(s->file_path, path);
  s->ttl = ttl;
  s->uptodate = 1;
  free(id);
}

struct RrListByTtl *GetRrListByTtl(const struct RrListByTtl **buf, int ttl) {
  struct RrListByTtl *s = NULL;
  
  HASH_FIND_INT(*buf, &ttl, s);
  return s;
}

struct MdnsService *GetServiceById(char *id) {
  struct MdnsService *s = NULL;
  HASH_FIND_STR(ServiceList, id, s);
  return s;
}

void DeleteListByTtl(struct RrListByTtl **buf, int ttl) {
  struct RrListByTtl *s = NULL;
  HASH_FIND_INT(*buf, &ttl, s);
  if (s!=NULL) {
    DeleteList(buf, s);
  }
}

void DeleteList(struct RrListByTtl **buf, struct RrListByTtl *list) {
  HASH_DEL(*buf, list);
  //ldns_rr_list_deep_free(list->rr_list); /* this is done elsewhere */
  free(list);
}

void DeleteListArray(struct RrListByTtl **buf) {
  struct RrListByTtl *s, *tmp;
  HASH_ITER(hh, *buf, s, tmp) {
    DeleteList(buf, s);
  }
}

void DeleteAllServices(void) {
  struct MdnsService *s, *tmp;
  HASH_ITER(hh, ServiceList, s, tmp) {
    DeleteService(s);
  }
}

void DeleteService(struct MdnsService *service) {
  HASH_DEL(ServiceList, service);
  free(service);
}

void RemoveStaleServices(void) {
  struct MdnsService *s, *tmp;
  HASH_ITER(hh, ServiceList, s, tmp) {
    if (!s->uptodate) {
      OLSR_PRINTF(1, "%s: Removing local service: %s\n", PLUGIN_NAME_SHORT, s->file_path);
      DeleteService(s);
    }
  }
}

void removeChar(char *str, size_t *str_len, char garbage) {
  char *src, *dst;
  
  if (str[*str_len] != '\0')
    return;
  
  for (src = dst = str; *src != '\0'; src++) {
    *dst = *src;
    if (*dst != garbage) 
      dst++;
    else
      *str_len -= 1;
  }
  *dst = '\0';
}
