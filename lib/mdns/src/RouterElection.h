#include <netinet/in.h>

#define ELECTION_TIMER		15
#define HELLO_TIMER		20
#define INIT_TIMER		1
#define ENTRYTTL		10

struct RtElHelloPkt{
  unsigned char head[4]; //"$REP"
  int ipFamily;
  union olsr_ip_addr router_id;
  uint8_t network_id;
} __attribute__((__packed__));

struct RouterListEntry{
  struct in_addr router_id;
  uint8_t network_id;
  int ttl;

  struct list_entity list;
};

struct RouterListEntry6{
  struct in6_addr router_id;
  uint8_t network_id;
  int ttl;

  struct list_entity list;
};

extern int ISMASTER;
uint8_t NETWORK_ID;
union olsr_ip_addr ROUTER_ID;

int UpdateRouterList (struct RouterListEntry *listEntry);	//update router list
int UpdateRouterList6 (struct RouterListEntry6 *listEntry6);
int ParseElectionPacket (struct RtElHelloPkt *rcvPkt, struct RouterListEntry *listEntry);	//used to parse a received packet into
int ParseElectionPacket6 (struct RtElHelloPkt *rcvPkt, struct RouterListEntry6 *listEntry6);	//a list entry for ipv4/ipv6
int InitRouterList ();
void helloTimer (void *foo __attribute__ ((unused)));
void electTimer (void *foo __attribute__ ((unused)));
void initTimer (void *foo __attribute__ ((unused)));
int set_Network_ID(const char *Network_ID, void *data __attribute__ ((unused)), set_plugin_parameter_addon addon __attribute__ ((unused)));
