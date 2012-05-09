#ifndef GATEWAYSPEEDFILE_H
#define GATEWAYSPEEDFILE_H

#include "olsr.h"

#define GATEWAY_SPEED_UPLINK   "upstream"
#define GATEWAY_SPEED_DOWNLINK "downstream"

bool startGatewaySpeedFile(void);
void stopGatewaySpeedFile(void);
void readGatewaySpeedFile(char * fileName);

#endif /* GATEWAYSPEEDFILE_H */
