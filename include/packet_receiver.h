#ifndef PACKET_RECEIVER_H
#define PACKET_RECEIVER_H

#include "packet_metadata.h"

int start_packet_receiver(PacketHandler callback, unsigned char* user_data);

#endif