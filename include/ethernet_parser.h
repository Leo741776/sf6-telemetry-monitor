#ifndef ETHERNET_PARSER_H
#define ETHERNET_PARSER_H

#include <cstdint>
#include "packet_metadata.h"

bool parse_ethernet(const PacketMetadata* header, const unsigned char* packet, uint16_t& ether_type);

#endif