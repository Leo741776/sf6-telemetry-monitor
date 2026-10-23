#ifndef UDP_PARSER_H
#define UDP_PARSER_H

#include "ipv4_parser.h"
#include "packet_metadata.h"

#include <cstddef>
#include <cstdint>

struct UDPHeader {
    uint16_t source_port;
    uint16_t destination_port;
    uint16_t length;
    size_t payload_length;
    size_t captured_payload_length;
};

bool parse_udp(const PacketMetadata* header, const unsigned char* packet, size_t ipv4_offset, const IPv4Header& ipv4, UDPHeader& udp);

#endif