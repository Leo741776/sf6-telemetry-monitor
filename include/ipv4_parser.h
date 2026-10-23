#ifndef IPV4_PARSER_H
#define IPV4_PARSER_H

#include "packet_metadata.h"

#include <cstddef>
#include <cstdint>

struct IPv4Header {
    unsigned char version;
    unsigned char ihl;
    size_t header_length;
    unsigned char protocol;
    unsigned char source_ip[4];
    unsigned char destination_ip[4];
};

bool parse_ipv4(const PacketMetadata* header, const unsigned char* packet, size_t ipv4_offset, IPv4Header& ipv4);

#endif