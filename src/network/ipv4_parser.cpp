#include "ipv4_parser.h"

bool parse_ipv4(const PacketMetadata* header, const unsigned char* packet, size_t ipv4_offset, IPv4Header& ipv4) {
    constexpr size_t IPV4_MIN_HEADER_LENGTH = 20;

    if (header->caplen < ipv4_offset + 1) {
        return false;
    }

    unsigned char version = packet[ipv4_offset] >> 4;
    unsigned char ihl = packet[ipv4_offset] & 0x0F;

    size_t ipv4_header_length = ihl * 4;

    if (version != 4 || ipv4_header_length < IPV4_MIN_HEADER_LENGTH) {
        return false;
    }

    if (header->caplen < ipv4_offset + ipv4_header_length) {
        return false;
    }

    unsigned char protocol = packet[ipv4_offset + 9];

    const unsigned char* source_ip = packet + ipv4_offset + 12;
    const unsigned char* destination_ip = packet + ipv4_offset + 16;

    ipv4.version = version;
    ipv4.ihl = ihl;
    ipv4.header_length = ipv4_header_length;
    ipv4.protocol = protocol;

    for (size_t i = 0; i < 4; ++i) {
        ipv4.source_ip[i] = source_ip[i];
        ipv4.destination_ip[i] = destination_ip[i];
    }

    return true;
}