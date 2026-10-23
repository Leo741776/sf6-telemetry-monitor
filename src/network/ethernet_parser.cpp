#include "ethernet_parser.h"

#include <cstddef>

bool parse_ethernet(const PacketMetadata* header, const unsigned char* packet, uint16_t& ether_type) {
    constexpr size_t ETHERNET_HEADER_LENGTH = 14;
    constexpr size_t ETHERTYPE_OFFSET = 12;

    if (header->caplen < ETHERNET_HEADER_LENGTH) {
        return false;
    }

    ether_type = (static_cast<uint16_t>(packet[ETHERTYPE_OFFSET]) << 8) |
                 static_cast<uint16_t>(packet[ETHERTYPE_OFFSET + 1]);

    return true;
}