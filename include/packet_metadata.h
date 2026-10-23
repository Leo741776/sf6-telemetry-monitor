#ifndef PACKET_METADATA_H
#define PACKET_METADATA_H

#include <cstdint>

struct PacketMetadata {
    struct {
        uint64_t tv_sec;
        uint32_t tv_usec;
    } ts;

    uint32_t caplen;
    uint32_t len;
};

using PacketHandler = void (*)(unsigned char* user_data, const PacketMetadata* header, const unsigned char* packet);

#endif