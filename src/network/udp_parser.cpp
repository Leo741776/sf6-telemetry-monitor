#include "udp_parser.h"

constexpr size_t UDP_HEADER_LENGTH = 8;

bool parse_udp(const PacketMetadata* header, const unsigned char* packet, size_t ipv4_offset, const IPv4Header& ipv4, UDPHeader& udp) {
    if (header == nullptr || packet == nullptr) {
        return false;
    }

    if (ipv4.header_length < 20) {
        return false;
    }

    if (ipv4_offset > header->caplen ||
        ipv4.header_length > header->caplen - ipv4_offset) {
        return false;
    }

    size_t total_length =
        (static_cast<size_t>(packet[ipv4_offset + 2]) << 8) |
        static_cast<size_t>(packet[ipv4_offset + 3]);

    if (total_length < ipv4.header_length + UDP_HEADER_LENGTH) {
        return false;
    }

    uint16_t fragment_field =
        (static_cast<uint16_t>(packet[ipv4_offset + 6]) << 8) |
        static_cast<uint16_t>(packet[ipv4_offset + 7]);

    if ((fragment_field & 0x3FFF) != 0) {
        return false;
    }

    if (ipv4.protocol != 17) {
        return false;
    }

    size_t udp_offset = ipv4_offset + ipv4.header_length;

    if (udp_offset > header->caplen ||
        UDP_HEADER_LENGTH > header->caplen - udp_offset) {
        return false;
    }

    uint16_t source_port =
        (static_cast<uint16_t>(packet[udp_offset]) << 8) |
        static_cast<uint16_t>(packet[udp_offset + 1]);

    uint16_t destination_port =
        (static_cast<uint16_t>(packet[udp_offset + 2]) << 8) |
        static_cast<uint16_t>(packet[udp_offset + 3]);

    uint16_t udp_length =
        (static_cast<uint16_t>(packet[udp_offset + 4]) << 8) |
        static_cast<uint16_t>(packet[udp_offset + 5]);

    if (udp_length < UDP_HEADER_LENGTH ||
        udp_length > total_length - ipv4.header_length) {
        return false;
    }

    size_t payload_length = udp_length - UDP_HEADER_LENGTH;
    size_t captured_payload_length = 0;

    if (header->caplen > udp_offset + UDP_HEADER_LENGTH) {
        captured_payload_length = header->caplen - (udp_offset + UDP_HEADER_LENGTH);
    }

    if (captured_payload_length > payload_length) {
        captured_payload_length = payload_length;
    }

    udp.source_port = source_port;
    udp.destination_port = destination_port;
    udp.length = udp_length;
    udp.payload_length = payload_length;
    udp.captured_payload_length = captured_payload_length;

    return true;
}