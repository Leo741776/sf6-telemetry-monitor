#include "packet_receiver.h"

#include <arpa/inet.h>
#include <array>
#include <cerrno>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {

constexpr uint16_t LISTEN_PORT = 47000;

constexpr size_t WIRE_HEADER_LENGTH = 24;
constexpr size_t BUFFER_SIZE = 65536;

constexpr uint8_t PROTOCOL_VERSION = 2;
constexpr uint8_t PROTOCOL_FLAGS = 0;

constexpr size_t OFFSET_MAGIC = 0;
constexpr size_t OFFSET_VERSION = 4;
constexpr size_t OFFSET_FLAGS = 5;
constexpr size_t OFFSET_HEADER_LENGTH = 6;
constexpr size_t OFFSET_TIMESTAMP_SECONDS = 8;
constexpr size_t OFFSET_TIMESTAMP_MICROSECONDS = 12;
constexpr size_t OFFSET_CAPTURED_LENGTH = 16;
constexpr size_t OFFSET_ORIGINAL_LENGTH = 18;
constexpr size_t OFFSET_SEQUENCE_NUMBER = 20;
constexpr size_t OFFSET_PACKET_DATA = WIRE_HEADER_LENGTH;

constexpr uint32_t MICROSECONDS_PER_SECOND = 1000000;
constexpr size_t SEQUENCE_WINDOW_SIZE = 256;

constexpr unsigned char MAGIC[] = {'S', 'F', '6', 'P'};

static_assert(OFFSET_PACKET_DATA == 24, "SF6P version 2 requires a 24-byte header");

volatile std::sig_atomic_t stop_requested = 0;

struct ReceiverStatistics {
    uint64_t datagrams_received = 0;
    uint64_t packets_processed = 0;
    uint64_t datagrams_rejected = 0;

    uint64_t unique_sequences = 0;
    uint64_t missing_sequences = 0;
    uint64_t late_arrivals = 0;
    uint64_t out_of_order = 0;
    uint64_t duplicates = 0;
    uint64_t too_old = 0;
};

ReceiverStatistics statistics;

class SequenceTracker {
public:
    void process(uint32_t sequence) {
        if (!initialized) {
            initialized = true;
            highest_sequence = sequence;
            mark_received(sequence);
            ++statistics.unique_sequences;
            return;
        }

        const int32_t difference = static_cast<int32_t>(sequence - highest_sequence);

        if (difference > 0) {
            const uint32_t gap = static_cast<uint32_t>(difference - 1);

            statistics.missing_sequences += gap;
            highest_sequence = sequence;

            mark_received(sequence);

            ++statistics.unique_sequences;
            return;
        }

        if (difference == 0) {
            ++statistics.duplicates;
            return;
        }

        const uint32_t distance = highest_sequence - sequence;

        if (distance >= SEQUENCE_WINDOW_SIZE) {
            ++statistics.too_old;
            return;
        }

        if (was_received(sequence)) {
            ++statistics.duplicates;
            return;
        }

        mark_received(sequence);

        ++statistics.unique_sequences;
        ++statistics.out_of_order;
        ++statistics.late_arrivals;

        if (statistics.missing_sequences > 0) {
            --statistics.missing_sequences;
        }
    }

private:
    struct SequenceSlot {
        uint32_t sequence = 0;
        bool valid = false;
    };

    std::array<SequenceSlot, SEQUENCE_WINDOW_SIZE> slots{};

    bool initialized = false;
    uint32_t highest_sequence = 0;

    void mark_received(uint32_t sequence) {
        SequenceSlot& slot = slots[sequence % SEQUENCE_WINDOW_SIZE];

        slot.sequence = sequence;
        slot.valid = true;
    }

    bool was_received(uint32_t sequence) const {
        const SequenceSlot& slot = slots[sequence % SEQUENCE_WINDOW_SIZE];

        return slot.valid && slot.sequence == sequence;
    }
};

void handle_interrupt(int signal_number) {
    (void)signal_number;
    stop_requested = 1;
}

uint16_t read_u16_be(const unsigned char* data) {
    return static_cast<uint16_t>(
        (static_cast<uint16_t>(data[0]) << 8) |
        static_cast<uint16_t>(data[1])
    );
}

uint32_t read_u32_be(const unsigned char* data) {
    return (static_cast<uint32_t>(data[0]) << 24) |
           (static_cast<uint32_t>(data[1]) << 16) |
           (static_cast<uint32_t>(data[2]) << 8) |
           static_cast<uint32_t>(data[3]);
}

bool decode_datagram(
    const unsigned char* datagram,
    size_t datagram_length,
    PacketMetadata& packet_header,
    const unsigned char*& packet,
    uint32_t& sequence_number
) {
    if (datagram == nullptr || datagram_length < WIRE_HEADER_LENGTH) {
        return false;
    }

    if (std::memcmp(datagram + OFFSET_MAGIC, MAGIC, sizeof(MAGIC)) != 0) {
        return false;
    }

    if (datagram[OFFSET_VERSION] != PROTOCOL_VERSION ||
        datagram[OFFSET_FLAGS] != PROTOCOL_FLAGS) {
        return false;
    }

    const uint16_t header_length = read_u16_be(datagram + OFFSET_HEADER_LENGTH);

    if (header_length != WIRE_HEADER_LENGTH) {
        return false;
    }

    const uint32_t timestamp_seconds = read_u32_be(datagram + OFFSET_TIMESTAMP_SECONDS);
    const uint32_t timestamp_microseconds = read_u32_be(datagram + OFFSET_TIMESTAMP_MICROSECONDS);
    const uint16_t captured_length = read_u16_be(datagram + OFFSET_CAPTURED_LENGTH);
    const uint16_t original_length = read_u16_be(datagram + OFFSET_ORIGINAL_LENGTH);

    sequence_number = read_u32_be(datagram + OFFSET_SEQUENCE_NUMBER);

    if (timestamp_microseconds >= MICROSECONDS_PER_SECOND) {
        return false;
    }

    if (original_length < captured_length) {
        return false;
    }

    if (datagram_length != OFFSET_PACKET_DATA + static_cast<size_t>(captured_length)) {
        return false;
    }

    packet_header = {};

    packet_header.ts.tv_sec =
        static_cast<decltype(packet_header.ts.tv_sec)>(timestamp_seconds);

    packet_header.ts.tv_usec =
        static_cast<decltype(packet_header.ts.tv_usec)>(timestamp_microseconds);

    packet_header.caplen = captured_length;
    packet_header.len = original_length;

    packet = datagram + OFFSET_PACKET_DATA;

    return true;
}

}

int start_packet_receiver(PacketHandler callback, unsigned char* user_data) {
    if (callback == nullptr) {
        std::cerr << "Packet receiver requires a callback." << std::endl;
        return 1;
    }

    statistics = {};
    stop_requested = 0;

    SequenceTracker sequence_tracker;

    const int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (socket_fd < 0) {
        std::cerr << "Failed to create UDP socket: "
                  << std::strerror(errno) << std::endl;
        return 1;
    }

    constexpr int RECEIVE_BUFFER_SIZE = 4 * 1024 * 1024;

    if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVBUF,
                   &RECEIVE_BUFFER_SIZE, sizeof(RECEIVE_BUFFER_SIZE)) < 0) {
        std::cerr << "Warning: Could not increase receive buffer: "
                  << std::strerror(errno) << std::endl;
    }

    sockaddr_in address{};

    address.sin_family = AF_INET;
    address.sin_port = htons(LISTEN_PORT);
    address.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(socket_fd, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) < 0) {
        std::cerr << "Failed to bind UDP port " << LISTEN_PORT << ": "
                  << std::strerror(errno) << std::endl;

        close(socket_fd);
        return 1;
    }

    struct sigaction action{};
    struct sigaction previous_action{};

    action.sa_handler = handle_interrupt;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;

    if (sigaction(SIGINT, &action, &previous_action) < 0) {
        std::cerr << "Failed to install SIGINT handler: "
                  << std::strerror(errno) << std::endl;

        close(socket_fd);
        return 1;
    }

    std::cout << "SF6 Telemetry Monitor" << std::endl;
    std::cout << "UDP receiver listening on port " << LISTEN_PORT << std::endl;
    std::cout << "Protocol version: " << static_cast<unsigned>(PROTOCOL_VERSION) << std::endl;
    std::cout << "Expected wire header: " << WIRE_HEADER_LENGTH << " bytes" << std::endl;
    std::cout << "Sequence tracking window: " << SEQUENCE_WINDOW_SIZE << " packets" << std::endl;
    std::cout << "Press Ctrl+C to stop." << std::endl;

    unsigned char buffer[BUFFER_SIZE];

    while (!stop_requested) {
        sockaddr_in sender{};
        socklen_t sender_length = sizeof(sender);

        const ssize_t received = recvfrom(
            socket_fd,
            buffer,
            sizeof(buffer),
            0,
            reinterpret_cast<sockaddr*>(&sender),
            &sender_length
        );

        if (received < 0) {
            if (errno == EINTR && stop_requested) {
                break;
            }

            if (errno == EINTR) {
                continue;
            }

            std::cerr << "UDP receive error: "
                      << std::strerror(errno) << std::endl;
            break;
        }

        ++statistics.datagrams_received;

        PacketMetadata packet_header{};
        const unsigned char* packet = nullptr;
        uint32_t sequence_number = 0;

        if (!decode_datagram(
                buffer,
                static_cast<size_t>(received),
                packet_header,
                packet,
                sequence_number
            )) {
            ++statistics.datagrams_rejected;
            continue;
        }

        sequence_tracker.process(sequence_number);

        callback(user_data, &packet_header, packet);

        ++statistics.packets_processed;
    }

    sigaction(SIGINT, &previous_action, nullptr);
    close(socket_fd);

    std::cout << "\nUDP receiver stopped." << std::endl;
    std::cout << "Datagrams received: " << statistics.datagrams_received << std::endl;
    std::cout << "Packets processed: " << statistics.packets_processed << std::endl;
    std::cout << "Datagrams rejected: " << statistics.datagrams_rejected << std::endl;

    std::cout << "\nTransport statistics" << std::endl;
    std::cout << "Unique sequences: " << statistics.unique_sequences << std::endl;
    std::cout << "Missing sequences (unresolved): " << statistics.missing_sequences << std::endl;
    std::cout << "Out-of-order arrivals: " << statistics.out_of_order << std::endl;
    std::cout << "Late arrivals: " << statistics.late_arrivals << std::endl;
    std::cout << "Duplicate sequences: " << statistics.duplicates << std::endl;
    std::cout << "Too-old sequences: " << statistics.too_old << std::endl;

    return stop_requested ? 0 : 1;
}