#ifndef FLOW_DISCOVERY_H
#define FLOW_DISCOVERY_H

#include "ipv4_parser.h"
#include "udp_parser.h"

#include <chrono>
#include <cstdint>
#include <map>
#include <string>
#include <tuple>

struct Endpoint {
    std::string ip;
    uint16_t port = 0;

    bool operator<(const Endpoint& other) const {
        return std::tie(ip, port) < std::tie(other.ip, other.port);
    }

    bool operator==(const Endpoint& other) const {
        return ip == other.ip && port == other.port;
    }
};

struct ConversationKey {
    Endpoint local;
    Endpoint remote;

    bool operator<(const ConversationKey& other) const {
        return std::tie(local, remote) < std::tie(other.local, other.remote);
    }

    bool operator==(const ConversationKey& other) const {
        return local == other.local && remote == other.remote;
    }
};

struct ConversationStatistics {
    uint64_t incoming_packets = 0;
    uint64_t outgoing_packets = 0;
    uint64_t small_packets = 0;

    uint64_t interval_incoming = 0;
    uint64_t interval_outgoing = 0;
    uint64_t interval_small = 0;

    std::chrono::steady_clock::time_point last_seen{};
};

class FlowDiscovery {
public:
    using Clock = std::chrono::steady_clock;

    explicit FlowDiscovery(const std::string& local_ip);

    void process_packet(const IPv4Header& ipv4, const UDPHeader& udp);
    void update();

    bool matches_selected(const IPv4Header& ipv4, const UDPHeader& udp) const;
    bool selection_changed();

private:
    std::string local_ip;
    std::map<ConversationKey, ConversationStatistics> conversations;

    ConversationKey selected_flow{};
    bool selected = false;
    bool selection_changed_flag = false;

    Clock::time_point interval_start = Clock::now();

    static constexpr int REPORT_INTERVAL_SECONDS = 5;
    static constexpr int FLOW_TIMEOUT_SECONDS = 10;
    static constexpr uint64_t MIN_PACKETS = 50;
    static constexpr uint16_t MAX_PACKET_SIZE = 256;

    bool build_key(
        const IPv4Header& ipv4,
        const UDPHeader& udp,
        ConversationKey& key,
        bool& incoming
    ) const;

    double score(const ConversationStatistics& stats) const;
    void select_flow();
    void remove_inactive();
    void reset_interval();
    void print_status() const;
};

#endif