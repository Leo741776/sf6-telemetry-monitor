#include "flow_discovery.h"

#include <algorithm>
#include <iomanip>
#include <iostream>

namespace {

std::string format_ipv4(const unsigned char address[4]) {
    return std::to_string(address[0]) + "." +
           std::to_string(address[1]) + "." +
           std::to_string(address[2]) + "." +
           std::to_string(address[3]);
}

}

FlowDiscovery::FlowDiscovery(const std::string& local_ip)
    : local_ip(local_ip) {
}

bool FlowDiscovery::build_key(
    const IPv4Header& ipv4,
    const UDPHeader& udp,
    ConversationKey& key,
    bool& incoming
) const {
    const std::string source = format_ipv4(ipv4.source_ip);
    const std::string destination = format_ipv4(ipv4.destination_ip);

    if (source == local_ip) {
        key.local = {source, udp.source_port};
        key.remote = {destination, udp.destination_port};
        incoming = false;
        return true;
    }

    if (destination == local_ip) {
        key.local = {destination, udp.destination_port};
        key.remote = {source, udp.source_port};
        incoming = true;
        return true;
    }

    return false;
}

void FlowDiscovery::process_packet(const IPv4Header& ipv4, const UDPHeader& udp) {
    ConversationKey key;
    bool incoming = false;

    if (!build_key(ipv4, udp, key, incoming)) {
        return;
    }

    ConversationStatistics& stats = conversations[key];

    if (incoming) {
        ++stats.incoming_packets;
        ++stats.interval_incoming;
    } else {
        ++stats.outgoing_packets;
        ++stats.interval_outgoing;
    }

    if (udp.length <= MAX_PACKET_SIZE) {
        ++stats.small_packets;
        ++stats.interval_small;
    }

    stats.last_seen = Clock::now();
}

double FlowDiscovery::score(const ConversationStatistics& stats) const {
    const uint64_t incoming = stats.interval_incoming;
    const uint64_t outgoing = stats.interval_outgoing;
    const uint64_t total = incoming + outgoing;

    if (total < MIN_PACKETS || incoming == 0 || outgoing == 0) {
        return 0.0;
    }

    const double balance =
        static_cast<double>(std::min(incoming, outgoing)) /
        static_cast<double>(std::max(incoming, outgoing));

    const double small_ratio =
        static_cast<double>(stats.interval_small) /
        static_cast<double>(total);

    return static_cast<double>(total) *
           (0.5 + balance) *
           (0.5 + small_ratio);
}

void FlowDiscovery::remove_inactive() {
    const auto now = Clock::now();

    for (auto it = conversations.begin(); it != conversations.end();) {
        const double idle =
            std::chrono::duration<double>(now - it->second.last_seen).count();

        if (idle >= FLOW_TIMEOUT_SECONDS) {
            if (selected && it->first == selected_flow) {
                selected = false;
                std::cout << "\nSelected flow inactive\n";
            }

            it = conversations.erase(it);
        } else {
            ++it;
        }
    }
}

void FlowDiscovery::select_flow() {
    double best_score = 0.0;
    ConversationKey best_key;
    bool found = false;

    for (const auto& entry : conversations) {
        const double candidate_score = score(entry.second);

        if (candidate_score > best_score) {
            best_score = candidate_score;
            best_key = entry.first;
            found = true;
        }
    }

    if (!found) {
        return;
    }

    selected_flow = best_key;
    selected = true;
    selection_changed_flag = true;

    std::cout << "\nSelected UDP flow\n";
    std::cout << "Local: "
              << selected_flow.local.ip << ':'
              << selected_flow.local.port << '\n';
    std::cout << "Remote: "
              << selected_flow.remote.ip << ':'
              << selected_flow.remote.port << '\n';
}

void FlowDiscovery::reset_interval() {
    for (auto& entry : conversations) {
        entry.second.interval_incoming = 0;
        entry.second.interval_outgoing = 0;
        entry.second.interval_small = 0;
    }
}

void FlowDiscovery::print_status() const {
    std::cout << "\n========== UDP FLOW DISCOVERY ==========\n";
    std::cout << "Tracked conversations: " << conversations.size() << '\n';

    if (selected) {
        std::cout << "Selected: "
                  << selected_flow.local.ip << ':'
                  << selected_flow.local.port
                  << " <-> "
                  << selected_flow.remote.ip << ':'
                  << selected_flow.remote.port << '\n';
    } else {
        std::cout << "Selected: None\n";
    }

    std::cout << "========================================\n" << std::flush;
}

void FlowDiscovery::update() {
    const auto now = Clock::now();

    const double elapsed =
        std::chrono::duration<double>(now - interval_start).count();

    if (elapsed < REPORT_INTERVAL_SECONDS) {
        return;
    }

    remove_inactive();

    if (!selected) {
        select_flow();
    }

    print_status();
    reset_interval();

    interval_start = now;
}

bool FlowDiscovery::matches_selected(
    const IPv4Header& ipv4,
    const UDPHeader& udp
) const {
    if (!selected) {
        return false;
    }

    ConversationKey key;
    bool incoming = false;

    if (!build_key(ipv4, udp, key, incoming)) {
        return false;
    }

    return key == selected_flow;
}

bool FlowDiscovery::selection_changed() {
    const bool changed = selection_changed_flag;
    selection_changed_flag = false;
    return changed;
}