#include "traffic_analyzer.h"

#include <algorithm>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <tuple>
#include <vector>

namespace {

constexpr auto WINDOW_DURATION = std::chrono::seconds(2);
constexpr auto FLOW_TIMEOUT = std::chrono::seconds(3);

std::string format_ipv4(const unsigned char address[4]) {
    return std::to_string(address[0]) + "." +
           std::to_string(address[1]) + "." +
           std::to_string(address[2]) + "." +
           std::to_string(address[3]);
}

uint64_t timestamp_to_microseconds(const PacketMetadata* header) {
    return static_cast<uint64_t>(header->ts.tv_sec) * 1000000ULL +
           static_cast<uint64_t>(header->ts.tv_usec);
}

void prune_window(
    FlowStatistics& stats,
    std::chrono::steady_clock::time_point now
) {
    while (!stats.window_samples.empty() &&
           now - stats.window_samples.front().timestamp >= WINDOW_DURATION) {

        const WindowSample& expired = stats.window_samples.front();

        stats.window_bytes -= expired.bytes;

        if (expired.has_jitter) {
            stats.window_jitter_sum_ms -= expired.jitter_ms;
            --stats.window_jitter_samples;
        }

        stats.window_samples.pop_front();
    }
}

}

bool FlowKey::operator<(const FlowKey& other) const {
    return std::tie(source_ip, source_port, destination_ip, destination_port) <
           std::tie(other.source_ip, other.source_port, other.destination_ip, other.destination_port);
}

void TrafficAnalyzer::process_packet(const IPv4Header& ipv4, const UDPHeader& udp, const PacketMetadata* header) {
    if (header == nullptr) {
        return;
    }

    const auto now = Clock::now();

    FlowKey key{
        format_ipv4(ipv4.source_ip),
        format_ipv4(ipv4.destination_ip),
        udp.source_port,
        udp.destination_port
    };

    FlowStatistics& stats = flows[key];

    ++stats.total_packets;
    stats.total_bytes += udp.length;

    ++stats.interval_packets;
    stats.interval_bytes += udp.length;

    stats.last_seen = now;

    const uint64_t timestamp_us = timestamp_to_microseconds(header);

    bool has_jitter = false;
    double jitter_ms = 0.0;

    if (stats.has_previous_timestamp) {
        if (timestamp_us >= stats.previous_timestamp_us) {
            const double interval_ms =
                static_cast<double>(timestamp_us - stats.previous_timestamp_us) / 1000.0;

            stats.interval_sum_ms += interval_ms;
            ++stats.interval_samples;

            if (stats.has_previous_interval) {
                jitter_ms = std::abs(interval_ms - stats.previous_interval_ms);
                has_jitter = true;

                stats.jitter_sum_ms += jitter_ms;
                ++stats.jitter_samples;
            }

            stats.previous_interval_ms = interval_ms;
            stats.has_previous_interval = true;
        } else {
            ++stats.out_of_order_timestamps;
            stats.has_previous_interval = false;
        }
    }

    stats.previous_timestamp_us = timestamp_us;
    stats.has_previous_timestamp = true;

    stats.window_samples.push_back({now, udp.length, has_jitter, jitter_ms});
    stats.window_bytes += udp.length;

    if (has_jitter) {
        stats.window_jitter_sum_ms += jitter_ms;
        ++stats.window_jitter_samples;
    }

    prune_window(stats, now);

    const double elapsed = std::chrono::duration<double>(now - interval_start).count();

    if (elapsed >= REPORT_INTERVAL_SECONDS) {
        print_report(now, elapsed);

        for (auto& entry : flows) {
            FlowStatistics& flow = entry.second;

            flow.interval_packets = 0;
            flow.interval_bytes = 0;

            flow.interval_samples = 0;
            flow.interval_sum_ms = 0.0;

            flow.jitter_samples = 0;
            flow.jitter_sum_ms = 0.0;
        }

        interval_start = now;
    }
}

TelemetrySnapshot TrafficAnalyzer::sample(const std::string& local_ip) {
    const auto now = Clock::now();

    const double elapsed_since_reset =
        std::chrono::duration<double>(now - window_start).count();

    const double observation_seconds =
        std::min(static_cast<double>(WINDOW_DURATION.count()), elapsed_since_reset);

    TelemetrySnapshot snapshot;

    uint64_t incoming_packets = 0;
    uint64_t incoming_bytes = 0;
    uint64_t incoming_jitter_samples = 0;
    double incoming_jitter_sum = 0.0;

    uint64_t outgoing_packets = 0;
    uint64_t outgoing_bytes = 0;
    uint64_t outgoing_jitter_samples = 0;
    double outgoing_jitter_sum = 0.0;

    for (auto& entry : flows) {
        const FlowKey& key = entry.first;
        FlowStatistics& stats = entry.second;

        prune_window(stats, now);

        const bool incoming = key.destination_ip == local_ip;
        const bool outgoing = key.source_ip == local_ip;

        if (incoming || outgoing) {
            if (now - stats.last_seen < FLOW_TIMEOUT) {
                snapshot.flow_detected = true;
            }
        }

        if (incoming) {
            incoming_packets += stats.window_samples.size();
            incoming_bytes += stats.window_bytes;
            incoming_jitter_samples += stats.window_jitter_samples;
            incoming_jitter_sum += stats.window_jitter_sum_ms;
        }

        if (outgoing) {
            outgoing_packets += stats.window_samples.size();
            outgoing_bytes += stats.window_bytes;
            outgoing_jitter_samples += stats.window_jitter_samples;
            outgoing_jitter_sum += stats.window_jitter_sum_ms;
        }
    }

    if (observation_seconds > 0.0) {
        snapshot.incoming.packets_per_second = incoming_packets / observation_seconds;
        snapshot.incoming.kilobytes_per_second = incoming_bytes / (observation_seconds * 1000.0);

        snapshot.outgoing.packets_per_second = outgoing_packets / observation_seconds;
        snapshot.outgoing.kilobytes_per_second = outgoing_bytes / (observation_seconds * 1000.0);
    }

    if (incoming_jitter_samples > 0) {
        snapshot.incoming.jitter_ms = incoming_jitter_sum / incoming_jitter_samples;
        snapshot.incoming.jitter_valid = true;
    }

    if (outgoing_jitter_samples > 0) {
        snapshot.outgoing.jitter_ms = outgoing_jitter_sum / outgoing_jitter_samples;
        snapshot.outgoing.jitter_valid = true;
    }

    return snapshot;
}

void TrafficAnalyzer::print_report(Clock::time_point now, double interval_seconds) {
    using FlowEntry = std::pair<const FlowKey, FlowStatistics>;

    std::vector<const FlowEntry*> active_flows;

    for (const auto& entry : flows) {
        if (entry.second.interval_packets > 0) {
            active_flows.push_back(&entry);
        }
    }

    std::sort(active_flows.begin(), active_flows.end(),
        [](const FlowEntry* a, const FlowEntry* b) {
            return a->second.interval_packets > b->second.interval_packets;
        }
    );

    std::cout << "\n========== SF6 NETWORK TELEMETRY ==========\n";
    std::cout << "Active flows: " << active_flows.size() << '\n';

    const size_t display_count = std::min(active_flows.size(), MAX_DISPLAY_FLOWS);

    std::cout << std::fixed << std::setprecision(2);

    for (size_t i = 0; i < display_count; ++i) {
        const auto& key = active_flows[i]->first;
        const auto& stats = active_flows[i]->second;

        const double packets_per_second = stats.interval_packets / interval_seconds;
        const double bytes_per_second = stats.interval_bytes / interval_seconds;

        const double average_interval_ms =
            stats.interval_samples > 0
                ? stats.interval_sum_ms / stats.interval_samples
                : 0.0;

        const double average_jitter_ms =
            stats.jitter_samples > 0
                ? stats.jitter_sum_ms / stats.jitter_samples
                : 0.0;

        const double seconds_since_last_packet =
            std::chrono::duration<double>(now - stats.last_seen).count();

        std::cout << "\nFlow " << (i + 1) << '\n';

        std::cout << "  "
                  << key.source_ip << ':'
                  << key.source_port
                  << " -> "
                  << key.destination_ip << ':'
                  << key.destination_port << '\n';

        std::cout << "  Total packets: " << stats.total_packets << '\n';
        std::cout << "  Total bytes: " << stats.total_bytes << '\n';
        std::cout << "  Packets/sec: " << packets_per_second << '\n';
        std::cout << "  Bytes/sec: " << bytes_per_second << '\n';

        if (stats.interval_samples > 0) {
            std::cout << "  Average interval: " << average_interval_ms << " ms\n";
        } else {
            std::cout << "  Average interval: N/A\n";
        }

        if (stats.jitter_samples > 0) {
            std::cout << "  Average jitter: " << average_jitter_ms << " ms\n";
        } else {
            std::cout << "  Average jitter: N/A\n";
        }

        std::cout << "  Out-of-order timestamps: " << stats.out_of_order_timestamps << '\n';
        std::cout << "  Last seen: " << seconds_since_last_packet << " seconds ago\n";
    }

    std::cout << "\n===========================================\n" << std::flush;
}

void TrafficAnalyzer::reset() {
    flows.clear();
    interval_start = Clock::now();
    window_start = Clock::now();
}