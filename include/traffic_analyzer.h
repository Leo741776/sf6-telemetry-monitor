#ifndef TRAFFIC_ANALYZER_H
#define TRAFFIC_ANALYZER_H

#include "ipv4_parser.h"
#include "udp_parser.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <string>

struct FlowKey {
    std::string source_ip;
    std::string destination_ip;
    uint16_t source_port;
    uint16_t destination_port;

    bool operator<(const FlowKey& other) const;
};

struct WindowSample {
    std::chrono::steady_clock::time_point timestamp;
    uint64_t bytes = 0;
    bool has_jitter = false;
    double jitter_ms = 0.0;
};

struct FlowStatistics {
    std::deque<WindowSample> window_samples;
    uint64_t window_bytes = 0;
    uint64_t window_jitter_samples = 0;
    double window_jitter_sum_ms = 0.0;

    uint64_t total_packets = 0;
    uint64_t total_bytes = 0;

    uint64_t interval_packets = 0;
    uint64_t interval_bytes = 0;

    uint64_t previous_timestamp_us = 0;
    bool has_previous_timestamp = false;

    double previous_interval_ms = 0.0;
    bool has_previous_interval = false;

    uint64_t interval_samples = 0;
    double interval_sum_ms = 0.0;

    uint64_t jitter_samples = 0;
    double jitter_sum_ms = 0.0;

    uint64_t out_of_order_timestamps = 0;

    std::chrono::steady_clock::time_point last_seen;
};

struct DirectionMetrics {
    double packets_per_second = 0.0;
    double kilobytes_per_second = 0.0;
    double jitter_ms = 0.0;
    bool jitter_valid = false;
};

struct TelemetrySnapshot {
    DirectionMetrics incoming;
    DirectionMetrics outgoing;
    bool flow_detected = false;
};

class TrafficAnalyzer {
public:
    void process_packet(const IPv4Header& ipv4, const UDPHeader& udp, const PacketMetadata* header);
    void reset();

    TelemetrySnapshot sample(const std::string& local_ip);

private:
    using Clock = std::chrono::steady_clock;

    std::map<FlowKey, FlowStatistics> flows;

    Clock::time_point interval_start = Clock::now();
    Clock::time_point window_start = Clock::now();

    static constexpr int REPORT_INTERVAL_SECONDS = 5;
    static constexpr size_t MAX_DISPLAY_FLOWS = 10;

    void print_report(Clock::time_point now, double interval_seconds);
};

#endif