#include "ethernet_parser.h"
#include "flow_discovery.h"
#include "ipv4_parser.h"
#include "packet_receiver.h"
#include "st7735.h"
#include "traffic_analyzer.h"
#include "udp_parser.h"

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>

namespace {

TrafficAnalyzer analyzer;
std::unique_ptr<FlowDiscovery> discovery;
std::mutex analyzer_mutex;

std::string FormatValue(double value, int precision) {
    std::ostringstream stream;
    stream << std::fixed << std::setprecision(precision) << value;
    return stream.str();
}

void UpdateLine(
    ST7735& display,
    std::array<std::string, 8>& previous,
    std::size_t index,
    int y,
    const std::string& text,
    uint16_t color
) {
    if (previous[index] == text) {
        return;
    }

    display.FillRectangle(7, y, 114, 8, ST7735::BLACK);
    display.DrawString(7, y, text, color);

    previous[index] = text;
}

void InitializeDashboard(ST7735& display) {
    display.Initialize();
    display.FillScreen(ST7735::BLACK);

    display.DrawString(7, 6, "SF6 NETWORK MONITOR", ST7735::CYAN);
    display.FillRectangle(7, 18, 114, 1, ST7735::WHITE);

    display.DrawString(7, 43, "INCOMING", ST7735::YELLOW);
    display.DrawString(7, 97, "OUTGOING", ST7735::YELLOW);

    display.FillRectangle(7, 143, 114, 1, ST7735::WHITE);
}

void RenderDashboard(
    ST7735& display,
    std::array<std::string, 8>& previous,
    const TelemetrySnapshot& snapshot
) {
    const bool active = snapshot.flow_detected;

    UpdateLine(
        display,
        previous,
        0,
        26,
        active ? "STATUS: ACTIVE" : "STATUS: WAITING",
        active ? ST7735::GREEN : ST7735::YELLOW
    );

    UpdateLine(
        display,
        previous,
        1,
        55,
        "PPS: " + FormatValue(snapshot.incoming.packets_per_second, 1),
        ST7735::WHITE
    );

    UpdateLine(
        display,
        previous,
        2,
        67,
        "KB/S: " + FormatValue(snapshot.incoming.kilobytes_per_second, 2),
        ST7735::WHITE
    );

    UpdateLine(
        display,
        previous,
        3,
        79,
        snapshot.incoming.jitter_valid
            ? "JITTER: " + FormatValue(snapshot.incoming.jitter_ms, 2) + " MS"
            : "JITTER: N/A",
        ST7735::WHITE
    );

    UpdateLine(
        display,
        previous,
        4,
        109,
        "PPS: " + FormatValue(snapshot.outgoing.packets_per_second, 1),
        ST7735::WHITE
    );

    UpdateLine(
        display,
        previous,
        5,
        121,
        "KB/S: " + FormatValue(snapshot.outgoing.kilobytes_per_second, 2),
        ST7735::WHITE
    );

    UpdateLine(
        display,
        previous,
        6,
        133,
        snapshot.outgoing.jitter_valid
            ? "JITTER: " + FormatValue(snapshot.outgoing.jitter_ms, 2) + " MS"
            : "JITTER: N/A",
        ST7735::WHITE
    );

    UpdateLine(
        display,
        previous,
        7,
        149,
        active ? "FLOW: DETECTED" : "FLOW: NONE",
        active ? ST7735::GREEN : ST7735::YELLOW
    );
}

void DisplayTask(const std::string& local_ip, std::atomic<bool>& running) {
    try {
        ST7735 display;
        InitializeDashboard(display);

        std::array<std::string, 8> previous{};

        while (running.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));

            if (!running.load()) {
                break;
            }

            TelemetrySnapshot snapshot;

            {
                std::lock_guard<std::mutex> lock(analyzer_mutex);
                snapshot = analyzer.sample(local_ip);
            }

            std::cerr << "[DISPLAY] Incoming PPS: "
                      << snapshot.incoming.packets_per_second
                      << " | Outgoing PPS: "
                      << snapshot.outgoing.packets_per_second
                      << " | Flow active: "
                      << snapshot.flow_detected
                      << '\n';

            RenderDashboard(display, previous, snapshot);
        }
    } catch (const std::exception& error) {
        std::cerr << "Display error: " << error.what() << '\n';
    }
}

}

void packet_callback(unsigned char* user_data, const PacketMetadata* header, const unsigned char* packet) {
    (void)user_data;

    uint16_t ether_type;

    if (!parse_ethernet(header, packet, ether_type) || ether_type != 0x0800) {
        return;
    }

    constexpr size_t IPV4_OFFSET = 14;

    IPv4Header ipv4;

    if (!parse_ipv4(header, packet, IPV4_OFFSET, ipv4)) {
        return;
    }

    if (ipv4.protocol != 17) {
        return;
    }

    UDPHeader udp;

    if (!parse_udp(header, packet, IPV4_OFFSET, ipv4, udp)) {
        return;
    }

    discovery->process_packet(ipv4, udp);
    discovery->update();

    if (discovery->selection_changed()) {
        std::cerr << "[FLOW] Selection changed, resetting analyzer\n";

        std::lock_guard<std::mutex> lock(analyzer_mutex);
        analyzer.reset();
    }

    if (discovery->matches_selected(ipv4, udp)) {
        std::lock_guard<std::mutex> lock(analyzer_mutex);
        analyzer.process_packet(ipv4, udp, header);
    }
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <local_ip>\n";
        return 1;
    }

    const std::string local_ip = argv[1];

    discovery = std::make_unique<FlowDiscovery>(local_ip);

    std::cout << "SF6 Telemetry Monitor\n";
    std::cout << "Automatic UDP flow discovery enabled\n";
    std::cout << "Local IP: " << local_ip << '\n';

    std::atomic<bool> running{true};

    std::thread display_thread(DisplayTask, std::cref(local_ip), std::ref(running));

    int result = 1;

    try {
        result = start_packet_receiver(packet_callback, nullptr);
    } catch (const std::exception& error) {
        std::cerr << "Packet receiver error: " << error.what() << '\n';
    }

    running.store(false);
    display_thread.join();

    return result;
}