#include "st7735.h"

#include <linux/gpio.h>
#include <linux/spi/spidev.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>

#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

namespace {

using Glyph = std::array<uint8_t, 5>;

Glyph GetGlyph(char character) {
    if (character >= 'a' && character <= 'z') {
        character = static_cast<char>(character - 'a' + 'A');
    }

    switch (character) {
        case ' ': return {0x00, 0x00, 0x00, 0x00, 0x00};
        case '!': return {0x00, 0x00, 0x5F, 0x00, 0x00};
        case '#': return {0x14, 0x7F, 0x14, 0x7F, 0x14};
        case '%': return {0x23, 0x13, 0x08, 0x64, 0x62};
        case '(': return {0x00, 0x1C, 0x22, 0x41, 0x00};
        case ')': return {0x00, 0x41, 0x22, 0x1C, 0x00};
        case '+': return {0x08, 0x08, 0x3E, 0x08, 0x08};
        case ',': return {0x00, 0x50, 0x30, 0x00, 0x00};
        case '-': return {0x08, 0x08, 0x08, 0x08, 0x08};
        case '.': return {0x00, 0x60, 0x60, 0x00, 0x00};
        case '/': return {0x20, 0x10, 0x08, 0x04, 0x02};
        case ':': return {0x00, 0x36, 0x36, 0x00, 0x00};
        case '=': return {0x14, 0x14, 0x14, 0x14, 0x14};
        case '?': return {0x02, 0x01, 0x51, 0x09, 0x06};
        case '_': return {0x40, 0x40, 0x40, 0x40, 0x40};

        case '0': return {0x3E, 0x51, 0x49, 0x45, 0x3E};
        case '1': return {0x00, 0x42, 0x7F, 0x40, 0x00};
        case '2': return {0x42, 0x61, 0x51, 0x49, 0x46};
        case '3': return {0x21, 0x41, 0x45, 0x4B, 0x31};
        case '4': return {0x18, 0x14, 0x12, 0x7F, 0x10};
        case '5': return {0x27, 0x45, 0x45, 0x45, 0x39};
        case '6': return {0x3C, 0x4A, 0x49, 0x49, 0x30};
        case '7': return {0x01, 0x71, 0x09, 0x05, 0x03};
        case '8': return {0x36, 0x49, 0x49, 0x49, 0x36};
        case '9': return {0x06, 0x49, 0x49, 0x29, 0x1E};

        case 'A': return {0x7E, 0x11, 0x11, 0x11, 0x7E};
        case 'B': return {0x7F, 0x49, 0x49, 0x49, 0x36};
        case 'C': return {0x3E, 0x41, 0x41, 0x41, 0x22};
        case 'D': return {0x7F, 0x41, 0x41, 0x22, 0x1C};
        case 'E': return {0x7F, 0x49, 0x49, 0x49, 0x41};
        case 'F': return {0x7F, 0x09, 0x09, 0x09, 0x01};
        case 'G': return {0x3E, 0x41, 0x49, 0x49, 0x7A};
        case 'H': return {0x7F, 0x08, 0x08, 0x08, 0x7F};
        case 'I': return {0x00, 0x41, 0x7F, 0x41, 0x00};
        case 'J': return {0x20, 0x40, 0x41, 0x3F, 0x01};
        case 'K': return {0x7F, 0x08, 0x14, 0x22, 0x41};
        case 'L': return {0x7F, 0x40, 0x40, 0x40, 0x40};
        case 'M': return {0x7F, 0x02, 0x0C, 0x02, 0x7F};
        case 'N': return {0x7F, 0x04, 0x08, 0x10, 0x7F};
        case 'O': return {0x3E, 0x41, 0x41, 0x41, 0x3E};
        case 'P': return {0x7F, 0x09, 0x09, 0x09, 0x06};
        case 'Q': return {0x3E, 0x41, 0x51, 0x21, 0x5E};
        case 'R': return {0x7F, 0x09, 0x19, 0x29, 0x46};
        case 'S': return {0x46, 0x49, 0x49, 0x49, 0x31};
        case 'T': return {0x01, 0x01, 0x7F, 0x01, 0x01};
        case 'U': return {0x3F, 0x40, 0x40, 0x40, 0x3F};
        case 'V': return {0x1F, 0x20, 0x40, 0x20, 0x1F};
        case 'W': return {0x7F, 0x20, 0x18, 0x20, 0x7F};
        case 'X': return {0x63, 0x14, 0x08, 0x14, 0x63};
        case 'Y': return {0x03, 0x04, 0x78, 0x04, 0x03};
        case 'Z': return {0x61, 0x51, 0x49, 0x45, 0x43};

        default: return {0x02, 0x01, 0x51, 0x09, 0x06};
    }
}

}

int ST7735::RequestGpio(unsigned int offset) {
    int chip = open("/dev/gpiochip0", O_RDONLY);

    if (chip < 0) {
        throw std::system_error(errno, std::generic_category(), "Opening GPIO chip");
    }

    gpiohandle_request request{};
    request.lineoffsets[0] = offset;
    request.flags = GPIOHANDLE_REQUEST_OUTPUT;
    request.default_values[0] = 1;
    request.lines = 1;

    std::strncpy(
        request.consumer_label,
        "st7735",
        sizeof(request.consumer_label) - 1
    );

    int result = ioctl(chip, GPIO_GET_LINEHANDLE_IOCTL, &request);
    int error = errno;

    close(chip);

    if (result < 0) {
        throw std::system_error(
            error,
            std::generic_category(),
            "Requesting GPIO line " + std::to_string(offset)
        );
    }

    return request.fd;
}

void ST7735::SetGpio(int fd, bool high) {
    gpiohandle_data data{};
    data.values[0] = high ? 1 : 0;

    if (ioctl(fd, GPIOHANDLE_SET_LINE_VALUES_IOCTL, &data) < 0) {
        throw std::system_error(errno, std::generic_category(), "Setting GPIO");
    }
}

void ST7735::Delay(int milliseconds) {
    std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
}

ST7735::ST7735() {
    try {
        dc_fd_ = RequestGpio(16);
        reset_fd_ = RequestGpio(17);

        spi_fd_ = open("/dev/spidev0.0", O_RDWR);

        if (spi_fd_ < 0) {
            throw std::system_error(errno, std::generic_category(), "Opening SPI device");
        }

        uint8_t mode = SPI_MODE_0;
        uint8_t bits = 8;
        uint32_t speed = 4000000;

        if (ioctl(spi_fd_, SPI_IOC_WR_MODE, &mode) < 0 ||
            ioctl(spi_fd_, SPI_IOC_WR_BITS_PER_WORD, &bits) < 0 ||
            ioctl(spi_fd_, SPI_IOC_WR_MAX_SPEED_HZ, &speed) < 0) {
            throw std::system_error(errno, std::generic_category(), "Configuring SPI");
        }
    } catch (...) {
        if (spi_fd_ >= 0) close(spi_fd_);
        if (dc_fd_ >= 0) close(dc_fd_);
        if (reset_fd_ >= 0) close(reset_fd_);
        throw;
    }
}

ST7735::~ST7735() {
    if (spi_fd_ >= 0) close(spi_fd_);
    if (dc_fd_ >= 0) close(dc_fd_);
    if (reset_fd_ >= 0) close(reset_fd_);
}

void ST7735::Write(const uint8_t* data, std::size_t size) {
    while (size > 0) {
        ssize_t written = write(spi_fd_, data, size);

        if (written < 0 && errno == EINTR) {
            continue;
        }

        if (written <= 0) {
            throw std::system_error(
                written < 0 ? errno : EIO,
                std::generic_category(),
                "SPI transfer"
            );
        }

        data += written;
        size -= static_cast<std::size_t>(written);
    }
}

void ST7735::Command(uint8_t command) {
    SetGpio(dc_fd_, false);
    Write(&command, 1);
}

void ST7735::Data(std::initializer_list<uint8_t> data) {
    SetGpio(dc_fd_, true);
    Write(data.begin(), data.size());
}

void ST7735::Initialize() {
    SetGpio(reset_fd_, true);
    Delay(20);

    SetGpio(reset_fd_, false);
    Delay(20);

    SetGpio(reset_fd_, true);
    Delay(150);

    Command(0x01);
    Delay(150);

    Command(0x11);
    Delay(150);

    Command(0xB1);
    Data({0x01, 0x2C, 0x2D});

    Command(0xB2);
    Data({0x01, 0x2C, 0x2D});

    Command(0xB3);
    Data({0x01, 0x2C, 0x2D, 0x01, 0x2C, 0x2D});

    Command(0xB4);
    Data({0x07});

    Command(0xC0);
    Data({0xA2, 0x02, 0x84});

    Command(0xC1);
    Data({0xC5});

    Command(0xC2);
    Data({0x0A, 0x00});

    Command(0xC3);
    Data({0x8A, 0x2A});

    Command(0xC4);
    Data({0x8A, 0xEE});

    Command(0xC5);
    Data({0x0E});

    Command(0x36);
    Data({0xC8});

    Command(0x3A);
    Data({0x05});

    Command(0x13);
    Delay(10);

    Command(0x29);
    Delay(100);
}

void ST7735::SetWindow(int x0, int y0, int x1, int y1) {
    Command(0x2A);
    Data({
        static_cast<uint8_t>(x0 >> 8),
        static_cast<uint8_t>(x0),
        static_cast<uint8_t>(x1 >> 8),
        static_cast<uint8_t>(x1)
    });

    Command(0x2B);
    Data({
        static_cast<uint8_t>(y0 >> 8),
        static_cast<uint8_t>(y0),
        static_cast<uint8_t>(y1 >> 8),
        static_cast<uint8_t>(y1)
    });

    Command(0x2C);
    SetGpio(dc_fd_, true);
}

void ST7735::FillScreen(uint16_t color) {
    FillRectangle(0, 0, WIDTH, HEIGHT, color);
}

void ST7735::FillRectangle(int x, int y, int width, int height, uint16_t color) {
    if (width <= 0 || height <= 0) {
        return;
    }

    if (x < 0) {
        width += x;
        x = 0;
    }

    if (y < 0) {
        height += y;
        y = 0;
    }

    if (x >= WIDTH || y >= HEIGHT) {
        return;
    }

    width = std::min(width, WIDTH - x);
    height = std::min(height, HEIGHT - y);

    if (width <= 0 || height <= 0) {
        return;
    }

    SetWindow(x, y, x + width - 1, y + height - 1);

    std::array<uint8_t, 512> buffer{};

    for (std::size_t i = 0; i < buffer.size(); i += 2) {
        buffer[i] = static_cast<uint8_t>(color >> 8);
        buffer[i + 1] = static_cast<uint8_t>(color);
    }

    std::size_t remaining = static_cast<std::size_t>(width) * height;

    while (remaining > 0) {
        std::size_t count = std::min<std::size_t>(remaining, 256);
        Write(buffer.data(), count * 2);
        remaining -= count;
    }
}

void ST7735::DrawPixel(int x, int y, uint16_t color) {
    FillRectangle(x, y, 1, 1, color);
}

void ST7735::DrawCharacter(
    int x,
    int y,
    char character,
    uint16_t color,
    uint16_t background
) {
    if (x < 0 || y < 0 || x + 6 > WIDTH || y + 8 > HEIGHT) {
        return;
    }

    Glyph glyph = GetGlyph(character);
    std::array<uint8_t, 6 * 8 * 2> buffer{};

    for (int row = 0; row < 8; ++row) {
        for (int column = 0; column < 6; ++column) {
            bool active = column < 5 &&
                          row < 7 &&
                          ((glyph[column] >> row) & 1);

            uint16_t pixel = active ? color : background;
            std::size_t index = static_cast<std::size_t>(row * 6 + column) * 2;

            buffer[index] = static_cast<uint8_t>(pixel >> 8);
            buffer[index + 1] = static_cast<uint8_t>(pixel);
        }
    }

    SetWindow(x, y, x + 5, y + 7);
    Write(buffer.data(), buffer.size());
}

void ST7735::DrawString(
    int x,
    int y,
    const std::string& text,
    uint16_t color,
    uint16_t background
) {
    int cursor_x = x;
    int cursor_y = y;

    for (char character : text) {
        if (character == '\n') {
            cursor_x = x;
            cursor_y += 8;
            continue;
        }

        if (cursor_x + 6 > WIDTH) {
            cursor_x = x;
            cursor_y += 8;
        }

        if (cursor_y + 8 > HEIGHT) {
            break;
        }

        DrawCharacter(cursor_x, cursor_y, character, color, background);
        cursor_x += 6;
    }
}