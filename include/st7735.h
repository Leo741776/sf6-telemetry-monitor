#pragma once

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <string>

class ST7735 {
public:
    static constexpr int WIDTH = 128;
    static constexpr int HEIGHT = 160;

    static constexpr uint16_t BLACK = 0x0000;
    static constexpr uint16_t WHITE = 0xFFFF;
    static constexpr uint16_t RED = 0xF800;
    static constexpr uint16_t GREEN = 0x07E0;
    static constexpr uint16_t BLUE = 0x001F;
    static constexpr uint16_t CYAN = 0x07FF;
    static constexpr uint16_t YELLOW = 0xFFE0;

    ST7735();
    ~ST7735();

    ST7735(const ST7735&) = delete;
    ST7735& operator=(const ST7735&) = delete;

    void Initialize();

    void FillScreen(uint16_t color);
    void FillRectangle(int x, int y, int width, int height, uint16_t color);
    void DrawPixel(int x, int y, uint16_t color);

    void DrawCharacter(int x, int y, char character, uint16_t color, uint16_t background = BLACK);
    void DrawString(int x, int y, const std::string& text, uint16_t color, uint16_t background = BLACK);

private:
    int spi_fd_ = -1;
    int dc_fd_ = -1;
    int reset_fd_ = -1;

    static int RequestGpio(unsigned int offset);
    static void SetGpio(int fd, bool high);
    static void Delay(int milliseconds);

    void Write(const uint8_t* data, std::size_t size);
    void Command(uint8_t command);
    void Data(std::initializer_list<uint8_t> data);
    void SetWindow(int x0, int y0, int x1, int y1);
};