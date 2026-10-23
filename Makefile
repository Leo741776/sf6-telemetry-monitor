CXX = g++
CXXFLAGS = -Wall -Wextra -std=c++17 -Iinclude -MMD -MP
THREADFLAGS = -pthread

TARGET = build/sf6-monitor

SRC = $(wildcard src/*.cpp src/network/*.cpp src/telemetry/*.cpp src/display/*.cpp)
OBJ = $(patsubst src/%.cpp,build/%.o,$(SRC))
DEP = $(OBJ:.o=.d)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CXX) $(OBJ) $(THREADFLAGS) -o $@

build/%.o: src/%.cpp
	mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $(THREADFLAGS) -c $< -o $@

-include $(DEP)

clean:
	rm -rf build