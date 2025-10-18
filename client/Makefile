# === Makefile for client_cpp project ===

CXX := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -O2
LDFLAGS := -lws2_32

SRC := main.cpp ServerConnection.cpp FileConfig.cpp Message.cpp
OBJ := $(SRC:.cpp=.o)
TARGET := client.exe

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CXX) $(OBJ) $(LDFLAGS) -o $(TARGET)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	del /Q $(OBJ) $(TARGET) 2>nul || true

.PHONY: all clean
