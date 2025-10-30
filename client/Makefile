CXX := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -O2 -IC:/libs/cryptopp/include
LDFLAGS := -LC:/libs/cryptopp/cryptopp-master -lcryptopp -lws2_32
# If you moved the lib: -LC:/libs/cryptopp/libcryptopp instead

SRC := main.cpp ServerConnection.cpp FileConfig.cpp Message.cpp Protocol.cpp Encryption.cpp Utils.cpp

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
