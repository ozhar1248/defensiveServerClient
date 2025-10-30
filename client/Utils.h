#pragma once
#include <string>
#include <vector>
#include <array>
#include <cstdint>
#include <cstddef>

std::string toHex32(const std::array<uint8_t,16>& id);
void dumpHexPrefix(const std::vector<uint8_t>& v, size_t n = 16);
