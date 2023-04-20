#pragma once
#include <Windows.h>
#include <string>
#include <sstream>
#include <vector>
#include "psapi.h"

uintptr_t memory::find_pattern(HMODULE module, std::string pattern) {

	if (module == NULL) {
		return NULL;
	}

	MODULEINFO module_info;
	if (!GetModuleInformation(GetCurrentProcess(), module, &module_info, sizeof(MODULEINFO))) {
		return NULL;
	}
	auto* module_base = static_cast<const char*>(module_info.lpBaseOfDll);
	auto module_size = module_info.SizeOfImage;

	//convert bytes string to pattern bytes and mask bytes
	std::vector<char> pattern_bytes;
	std::vector<char> mask;
	std::stringstream ss(pattern);
	std::string byte_str;
	while (ss >> byte_str) {
		if (byte_str == "?") {
			pattern_bytes.push_back(0x00);

			//comparing to bool is way slower so we just use char instead
			mask.push_back('?');
		}
		else {
			pattern_bytes.push_back(static_cast<char>(std::stoi(byte_str, nullptr, 16)));
			mask.push_back(' ');
		}
	}

	auto pattern_size = pattern_bytes.size();
	auto max_offset = module_size - pattern_size;


	MEMORY_BASIC_INFORMATION mbi;
	auto* current_region_end_address = module_base;

	for (size_t offset = 0; offset <= max_offset; ++offset) {
		const char* module_bytes = module_base + offset;

		//if this round we're going to read in 2 regions at once, check the next region
		if (module_bytes > current_region_end_address - pattern_size) {

			//Check read permissions when a new region is hit, skip the region if no read permission is present
			if (VirtualQuery(current_region_end_address + 1, &mbi, sizeof(mbi)) == sizeof(mbi)) {

				//Add the region size to the current end address, the sum of both will be the end address of this region
				current_region_end_address += mbi.RegionSize;

				if (!(mbi.Protect & (PAGE_READONLY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_READWRITE))) {

					//The offset is set to skip the whole region if no read permission is present
					offset = current_region_end_address - module_base;
					continue;
				}
			}
			else {
				return NULL;
			}
		}

		//search memory
		for (size_t i = 0; i < pattern_size; ++i) {
			if (mask[i] != '?' && module_bytes[i] != pattern_bytes[i]) {
				break;
			}
			//if this is the last byte in the pattern, we found it
			else if (i == pattern_size - 1) {
				return reinterpret_cast<uintptr_t>(module_bytes);
			}
		}
	}

	return NULL;
}
