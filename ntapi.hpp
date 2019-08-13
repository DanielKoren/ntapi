#pragma once

#include <Windows.h>
#include <stdio.h>
#include <stdint.h>

inline bool is_handle_valid(HANDLE handle)
{
	return handle && handle != INVALID_HANDLE_VALUE;
}

namespace ntapi
{

	enum file_creation : ULONG
	{
		file_supersede = 0x00000000, // If file exists, deletes it before creation of new one.
		file_open = 0x00000001, // Fails, if file not exists.
		file_create = 0x00000002, // Fails, if file exists.
		file_open_if = 0x00000003, // If file exists, opens it. If not, creates new one and then open it.
		file_overwrite = 0x00000004, // If file not exists, create and open it. If exists, open them and reset content.
		file_overwrite_if = 0x00000005 // As FILE_OVERWRITE, but fails if file not exists.
		//file_maximum_disposition        = 0x00000005
	};

	//NT OBJS
	bool close_handle(HANDLE handle);

	//FILE I/O
	HANDLE create_file(const wchar_t* file_path, file_creation create_disposition = file_open_if);
	bool delete_file(const wchar_t* file_path);
	bool read_file(HANDLE handle, void* buffer, DWORD size);
	bool write_file(HANDLE handle, void* data, DWORD size);
	uint64_t get_file_size(HANDLE handle);

	//PROCESS ~ create_process() broken
	HANDLE create_process(const wchar_t* process_name);
	HANDLE open_process(const uint32_t process_id, ACCESS_MASK desired_access);
	bool terminate_process(HANDLE handle);

	//THREAD
	HANDLE create_thread(HANDLE handle, void* start_address, void* param);

	//MEMORY
	bool allocate_memory(HANDLE handle, void* address, size_t size);
	bool free_memory(HANDLE handle, void* address);
	bool read_memory(HANDLE handle, void* address, void* buffer, size_t size);
	bool write_memory(HANDLE handle, void* address, void* buffer, size_t size);

	//
	uint32_t get_process_id(const wchar_t* image_name);

}