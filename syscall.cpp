#include "syscall.hpp"

std::vector<std::pair<std::string, int32_t>> syscall::syscalls;

int32_t syscall::get_syscall_id(const std::string& name)
{
	if (name.empty())
		return 0;

	for (auto it = syscall::syscalls.begin(); it != syscall::syscalls.end(); it++)
		if (it->first == name)
			return it->second;

	return 0;
}

bool syscall::initialise()
{
	auto ntdll_module = GetModuleHandle("ntdll.dll");
	auto ntdll_buffer = reinterpret_cast<BYTE*>(ntdll_module);
	if (!ntdll_buffer)
	{
		//fprintf(stderr, "ntdll not found.\n");
		return false;
	}

	auto dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(ntdll_buffer);
	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
	{
		//fprintf(stderr, "invalid dos signature.\n");
		return false;
	}
	auto nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(ntdll_buffer + dos_header->e_lfanew);
	if (nt_headers->Signature != IMAGE_NT_SIGNATURE)
	{
		//fprintf(stderr, "invalid nt signature.\n");
		return false;
	}

	IMAGE_DATA_DIRECTORY data_directory = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	auto export_dir_rva = data_directory.VirtualAddress;
	auto export_dir_size = data_directory.Size;
	if (!export_dir_rva || !export_dir_size)
	{
		//fprintf(stderr, "error reading image directory export.\n");
		return false;
	}

	IMAGE_EXPORT_DIRECTORY* export_directory = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(ntdll_buffer + export_dir_rva);
	if (!export_directory)
	{
		//fprintf(stderr, "invalid export directory address.\n");
		return false;
	}

	auto export_dir_functions = reinterpret_cast<DWORD*>(ntdll_buffer + export_directory->AddressOfFunctions);
	auto export_dir_names = reinterpret_cast<DWORD*>(ntdll_buffer + export_directory->AddressOfNames);
	auto export_dir_ordinals = reinterpret_cast<WORD*>(ntdll_buffer + export_directory->AddressOfNameOrdinals); //this is 16-bit aligned
	for (int i = 0; i < export_directory->NumberOfNames; i++)
	{
		auto export_name = reinterpret_cast<const char*>(ntdll_buffer + export_dir_names[i]);
		auto raw_bytes = reinterpret_cast<BYTE*>(ntdll_buffer + export_dir_functions[export_dir_ordinals[i]]);
		if (!raw_bytes)
		{
			//fprintf(stderr, "invalid address of function.\n");
			break;
		}
		//syscall wrapper prolouge 
		if (memcmp(raw_bytes, "\x4C\x8B\xD1\xB8", 4) == 0)
		{
			//auto syscall_id = *((INT32*)(raw_bytes + 4));
			auto syscall_id = *reinterpret_cast<int32_t*>(raw_bytes + 4);
			syscalls.emplace_back(std::make_pair(export_name, syscall_id));
		}

	}

	return true;
}
