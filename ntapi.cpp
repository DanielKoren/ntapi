#include "ntapi.hpp"
#include "do_syscall.hpp"
#include "syscall.hpp"
#include "ntdefs.h"

#define DEBUG_PRINT FALSE

OBJECT_ATTRIBUTES init_obj_attributes(const wchar_t* object_name)
{
	OBJECT_ATTRIBUTES	object_attributes{};
	UNICODE_STRING		unicode_string{};

	//For file I/O, the "\\?\" prefix to a path string tells the Windows APIs to disable all string parsing and to send the string that follows it straight to the file system.
	wchar_t	fullpath[4096]{};
	wcscat_s(fullpath, L"\\??\\");
	wcscat_s(fullpath, sizeof(fullpath), object_name);

	using RtlInitUnicodeString_t = void (NTAPI*)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
	auto RtlInitUnicodeString = reinterpret_cast<RtlInitUnicodeString_t>(GetProcAddress(GetModuleHandle("NTDLL"), "RtlInitUnicodeString"));
	RtlInitUnicodeString(&unicode_string, fullpath);
	InitializeObjectAttributes(&object_attributes, &unicode_string, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

	return object_attributes;
}

bool ntapi::close_handle(HANDLE handle)
{
	auto syscall_id = syscall::get_syscall_id("NtClose");
	auto status = do_syscall<NTSTATUS>(syscall_id,
		handle);

	if (!NT_SUCCESS(status))
	{
#if DEBUG_PRINT
		fprintf(stderr, "[!] NtClose failed [ 0x%.8X ]\n", status);
#endif
		return false;
	}

	return true;
}

HANDLE ntapi::create_file(const wchar_t* file_path, file_creation create_disposition)
{
	HANDLE				file_handle = nullptr;
	IO_STATUS_BLOCK		io_status_block{};

	auto object_attributes = init_obj_attributes(file_path);

	auto syscall_id = syscall::get_syscall_id("NtCreateFile");
	auto status = do_syscall<NTSTATUS>(syscall_id,
		&file_handle,
		GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
		&object_attributes, &io_status_block,
		nullptr,
		FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE,
		create_disposition,
		FILE_SYNCHRONOUS_IO_NONALERT, /**/
		nullptr, 0);

	if (!NT_SUCCESS(status))
	{
#if DEBUG_PRINT
		fprintf(stderr, "[!] NtCreateFile failed [ 0x%.8X ]\n", status);
#endif
		return nullptr;
	}

	return file_handle;
}

bool ntapi::delete_file(const wchar_t* file_path)
{
	auto object_attributes = init_obj_attributes(file_path);

	auto syscall_id = syscall::get_syscall_id("NtDeleteFile");
	auto status = do_syscall<NTSTATUS>(syscall_id,
		&object_attributes);

	if (!NT_SUCCESS(status))
	{
#if DEBUG_PRINT
		fprintf(stderr, "[!] NtDeleteFile failed [ 0x%.8X ]\n", status);
#endif
		return false;
	}

	return true;
}

bool ntapi::read_file(HANDLE handle, void* buffer, DWORD size)
{
	IO_STATUS_BLOCK io_status_block{};

	auto syscall_id = syscall::get_syscall_id("NtReadFile");
	auto status = do_syscall<NTSTATUS>(syscall_id,
		handle,
		nullptr, nullptr, nullptr,
		&io_status_block,
		buffer, size,
		nullptr, nullptr);

	if (!NT_SUCCESS(status))
	{
#if DEBUG_PRINT
		fprintf(stderr, "[!] NtReadFile failed [ 0x%.8X ]\n", status);
#endif
		return false;
	}

	return true;
}

bool ntapi::write_file(HANDLE handle, void* data, DWORD size)
{
	IO_STATUS_BLOCK io_status_block{};

	auto syscall_id = syscall::get_syscall_id("NtWriteFile");
	auto status = do_syscall<NTSTATUS>(syscall_id,
		handle,
		nullptr, nullptr, nullptr,
		&io_status_block,
		data, size,
		nullptr, nullptr);

	if (!NT_SUCCESS(status))
	{
#if DEBUG_PRINT
		fprintf(stderr, "[!] NtWriteFile failed [ 0x%.8X ]\n", status);
#endif
		return false;
	}

	return true;
}

uint64_t ntapi::get_file_size(HANDLE handle)
{
	IO_STATUS_BLOCK io_status_block{};
	FILE_STANDARD_INFORMATION file_info{};

	auto syscall_id = syscall::get_syscall_id("NtQueryInformationFile");
	auto status = do_syscall<NTSTATUS>(syscall_id,
		handle,
		&io_status_block,
		&file_info, sizeof(FILE_STANDARD_INFORMATION),
		FileStandardInformation);

	if (!NT_SUCCESS(status))
	{
#if DEBUG_PRINT
		fprintf(stderr, "[!] NtQueryInformationFile failed [ 0x%.8X ]\n", status);
#endif
		return 0;
	}

	return file_info.EndOfFile.QuadPart;
}

HANDLE ntapi::create_process(const wchar_t* process_name)
{
	/*
		taken from https://github.com/Microwave89/createuserprocess
		process gets executed but seems like PE sections are either missing or something.
	*/
	
	HANDLE process_handle = nullptr;
	HANDLE thread_handle = nullptr;

	UNICODE_STRING process_name_str{};
	//initialise unicode string
	//For file I/O, the "\\?\" prefix to a path string tells the Windows APIs to disable all string parsing and to send the string that follows it straight to the file system.
	wchar_t	fullpath[1024]{};
	wcscat_s(fullpath, L"\\??\\");
	wcscat_s(fullpath, sizeof(fullpath), process_name);

	using RtlInitUnicodeString_t = void (NTAPI*)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
	auto RtlInitUnicodeString = reinterpret_cast<RtlInitUnicodeString_t>(GetProcAddress(GetModuleHandle("NTDLL"), "RtlInitUnicodeString"));
	RtlInitUnicodeString(&process_name_str, fullpath);

	RTL_USER_PROCESS_PARAMETERS process_params{};
	PS_CREATE_INFO				process_info{};
	PS_ATTRIBUTE_LIST			attribute_list{};

	RtlSecureZeroMemory(&process_params, sizeof(RTL_USER_PROCESS_PARAMETERS));
	RtlSecureZeroMemory(&process_info, sizeof(PS_CREATE_INFO));
	RtlSecureZeroMemory(&attribute_list, sizeof(PS_ATTRIBUTE_LIST));

	process_params.Length = sizeof(RTL_USER_PROCESS_PARAMETERS);
	process_params.MaximumLength = sizeof(RTL_USER_PROCESS_PARAMETERS);
	process_info.Size = sizeof(PS_CREATE_INFO);
	attribute_list.TotalLength = sizeof(PS_ATTRIBUTE_LIST) - sizeof(PS_ATTRIBUTE);

	///We should supply a minimal environment (environment variables). Following one is simple yet fits our needs. 
	char data[2 * sizeof(ULONGLONG)] = { 'Y', 0x00, 0x3D, 0x00, 'Q', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	process_params.Environment = (WCHAR*)data;
	process_params.EnvironmentSize = sizeof(data);
	process_params.EnvironmentVersion = 0;
	process_params.Flags = RTL_USER_PROCESS_PARAMETERS_NORMALIZED;

	attribute_list.Attributes[0].Attribute = PsAttributeValue(PsAttributeImageName, FALSE, TRUE, FALSE);
	attribute_list.Attributes[0].Size = process_name_str.Length;
	attribute_list.Attributes[0].Value = (ULONG_PTR)process_name_str.Buffer;

	auto syscall_id = syscall::get_syscall_id("NtCreateUserProcess");
	auto status = do_syscall<NTSTATUS>(syscall_id,
		&process_handle, &thread_handle,
		MAXIMUM_ALLOWED, //process access
		MAXIMUM_ALLOWED, //thread access
		nullptr, nullptr,//obj attributes
		1, // ProcessFlags
		1, // ThreadFlags
		&process_params,
		&process_info,
		&attribute_list);

	if (!NT_SUCCESS(status))
	{
//#if DEBUG_PRINT
		fprintf(stderr, "[!] NtCreateUserProcess failed [ 0x%.8X ]\n", status);
//#endif
		return nullptr;
	}

	return process_handle;
}

HANDLE ntapi::open_process(const uint32_t process_id, ACCESS_MASK desired_access)
{
	HANDLE process_handle = nullptr;

	CLIENT_ID client_id{};
	client_id.UniqueProcess = reinterpret_cast<HANDLE>(process_id);
	client_id.UniqueThread = nullptr;

	OBJECT_ATTRIBUTES object_attributes{};
	InitializeObjectAttributes(&object_attributes, 0, 0, 0, 0);

	auto syscall_id = syscall::get_syscall_id("NtOpenProcess");
	auto status = do_syscall<NTSTATUS>(syscall_id,
		&process_handle,
		desired_access,
		&object_attributes,
		&client_id);

	if (!NT_SUCCESS(status))
	{
#if DEBUG_PRINT
		fprintf(stderr, "[!] NtOpenProcess failed [ 0x%.8X ]\n", status);
#endif
		return nullptr;
	}

	return process_handle;
}

bool ntapi::terminate_process(HANDLE handle)
{
	auto syscall_id = syscall::get_syscall_id("NtTerminateProcess");
	auto status = do_syscall<NTSTATUS>(syscall_id,
		handle,
		NULL);

	if (!NT_SUCCESS(status))
	{
#if DEBUG_PRINT
		fprintf(stderr, "[!] NtTerminateProcess failed [ 0x%.8X ]\n", status);
#endif
		return false;
	}

	return true;
}

HANDLE ntapi::create_thread(HANDLE handle, void* start_address, void* param)
{
	HANDLE thread_handle = nullptr;

	auto syscall_id = syscall::get_syscall_id("NtCreateThreadEx");
	auto status = do_syscall<NTSTATUS>(syscall_id,
		&thread_handle,
		THREAD_ALL_ACCESS, //DesiredAccess
		nullptr, //ObjectAttributes
		handle,
		reinterpret_cast<LPTHREAD_START_ROUTINE>(start_address),
		param,
		FALSE, //CreateSuspended
		0,
		nullptr, nullptr, nullptr);

	if (!NT_SUCCESS(status))
	{
#if DEBUG_PRINT
		fprintf(stderr, "[!] NtCreateThreadEx failed [ 0x%.8X ]\n", status);
#endif
		return nullptr;
	}

	return thread_handle;
}

bool ntapi::allocate_memory(HANDLE handle, void* address, size_t size)
{
	auto syscall_id = syscall::get_syscall_id("NtAllocateVirtualMemory");
	auto status = do_syscall<NTSTATUS>(syscall_id,
		handle,
		reinterpret_cast<void**>(address),
		0, //ZeroBits
		&size,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);

	if (!NT_SUCCESS(status))
	{
#if DEBUG_PRINT
		fprintf(stderr, "[!] NtAllocateVirtualMemory failed [ 0x%.8X ]\n", status);
#endif
		return false;
	}

	return true;
}

bool ntapi::free_memory(HANDLE handle, void* address)
{
	size_t size = 0;
	auto syscall_id = syscall::get_syscall_id("NtFreeVirtualMemory");
	auto status = do_syscall<NTSTATUS>(syscall_id,
		handle,
		(void**)address,
		&size,
		MEM_RELEASE);

	if (!NT_SUCCESS(status))
	{
#if DEBUG_PRINT
		fprintf(stderr, "[!] NtFreeVirtualMemory failed [ 0x%.8X ]\n", status);
#endif
		return false;
	}

	return true;
}

bool ntapi::read_memory(HANDLE handle, void* address, void* buffer, size_t size)
{
	auto syscall_id = syscall::get_syscall_id("NtReadVirtualMemory");
	auto status = do_syscall<NTSTATUS>(syscall_id,
		handle,
		address,
		buffer,
		size,
		nullptr);

	if (!NT_SUCCESS(status))
	{
#if DEBUG_PRINT
		fprintf(stderr, "[!] NtReadVirtualMemory failed [ 0x%.8X ]\n", status);
#endif
		return false;
	}

	return true;
}

bool ntapi::write_memory(HANDLE handle, void* address, void* buffer, size_t size)
{
	auto syscall_id = syscall::get_syscall_id("NtWriteVirtualMemory");
	auto status = do_syscall<NTSTATUS>(syscall_id,
		handle,
		address,
		buffer,
		size,
		nullptr);

	if (!NT_SUCCESS(status))
	{
#if DEBUG_PRINT
		fprintf(stderr, "[!] NtWriteVirtualMemory failed [ 0x%.8X ]\n", status);
#endif
		return false;
	}

	return true;
}

uint32_t ntapi::get_process_id(const wchar_t* process_name)
{
	uint32_t process_id = 0;
	ULONG bytes_needed = 0;
	SYSTEM_PROCESS_INFO* spi = nullptr;

	auto syscall_id = syscall::get_syscall_id("NtQuerySystemInformation");
	auto status = do_syscall<NTSTATUS>(syscall_id,
		SystemProcessInformation,
		0, 0,
		&bytes_needed);

	if (!bytes_needed)
		return 0;

	auto buffer = VirtualAlloc(nullptr, bytes_needed, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	spi = reinterpret_cast<SYSTEM_PROCESS_INFO*>(buffer);

	status = do_syscall<NTSTATUS>(syscall_id,
		SystemProcessInformation,
		spi,
		bytes_needed,
		NULL);

	if (!NT_SUCCESS(status))
	{
#if DEBUG_PRINT
		fprintf(stderr, "[!] NtQuerySystemInformation failed [ 0x%.8X ]\n", status);
#endif
		VirtualFree(buffer, 0, MEM_RELEASE);
		return 0;
	}

	while (spi->NextEntryOffset)
	{
		if (!spi->ImageName.Buffer)
		{
			spi = reinterpret_cast<SYSTEM_PROCESS_INFO*>((LPBYTE)spi + spi->NextEntryOffset);
			continue;
		}

		//printf("%ws - %d\n", spi->ImageName.Buffer, spi->ProcessId);
		if (!wcscmp(spi->ImageName.Buffer, process_name))
		{
			process_id = reinterpret_cast<uint32_t>(spi->ProcessId);
			break;
		}

		spi = reinterpret_cast<SYSTEM_PROCESS_INFO*>((LPBYTE)spi + spi->NextEntryOffset);
	}

	VirtualFree(buffer, 0, MEM_RELEASE);
	return process_id;
}

