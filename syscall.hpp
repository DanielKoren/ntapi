#pragma once

#include <Windows.h>
#include <string>
#include <vector>

namespace syscall
{
	
	extern std::vector<std::pair<std::string, int32_t>> syscalls;
	int32_t get_syscall_id(const std::string& name);
	
	bool initialise();

}