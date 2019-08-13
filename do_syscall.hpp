#pragma once

#include <stdint.h>

/* credits; https://github.com/adrianyy/x64-syscall */

extern "C" void _do_syscall();

template< typename ReturnType = void, typename... Args,
	typename T1 = void*, typename T2 = void*, typename T3 = void*, typename T4 = void* >
	ReturnType do_syscall(const uint64_t syscall_id, T1 A1 = { }, T2 A2 = { }, T3 A3 = { }, T4 A4 = { }, Args... Arguments)
{
	return reinterpret_cast<ReturnType(*)(T1, T2, T3, T4, uint64_t, uint64_t, Args...)>(_do_syscall)(
		A1, A2, A3, A4, syscall_id, 0, Arguments... // Stack must be aligned to 16 byte boundary.
		);
}