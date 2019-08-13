# ntapi
simple lib wrapper around system calls (windows X64)
--
designed year ago mainly for obfuscation- makes harder to revesre engineer an executable with no IAT calls.
it works by reading NTDLL module (using GetModuleHandle) and enumerating its exported functions

usage
<pre>
int main(int argc, char** argv)
{
	if (!syscall::initialise())
		return 1;

	const uint32_t process_id = 8272;

	auto process_handle = ntapi::open_process(process_id, PROCESS_TERMINATE);
	if (!is_handle_valid(process_handle))
	{
		printf("failed to obtain valid handle.\n");
		return 1;
	}

	ntapi::terminate_process(process_handle);

	if (is_handle_valid(process_handle))
	{
		ntapi::close_handle(process_handle);
	}

	return 0;
}
</pre>
