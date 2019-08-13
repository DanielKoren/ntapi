# ntapi
simple lib wrapper around system calls (windows X64)
--
designed year ago mainly for obfuscation- makes harder to revesre engineer an executable with no IAT calls.
it works by reading NTDLL module (using GetModuleHandle) and enumerating its exported functions
