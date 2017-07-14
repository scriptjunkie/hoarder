#pragma once
#include <Windows.h>
DWORD NTAPI NtAllocateVirtualMemoryR(HANDLE ProcessHandle, PVOID *BaseAddress,
  ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
