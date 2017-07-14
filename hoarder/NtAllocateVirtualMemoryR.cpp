#include <Windows.h>
#include "GetProcAddressInPlaceR.h"
#include "NtAllocateVirtualMemoryR.h"
//#include "syscalls.h"
extern unsigned char ntdll[]; // better have ntdll.dll.includeme.h in your project somewhere!

static DWORD (NTAPI * NtAllocateVirtualMemoryReal)(HANDLE ProcessHandle, PVOID *BaseAddress, 
			ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect) = NULL;

DWORD NTAPI NtAllocateVirtualMemoryR(HANDLE ProcessHandle, PVOID *BaseAddress, 
			ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect){
	if(NtAllocateVirtualMemoryReal == NULL)
    NtAllocateVirtualMemoryReal = (DWORD(NTAPI * )(HANDLE, PVOID *, ULONG_PTR, PSIZE_T, ULONG, ULONG))
        GetProcAddressInPlaceR(ntdll, "NtAllocateVirtualMemory");
	return NtAllocateVirtualMemoryReal(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
/**
//The old way of doing it; inline asm (wow64 variety)
	__asm{
mov     eax, NtAllocateVirtualMemory_SYSCALL_NUM 
xor     ecx, ecx
lea     edx, [ProcessHandle]
call    dword ptr fs:0C0h
add     esp, 4
	}
	*/
}
