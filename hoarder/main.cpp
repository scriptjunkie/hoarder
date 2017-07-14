// A hoarded main

#include "ReflectiveLoader.h"
#include "DllSet.h"
#include "NtAllocateVirtualMemoryR.h"

///// GENERATED INCLUDES HERE
#include "testbin.exe.includeme.h"
#include "KERNEL32.DLL.includeme.h"
#include "ntdll.dll.includeme.h"
#include "KERNELBASE.dll.includeme.h"
///// END GENERATED INCLUDES

DWORD start(){
	SIZE_T RegionSize = 100;
	UINT_PTR uiBaseAddress = NULL;

  ///// GENERATED ADDS HERE
  dllRecord* KERNEL32_alias = addImage("KERNEL32.dll", KERNEL32);
  dllRecord* ntdll_alias = addImage("api-ms-win-core-rtlsupport-l1-2-0.dll", ntdll);
  addAlias("ntdll.dll", ntdll_alias);
  dllRecord* KERNELBASE_alias = addImage("KERNELBASE.dll", KERNELBASE);
  addAlias("api-ms-win-core-processthreads-l1-1-2.dll", KERNEL32_alias);
  addAlias("api-ms-win-core-registry-l1-1-0.dll", KERNELBASE_alias);
  addAlias("api-ms-win-core-heap-l1-2-0.dll", KERNELBASE_alias);
  addAlias("api-ms-win-core-memory-l1-1-2.dll", KERNELBASE_alias);
  addAlias("api-ms-win-core-handle-l1-1-0.dll", KERNELBASE_alias);
  addAlias("api-ms-win-core-synch-l1-2-0.dll", KERNELBASE_alias);
  addAlias("api-ms-win-core-file-l1-2-1.dll", KERNELBASE_alias);
  addAlias("api-ms-win-core-delayload-l1-1-1.dll", KERNEL32_alias);
  addAlias("api-ms-win-core-io-l1-1-1.dll", KERNEL32_alias);
  addAlias("api-ms-win-core-job-l1-1-0.dll", KERNELBASE_alias);
  addAlias("api-ms-win-core-threadpool-legacy-l1-1-0.dll", KERNELBASE_alias);
  addAlias("api-ms-win-core-threadpool-private-l1-1-0.dll", KERNELBASE_alias);
  addAlias("api-ms-win-core-libraryloader-l1-2-0.dll", KERNELBASE_alias);
  addAlias("api-ms-win-core-namedpipe-l1-2-0.dll", KERNELBASE_alias);
  addAlias("api-ms-win-core-datetime-l1-1-1.dll", KERNELBASE_alias);
  addAlias("api-ms-win-core-sysinfo-l1-2-1.dll", KERNELBASE_alias);
  addAlias("api-ms-win-core-timezone-l1-1-0.dll", KERNELBASE_alias);
  addAlias("api-ms-win-core-localization-l1-2-1.dll", KERNELBASE_alias);
  addAlias("api-ms-win-core-localization-private-l1-1-0.dll", KERNELBASE_alias);
  addAlias("api-ms-win-core-processenvironment-l1-2-0.dll", KERNELBASE_alias);
  addAlias("api-ms-win-core-string-l1-1-0.dll", KERNELBASE_alias);
  addAlias("api-ms-win-core-debug-l1-1-1.dll", KERNELBASE_alias);
  addAlias("api-ms-win-core-errorhandling-l1-1-1.dll", KERNELBASE_alias);
  addAlias("api-ms-win-core-fibers-l1-1-1.dll", KERNELBASE_alias);
  addAlias("api-ms-win-core-util-l1-1-0.dll", KERNEL32_alias);
  addAlias("api-ms-win-core-profile-l1-1-0.dll", KERNELBASE_alias);
  addAlias("api-ms-win-security-base-l1-2-0.dll", KERNELBASE_alias);
  addAlias("api-ms-win-core-comm-l1-1-0.dll", KERNELBASE_alias);
  addAlias("api-ms-win-core-wow64-l1-1-0.dll", KERNELBASE_alias);
  addAlias("api-ms-win-core-realtime-l1-1-0.dll", KERNELBASE_alias);
  addAlias("api-ms-win-core-systemtopology-l1-1-0.dll", KERNELBASE_alias);
  addAlias("api-ms-win-core-processtopology-l1-2-0.dll", KERNELBASE_alias);
  addAlias("api-ms-win-core-namespace-l1-1-0.dll", KERNELBASE_alias);
  addAlias("api-ms-win-core-file-l2-1-1.dll", KERNELBASE_alias);
  addAlias("api-ms-win-core-xstate-l2-1-0.dll", KERNELBASE_alias);
  addAlias("api-ms-win-core-localization-l2-1-0.dll", KERNELBASE_alias);
  addAlias("api-ms-win-core-normalization-l1-1-0.dll", KERNELBASE_alias);
  addAlias("api-ms-win-core-sidebyside-l1-1-0.dll", KERNELBASE_alias);
  addAlias("api-ms-win-core-appcompat-l1-1-1.dll", KERNELBASE_alias);
  addAlias("api-ms-win-core-windowserrorreporting-l1-1-0.dll", KERNELBASE_alias);
  addAlias("api-ms-win-core-console-l1-1-0.dll", KERNELBASE_alias);
  addAlias("api-ms-win-core-console-l2-1-0.dll", KERNELBASE_alias);
  addAlias("api-ms-win-core-psapi-l1-1-0.dll", KERNELBASE_alias);
  addAlias("api-ms-win-core-psapi-ansi-l1-1-0.dll", KERNELBASE_alias);
  addAlias("api-ms-win-core-psapi-obsolete-l1-1-0.dll", KERNELBASE_alias);
  addAlias("api-ms-win-security-appcontainer-l1-1-0.dll", KERNELBASE_alias);
  ///// END GENERATED ADDS

	//Load and start our executable!
	ReflectivelyLoadLibbuf(testbin, NULL);
	return 0;
}
