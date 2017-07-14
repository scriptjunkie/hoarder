Hoarder
=======

A proof-of-concept to wrap executables on Windows with all of their required system DLL's into a single importless executable that makes direct syscalls.

This allows simple programs to generically evade user-mode hooks and hot patches, whether inline, IAT, or EAT. These are frequently used by sandboxes, intrusion detection systems, rootkits, etc.

This also allows your code to avoid triggering Export Address Table filtering used by EMET.

Usage
-----

- Open the solution in Visual Studio and put your code in the testbin project and build it. Or just compile the one that's already there.

- Next compile getdlls, open a command prompt in the hoarder Release folder, and run 

        getdlls.exe testbin.exe

It will spit out output like this and write a few files:

        readDumping testbin.exe
        KERNEL32.dll is C:\Windows\SYSTEM32\KERNEL32.DLL
        readDumping C:\Windows\SYSTEM32\KERNEL32.DLL
        api-ms-win-core-rtlsupport-l1-2-0.dll is C:\Windows\SYSTEM32\ntdll.dll
        readDumping C:\Windows\SYSTEM32\ntdll.dll
        ntdll.dll is C:\Windows\SYSTEM32\ntdll.dll
        aliased  C:\Windows\SYSTEM32\ntdll.dll
        KERNELBASE.dll is C:\Windows\SYSTEM32\KERNELBASE.dll
        readDumping C:\Windows\SYSTEM32\KERNELBASE.dll
        ntdll.dll is C:\Windows\SYSTEM32\ntdll.dll
        api-ms-win-core-processthreads-l1-1-2.dll is C:\Windows\SYSTEM32\KERNEL32.DLL
        aliased  C:\Windows\SYSTEM32\KERNEL32.DLL
        api-ms-win-core-registry-l1-1-0.dll is C:\Windows\SYSTEM32\KERNELBASE.dll
        aliased  C:\Windows\SYSTEM32\KERNELBASE.dll
        api-ms-win-core-heap-l1-2-0.dll is C:\Windows\SYSTEM32\KERNELBASE.dll
        aliased  C:\Windows\SYSTEM32\KERNELBASE.dll
        api-ms-win-core-memory-l1-1-2.dll is C:\Windows\SYSTEM32\KERNELBASE.dll
        aliased  C:\Windows\SYSTEM32\KERNELBASE.dll
        api-ms-win-core-handle-l1-1-0.dll is C:\Windows\SYSTEM32\KERNELBASE.dll
        aliased  C:\Windows\SYSTEM32\KERNELBASE.dll
        api-ms-win-core-synch-l1-2-0.dll is C:\Windows\SYSTEM32\KERNELBASE.dll
        aliased  C:\Windows\SYSTEM32\KERNELBASE.dll
        api-ms-win-core-file-l1-2-1.dll is C:\Windows\SYSTEM32\KERNELBASE.dll
        aliased  C:\Windows\SYSTEM32\KERNELBASE.dll
        api-ms-win-core-delayload-l1-1-1.dll is C:\Windows\SYSTEM32\KERNEL32.DLL
        aliased  C:\Windows\SYSTEM32\KERNEL32.DLL
        api-ms-win-core-io-l1-1-1.dll is C:\Windows\SYSTEM32\KERNEL32.DLL
        aliased  C:\Windows\SYSTEM32\KERNEL32.DLL
        api-ms-win-core-job-l1-1-0.dll is C:\Windows\SYSTEM32\KERNELBASE.dll
        aliased  C:\Windows\SYSTEM32\KERNELBASE.dll
        api-ms-win-core-threadpool-legacy-l1-1-0.dll is C:\Windows\SYSTEM32\KERNELBASE.dll
        aliased  C:\Windows\SYSTEM32\KERNELBASE.dll
        api-ms-win-core-threadpool-private-l1-1-0.dll is C:\Windows\SYSTEM32\KERNELBASE.dll
        aliased  C:\Windows\SYSTEM32\KERNELBASE.dll
        api-ms-win-core-libraryloader-l1-2-0.dll is C:\Windows\SYSTEM32\KERNELBASE.dll
        aliased  C:\Windows\SYSTEM32\KERNELBASE.dll
        api-ms-win-core-namedpipe-l1-2-0.dll is C:\Windows\SYSTEM32\KERNELBASE.dll
        aliased  C:\Windows\SYSTEM32\KERNELBASE.dll
        api-ms-win-core-datetime-l1-1-1.dll is C:\Windows\SYSTEM32\KERNELBASE.dll
        aliased  C:\Windows\SYSTEM32\KERNELBASE.dll
        api-ms-win-core-sysinfo-l1-2-1.dll is C:\Windows\SYSTEM32\KERNELBASE.dll
        aliased  C:\Windows\SYSTEM32\KERNELBASE.dll
        api-ms-win-core-timezone-l1-1-0.dll is C:\Windows\SYSTEM32\KERNELBASE.dll
        aliased  C:\Windows\SYSTEM32\KERNELBASE.dll
        api-ms-win-core-localization-l1-2-1.dll is C:\Windows\SYSTEM32\KERNELBASE.dll
        aliased  C:\Windows\SYSTEM32\KERNELBASE.dll
        api-ms-win-core-localization-private-l1-1-0.dll is C:\Windows\SYSTEM32\KERNELBASE.dll
        aliased  C:\Windows\SYSTEM32\KERNELBASE.dll
        api-ms-win-core-processenvironment-l1-2-0.dll is C:\Windows\SYSTEM32\KERNELBASE.dll
        aliased  C:\Windows\SYSTEM32\KERNELBASE.dll
        api-ms-win-core-string-l1-1-0.dll is C:\Windows\SYSTEM32\KERNELBASE.dll
        aliased  C:\Windows\SYSTEM32\KERNELBASE.dll
        api-ms-win-core-debug-l1-1-1.dll is C:\Windows\SYSTEM32\KERNELBASE.dll
        aliased  C:\Windows\SYSTEM32\KERNELBASE.dll
        api-ms-win-core-errorhandling-l1-1-1.dll is C:\Windows\SYSTEM32\KERNELBASE.dll
        aliased  C:\Windows\SYSTEM32\KERNELBASE.dll
        api-ms-win-core-fibers-l1-1-1.dll is C:\Windows\SYSTEM32\KERNELBASE.dll
        aliased  C:\Windows\SYSTEM32\KERNELBASE.dll
        api-ms-win-core-util-l1-1-0.dll is C:\Windows\SYSTEM32\KERNEL32.DLL
        aliased  C:\Windows\SYSTEM32\KERNEL32.DLL
        api-ms-win-core-profile-l1-1-0.dll is C:\Windows\SYSTEM32\KERNELBASE.dll
        aliased  C:\Windows\SYSTEM32\KERNELBASE.dll
        api-ms-win-security-base-l1-2-0.dll is C:\Windows\SYSTEM32\KERNELBASE.dll
        aliased  C:\Windows\SYSTEM32\KERNELBASE.dll
        api-ms-win-core-comm-l1-1-0.dll is C:\Windows\SYSTEM32\KERNELBASE.dll
        aliased  C:\Windows\SYSTEM32\KERNELBASE.dll
        api-ms-win-core-wow64-l1-1-0.dll is C:\Windows\SYSTEM32\KERNELBASE.dll
        aliased  C:\Windows\SYSTEM32\KERNELBASE.dll
        api-ms-win-core-realtime-l1-1-0.dll is C:\Windows\SYSTEM32\KERNELBASE.dll
        aliased  C:\Windows\SYSTEM32\KERNELBASE.dll
        api-ms-win-core-systemtopology-l1-1-0.dll is C:\Windows\SYSTEM32\KERNELBASE.dll
        aliased  C:\Windows\SYSTEM32\KERNELBASE.dll
        api-ms-win-core-processtopology-l1-2-0.dll is C:\Windows\SYSTEM32\KERNELBASE.dll
        aliased  C:\Windows\SYSTEM32\KERNELBASE.dll
        api-ms-win-core-namespace-l1-1-0.dll is C:\Windows\SYSTEM32\KERNELBASE.dll
        aliased  C:\Windows\SYSTEM32\KERNELBASE.dll
        api-ms-win-core-file-l2-1-1.dll is C:\Windows\SYSTEM32\KERNELBASE.dll
        aliased  C:\Windows\SYSTEM32\KERNELBASE.dll
        api-ms-win-core-xstate-l2-1-0.dll is C:\Windows\SYSTEM32\KERNELBASE.dll
        aliased  C:\Windows\SYSTEM32\KERNELBASE.dll
        api-ms-win-core-localization-l2-1-0.dll is C:\Windows\SYSTEM32\KERNELBASE.dll
        aliased  C:\Windows\SYSTEM32\KERNELBASE.dll
        api-ms-win-core-normalization-l1-1-0.dll is C:\Windows\SYSTEM32\KERNELBASE.dll
        aliased  C:\Windows\SYSTEM32\KERNELBASE.dll
        api-ms-win-core-sidebyside-l1-1-0.dll is C:\Windows\SYSTEM32\KERNELBASE.dll
        aliased  C:\Windows\SYSTEM32\KERNELBASE.dll
        api-ms-win-core-appcompat-l1-1-1.dll is C:\Windows\SYSTEM32\KERNELBASE.dll
        aliased  C:\Windows\SYSTEM32\KERNELBASE.dll
        api-ms-win-core-windowserrorreporting-l1-1-0.dll is C:\Windows\SYSTEM32\KERNELBASE.dll
        aliased  C:\Windows\SYSTEM32\KERNELBASE.dll
        api-ms-win-core-console-l1-1-0.dll is C:\Windows\SYSTEM32\KERNELBASE.dll
        aliased  C:\Windows\SYSTEM32\KERNELBASE.dll
        api-ms-win-core-console-l2-1-0.dll is C:\Windows\SYSTEM32\KERNELBASE.dll
        aliased  C:\Windows\SYSTEM32\KERNELBASE.dll
        api-ms-win-core-psapi-l1-1-0.dll is C:\Windows\SYSTEM32\KERNELBASE.dll
        aliased  C:\Windows\SYSTEM32\KERNELBASE.dll
        api-ms-win-core-psapi-ansi-l1-1-0.dll is C:\Windows\SYSTEM32\KERNELBASE.dll
        aliased  C:\Windows\SYSTEM32\KERNELBASE.dll
        api-ms-win-core-psapi-obsolete-l1-1-0.dll is C:\Windows\SYSTEM32\KERNELBASE.dll
        aliased  C:\Windows\SYSTEM32\KERNELBASE.dll
        api-ms-win-security-appcontainer-l1-1-0.dll is C:\Windows\SYSTEM32\KERNELBASE.dll
        aliased  C:\Windows\SYSTEM32\KERNELBASE.dll
        Add this to your includes:
        #include "testbin.exe.includeme.h"
        #include "KERNEL32.DLL.includeme.h"
        #include "ntdll.dll.includeme.h"
        #include "KERNELBASE.dll.includeme.h"
        
        Add this to your initialization:
        dllRecord* testbin_alias = addImage("testbin.exe",testbin);
        dllRecord* KERNEL32_alias = addImage("KERNEL32.dll",KERNEL32);
        dllRecord* ntdll_alias = addImage("api-ms-win-core-rtlsupport-l1-2-0.dll",ntdll);
        addAlias("ntdll.dll",ntdll_alias);
        dllRecord* KERNELBASE_alias = addImage("KERNELBASE.dll",KERNELBASE);
        addAlias("api-ms-win-core-processthreads-l1-1-2.dll",KERNEL32_alias);
        addAlias("api-ms-win-core-registry-l1-1-0.dll",KERNELBASE_alias);
        addAlias("api-ms-win-core-heap-l1-2-0.dll",KERNELBASE_alias);
        addAlias("api-ms-win-core-memory-l1-1-2.dll",KERNELBASE_alias);
        addAlias("api-ms-win-core-handle-l1-1-0.dll",KERNELBASE_alias);
        addAlias("api-ms-win-core-synch-l1-2-0.dll",KERNELBASE_alias);
        addAlias("api-ms-win-core-file-l1-2-1.dll",KERNELBASE_alias);
        addAlias("api-ms-win-core-delayload-l1-1-1.dll",KERNEL32_alias);
        addAlias("api-ms-win-core-io-l1-1-1.dll",KERNEL32_alias);
        addAlias("api-ms-win-core-job-l1-1-0.dll",KERNELBASE_alias);
        addAlias("api-ms-win-core-threadpool-legacy-l1-1-0.dll",KERNELBASE_alias);
        addAlias("api-ms-win-core-threadpool-private-l1-1-0.dll",KERNELBASE_alias);
        addAlias("api-ms-win-core-libraryloader-l1-2-0.dll",KERNELBASE_alias);
        addAlias("api-ms-win-core-namedpipe-l1-2-0.dll",KERNELBASE_alias);
        addAlias("api-ms-win-core-datetime-l1-1-1.dll",KERNELBASE_alias);
        addAlias("api-ms-win-core-sysinfo-l1-2-1.dll",KERNELBASE_alias);
        addAlias("api-ms-win-core-timezone-l1-1-0.dll",KERNELBASE_alias);
        addAlias("api-ms-win-core-localization-l1-2-1.dll",KERNELBASE_alias);
        addAlias("api-ms-win-core-localization-private-l1-1-0.dll",KERNELBASE_alias);
        addAlias("api-ms-win-core-processenvironment-l1-2-0.dll",KERNELBASE_alias);
        addAlias("api-ms-win-core-string-l1-1-0.dll",KERNELBASE_alias);
        addAlias("api-ms-win-core-debug-l1-1-1.dll",KERNELBASE_alias);
        addAlias("api-ms-win-core-errorhandling-l1-1-1.dll",KERNELBASE_alias);
        addAlias("api-ms-win-core-fibers-l1-1-1.dll",KERNELBASE_alias);
        addAlias("api-ms-win-core-util-l1-1-0.dll",KERNEL32_alias);
        addAlias("api-ms-win-core-profile-l1-1-0.dll",KERNELBASE_alias);
        addAlias("api-ms-win-security-base-l1-2-0.dll",KERNELBASE_alias);
        addAlias("api-ms-win-core-comm-l1-1-0.dll",KERNELBASE_alias);
        addAlias("api-ms-win-core-wow64-l1-1-0.dll",KERNELBASE_alias);
        addAlias("api-ms-win-core-realtime-l1-1-0.dll",KERNELBASE_alias);
        addAlias("api-ms-win-core-systemtopology-l1-1-0.dll",KERNELBASE_alias);
        addAlias("api-ms-win-core-processtopology-l1-2-0.dll",KERNELBASE_alias);
        addAlias("api-ms-win-core-namespace-l1-1-0.dll",KERNELBASE_alias);
        addAlias("api-ms-win-core-file-l2-1-1.dll",KERNELBASE_alias);
        addAlias("api-ms-win-core-xstate-l2-1-0.dll",KERNELBASE_alias);
        addAlias("api-ms-win-core-localization-l2-1-0.dll",KERNELBASE_alias);
        addAlias("api-ms-win-core-normalization-l1-1-0.dll",KERNELBASE_alias);
        addAlias("api-ms-win-core-sidebyside-l1-1-0.dll",KERNELBASE_alias);
        addAlias("api-ms-win-core-appcompat-l1-1-1.dll",KERNELBASE_alias);
        addAlias("api-ms-win-core-windowserrorreporting-l1-1-0.dll",KERNELBASE_alias);
        addAlias("api-ms-win-core-console-l1-1-0.dll",KERNELBASE_alias);
        addAlias("api-ms-win-core-console-l2-1-0.dll",KERNELBASE_alias);
        addAlias("api-ms-win-core-psapi-l1-1-0.dll",KERNELBASE_alias);
        addAlias("api-ms-win-core-psapi-ansi-l1-1-0.dll",KERNELBASE_alias);
        addAlias("api-ms-win-core-psapi-obsolete-l1-1-0.dll",KERNELBASE_alias);
        addAlias("api-ms-win-security-appcontainer-l1-1-0.dll",KERNELBASE_alias);
        
        all done!

Next copy the .includeme.h files into the hoarder project folder, add them to your header files (removing any old ones still there), and add the code snippets to the appropriate place in the main.cpp. Then compile the hoarder project and you'll have a hoarded binary you can run.

        E:\hoarder\hoarder\Release>hoarder.exe
        Hello World!
        
        E:\hoarder\hoarder\Release>