//===============================================================================================//
// Copyright (c) 2009, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are permitted 
// provided that the following conditions are met:
// 
//     * Redistributions of source code must retain the above copyright notice, this list of 
// conditions and the following disclaimer.
// 
//     * Redistributions in binary form must reproduce the above copyright notice, this list of 
// conditions and the following disclaimer in the documentation and/or other materials provided 
// with the distribution.
// 
//     * Neither the name of Harmony Security nor the names of its contributors may be used to
// endorse or promote products derived from this software without specific prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR 
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
// FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR 
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR 
// OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
// POSSIBILITY OF SUCH DAMAGE.
//===============================================================================================//
#include "ReflectiveLoader.h"
#include "DllSet.h"
#include "GetProcAddressR.h"
#include "NtAllocateVirtualMemoryR.h"
#include <stdio.h>
//===============================================================================================//
// Our loader will set this to a pseudo correct HINSTANCE/HMODULE value
HINSTANCE hAppInstance = NULL;
//===============================================================================================//
#ifdef _WIN64
#pragma intrinsic( _ReturnAddress )
UINT_PTR eip( VOID ) { return (UINT_PTR)_ReturnAddress(); }
#endif
//===============================================================================================//
DWORD indent = 0;
//LoadLibraryA sortof
HMODULE WINAPI ReflectivelyLoadLibraryA( PCHAR libName ){
	HMODULE loaded = GetModuleHandleR(libName);
	if(loaded != NULL){
		return loaded;
	}
	HMODULE result = ReflectivelyLoadLibbuf(getImage(libName), libName);
	return result;
}

//We're so messy and don't clean up our stuff
BOOL WINAPI ReflectivelyFreeLibrary(){
	return TRUE;
}

//Loads a DLL buffer
HMODULE WINAPI ReflectivelyLoadLibbuf( PVOID buf, PCHAR name ){
	// variables for processing the export table
	UINT_PTR uiAddressArray;
	UINT_PTR uiNameArray;
	UINT_PTR uiExportDir;
	UINT_PTR uiLibraryAddress;

	// variables for loading this image
	UINT_PTR uiValueA;
	UINT_PTR uiValueB;
	UINT_PTR uiValueC;
	UINT_PTR uiValueD;

	UINT_PTR libBuf = (UINT_PTR) buf;

	// STEP 1: load our image into a new permanent location in memory...

	// get the VA of the NT Header for the PE to be loaded
	UINT_PTR uiHeaderValue = libBuf + ((PIMAGE_DOS_HEADER)libBuf)->e_lfanew;

	// allocate all the memory for the DLL to be loaded into. we can load at any address because we will  
	// relocate the image. Also zeros all memory and marks it as READ, WRITE and EXECUTE to avoid any problems.
	UINT_PTR uiBaseAddress = ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.ImageBase;

	//We need to get the biggest offset included in the image sections
	// uiValueA = the VA of the first section
	uiValueA = ( (UINT_PTR)&((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader + ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.SizeOfOptionalHeader );
	SIZE_T RegionSize = ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfImage;
	DWORD numSections = ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.NumberOfSections;
	// iterate through all sections, loading them into memory.
	while( numSections-- ){
		DWORD sectionExtent = ((PIMAGE_SECTION_HEADER)uiValueA)->VirtualAddress
			+ ((PIMAGE_SECTION_HEADER)uiValueA)->SizeOfRawData;
		if(sectionExtent > RegionSize)
			RegionSize = sectionExtent;
		// get the VA of the next section
		//if(
		uiValueA += sizeof( IMAGE_SECTION_HEADER );
	}
  if (NtAllocateVirtualMemoryR((HANDLE)-1, (PVOID*)&uiBaseAddress,
      12, &RegionSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE) != ERROR_SUCCESS) {
    uiBaseAddress = NULL;
    UINT_PTR origAddress = uiBaseAddress;
    for (uiBaseAddress += RegionSize; uiBaseAddress != origAddress; uiBaseAddress += RegionSize) {
      if (NtAllocateVirtualMemoryR((HANDLE)-1, (PVOID*)&uiBaseAddress,
          12, &RegionSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE) == ERROR_SUCCESS) {
        break;
      }
    }
  }
  if (name) { //mark us as loaded in case we run into circular dependencies
    addLoadedImage(name, (HMODULE)uiBaseAddress);
  }

	// we must now copy over the headers
	DWORD size = ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfHeaders;
	__movsb( (PBYTE)uiBaseAddress, (PBYTE)libBuf, size );

	// STEP 2: load in all of our sections...

	// uiValueA = the VA of the first section
	uiValueA = ( (UINT_PTR)&((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader + ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.SizeOfOptionalHeader );
	
	// iterate through all sections, loading them into memory.
	while( ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.NumberOfSections-- ){
		// uiValueB is the VA for this section
		uiValueB = ( uiBaseAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->VirtualAddress );

		// uiValueC if the VA for this sections data
		uiValueC = ( libBuf + ((PIMAGE_SECTION_HEADER)uiValueA)->PointerToRawData );

		// copy the section over
		uiValueD = ((PIMAGE_SECTION_HEADER)uiValueA)->SizeOfRawData;
		__movsb( (PBYTE)uiValueB, (PBYTE)uiValueC, uiValueD );

		// get the VA of the next section
		uiValueA += sizeof( IMAGE_SECTION_HEADER );
	}

	// STEP 3: process our images import table...

	// uiValueB = the address of the import directory
	uiValueB = (UINT_PTR)&((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ];
	
	// we assume there is an import table to process
	// uiValueC is the first entry in the import table
	uiValueC = ( uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiValueB)->VirtualAddress );
	
	// iterate through all imports if there is an import table
	if(uiValueC != uiBaseAddress){
	  while( ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->Name ){
		  // use LoadLibraryA to load the imported module into memory
		  uiLibraryAddress = (UINT_PTR)ReflectivelyLoadLibraryA( (PCHAR)( uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->Name ) );

		  // uiValueD = VA of the OriginalFirstThunk
		  uiValueD = ( uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->OriginalFirstThunk );
	
		  // uiValueA = VA of the IAT (via first thunk not origionalfirstthunk)
		  uiValueA = ( uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->FirstThunk );

		  // itterate through all imported functions, importing by ordinal if no name present
		  while( DEREF(uiValueA) ){
			  // sanity check uiValueD as some compilers only import by FirstThunk
			  if( uiValueD && ((PIMAGE_THUNK_DATA)uiValueD)->u1.Ordinal & IMAGE_ORDINAL_FLAG ){
				  // get the VA of the modules NT Header
				  uiExportDir = uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;

				  // uiNameArray = the address of the modules export directory entry
				  uiNameArray = (UINT_PTR)&((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];

				  // get the VA of the export directory
				  uiExportDir = ( uiLibraryAddress + ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress );

				  // get the VA for the array of addresses
				  uiAddressArray = ( uiLibraryAddress + ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfFunctions );

				  // use the import ordinal (- export ordinal base) as an index into the array of addresses
				  uiAddressArray += ( ( IMAGE_ORDINAL( ((PIMAGE_THUNK_DATA)uiValueD)->u1.Ordinal ) - ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->Base ) * sizeof(DWORD) );

				  // patch in the address for this imported function
				  DEREF(uiValueA) = ( uiLibraryAddress + DEREF_32(uiAddressArray) );
			  }else{
				  // get the VA of this functions import by name struct
				  uiValueB = ( uiBaseAddress + DEREF(uiValueA) );

  //				__try{
					  // check if we need to hook this - LoadLibraryA, FreeLibrary
					  if(striequal((LPCSTR)((PIMAGE_IMPORT_BY_NAME)uiValueB)->Name, "LoadLibraryA"))
						  DEREF(uiValueA) = (UINT_PTR)&ReflectivelyLoadLibraryA;
					  else if(striequal((LPCSTR)((PIMAGE_IMPORT_BY_NAME)uiValueB)->Name, "FreeLibrary"))
						  DEREF(uiValueA) = (UINT_PTR)&ReflectivelyFreeLibrary;
					  else // use GetProcAddressR and patch in the address for this imported function
						  DEREF(uiValueA) = (UINT_PTR)GetProcAddressR( (HMODULE)uiLibraryAddress, (LPCSTR)((PIMAGE_IMPORT_BY_NAME)uiValueB)->Name );
  //				}__except(EXCEPTION_EXECUTE_HANDLER){
  //					//printf("Error :-(\n");
  //				}
			  }
			  // get the next imported function
			  uiValueA += sizeof( UINT_PTR );
			  if( uiValueD )
				  uiValueD += sizeof( UINT_PTR );
		  }

		  // get the next import
		  uiValueC += sizeof( IMAGE_IMPORT_DESCRIPTOR );
	  }
	}

	// STEP 4: process all of our images relocations...

	// calculate the base address delta and perform relocations (even if we load at desired image base)
	uiLibraryAddress = uiBaseAddress - ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.ImageBase;
	
	// uiValueB = the address of the relocation directory
	uiValueB = (UINT_PTR)&((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ];

	// check if their are any relocations present
	if( ((PIMAGE_DATA_DIRECTORY)uiValueB)->Size )
	{
		// uiValueC is now the first entry (IMAGE_BASE_RELOCATION)
		uiValueC = ( uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiValueB)->VirtualAddress );

		// and we itterate through all entries...
		while( ((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock )
		{
			// uiValueA = the VA for this relocation block
			uiValueA = ( uiBaseAddress + ((PIMAGE_BASE_RELOCATION)uiValueC)->VirtualAddress );

			// uiValueB = number of entries in this relocation block
			uiValueB = ( ((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION) ) / sizeof( IMAGE_RELOC );

			// uiValueD is now the first entry in the current relocation block
			uiValueD = uiValueC + sizeof(IMAGE_BASE_RELOCATION);

			// we itterate through all the entries in the current block...
			while( uiValueB-- )
			{
				// perform the relocation, skipping IMAGE_REL_BASED_ABSOLUTE as required.
				// we dont use a switch statement to avoid the compiler building a jump table
				// which would not be very position independent!
				if( ((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_DIR64 )
					*(UINT_PTR *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += uiLibraryAddress;
				else if( ((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_HIGHLOW )
					*(DWORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += (DWORD)uiLibraryAddress;
				else if( ((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_HIGH )
					*(WORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += HIWORD(uiLibraryAddress);
				else if( ((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_LOW )
					*(WORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += LOWORD(uiLibraryAddress);

				// get the next entry in the current relocation block
				uiValueD += sizeof( IMAGE_RELOC );
			}

			// get the next entry in the relocation directory
			uiValueC = uiValueC + ((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock;
		}
	}

	// STEP 5: process the images exception directory if it has one (PE32+ for x64)
  // Hoarder isn't dealing with x64 right now mk?
/*
	// uiValueB = the address of the relocation directory
	uiValueB = (UINT_PTR)&((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXCEPTION ];
	// check if their are any exception etries present
	if( ((PIMAGE_DATA_DIRECTORY)uiValueB)->Size )
	{
		// get the number of entries
		uiValueA = ((PIMAGE_DATA_DIRECTORY)uiValueB)->Size / sizeof( IMAGE_RUNTIME_FUNCTION_ENTRY );
		
		// uiValueC is now the first entry (IMAGE_RUNTIME_FUNCTION_ENTRY)
		uiValueC = ( uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiValueB)->VirtualAddress );

		// itterate through all entries
		while( uiValueA-- )
		{
			//((IMAGE_RUNTIME_FUNCTION_ENTRY)uiValueC).BeginAddress
		
			// get the next entry
			uiValueC += sizeof( IMAGE_RUNTIME_FUNCTION_ENTRY );
		}
	}
*/
	// STEP 6: call our images entry point

	// uiValueA = the VA of our newly loaded DLL/EXE's entry point
	uiValueA = ( uiBaseAddress + ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.AddressOfEntryPoint );

	// call our respective entry point, fudging our hInstance value, if it exists and we're an exe
  if (uiValueA != uiBaseAddress) {
    if ((((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)
        && (((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.Characteristics & IMAGE_FILE_DLL) == 0) {
      DWORD res = ((DWORD(WINAPI*)(HINSTANCE, HINSTANCE, LPSTR, int))uiValueA)((HINSTANCE)uiBaseAddress, NULL, NULL, 0);//TODO: fill these in with real winmain vals
    } else {
      //	((DLLMAIN)uiValueA)( (HINSTANCE)uiBaseAddress, DLL_PROCESS_ATTACH, NULL );
    }
  }

	// STEP 7: return our address 
	return (HMODULE)uiBaseAddress;
}
