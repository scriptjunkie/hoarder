//===============================================================================================//
// Copyright (c) 2013, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
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
#include "GetProcAddressInPlaceR.h"

PIMAGE_SECTION_HEADER GetEnclosingSectionHeader(DWORD rva, PIMAGE_NT_HEADERS pNTHeader)   // 'T' == PIMAGE_NT_HEADERS
{
  PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pNTHeader);
  unsigned i;

  for (i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++, section++)
  {
    DWORD size = section->Misc.VirtualSize;
    if (0 == size)
      size = section->SizeOfRawData;

    // Is the RVA within this section?
    if ((rva >= section->VirtualAddress) &&
      (rva < (section->VirtualAddress + size)))
      return section;
  }
  return 0;
}


UINT_PTR GetPtrFromRVA(DWORD rva, PIMAGE_NT_HEADERS pNTHeader, PBYTE imageBase) // 'T' = PIMAGE_NT_HEADERS
{
  PIMAGE_SECTION_HEADER pSectionHdr;
  INT delta;

  pSectionHdr = GetEnclosingSectionHeader(rva, pNTHeader);
  if (!pSectionHdr)
    return 0;

  delta = (INT)(pSectionHdr->VirtualAddress - pSectionHdr->PointerToRawData);
  return (UINT_PTR)(imageBase + rva - delta);
}

//===============================================================================================//
// We implement a minimal GetProcAddress to avoid using the native kernel32!GetProcAddress which
// wont be able to resolve exported addresses in reflectivly loaded libraries.
FARPROC WINAPI GetProcAddressInPlaceR( HANDLE hModule, LPCSTR lpProcName )
{
	UINT_PTR uiLibraryAddress = 0;
	FARPROC fpResult          = NULL;

	if( hModule == NULL )
		return NULL;

	// a module handle is really its base address
	uiLibraryAddress = (UINT_PTR)hModule;

//	__try
//	{
		UINT_PTR uiAddressArray = 0;
		UINT_PTR uiNameArray    = 0;
		UINT_PTR uiNameOrdinals = 0;
		PIMAGE_NT_HEADERS pNtHeaders             = NULL;
		PIMAGE_DATA_DIRECTORY pDataDirectory     = NULL;
		PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;
			
		// get the VA of the modules NT Header
		pNtHeaders = (PIMAGE_NT_HEADERS)(uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew);

		pDataDirectory = (PIMAGE_DATA_DIRECTORY)&pNtHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];

		// get the VA of the export directory
		pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)GetPtrFromRVA(pDataDirectory->VirtualAddress, pNtHeaders, (PBYTE)uiLibraryAddress );
			
		// get the VA for the array of addresses
		uiAddressArray = GetPtrFromRVA(pExportDirectory->AddressOfFunctions, pNtHeaders, (PBYTE)uiLibraryAddress);

		// get the VA for the array of name pointers
		uiNameArray = GetPtrFromRVA(pExportDirectory->AddressOfNames, pNtHeaders, (PBYTE)uiLibraryAddress);
				
		// get the VA for the array of name ordinals
		uiNameOrdinals = GetPtrFromRVA(pExportDirectory->AddressOfNameOrdinals, pNtHeaders, (PBYTE)uiLibraryAddress);

		// test if we are importing by name or by ordinal...
		if( ((DWORD)lpProcName & 0xFFFF0000 ) == 0x00000000 )
		{
			// import by ordinal...

			// use the import ordinal (- export ordinal base) as an index into the array of addresses
			uiAddressArray += ( ( IMAGE_ORDINAL( (DWORD)lpProcName ) - pExportDirectory->Base ) * sizeof(DWORD) );

			// resolve the address for this imported function
			fpResult = (FARPROC)GetPtrFromRVA(DEREF_32(uiAddressArray), pNtHeaders, (PBYTE)uiLibraryAddress);
		}
		else
		{
			// import by name...
			DWORD dwCounter = pExportDirectory->NumberOfNames;
			while( dwCounter-- )
			{
				char * cpExportedFunctionName = (char *)GetPtrFromRVA(DEREF_32( uiNameArray ), pNtHeaders, (PBYTE)uiLibraryAddress);
				
				// test if we have a match...
				if( strcmp( cpExportedFunctionName, lpProcName ) == 0 )
				{
					// use the functions name ordinal as an index into the array of name pointers
					uiAddressArray += ( DEREF_16( uiNameOrdinals ) * sizeof(DWORD) );
					
					// calculate the virtual address for the function
					fpResult = (FARPROC)GetPtrFromRVA(DEREF_32( uiAddressArray ), pNtHeaders, (PBYTE)uiLibraryAddress);
					
					// finish...
					break;
				}
						
				// get the next exported function name
				uiNameArray += sizeof(DWORD);

				// get the next exported function name ordinal
				uiNameOrdinals += sizeof(WORD);
			}
		}
//	}
//	__except( EXCEPTION_EXECUTE_HANDLER )
//	{
//		fpResult = NULL;
//	}

	return fpResult;
}
//===============================================================================================//
