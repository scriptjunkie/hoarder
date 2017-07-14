#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
using namespace std;
string includes;
string loads;
map<string,string> importsToDlls;
PBYTE readDumpFile(const char* fpath, PCHAR name){
	//Get filename to prepare output and check whether we already did this DLL.
	string ffullpath(fpath);
	int i = ffullpath.length() - 1;
	while(i >= 0 && ffullpath[i] != '\\')
		i--;
	string fname = ffullpath.substr(i+1);
	string fsimplename(fname);
	DWORD dotoff = fsimplename.find_first_of(".");
	fsimplename.replace(dotoff, fsimplename.length() - dotoff, "");
	fname.append(".includeme.h");
	string namestr(name);
	if(importsToDlls.count(namestr) > 0)
		return NULL; // already exists. ohwell.

	if(GetFileAttributesA(fname.c_str()) != INVALID_FILE_ATTRIBUTES){
		loads.append("addAlias(\"").append(name).append("\",").append(fsimplename).append("_alias);\n");
		cerr << "aliased  " << fpath << endl;
		importsToDlls[namestr] = fname;
		return NULL; // already exists as an alias. ohwell.
	}

	includes.append("#include \"").append(fname).append("\"\n");
	cerr << "readDumping " << fpath << endl;
	//Ok, let's read it in
	HANDLE f = CreateFileA(fpath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if(f == INVALID_HANDLE_VALUE){
		cerr << "Usage: getdlls exepath" << endl;
		return NULL;
	}
	DWORD size = GetFileSize(f, NULL);
	PBYTE mem = (PBYTE)HeapAlloc(GetProcessHeap(), 0, size);
	if(mem == NULL){
		cerr << "File too large." << endl;
		return NULL;
	}
	DWORD read = 0;
	ReadFile(f, mem, size, &read, NULL);
	if(read != size){
		cerr << "File read error." << endl;
		return NULL;
	}
	CloseHandle(f);
	// Now write out the contents
	ofstream fout(fname.c_str());
	loads.append("dllRecord* ").append(fsimplename).append("_alias = addImage(\"").append(name).append("\",").append(fsimplename).append(");\n");
	fout << "unsigned char " << fsimplename << "[] = {";
	for(DWORD i = 0; i < size; i++)
		fout << ((i % 16 == 0) ? "\n" : " ")<< "0x" << hex 
			<< (DWORD)mem[i] << ((i < size - 1) ? "," : "");
	fout << "};" << endl;
	fout.close();
	importsToDlls[namestr] = fname;
	return mem;
}

//Loads a PE buffer, and recursively loads imports
void ReflectivelyDumpLibbuf( PBYTE libBuf ){
	// variables for processing the export table
	UINT_PTR uiLibraryAddress;

	// variables for loading this image
	UINT_PTR uiValueA;
	UINT_PTR uiValueB;
	UINT_PTR uiValueC;
	UINT_PTR uiValueD;

	if(libBuf == NULL)
		return;
	// STEP 1: load our image into a new permanent location in memory...

	// get the VA of the NT Header for the PE to be loaded
	PBYTE uiHeaderValue = libBuf + ((PIMAGE_DOS_HEADER)libBuf)->e_lfanew;

	// allocate all the memory for the DLL to be loaded into. we can load at any address because we will  
	// relocate the image. Also zeros all memory and marks it as READ, WRITE and EXECUTE to avoid any problems.
	UINT_PTR uiBaseAddress = NULL;
	SIZE_T RegionSize = ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfImage;
	uiBaseAddress = (UINT_PTR)VirtualAlloc(0, RegionSize, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE );

	// we must now copy over the headers
	DWORD size = ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfHeaders;
	memcpy( (PBYTE)uiBaseAddress, (PBYTE)libBuf, size );

	// STEP 2: load in all of our sections...

	// uiValueA = the VA of the first section
	uiValueA = ( (UINT_PTR)&((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader + ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.SizeOfOptionalHeader );
	
	// itterate through all sections, loading them into memory.
	while( ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.NumberOfSections-- ){
		// uiValueB is the VA for this section
		uiValueB = ( uiBaseAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->VirtualAddress );

		// uiValueC if the VA for this sections data
		uiValueC = (UINT_PTR)( libBuf + ((PIMAGE_SECTION_HEADER)uiValueA)->PointerToRawData );

		// copy the section over
		uiValueD = ((PIMAGE_SECTION_HEADER)uiValueA)->SizeOfRawData;
		memcpy( (PBYTE)uiValueB, (PBYTE)uiValueC, uiValueD );

		// get the VA of the next section
		uiValueA += sizeof( IMAGE_SECTION_HEADER );
	}

	// STEP 3: process our images import table...

	// uiValueB = the address of the import directory
	uiValueB = (UINT_PTR)&((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ];
	
	// we assume their is an import table to process
	// uiValueC is the first entry in the import table
	uiValueC = (UINT_PTR)( uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiValueB)->VirtualAddress );
	
	// iterate through all imports
	while( ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->Name ){
		// use LoadLibraryA to load the imported module into memory
		uiLibraryAddress = (UINT_PTR)LoadLibraryA( (PCHAR)( uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->Name ) );

		if(uiLibraryAddress != NULL){
			char fname[MAX_PATH];
			GetModuleFileNameA((HMODULE)uiLibraryAddress, fname, sizeof(fname));
			printf("%s is %s\n", (PCHAR)( uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->Name ), fname);
			ReflectivelyDumpLibbuf(readDumpFile(fname,
				(PCHAR)( uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->Name )));
		}
		// get the next import
		uiValueC += sizeof( IMAGE_IMPORT_DESCRIPTOR );
	}
}
int main(int argc, char**argv){
  if (argc < 2) {
    cerr << "Usage: " << argv[0] << " target.exe [lib1.dll] [lib2.dll]";
    return 1;
  }
  for (int i = 1; i < argc; i++) {
    PBYTE exepath = readDumpFile(argv[i], argv[i]);
    ReflectivelyDumpLibbuf(exepath);
  }
  cerr << "Add this to your includes:" << endl;
	cout << includes << endl;
  cerr << "Add this to your initialization:" << endl;
	cout << loads << endl;
	cerr << "all done!" << endl;
  return 0;
}
