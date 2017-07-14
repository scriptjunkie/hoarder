#include "DllSet.h"

//We keep track of images in this array
dllRecord dllRecords[MAX_DLL_RECORDS];
aliasRecord aliasRecords[MAX_DLL_RECORDS];

//And count
unsigned int dllCount;
unsigned int aliasCount;

//Adds a new dll
dllRecord* addImage(const char* name, unsigned char* image){
	dllRecords[dllCount].image = image;
	dllRecords[dllCount].loadedImage = 0;
  dllRecord* pdllRecord = &(dllRecords[dllCount]);
	aliasRecords[aliasCount].name = name;
	aliasRecords[aliasCount].dllr = pdllRecord;
	dllCount++;
	aliasCount++;
  return pdllRecord;
}

//Adds alias to known dll
void addAlias(const char* name, dllRecord * dllr){
	aliasRecords[aliasCount].name = name;
	aliasRecords[aliasCount].dllr = dllr;
	aliasCount++;
}

//Adds all the DLL's we know about
void setupImages(){
	dllCount = 0;
	aliasCount = 0;
}

//tests whether two strings are equal
bool striequal(const char* first, const char* second){
	if(first == NULL || second == NULL)
		return first == second;
	int i;
	for(i = 0; first[i] != 0 && second[i] != 0; i++)
		if(first[i] != second[i]  //not equal
				&& ((first[i] ^ 0x20) != second[i] // not case insensitive match
					|| (first[i] | 0x20) < 'a'
					|| (first[i] | 0x20) > 'z'))
			return false;
	return first[i] == second[i];
}

//Gets a DLL record by name
dllRecord* findDll(const char* name){
	// for each record
	for(int i = 0; i < MAX_DLL_RECORDS; i++)
		if(striequal(name,aliasRecords[i].name))
			return aliasRecords[i].dllr;
	return 0;
}

//Adds a new one
void addLoadedImage(const char* name, HMODULE loadedImage){
	findDll(name)->loadedImage = loadedImage;
}

//Returns an image to be inspectively loaded
unsigned char * getImage(const char* name){
	dllRecord* record = findDll(name);
	if(record == 0)
		return 0;
	return record->image;
}

//Returns a module handle to an image that has been inspectively loaded
HMODULE GetModuleHandleR(const char* name){
	dllRecord* record = findDll(name);
	if(record == 0 || record->loadedImage == 0)
		return 0;
	return record->loadedImage;
}