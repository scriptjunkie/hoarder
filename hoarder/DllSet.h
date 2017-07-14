#ifndef DLL_SET_H
#define DLL_SET_H

#include <Windows.h>
#define MAX_DLL_RECORDS 100
typedef struct dllr {
  unsigned char* image;
  HMODULE loadedImage;
} dllRecord;
typedef struct aliasr {
  const char* name;
  dllRecord * dllr;
} aliasRecord;

//Handles saving/finding DLL images, as well as saving/getting loaded images
void setupImages();
dllRecord* addImage(const char* name, unsigned char* image);
void addAlias(const char* name, dllRecord * existingImage);
unsigned char * getImage(const char* dllName);
void addLoadedImage(const char* name, HMODULE loadedImage);
HMODULE GetModuleHandleR(const char* name);
//helper function
bool striequal(const char* first, const char* second);

#endif