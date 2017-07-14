//This is a super simple test binary that will work when hoarded.
//Unfortunately, most other programs won't, but hey, it's a proof of concept
//Matt Weeks

#include <Windows.h>

void start() { // there is no main, since there is no CRT
  DWORD wrote = 0;
  WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), "Hello World!\n", 13, &wrote, NULL);
}
