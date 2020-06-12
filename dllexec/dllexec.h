#ifndef __DLLEXEC__
#define __DLLEXEC__

#include <Windows.h>

#ifdef __cplusplus
extern "C" {
#endif

void freeDllExec();
int initDllExec();
HMODULE loadDllExec(char* name, void* memory, int size);

#ifdef __cplusplus
}
#endif

#endif
