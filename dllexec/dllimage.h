#ifndef __DLLIMAGE__ 
#define __DLLIMAGE__ 

#include <Winsock2.h>
#include <Windows.h>
#include <intrin.h>

ULONG_PTR WINAPI loadImage(ULONG_PTR memory, int size, int* sizeImage);

#endif