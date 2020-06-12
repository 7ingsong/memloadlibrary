# memloadlibrary

The newest way to run dynamic library from memory.

## How it works

First the library loads sections and relocated target library target.dll 

Then it hooks functions responsible to mapping library which we want to load memory NtOpenFile, NtOpenSection, ZwCreateSection, ZwMapViewOfSection, ZwUnmapViewOfSection, ZwClose. 

Finally it runs LoadLibraryA/W("target.dll"), this operation sets up import and registers library in PEB.

## Build

```
mkdir build
cd build
cmake ..
nmake
```

## Example

``` 
#include "dllexec.h"
#include <stdio.h>
#include <stdlib.h>

void* loadFile(char* fileName, int* len)
{
	int sz = 0;
	void* p = 0;
	*len = 0;
	FILE* f = fopen(fileName, "rb");
	if (f)
	{
		fseek(f, 0L, SEEK_END);
		sz = ftell(f);
		fseek(f, 0L, SEEK_SET);
		p = malloc(sz);
		if (p)
		{
			fread(p, 1, sz, f);
			*len = sz;
		}
		else
		{
			sz = 0;
		}
		fclose(f);
	}
	return p;
}


int main()
{
	if (initDllExec() == 1)
	{
		int len;
		void* mem = loadFile("testdll.dll", &len);
		if (mem)
		{
			HMODULE m = loadDllExec("fake.dll", mem, len);

			VOID(__cdecl * p)(void) = (void*)GetProcAddress(m, "Message");
			p();

			FreeLibrary(m);
			free(mem);
		}

		freeDllExec();
	}
	return 0;
}

``` 
