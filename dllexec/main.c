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