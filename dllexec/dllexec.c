#include "dllimage.h"
#include <MinHook.h>
#include <stdio.h>
#include <stdlib.h>


#define NTDLL "ntdll.dll"
#define ppv(x) ((void**)(x))


#define MAGIC_HANDLE 0x12345678

static
PVOID targetBaseAddress = 0;

static
SIZE_T targetViewSize = 0;

static
CHAR targetDllName[MAX_PATH];

static
PVOID targetMemory = 0;

static
SIZE_T targetSizeMemory = 0;


typedef struct _STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PCHAR Buffer;
} STRING;

typedef STRING* PANSI_STRING;



typedef struct _IO_STATUS_BLOCK
{
	union
	{
		LONG Status;
		PVOID Pointer;
	};
	ULONG Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef struct _UNICODE_STRING
{
	WORD Length;
	WORD MaximumLength;
	WORD* Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG Length;
	PVOID RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;


typedef const UNICODE_STRING* PCUNICODE_STRING;

void(__stdcall* pRtlInitUnicodeString)(
	PUNICODE_STRING DestinationString,
	PCWSTR          SourceString
	);



BOOLEAN(__stdcall* pRtlEqualUnicodeString)(
	PCUNICODE_STRING String1,
	PCUNICODE_STRING String2,
	BOOLEAN          CaseInSensitive
	);

HANDLE targetFileHandle = 0;
HANDLE targetSectionHandle = 0;


NTSTATUS(__stdcall* pRtlUnicodeStringToAnsiString)(
	PANSI_STRING     DestinationString,
	PCUNICODE_STRING SourceString,
	BOOLEAN          AllocateDestinationString
	);


void(__stdcall* pRtlFreeAnsiString)(
	PANSI_STRING AnsiString
	);


int(__stdcall* pNtOpenSection)(PHANDLE SectionHandle, ACCESS_MASK   DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
int(__stdcall* oldNtOpenSection)(PHANDLE SectionHandle, ACCESS_MASK   DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);

int __stdcall newNtOpenSection(PHANDLE SectionHandle, ACCESS_MASK   DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes)
{
	STRING name;
	memset(&name, 0, sizeof(name));
	if (pRtlUnicodeStringToAnsiString(&name, ObjectAttributes->ObjectName, TRUE)==0);
	{
		if (strcmp(name.Buffer, targetDllName) == 0)
		{
			*SectionHandle = MAGIC_HANDLE;
			pRtlFreeAnsiString(&name);
			return 0;
		}
		pRtlFreeAnsiString(&name);
	}

	return oldNtOpenSection(SectionHandle, DesiredAccess, ObjectAttributes);
}

typedef enum _SECTION_INHERIT {
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT;


NTSTATUS(__stdcall* pZwMapViewOfSection)(
	HANDLE          SectionHandle,
	HANDLE          ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR       ZeroBits,
	SIZE_T          CommitSize,
	PLARGE_INTEGER  SectionOffset,
	PSIZE_T         ViewSize,
	SECTION_INHERIT InheritDisposition,
	ULONG           AllocationType,
	ULONG           Win32Protect
	);

NTSTATUS(__stdcall* oldZwMapViewOfSection)(
	HANDLE          SectionHandle,
	HANDLE          ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR       ZeroBits,
	SIZE_T          CommitSize,
	PLARGE_INTEGER  SectionOffset,
	PSIZE_T         ViewSize,
	SECTION_INHERIT InheritDisposition,
	ULONG           AllocationType,
	ULONG           Win32Protect
	);


NTSTATUS __stdcall newZwMapViewOfSection(
	HANDLE          SectionHandle,
	HANDLE          ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR       ZeroBits,
	SIZE_T          CommitSize,
	PLARGE_INTEGER  SectionOffset,
	PSIZE_T         ViewSize,
	SECTION_INHERIT InheritDisposition,
	ULONG           AllocationType,
	ULONG           Win32Protect
)
{
	if (SectionHandle == MAGIC_HANDLE)
	{
		*BaseAddress = loadImage(targetMemory, targetSizeMemory, ViewSize);
		if (*BaseAddress == 0)
		{
			return -1;
		}

		targetBaseAddress = *BaseAddress;
		targetViewSize = *ViewSize;
		return 0;
	}
	return oldZwMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect);
}




NTSTATUS(__stdcall* pZwCreateSection)(
	PHANDLE            SectionHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PLARGE_INTEGER     MaximumSize,
	ULONG              SectionPageProtection,
	ULONG              AllocationAttributes,
	HANDLE             FileHandle
	);

NTSTATUS(__stdcall* oldZwCreateSection)(
	PHANDLE            SectionHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PLARGE_INTEGER     MaximumSize,
	ULONG              SectionPageProtection,
	ULONG              AllocationAttributes,
	HANDLE             FileHandle
	);

NTSTATUS __stdcall newZwCreateSection(
	PHANDLE            SectionHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PLARGE_INTEGER     MaximumSize,
	ULONG              SectionPageProtection,
	ULONG              AllocationAttributes,
	HANDLE             FileHandle
)
{
	if (FileHandle == MAGIC_HANDLE)
	{
		*SectionHandle = MAGIC_HANDLE;
		return 0;
	}

	return oldZwCreateSection(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle);
}


NTSTATUS(__stdcall* pNtOpenFile)(
	OUT PHANDLE           FileHandle,
	IN ACCESS_MASK        DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK  IoStatusBlock,
	IN ULONG              ShareAccess,
	IN ULONG              OpenOptions
	);

NTSTATUS(__stdcall* oldNtOpenFile)(
	OUT PHANDLE           FileHandle,
	IN ACCESS_MASK        DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK  IoStatusBlock,
	IN ULONG              ShareAccess,
	IN ULONG              OpenOptions
	);

int k = 0;

NTSTATUS __stdcall newNtOpenFile(
	OUT PHANDLE           FileHandle,
	IN ACCESS_MASK        DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK  IoStatusBlock,
	IN ULONG              ShareAccess,
	IN ULONG              OpenOptions
)
{

	STRING name;
	memset(&name, 0, sizeof(name));
	if (pRtlUnicodeStringToAnsiString(&name, ObjectAttributes->ObjectName, TRUE) == 0);
	{
		if (strstr(name.Buffer, targetDllName) != 0)
		{
			*FileHandle = MAGIC_HANDLE;
			pRtlFreeAnsiString(&name);
			return 0;
		}
		pRtlFreeAnsiString(&name);
	}

	return oldNtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
}


NTSTATUS(__stdcall* pZwClose)(
	HANDLE Handle
	);

NTSTATUS(__stdcall* oldZwClose)(
	HANDLE Handle
	);


NTSTATUS __stdcall newZwClose(
	HANDLE Handle
)
{
	if (Handle == MAGIC_HANDLE)
	{
		return 0;
	}
	return oldZwClose(Handle);
}


void (__stdcall *pRtlFreeUnicodeString)(PUNICODE_STRING UnicodeString);


NTSTATUS (__stdcall *pZwUnmapViewOfSection)(
	HANDLE ProcessHandle,
	PVOID  BaseAddress
);

NTSTATUS(__stdcall* oldZwUnmapViewOfSection)(
	HANDLE ProcessHandle,
	PVOID  BaseAddress
	);

NTSTATUS __stdcall newZwUnmapViewOfSection(
	HANDLE ProcessHandle,
	PVOID  BaseAddress
)
{
	if (targetBaseAddress == BaseAddress && targetBaseAddress)
	{
		if (BaseAddress)
		{
			VirtualFree(BaseAddress, targetViewSize, MEM_RELEASE);
		}
		targetBaseAddress = 0;
		return 0;
	}
	return oldZwUnmapViewOfSection(ProcessHandle, BaseAddress);
}

__declspec(dllexport)
void freeDllExec()
{
	MH_Uninitialize();
}

__declspec(dllexport)
int initDllExec()
{

	MH_Initialize();
	pRtlInitUnicodeString = GetProcAddress(LoadLibrary(NTDLL), "RtlInitUnicodeString");
	if (!pRtlInitUnicodeString)
	{
		return 0;
	}

	pRtlEqualUnicodeString = GetProcAddress(LoadLibrary(NTDLL), "RtlEqualUnicodeString");
	if (!pRtlEqualUnicodeString)
	{
		return 0;
	}

	pRtlFreeUnicodeString = GetProcAddress(LoadLibrary(NTDLL), "RtlFreeUnicodeString");
	if (!pRtlFreeUnicodeString)
	{
		return 0;
	}


	pZwUnmapViewOfSection = GetProcAddress(LoadLibrary(NTDLL), "ZwUnmapViewOfSection");
	if (!pZwUnmapViewOfSection)
	{
		return 0;
	}

	pZwClose = GetProcAddress(LoadLibrary(NTDLL), "ZwClose");
	if (!pZwClose)
	{
		return 0;
	}

	pNtOpenFile = GetProcAddress(LoadLibrary(NTDLL), "NtOpenFile");
	if (!pNtOpenFile)
	{
		return 0;
	}

	pZwCreateSection = GetProcAddress(LoadLibrary(NTDLL), "ZwCreateSection");
	if (!pZwCreateSection)
	{
		return 0;
	}

	pNtOpenSection = GetProcAddress(LoadLibrary(NTDLL), "ZwOpenSection");
	if (!pNtOpenSection)
	{
		return 0;
	}

	pZwMapViewOfSection = GetProcAddress(LoadLibrary(NTDLL), "ZwMapViewOfSection");
	if (!pZwMapViewOfSection)
	{
		return 0;
	}


	pRtlUnicodeStringToAnsiString = GetProcAddress(LoadLibrary(NTDLL), "RtlUnicodeStringToAnsiString");
	if (!pRtlUnicodeStringToAnsiString)
	{
		return 0;
	}

	pRtlFreeAnsiString = GetProcAddress(LoadLibrary(NTDLL), "RtlFreeAnsiString");
	if (!pRtlFreeAnsiString)
	{
		return 0;
	}


	if (MH_CreateHook(pZwUnmapViewOfSection, &newZwUnmapViewOfSection, ppv(&oldZwUnmapViewOfSection)) != MH_OK) 
	{
		return 0;
	}

	
	if (MH_CreateHook(pZwClose, &newZwClose, ppv(&oldZwClose)) != MH_OK) 
	{
		return 0;
	}

	
	if (MH_CreateHook(pNtOpenFile, &newNtOpenFile, ppv(&oldNtOpenFile)) != MH_OK) 
	{
		return 0;
	}

	
	if (MH_CreateHook(pZwCreateSection, &newZwCreateSection, ppv(&oldZwCreateSection)) != MH_OK) 
	{
		return 0;
	}
	
	if (MH_CreateHook(pNtOpenSection, &newNtOpenSection, ppv(&oldNtOpenSection)) != MH_OK) 
	{
		return 0;
	}

	
	if (MH_CreateHook(pZwMapViewOfSection, &newZwMapViewOfSection, ppv(&oldZwMapViewOfSection)) != MH_OK) 
	{
		return 0;
	}

	MH_EnableHook(pZwUnmapViewOfSection);
	MH_EnableHook(pZwClose);
	MH_EnableHook(pNtOpenFile);
	MH_EnableHook(pZwCreateSection);
	MH_EnableHook(pNtOpenSection);
	MH_EnableHook(pZwMapViewOfSection);

	return 1;
}

__declspec(dllexport)
HMODULE loadDllExec(char* name, void* memory, int size)
{
	strncpy(targetDllName, name,sizeof(targetDllName));
	targetMemory = memory;
	targetSizeMemory = size;
	HMODULE m = LoadLibrary(name);
	return m;
}
