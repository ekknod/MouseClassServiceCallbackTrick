#include <ntifs.h>

/*
 * MouseClassServiceCallbackTrick
 * 
 * initializing data, jmps at MouHid_ReadComplete ->
 * MouHid_ReadComplete will call MouseClassServiceCallback, what does in the end spoof the _ReturnAddress.
 * 
 * this method was used safely at many platforms since of May 2021 to this day.
 * 
 * the method did get blocked by VGK.sys 19.08.2022, (asdf144) did use it there.
 * from what i have heard, he didn't get banned.
 * 
 * maybe they are checking: (PsGetCurrentThreadId() != 0) = block input
 * since all mouse DPC is done by system KiIdleLoop, ThreadId (0).
 * 
 * otherwise should be fine, until anti-cheats start to properly validate it.
 * 
 * 
 * Pros: Anti-Cheat hook does get called, and if they do compare input data to game, it will match.
 * Cons: Ballsy move, its about taking risk and hoping anti-cheat is not going to check anything else than _ReturnAddress.
 * 
 */

typedef int BOOL;
typedef unsigned int DWORD;
typedef ULONG_PTR QWORD;

#pragma warning(disable : 4201)
typedef struct _MOUSE_INPUT_DATA {
	USHORT UnitId;
	USHORT Flags;
	union {
	ULONG Buttons;
	struct {
	USHORT ButtonFlags;
	USHORT ButtonData;
	};
	};
	ULONG  RawButtons;
	LONG   LastX;
	LONG   LastY;
	ULONG  ExtraInformation;
} MOUSE_INPUT_DATA, *PMOUSE_INPUT_DATA;



typedef struct _MOUSE_OBJECT
{
	PDEVICE_OBJECT              mouse_device;
	QWORD                       service_callback;
	BOOL                        use_mouse;
} MOUSE_OBJECT, * PMOUSE_OBJECT;


BOOL mouse_open(void);
MOUSE_OBJECT gMouseObject;



NTSYSCALLAPI
POBJECT_TYPE* IoDriverObjectType;

NTSYSCALLAPI
NTSTATUS
ObReferenceObjectByName(
      __in PUNICODE_STRING ObjectName,
      __in ULONG Attributes,
      __in_opt PACCESS_STATE AccessState,
      __in_opt ACCESS_MASK DesiredAccess,
      __in POBJECT_TYPE ObjectType,
      __in KPROCESSOR_MODE AccessMode,
      __inout_opt PVOID ParseContext,
      __out PVOID *Object
  );


void NtSleep(DWORD milliseconds)
{
	QWORD ms = milliseconds;
	ms = (ms * 1000) * 10;
	ms = ms * -1;
#ifdef _KERNEL_MODE
	KeDelayExecutionThread(KernelMode, 0, (PLARGE_INTEGER)&ms);
#else
	NtDelayExecution(0, (PLARGE_INTEGER)&ms);
#endif
}

void mouse_move(long x, long y, unsigned short button_flags);
static QWORD GetSystemBaseAddress(PDRIVER_OBJECT DriverObject, const unsigned short* driver_name);
static QWORD FindPattern(QWORD module, unsigned char *bMask, char *szMask, QWORD len);

VOID
DriverUnload(
	_In_ struct _DRIVER_OBJECT* DriverObject
)
{
	UNREFERENCED_PARAMETER(DriverObject);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] MouseClassServiceCallbackTrick.sys is closed\n");
}

QWORD g_target_routine = 0;

NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT  DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	if (!mouse_open())
	{
		return STATUS_DRIVER_ENTRYPOINT_NOT_FOUND;
	}


	QWORD base = GetSystemBaseAddress(DriverObject, L"mouhid.sys");
	if (base == 0)
	{
		return STATUS_DRIVER_ENTRYPOINT_NOT_FOUND;
	}

	g_target_routine = FindPattern((QWORD)base, (unsigned char*)"\x74\x54", "xx", 2);
	if (g_target_routine == 0)
	{
		return STATUS_DRIVER_ENTRYPOINT_NOT_FOUND;
	}
	g_target_routine += 0x56;


	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] MouseClassServiceCallbackTrick.sys is launched\n");
	DriverObject->DriverUnload = DriverUnload;


	for (int i = 0; i < 32; i++) {
		NtSleep(100);
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] Moving mouse\n");

		mouse_move(-10, -10, 0);
	}


	return STATUS_SUCCESS;
}

BOOL mouse_open(void)
{
	// https://github.com/nbqofficial/norsefire

	if (gMouseObject.use_mouse == 0) {

		UNICODE_STRING class_string;
		RtlInitUnicodeString(&class_string, L"\\Driver\\MouClass");
	

		PDRIVER_OBJECT class_driver_object = NULL;
		NTSTATUS status = ObReferenceObjectByName(&class_string, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, (PVOID*)&class_driver_object);
		if (!NT_SUCCESS(status)) {
			gMouseObject.use_mouse = 0;
			return 0;
		}

		UNICODE_STRING hid_string;
		RtlInitUnicodeString(&hid_string, L"\\Driver\\MouHID");
	

		PDRIVER_OBJECT hid_driver_object = NULL;
	
		status = ObReferenceObjectByName(&hid_string, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, (PVOID*)&hid_driver_object);
		if (!NT_SUCCESS(status))
		{
			if (class_driver_object) {
				ObfDereferenceObject(class_driver_object);
			}
			gMouseObject.use_mouse = 0;
			return 0;
		}

		PVOID class_driver_base = NULL;


		PDEVICE_OBJECT hid_device_object = hid_driver_object->DeviceObject;
		while (hid_device_object && !gMouseObject.service_callback)
		{
			PDEVICE_OBJECT class_device_object = class_driver_object->DeviceObject;
			while (class_device_object && !gMouseObject.service_callback)
			{
				if (!class_device_object->NextDevice && !gMouseObject.mouse_device)
				{
					gMouseObject.mouse_device = class_device_object;
				}

				PULONG_PTR device_extension = (PULONG_PTR)hid_device_object->DeviceExtension;
				ULONG_PTR device_ext_size = ((ULONG_PTR)hid_device_object->DeviceObjectExtension - (ULONG_PTR)hid_device_object->DeviceExtension) / 4;
				class_driver_base = class_driver_object->DriverStart;
				for (ULONG_PTR i = 0; i < device_ext_size; i++)
				{
					if (device_extension[i] == (ULONG_PTR)class_device_object && device_extension[i + 1] > (ULONG_PTR)class_driver_object)
					{
						gMouseObject.service_callback = (QWORD)(device_extension[i + 1]);
					
						break;
					}
				}
				class_device_object = class_device_object->NextDevice;
			}
			hid_device_object = hid_device_object->AttachedDevice;
		}
	
		if (!gMouseObject.mouse_device)
		{
			PDEVICE_OBJECT target_device_object = class_driver_object->DeviceObject;
			while (target_device_object)
			{
				if (!target_device_object->NextDevice)
				{
					gMouseObject.mouse_device = target_device_object;
					break;
				}
				target_device_object = target_device_object->NextDevice;
			}
		}

		ObfDereferenceObject(class_driver_object);
		ObfDereferenceObject(hid_driver_object);

		if (gMouseObject.mouse_device && gMouseObject.service_callback) {
			gMouseObject.use_mouse = 1;
		}

	}

	return gMouseObject.mouse_device && gMouseObject.service_callback;
}

VOID MouseClassServiceCallbackTrick(QWORD rdi_buffer, QWORD rbp_buffer, QWORD target_address);
void mouse_move(long x, long y, unsigned short button_flags)
{
	char rdi_buffer[0x500];
	char rbp_buffer[0x100];

	for (QWORD i = 0; i < 0x500; i++)
		rdi_buffer[i] = 0;

	for (QWORD i = 0; i < 0x100; i++)
		rbp_buffer[i] = 0;

	MOUSE_INPUT_DATA *mid = (MOUSE_INPUT_DATA*)&rdi_buffer[0x160];
	*(QWORD*)&rdi_buffer[0x178] = (QWORD)(PMOUSE_INPUT_DATA)mid + 1;

	mid->LastX = x;
	mid->LastY = y;
	mid->ButtonFlags = button_flags;
	mid->UnitId = 1;

	*(QWORD*)&rdi_buffer[0xE0] = (QWORD)gMouseObject.mouse_device;
	*(QWORD*)&rdi_buffer[0xE8] = (QWORD)gMouseObject.service_callback;
	MouseClassServiceCallbackTrick( (QWORD)rdi_buffer, (QWORD)rbp_buffer, (QWORD)g_target_routine );
}

#pragma warning(disable : 4201)
typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	short LoadCount;
	short TlsIndex;
	union
	{
		LIST_ENTRY HashLinks;
		struct
		{
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union
	{
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
	PVOID* EntryPointActivationContext;
	PVOID PatchInformation;
	LIST_ENTRY ForwarderLinks;
	LIST_ENTRY ServiceTagLinks;
	LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

static QWORD GetSystemBaseAddress(PDRIVER_OBJECT DriverObject, const unsigned short* driver_name)
{
	PLDR_DATA_TABLE_ENTRY ldr = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
	for (PLIST_ENTRY pListEntry = ldr->InLoadOrderLinks.Flink; pListEntry != &ldr->InLoadOrderLinks; pListEntry = pListEntry->Flink)
	{
		PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		if (pEntry->BaseDllName.Buffer && wcscmp(pEntry->BaseDllName.Buffer, driver_name) == 0) {
			
			return (QWORD)pEntry->DllBase;
		}
	}
	return 0;
}

typedef unsigned char BYTE;

static BOOLEAN bDataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask)
{
	for (; *szMask; ++szMask, ++pData, ++bMask)
		if ((*szMask == 1 || *szMask == 'x') && *pData != *bMask)
			return 0;
	return (*szMask) == 0;
}

static QWORD FindPatternEx(UINT64 dwAddress, QWORD dwLen, BYTE *bMask, char * szMask)
{
	if (dwLen <= 0)
		return 0;
	for (QWORD i = 0; i < dwLen; i++)
		if (bDataCompare((BYTE*)(dwAddress + i), bMask, szMask))
			return (QWORD)(dwAddress + i);
	return 0;
}


#ifdef _KERNEL_MODE
typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
    unsigned short  e_magic;                     // Magic number
    unsigned short  e_cblp;                      // Bytes on last page of file
    unsigned short  e_cp;                        // Pages in file
    unsigned short  e_crlc;                      // Relocations
    unsigned short  e_cparhdr;                   // Size of header in paragraphs
    unsigned short  e_minalloc;                  // Minimum extra paragraphs needed
    unsigned short  e_maxalloc;                  // Maximum extra paragraphs needed
    unsigned short  e_ss;                        // Initial (relative) SS value
    unsigned short  e_sp;                        // Initial SP value
    unsigned short  e_csum;                      // Checksum
    unsigned short  e_ip;                        // Initial IP value
    unsigned short  e_cs;                        // Initial (relative) CS value
    unsigned short  e_lfarlc;                    // File address of relocation table
    unsigned short  e_ovno;                      // Overlay number
    unsigned short  e_res[4];                    // Reserved words
    unsigned short  e_oemid;                     // OEM identifier (for e_oeminfo)
    unsigned short  e_oeminfo;                   // OEM information; e_oemid specific
    unsigned short  e_res2[10];                  // Reserved words
    LONG   e_lfanew;                    // File address of new exe header
  } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
    unsigned short   Machine;
    unsigned short   NumberOfSections;
    DWORD   TimeDateStamp;
    DWORD   PointerToSymbolTable;
    DWORD   NumberOfSymbols;
    unsigned short   SizeOfOptionalHeader;
    unsigned short   Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD   VirtualAddress;
    DWORD   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    short       Magic;
    BYTE        MajorLinkerVersion;
    BYTE        MinorLinkerVersion;
    DWORD       SizeOfCode;
    DWORD       SizeOfInitializedData;
    DWORD       SizeOfUninitializedData;
    DWORD       AddressOfEntryPoint;
    DWORD       BaseOfCode;
    ULONGLONG   ImageBase;
    DWORD       SectionAlignment;
    DWORD       FileAlignment;
    unsigned short       MajorOperatingSystemVersion;
    unsigned short       MinorOperatingSystemVersion;
    unsigned short       MajorImageVersion;
    unsigned short       MinorImageVersion;
    unsigned short       MajorSubsystemVersion;
    unsigned short       MinorSubsystemVersion;
    DWORD       Win32VersionValue;
    DWORD       SizeOfImage;
    DWORD       SizeOfHeaders;
    DWORD       CheckSum;
    unsigned short       Subsystem;
    unsigned short       DllCharacteristics;
    ULONGLONG   SizeOfStackReserve;
    ULONGLONG   SizeOfStackCommit;
    ULONGLONG   SizeOfHeapReserve;
    ULONGLONG   SizeOfHeapCommit;
    DWORD       LoaderFlags;
    DWORD       NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_SECTION_HEADER {
    BYTE    Name[8];
    union {
            DWORD   PhysicalAddress;
            DWORD   VirtualSize;
    } Misc;
    DWORD   VirtualAddress;
    DWORD   SizeOfRawData;
    DWORD   PointerToRawData;
    DWORD   PointerToRelocations;
    DWORD   PointerToLinenumbers;
    unsigned short   NumberOfRelocations;
    unsigned short   NumberOfLinenumbers;
    DWORD   Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
#endif

static QWORD FindPattern(QWORD module, unsigned char *bMask, char *szMask, QWORD len)
{
	ULONG_PTR ret = 0;
	PIMAGE_DOS_HEADER pidh = (PIMAGE_DOS_HEADER)module;
	PIMAGE_NT_HEADERS pinh = (PIMAGE_NT_HEADERS)((BYTE*)pidh + pidh->e_lfanew);
	PIMAGE_SECTION_HEADER pish = (PIMAGE_SECTION_HEADER)((BYTE*)pinh + sizeof(IMAGE_NT_HEADERS64));
	
	for (USHORT sec = 0; sec < pinh->FileHeader.NumberOfSections; sec++)
	{
		
		if ((pish[sec].Characteristics & 0x00000020))
		{
			QWORD address = FindPatternEx(pish[sec].VirtualAddress + (ULONG_PTR)(module),
				pish[sec].Misc.VirtualSize - len, bMask, szMask);
 
			if (address) {
				ret = address;

				break;
			}
		}
		
	}
	return ret;
}

