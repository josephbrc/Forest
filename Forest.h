#pragma once

#include "Structs.h"
#include <TlHelp32.h> // TlHelp Library
#include <vector>
#include <xmmintrin.h>

// Useful macros

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)
#define STATUS_INVALID_PAGE_PROTECTION   ((NTSTATUS)0xC0000045L)
#define STATUS_PROCEDURE_NOT_FOUND       ((NTSTATUS)0xC000007AL)

using U8 = unsigned char;
using U16 = unsigned short;
using U32 = unsigned int;
using U64 = unsigned long long;
using PTRDIFF = signed long long;
using U128 = __m128;
using GUEST_VIRT = U64;
using GUEST_PHYS = U64;
using HOST_VIRT = U64;
using HOST_PHYS = U64;
#define PAGE_SIZE 0x1000
#define LOW_ADDRESS_X86 0x00010000
#define HIGH_ADDRESS_X86 0x7FFEFFFF
#define LOW_ADDRESS_X64 0x0000000000010000
#define HIGH_ADDRESS_X64 0x00007FFFFFFEFFFF
#define LOW_ADDRESS_KERNEL 0x0008000000010000
#define HIGH_ADDRESS_KERNEL 0xFFFFFFFFFFFEFFFF
#define BYTES_TO_PAGES(bytes) bytes / 0x1000
#define PAGES_TO_BYTES(pages) pages * 0x1000
#define RVA(instruction, instruction_size) (instruction + *(int*)(instruction + instruction_size - 4) + instruction_size)
#define ISVALID(addr) (addr >= LOW_ADDRESS_X64 && addr < HIGH_ADDRESS_X64)
#define VALID_KERNEL_POINTER(addr) addr >= LOW_ADDRESS_KERNEL && addr < HIGH_ADDRESS_KERNEL
#define USER_THISCHECK if (!VALID_USER_POINTER((U64)this)) return {}
#define KERNEL_THISCHECK if (!VALID_KERNEL_POINTER((U64)this)) return {}

class Forest
{
public:
	inline static void* Memcpy(void* dest, const void* src, size_t n) {
		char* d = static_cast<char*>(dest);
		const char* s = static_cast<const char*>(src);

		for (size_t i = 0; i < n; ++i) {
			d[i] = s[i];
		}

		return dest;
	}
	inline static void* Memchr(const void* s, int c, size_t n) {
		const unsigned char* p = static_cast<const unsigned char*>(s);

		for (size_t i = 0; i < n; ++i) {
			if (p[i] == static_cast<unsigned char>(c)) {
				return (void*)(p + i);
			}
		}

		return nullptr;
	}
	inline static int Strcmp(const char* s1, const char* s2) {
		while (*s1 && (*s1 == *s2)) {
			s1++;
			s2++;
		}
		return *(const unsigned char*)s1 - *(const unsigned char*)s2;
	}
	static _TEB* NtCurrentTeb() { // Use MSVC intrinsic
		return (struct _TEB*)__readgsqword(((LONG)__builtin_offsetof(NT_TIB, Self)));
	}
	static __forceinline void Exit() {
		Forest::Call<NTSTATUS, HANDLE, NTSTATUS>("ntdll.dll", "NtTerminateProcess", (HANDLE)-1, STATUS_SUCCESS);
	}
	static __forceinline uint64_t GetModule(std::string module_name) {

		auto GetFileNameFromPath = [](wchar_t* Path) -> wchar_t*
			{
				wchar_t* LastSlash = NULL;
				for (DWORD i = 0; Path[i] != 0; i++)
				{
					if (Path[i] == '\\')
						LastSlash = &Path[i + 1];
				}
				return LastSlash;
			};

		auto RemoveFileExtension = [](wchar_t* FullFileName, wchar_t* OutputBuffer, DWORD OutputBufferSize)	-> wchar_t*
			{
				wchar_t* LastDot = NULL;
				for (DWORD i = 0; FullFileName[i] != NULL; i++)
					if (FullFileName[i] == '.')
						LastDot = &FullFileName[i];

				for (DWORD j = 0; j < OutputBufferSize; j++)
				{
					OutputBuffer[j] = FullFileName[j];
					if (&FullFileName[j] == LastDot)
					{
						OutputBuffer[j] = NULL;
						break;
					}
				}
				OutputBuffer[OutputBufferSize - 1] = NULL;
				return OutputBuffer;
			};

		PEB* ProcessEnvironmentBlock = ((PEB*)((TEB*)((TEB*)Forest::NtCurrentTeb())->ProcessEnvironmentBlock));
		PEB_LDR_DATA* Ldr = ProcessEnvironmentBlock->Ldr;

		std::wstring Temp(module_name.begin(), module_name.end());
		const wchar_t* lpModuleName = Temp.c_str();

		LIST_ENTRY* ModuleLists[3] = { 0,0,0 };
		ModuleLists[0] = &Ldr->InLoadOrderModuleList;
		ModuleLists[1] = &Ldr->InMemoryOrderModuleList;
		ModuleLists[2] = &Ldr->InInitializationOrderModuleList;

		for (int j = 0; j < 3; j++)
		{
			for (LIST_ENTRY* pListEntry = ModuleLists[j]->Flink; pListEntry != ModuleLists[j]; pListEntry = pListEntry->Flink)
			{
				LDR_DATA_TABLE_ENTRY* pEntry = (LDR_DATA_TABLE_ENTRY*)((BYTE*)pListEntry - sizeof(LIST_ENTRY) * j);

				if (_wcsicmp(pEntry->BaseDllName.Buffer, lpModuleName) == 0)
				{
					return (uintptr_t)pEntry->DllBase;
				}

				wchar_t* FileName = GetFileNameFromPath(pEntry->FullDllName.Buffer);
				if (!FileName)
					continue;

				if (_wcsicmp(FileName, lpModuleName) == 0)
				{
					return (uintptr_t)pEntry->DllBase;
				}

				wchar_t FileNameWithoutExtension[256];
				RemoveFileExtension(FileName, FileNameWithoutExtension, 256);

				if (_wcsicmp(FileNameWithoutExtension, lpModuleName) == 0)
				{
					return (uintptr_t)pEntry->DllBase;
				}
			}
		}
		return NULL;

	}
	static __forceinline uint64_t GetFirstModule()
	{

		PEB* ProcessEnvironmentBlock = ((PEB*)((TEB*)((TEB*)Forest::NtCurrentTeb())->ProcessEnvironmentBlock));
		PEB_LDR_DATA* Ldr = ProcessEnvironmentBlock->Ldr;

		LIST_ENTRY* ModuleLists[3] = { 0,0,0 };
		ModuleLists[0] = &Ldr->InLoadOrderModuleList;
		ModuleLists[1] = &Ldr->InMemoryOrderModuleList;
		ModuleLists[2] = &Ldr->InInitializationOrderModuleList;

		for (int j = 0; j < 3; j++)
		{
			for (LIST_ENTRY* pListEntry = ModuleLists[j]->Flink; pListEntry != ModuleLists[j]; pListEntry = pListEntry->Flink)
			{
				LDR_DATA_TABLE_ENTRY* pEntry = (LDR_DATA_TABLE_ENTRY*)((BYTE*)pListEntry - sizeof(LIST_ENTRY) * j);
				return (uint64_t)pEntry->DllBase;
			}
		}

	}
	static __forceinline uint64_t GetExport(std::string module_name, std::string exported_routine) {

		PIMAGE_DOS_HEADER pIDH;
		PIMAGE_NT_HEADERS pINH;
		PIMAGE_EXPORT_DIRECTORY pIED;

		HMODULE hModule;
		PDWORD Address, Name;
		PWORD Ordinal;

		DWORD i;

		hModule = (HMODULE)GetModule(module_name);
		if (!hModule) return 0;

		pIDH = (PIMAGE_DOS_HEADER)hModule;

		if (pIDH->e_magic != IMAGE_DOS_SIGNATURE) return 0;
		pINH = (PIMAGE_NT_HEADERS)((LPBYTE)hModule + pIDH->e_lfanew);

		if (pINH->Signature != IMAGE_NT_SIGNATURE) return 0;
		if (pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0) return 0;

		pIED = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)hModule + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
		Address = (PDWORD)((LPBYTE)hModule + pIED->AddressOfFunctions);
		Name = (PDWORD)((LPBYTE)hModule + pIED->AddressOfNames);
		Ordinal = (PWORD)((LPBYTE)hModule + pIED->AddressOfNameOrdinals);

		for (i = 0; i < pIED->AddressOfFunctions; i++)
		{
			if (!strcmp(exported_routine.c_str(), (char*)hModule + Name[i]))
			{
				return (std::uint64_t)((LPBYTE)hModule + Address[Ordinal[i]]);
			}
		}

		return NULL;
	}
	template<typename T = void*, typename ... Args>
	static __forceinline T Call(const char* szModule, const char* szExport, Args ... args)
	{
		auto fn = reinterpret_cast<T(*)(Args...)>(GetExport(szModule, szExport));
		if (!fn) return T();
		return fn(args ...);
	}
	static void Popup(std::string Caption, std::string Message, std::uint32_t Flags = (MB_OK | MB_ICONINFORMATION)) {

		MSGBOXPARAMSA msgbox;

		msgbox.cbSize = sizeof(MSGBOXPARAMSA);
		msgbox.hwndOwner = 0;
		msgbox.hInstance = 0;
		msgbox.lpszText = Message.c_str();
		msgbox.lpszCaption = Caption.c_str();
		msgbox.dwStyle = Flags;
		msgbox.lpszIcon = 0;
		msgbox.dwContextHelpId = 0;
		msgbox.lpfnMsgBoxCallback = 0;
		msgbox.dwLanguageId = LANG_NEUTRAL;

		auto function = reinterpret_cast<int(__stdcall*)(const tagMSGBOXPARAMSA*)>(GetExport("user32.dll", "MessageBoxIndirectA"));
		function(&msgbox);

	}
	static bool Init() {
		if (!Forest::Call<HMODULE, LPCSTR>("kernel32.dll", "LoadLibraryA", "user32.dll")) return false;
		return true;
	}
	static bool Patch(std::string Module, std::string Routine, const char* Bytes, int Len)
	{
		
		uint64_t Addr = Forest::GetExport(Module.c_str(), Routine.c_str());
		if (!Addr) return FALSE;

		DWORD Old;
		if (!Forest::Call<BOOL, LPVOID, SIZE_T, DWORD, PDWORD>("kernel32.dll", "VirtualProtect", (void*)Addr, Len, PAGE_EXECUTE_READWRITE, &Old)) return FALSE;
		memcpy((void*)Addr, Bytes, Len);
		if (!Forest::Call<BOOL, LPVOID, SIZE_T, DWORD, PDWORD>("kernel32.dll", "VirtualProtect", (void*)Addr, Len, Old, &Old)) return FALSE;

		return TRUE;
		
	}
	static bool GetService(const char* Service)
	{
		
		SC_HANDLE scm = Forest::Call<SC_HANDLE, LPCSTR, LPCSTR, DWORD>("advapi32.dll", "OpenSCManagerA", nullptr, nullptr, SC_MANAGER_CONNECT);
		if (!scm) return false;

		SC_HANDLE service = Forest::Call<SC_HANDLE, SC_HANDLE, LPCSTR, DWORD>("advapi32.dll", "OpenServiceA", scm, Service, SERVICE_QUERY_STATUS);
		if (!service) return false;

		SERVICE_STATUS status;
		Forest::Call<BOOL, SC_HANDLE, LPSERVICE_STATUS>("advapi32.dll", "QueryServiceStatus", service, &status);

		if (status.dwCurrentState == SERVICE_RUNNING) return true;

		Forest::Call<BOOL, SC_HANDLE>("advapi32.dll", "CloseServiceHandle", scm);
		Forest::Call<BOOL, SC_HANDLE>("advapi32.dll", "CloseServiceHandle", service);

		return false;
		
	}
	static PIMAGE_DOS_HEADER GetDos(uint64_t BaseAddress)
	{
		return (PIMAGE_DOS_HEADER)BaseAddress;
	}
	static PIMAGE_NT_HEADERS64 GetNt(PIMAGE_DOS_HEADER DosHeader)
	{
		return (PIMAGE_NT_HEADERS64)((uint64_t)DosHeader + DosHeader->e_lfanew);
	}
	static uint64_t Scan(std::string ModuleName, std::string Signature, int Index = 0)
	{

		auto ModuleToScan = GetModule(ModuleName);

		auto PatternToByte = [](std::string Pattern)
			{

				const char* PatternStr = Pattern.c_str();

				std::vector<int> Bytes = {};
				char* Start = (char*)PatternStr;
				char* End = (char*)PatternStr + strlen(PatternStr);

				for (auto Current = Start; Current < End; ++Current)
				{
					if (*Current == '?')
					{
						++Current;
						if (*Current == '?')
							++Current;
						Bytes.push_back(-1);
					}
					else {
						Bytes.push_back(strtoull((const char*)Current, &Current, 16));
					}
				}

				return Bytes;

			};

		std::vector<int> PatternBytes = PatternToByte(Signature);
		uint8_t* ScanBytes = (uint8_t*)GetDos(ModuleToScan);

		auto NtHeaders = GetNt(GetDos(ModuleToScan));

		for (auto i = 0ul; i < NtHeaders->OptionalHeader.SizeOfImage - PatternBytes.size(); ++i)
		{
			bool Found = true;

			for (auto j = 0ul; j < PatternBytes.size(); ++j)
			{
				if (PatternBytes.data()[j] != -1 && ScanBytes[i + j] != PatternBytes.data()[j]) {
					Found = false;
					break;
				}
			}

			if (Found)
			{
				if (Index > 0)
				{
					return ((uintptr_t)((UINT_PTR)(reinterpret_cast<uintptr_t>(&ScanBytes[i])) + *(PINT)((UINT_PTR)(reinterpret_cast<uintptr_t>(&ScanBytes[i])) + ((Index)-sizeof(INT))) + (Index)));
				}
				else
				{
					return reinterpret_cast<uintptr_t>(&ScanBytes[i]);
				}
			}

		}

		return NULL;

	}
	static DWORD GetProcess(const wchar_t* processName)
	{
		DWORD pid = 0;
		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hSnapshot != INVALID_HANDLE_VALUE) {
			PROCESSENTRY32 pe32;
			pe32.dwSize = sizeof(pe32);

			if (Process32First(hSnapshot, &pe32)) {
				do {
					if (_wcsicmp(pe32.szExeFile, processName) == 0) {
						pid = pe32.th32ProcessID;
						break;
					}
				} while (Process32Next(hSnapshot, &pe32));
			}
			CloseHandle(hSnapshot);
		}
		return pid;
	}
};
