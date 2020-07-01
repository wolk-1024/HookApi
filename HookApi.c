/*
*  Copyright (c) 2020 Wolk-1024 <wolk1024@gmail.com>
*
*  Permission is hereby granted, free of charge, to any person obtaining a
*  copy of this software and associated documentation files (the "Software"),
*  to deal in the Software without restriction, including without limitation
*  the rights to use, copy, modify, merge, publish, distribute, sublicense,
*  and/or sell copies of the Software, and to permit persons to whom the
*  Software is furnished to do so, subject to the following conditions:
*
*  The above copyright notice and this permission notice shall be included
*  in all copies or substantial portions of the Software.
*
*  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
*  OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
*  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
*  THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
*  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
*  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
*  IN THE SOFTWARE.
*/

#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <Psapi.h>

#include "HookApi.h"

PMemoryBlock g_MemoryFirstBlock = NULL; // Указатель на первый блок в списке.

PVOID g_VectoredHandler = NULL;

THookVEHList g_VEHList = { 0 };

CRITICAL_SECTION g_CriticalSection = { 0 };

BOOLEAN g_InitCritSection = FALSE;

HANDLE g_ProcessHeap = NULL;

/*
*/
static SIZE_T inline AlignDown(_In_ SIZE_T Value, _In_ SIZE_T Align)
{
	return Value & ~(Align - 1);
}

/*
*/
static SIZE_T inline AlignUp(_In_ SIZE_T Value, _In_ SIZE_T Align)
{
	return AlignDown(Value - 1, Align) + Align;
}

/*
*/
static inline BOOLEAN IsValidDelta(_In_ SIZE_T Source, _In_ SIZE_T Destination, _In_ SIZE_T Delta)
{
	SIZE_T Upper = max(Source, Destination);
	SIZE_T Lower = min(Source, Destination);

	return ((Upper - Lower) > Delta) ? FALSE : TRUE;
}

/*
*/
static inline BOOLEAN IsGreaterThan2Gb(_In_ PVOID Source, _In_ PVOID Destination)
{
	return !IsValidDelta((SIZE_T)Source, (SIZE_T)Destination, TWO_GIGABYTES);
}

/*
*/
static inline SSIZE_T GetJmpRelAddress(_In_ PVOID From, _In_ PVOID To, _In_ BYTE InstrSize)
{
	if (To < From)
		return 0 - ((SIZE_T)From - (SIZE_T)To) - InstrSize;
	else
		return (SIZE_T)To - ((SIZE_T)From + InstrSize);
}

/*
*/
static HANDLE MemGetHeap()
{
	if (!g_ProcessHeap)
	{
		g_ProcessHeap = HeapCreate(HEAP_GENERATE_EXCEPTIONS, 0, 0);

		if (!g_ProcessHeap)
			HeapDestroy(g_ProcessHeap);
	}
	return g_ProcessHeap;
}

/*
*/
static BOOLEAN MemDestroy()
{
	return HeapDestroy(g_ProcessHeap);
}

/*
*/
static PVOID MemAlloc(_In_ SIZE_T Size)
{
	if (Size)
		return HeapAlloc(MemGetHeap(), HEAP_ZERO_MEMORY, Size);
	else
		return NULL;
}

/*
*/
static PVOID MemReAlloc(_In_opt_ PVOID Memory, _In_ SIZE_T Size)
{
	if (Memory && Size)
		return HeapReAlloc(MemGetHeap(), HEAP_ZERO_MEMORY, Memory, Size);
	else
		return MemAlloc(Size);
}

/*
*/
static BOOLEAN MemFree(_In_ PVOID Memory, _In_opt_ SIZE_T Size)
{
	RtlSecureZeroMemory(Memory, Size);

	return HeapFree(MemGetHeap(), 0, Memory);
}

/*
	Функция для удаления произвольного количества байт из памяти.
*/
static BOOLEAN MemDelete(_In_ PVOID Address, _In_ SIZE_T Length, _In_ SIZE_T Position, _In_ SIZE_T ToDelete, _Out_ PVOID* OutBuffer)
{
	if (!Address || !OutBuffer || ToDelete > Length || Position > Length || (Position + ToDelete) > Length)
		return FALSE;

	SIZE_T NewLength = Length - ToDelete;

	if (!NewLength) // Если размер удаляемых данных равняется общему размеру, то удаляем всё.
	{
		*OutBuffer = NULL;

		return MemFree(Address, 0);
	}

	PBYTE NewBuffer = (PBYTE)MemAlloc(NewLength); // Выделяем новую память меньшего размера.

	if (NewBuffer)
	{
		*OutBuffer = NewBuffer;

		PBYTE CopyAddress = (PBYTE)Address;

		for (SIZE_T Count = 0; Count <= NewLength; Count++)
		{
			if (Count == Position)
			{
				CopyAddress += ToDelete; // Пропускаем удаляемую часть.
			}
			else
			{
				*NewBuffer = *CopyAddress;

				NewBuffer++;

				CopyAddress++;
			}
		}

		/*
		memcpy_s(NewBuffer, NewLength, Address, Position); // Сначала копируем данные, расположенные до удаляемой позиции.

		NewBuffer += Position;

		Pointer += Position + ToDelete; // Затем пропускаем удаляемую часть.

		SIZE_T RestBytes = Length - (Position + ToDelete);

		memcpy_s(NewBuffer, NewLength, Pointer, RestBytes); // После копируем оставшиеся данные.
		*/

		return MemFree(Address, Length); // Освобождаем старую память.
	}
	return FALSE;
}

/*
	Функция добавления в память произвольного количества байт.
*/
static BOOLEAN MemAdd(_In_ PVOID Destination, _In_ PVOID Source, _In_ SIZE_T DestLength, _In_ SIZE_T Position, _In_ SIZE_T SourceLength, _Out_ PVOID* OutBuffer)
{
	if (!Destination || !Source || !OutBuffer || Position > DestLength)
		return FALSE;

	SIZE_T NewLength = DestLength + SourceLength; // Новый размер.

	if (NewLength > DestLength)
	{
		PBYTE NewBuffer = (PBYTE)MemAlloc(NewLength);

		if (NewBuffer)
		{
			*OutBuffer = NewBuffer;

			PBYTE CopyAddress = (PBYTE)Destination;

			for (SIZE_T Count = 0; Count <= DestLength; Count++)
			{
				if (Count == Position)
				{
					memcpy_s(NewBuffer, NewLength, Source, SourceLength);

					NewBuffer += SourceLength;
				}
				else
				{
					*NewBuffer = *CopyAddress;

					NewBuffer++;

					CopyAddress++;
				}
			}

			/*
			memcpy_s(NewBuffer, NewLength, Destination, Position);

			NewBuffer += Position;

			memcpy_s(NewBuffer, NewLength, Source, SourceLength);

			NewBuffer += SourceLength;

			SIZE_T RestBytes = NewLength - (Position + SourceLength);

			memcpy_s(NewBuffer, NewLength, ((PBYTE)Destination + Position), RestBytes);
			*/

			return MemFree(Destination, DestLength);
		}
	}
	return TRUE;
}

/*
*/
static BOOLEAN MemDeleteFromArray(_Inout_ PVOID *Array, _In_ SIZE_T Count, _In_ SIZE_T Position, _In_ SIZE_T ElementSize)
{
	if (!Array || Position > Count)
		return FALSE;

	SIZE_T ArrayLength = (Count + 1) * ElementSize; // Размер массива.

	return MemDelete(*Array, ArrayLength, Position * ElementSize, ElementSize, Array);
}

/*
*/
static BOOLEAN MemAddToArray(_Inout_ PVOID *DestArray, _In_ PVOID Source, _In_ SIZE_T Count, _In_ SIZE_T Position, _In_ SIZE_T ElementSize)
{
	if (!DestArray || !Source || Position > Count)
		return FALSE;

	SIZE_T ArrayLength = (Count + 1) * ElementSize;

	return MemAdd(*DestArray, Source, ArrayLength, Position * ElementSize, ElementSize, DestArray);
}

/*
*/
static LPSTR CreateStringA(_In_ LPCSTR String)
{
	if (!String) return NULL;

	SIZE_T StrLength = strlen(String);

	if (StrLength)
	{
		StrLength++;

		LPSTR Buffer = (LPSTR)MemAlloc(StrLength);

		if (Buffer)
		{
			strcpy_s(Buffer, StrLength, String);

			return Buffer;
		}
	}
	return NULL;
}

/*
*/
static LPWSTR CreateStringW(_In_ LPCWSTR String)
{
	if (!String) return NULL;

	SIZE_T StrLength = wcslen(String);

	if (StrLength)
	{
		StrLength++;

		LPWSTR Buffer = (LPWSTR)MemAlloc(StrLength * sizeof(WCHAR));

		if (Buffer)
		{
			wcscpy_s(Buffer, StrLength, String);

			return Buffer;
		}
	}
	return NULL;
}

/*
*/
static BOOLEAN FreeStringA(_In_ LPSTR String)
{
	if (!String) return FALSE;

	SIZE_T StrLen = strlen(String);

	if (StrLen) StrLen++;

	return MemFree(String, StrLen);
}

/*
*/
static BOOLEAN FreeStringW(_In_ LPWSTR String)
{
	if (!String) return FALSE;

	SIZE_T StrLen = wcslen(String);

	if (StrLen)
	{
		StrLen++;

		StrLen *= sizeof(WCHAR);
	}
	return MemFree(String, StrLen);
}

/*
*/
static BOOLEAN strcmpAW(_In_ LPCSTR String1, _In_ LPCWSTR String2)
{
	size_t Str1Len = strlen(String1);

	size_t Str2Len = wcslen(String2);

	if (Str1Len != Str2Len)
		return FALSE;

	for (size_t i = 0; i < Str1Len; i++)
	{
		if (String1[i] != String2[i])
			return FALSE;
	}
	return TRUE;
}

/*
*/
static LPWSTR AnsiToUnicode(_In_ LPCSTR String)
{
	if (!String) return NULL;

	int DestSize = MultiByteToWideChar(CP_ACP, 0, String, -1, NULL, 0);

	if (DestSize > 0)
	{
		DestSize++;

		LPWSTR Buffer = (LPWSTR)MemAlloc((SIZE_T)DestSize * sizeof(WCHAR));

		if (Buffer)
		{
			MultiByteToWideChar(CP_ACP, 0, String, -1, Buffer, DestSize);

			return Buffer;
		}
	}
	return NULL;
}

/*
*/
static LPSTR UnicodeToAnsi(_In_ LPCWSTR String)
{
	if (!String) return NULL;

	int DestSize = WideCharToMultiByte(CP_UTF8, 0, String, -1, NULL, 0, NULL, NULL);

	if (DestSize > 0)
	{
		DestSize++;

		LPSTR Buffer = (LPSTR)MemAlloc(DestSize);

		if (Buffer)
		{
			WideCharToMultiByte(CP_UTF8, 0, String, -1, Buffer, DestSize, NULL, NULL);

			return Buffer;
		}
	}
	return NULL;
}

/*
*/
static void EnterCritSection()
{
	if (!g_InitCritSection)
	{
		InitializeCriticalSection(&g_CriticalSection);

		g_InitCritSection = TRUE;
	}
	EnterCriticalSection(&g_CriticalSection);
}

/*
*/
static void LeaveCritSection()
{
	LeaveCriticalSection(&g_CriticalSection);
}

/*
*/
static BOOLEAN IsExecutableAddress(_In_ PVOID Address)
{
	if (!Address) return FALSE;

	MEMORY_BASIC_INFORMATION MemoryInformation = { 0 };

	if (VirtualQuery(Address, &MemoryInformation, sizeof(MemoryInformation)))
	{
		if (MemoryInformation.State == MEM_COMMIT && (MemoryInformation.Protect & PAGE_EXECUTE_FLAGS))
			return TRUE;
	}
	return FALSE;
}

/*
*/
static BOOLEAN AreInSamePage(_In_ PVOID Address1, _In_ PVOID Address2)
{
	if (!Address1 || !Address2)
		return FALSE;

	MEMORY_BASIC_INFORMATION MemoryInformation1 = { 0 };

	if (VirtualQuery(Address1, &MemoryInformation1, sizeof(MemoryInformation1)))
	{
		MEMORY_BASIC_INFORMATION MemoryInformation2 = { 0 };

		if (VirtualQuery(Address2, &MemoryInformation2, sizeof(MemoryInformation2)))
		{
			if (MemoryInformation1.BaseAddress == MemoryInformation2.BaseAddress)
				return TRUE;
		}
	}
	return FALSE;
}

/*
*/
static PVOID GetModuleHandleByAddress(_In_ PVOID Address, _Inout_opt_ LPWSTR BaseDllName)
{
	if (!Address) return NULL;

	HMODULE hModule = NULL;

	if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (PWCHAR)Address, &hModule))
	{
		if (BaseDllName)
			GetModuleBaseNameW(GetCurrentProcess(), hModule, BaseDllName, _MAX_FNAME); // Нужно ли?

		return hModule;
	}
	return NULL;
}

/*
*/
static BOOLEAN CompareModulesA(_In_ LPCSTR ModuleName1, _In_ LPCSTR ModuleName2)
{
	if (!ModuleName1 || !ModuleName2)
		return FALSE;

	CHAR FileName1[_MAX_FNAME] = { 0 };

	_splitpath_s(ModuleName1, NULL, 0, NULL, 0, FileName1, _MAX_FNAME, NULL, 0);

	CHAR FileName2[_MAX_FNAME] = { 0 };

	_splitpath_s(ModuleName2, NULL, 0, NULL, 0, FileName2, _MAX_FNAME, NULL, 0);

	return !_strcmpi(FileName1, FileName2);
}

/*
*/
static BOOLEAN CompareModulesW(_In_ LPCWSTR ModuleName1, _In_ LPCWSTR ModuleName2)
{
	if (!ModuleName1 || !ModuleName2)
		return FALSE;

	WCHAR FileName1[_MAX_FNAME] = { 0 };

	_wsplitpath_s(ModuleName1, NULL, 0, NULL, 0, FileName1, _MAX_FNAME, NULL, 0);

	WCHAR FileName2[_MAX_FNAME] = { 0 };

	_wsplitpath_s(ModuleName2, NULL, 0, NULL, 0, FileName2, _MAX_FNAME, NULL, 0);

	return !_wcsicmp(FileName1, FileName2);
}

/*
*/
static BOOLEAN GetFileName(_In_ LPCWSTR FullPath, _Out_ LPWSTR FileName)
{
	if (!FullPath || !FileName)
		return FALSE;

	WCHAR File[_MAX_FNAME] = { 0 };

	WCHAR Ext[_MAX_EXT] = { 0 };

	_wsplitpath_s(FullPath, NULL, 0, NULL, 0, File, _MAX_FNAME, Ext, _MAX_EXT);

	return !_wmakepath_s(FileName, _MAX_FNAME, NULL, NULL, File, Ext);
}

/*
*/
static PIMAGE_NT_HEADERS GetImageNtHeaders(_In_ PVOID BaseAddress)
{
	PVOID ModuleHandle = BaseAddress ? BaseAddress : GetModuleHandleW(NULL);

	if (ModuleHandle)
	{
		PIMAGE_DOS_HEADER ImageDosHeader = (PIMAGE_DOS_HEADER)ModuleHandle;

		if (ImageDosHeader->e_magic == IMAGE_DOS_SIGNATURE)
		{
			PIMAGE_NT_HEADERS ImageNtHeaders = (PIMAGE_NT_HEADERS)(ImageDosHeader->e_lfanew + (SIZE_T)ModuleHandle);

			if (ImageNtHeaders->Signature == IMAGE_NT_SIGNATURE)
				return ImageNtHeaders;
		}
	}
	return NULL;
}

/*
*/
static PVOID GetImageDirectoryEntry(_In_ PVOID Base, _In_ WORD Directory, _Out_ PDWORD Size)
{
	PVOID ModuleHandle = Base ? Base : GetModuleHandleW(NULL);

	if (ModuleHandle)
	{
		PIMAGE_NT_HEADERS NtHeaders = GetImageNtHeaders(ModuleHandle);

		if (NtHeaders)
		{
			IMAGE_DATA_DIRECTORY DataDirectory = NtHeaders->OptionalHeader.DataDirectory[Directory];

			DWORD DirectoryEntry = DataDirectory.VirtualAddress;

			if (!DirectoryEntry)
				return NULL;

			if (Size) *Size = DataDirectory.Size;

			return (PVOID)(DirectoryEntry + (SIZE_T)ModuleHandle);
		}
	}
	return NULL;
}

/*
*/
static BOOLEAN IsImportFunction(_In_ PVOID Address)
{
	if (!Address) return FALSE;

	PVOID ModuleHandle = GetModuleHandleByAddress(Address, NULL);

	if (ModuleHandle)
	{
		PIMAGE_NT_HEADERS NtHeaders = GetImageNtHeaders(ModuleHandle);

		if (NtHeaders)
		{
			IMAGE_DATA_DIRECTORY Directory = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];

			SIZE_T VirtualAddress = Directory.VirtualAddress;

			if (!Directory.VirtualAddress)
				return FALSE;

			VirtualAddress += (SIZE_T)ModuleHandle;

			if ((SIZE_T)Address >= VirtualAddress && (SIZE_T)Address < (VirtualAddress + Directory.Size))
				return TRUE;
		}
	}
	return FALSE;
}

/*
*/
static BOOLEAN ThreadsFree(_In_ PProcessThreads Threads)
{
	if (!Threads) return FALSE;

	return MemFree(Threads->ThreadsID, Threads->Count * sizeof(DWORD));
}

/*
*/
static SIZE_T EnumProcessThreads(_In_ DWORD ProcessID, _Inout_ PProcessThreads Threads)
{
	if (!Threads) return 0;

	DWORD ThreadCount = 0;

	HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	if (hThreadSnapshot != INVALID_HANDLE_VALUE)
	{
		THREADENTRY32 ThreadEntry = { 0 };

		ThreadEntry.dwSize = sizeof(THREADENTRY32);

		if (Thread32First(hThreadSnapshot, &ThreadEntry))
		{
			Threads->ThreadsID = NULL;
			do 
			{
				if (ThreadEntry.th32OwnerProcessID == ProcessID)
				{
					PDWORD ThreadsBuffer = (PDWORD)MemReAlloc(Threads->ThreadsID, ((SIZE_T)ThreadCount + 1) * sizeof(DWORD)); // realloc

					if (!ThreadsBuffer)
					{
						MemFree(ThreadsBuffer, 0); // free

						CloseHandle(hThreadSnapshot);

						return 0;
					}
					Threads->ThreadsID = ThreadsBuffer;

					Threads->ThreadsID[ThreadCount] = ThreadEntry.th32ThreadID;

					ThreadCount++;
				}
			} 
			while (Thread32Next(hThreadSnapshot, &ThreadEntry));

			Threads->Count = ThreadCount;
		}
		CloseHandle(hThreadSnapshot);
	}
	return ThreadCount;
}

/*
*/
static BOOLEAN SuspendResumeThreadsEx(_In_ BOOLEAN Suspend, _In_ PProcessThreads Threads)
{
	if (!Threads) return FALSE;

	DWORD Count = 0;

	for (; Count < Threads->Count; Count++)
	{
		if (Threads->ThreadsID[Count] == GetCurrentThreadId()) // Пропускаем свой первый поток.
			continue;

		HANDLE ThreadHandle = OpenThread(THREAD_SUSPEND_RESUME, FALSE, Threads->ThreadsID[Count]);

		if (!ThreadHandle)
			break;

		if (Suspend)
			SuspendThread(ThreadHandle);
		else
			ResumeThread(ThreadHandle);

		CloseHandle(ThreadHandle);
	}
	if (Threads->Count == Count)
		return TRUE;

	return FALSE;
}

/*
*/
static BOOLEAN SuspendResumeThreads(_In_ BOOLEAN Suspend)
{
	BOOLEAN Result = FALSE;

	TProcessThreads Threads = { 0 };

	if (EnumProcessThreads(GetCurrentProcessId(), &Threads))
	{
		Result = SuspendResumeThreadsEx(Suspend, &Threads);

		ThreadsFree(&Threads);
	}
	return Result;
}

/*
    Fixme: Проверить работоспособность.
*/
static BOOLEAN FixupThreadContextsEx(_In_ PHookInfo HookInfo, _In_ PProcessThreads Threads)
{
	if (!HookInfo || !Threads) 
		return FALSE;

	DWORD Count = 0;

	for (; Count < Threads->Count; Count++)
	{
		if (Threads->ThreadsID[Count] == GetCurrentThreadId())
			continue;

		HANDLE ThreadHandle = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, Threads->ThreadsID[Count]);

		if (!ThreadHandle)
			break;

		CONTEXT Context = { 0 };

		Context.ContextFlags = CONTEXT_CONTROL; // Флаг для получения EIP/RIP

		if (!GetThreadContext(ThreadHandle, &Context))
		{
			CloseHandle(ThreadHandle);

			break;
		}
#ifdef _M_X64
		SIZE_T XipAddress = Context.Rip;
#elif _M_IX86
		SIZE_T XipAddress = Context.Eip;
#endif
		if ((XipAddress >= (SIZE_T)HookInfo->OriginalAddress) && 
			(XipAddress < (SIZE_T)HookInfo->OriginalAddress + HookInfo->OriginalSize)) // Если указатель потока находится в области перехватываемого кода.
		{
			XipAddress = (SIZE_T)HookInfo->BridgeCode + (XipAddress - (SIZE_T)HookInfo->OriginalAddress); // Передаём управление в перехватчик.

			XipAddress += HookInfo->BridgeSize - HookInfo->OriginalSize; // Нужна дельта, т.к релоцированный код может быть больше, чем оригинальный.
#ifdef _M_X64
			Context.Rip = XipAddress;
#elif _M_IX86
			Context.Eip = XipAddress;
#endif
			if (!SetThreadContext(ThreadHandle, &Context))
			{
				CloseHandle(ThreadHandle);

				break;
			}
		}
		CloseHandle(ThreadHandle);
	}
	if (Threads->Count == Count)
		return TRUE;
	
	return FALSE;
}

/*
*/
static BOOLEAN FixupThreadContexts(_In_ PHookInfo HookInfo)
{
	BOOLEAN Result = FALSE;

	TProcessThreads Threads = { 0 };

	if (EnumProcessThreads(GetCurrentProcessId(), &Threads))
	{
		Result = FixupThreadContextsEx(HookInfo, &Threads);

		ThreadsFree(&Threads);
	}
	return Result;
}

/*
*/
#ifdef _M_X64
static PVOID FindEmptyPrevBlock(_In_ PVOID Origin, _In_ SIZE_T RangeSize, _In_ SIZE_T BlockSize)
{
	if (!Origin || !BlockSize)
		return NULL;

	SYSTEM_INFO SystemInfo = { 0 };

	GetSystemInfo(&SystemInfo);

	DWORD Granularity = SystemInfo.dwAllocationGranularity;

	SIZE_T Address = AlignDown((SIZE_T)Origin, Granularity);

	SIZE_T EndAddress = Address - RangeSize;

	if ((EndAddress > (SIZE_T)SystemInfo.lpMinimumApplicationAddress) && (Address < (SIZE_T)SystemInfo.lpMaximumApplicationAddress))
	{
		while (Address >= EndAddress)
		{
			MEMORY_BASIC_INFORMATION MemoryInformation = { 0 };

			if (!VirtualQuery((PVOID)Address, &MemoryInformation, sizeof(MemoryInformation)))
				break;

			if ((MemoryInformation.State == MEM_FREE) && (MemoryInformation.RegionSize >= BlockSize))
			{
				if (IsValidDelta(Address, EndAddress, RangeSize))
					return (PVOID)Address;
			}
			Address = (SIZE_T)MemoryInformation.BaseAddress - 1;

			Address = AlignDown(Address, Granularity);
		}
	}
	return NULL;
}
#endif

/*
*/
#ifdef _M_X64
static PVOID FindEmptyNextBlock(_In_ PVOID Origin, _In_ SIZE_T RangeSize, _In_ SIZE_T BlockSize)
{
	if (!Origin || !BlockSize)
		return NULL;

	SYSTEM_INFO SystemInfo = { 0 };

	GetSystemInfo(&SystemInfo);

	DWORD Granularity = SystemInfo.dwAllocationGranularity;

	SIZE_T Address = AlignUp((SIZE_T)Origin, Granularity);

	SIZE_T EndAddress = Address + RangeSize;

	if ((EndAddress < (SIZE_T)SystemInfo.lpMaximumApplicationAddress) && (Address > (SIZE_T)SystemInfo.lpMinimumApplicationAddress))
	{
		while (Address <= EndAddress)
		{
			MEMORY_BASIC_INFORMATION MemoryInformation = { 0 };

			if (!VirtualQuery((PVOID)Address, &MemoryInformation, sizeof(MemoryInformation)))
				break;

			if ((MemoryInformation.State == MEM_FREE) && (MemoryInformation.RegionSize >= BlockSize))
			{
				if (IsValidDelta(Address, EndAddress, RangeSize))
					return (PVOID)Address;
			}
			Address = (SIZE_T)MemoryInformation.BaseAddress + MemoryInformation.RegionSize;

			Address = AlignUp(Address, Granularity);
		}
	}
	return NULL;
}
#endif

/*
*/
static PVOID AllocNextBlock(_In_ PVOID Origin, _In_ SIZE_T RangeSize, _In_ SIZE_T BlockSize)
{
#ifdef _M_X64
	PVOID Block = FindEmptyNextBlock(Origin, RangeSize, BlockSize);

	if (Block)
		return VirtualAlloc(Block, BlockSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	else
		return NULL;
#elif _M_IX86
	return VirtualAlloc(NULL, BlockSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
#endif
}

/*
*/
static PVOID AllocPrevBlock(_In_ PVOID Origin, _In_ SIZE_T RangeSize, _In_ SIZE_T BlockSize)
{
#ifdef _M_X64
	PVOID Block = FindEmptyPrevBlock(Origin, RangeSize, BlockSize);

	if (Block)
		return VirtualAlloc(Block, BlockSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	else
		return NULL;
#elif _M_IX86
	return VirtualAlloc(NULL, BlockSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
#endif
}

/*
*/
static PVOID AllocMemory(_In_ PVOID Origin, _In_ SIZE_T RangeSize, _In_ SIZE_T BlockSize, _In_ DWORD Protect)
{
	PVOID Block = AllocNextBlock(Origin, RangeSize, BlockSize);

	Block = Block ? Block : AllocPrevBlock(Origin, RangeSize, BlockSize);

	if (Block)
	{
#ifdef _DEBUG
		HookLog("Allocated block at 0x%p\n", Block);

		//memset(Result, INT3, BlockSize);
#endif
		return Block;
	}
	return NULL;
}

/*
*/
static BOOLEAN FreeMemory(_In_ PVOID Address)
{
	return VirtualFree(Address, 0, MEM_RELEASE);
}

/*
static PVOID AllocMemory(_In_ PVOID Origin, SIZE_T RangeSize, _In_ SIZE_T BlockSize, _In_ DWORD Protect)
{
#ifdef _M_X64
	SYSTEM_INFO SystemInfo = { 0 };

	MEMORY_BASIC_INFORMATION MemoryInformation = { 0 };

	GetSystemInfo(&SystemInfo);

	SIZE_T Address = (SIZE_T)SystemInfo.lpMinimumApplicationAddress;

	while (Address < (SIZE_T)SystemInfo.lpMaximumApplicationAddress) // Перебираем всю доступную приложению память.
	{
		Address = AlignUp(Address, SystemInfo.dwAllocationGranularity); // Выравниваем адрес.

		if (!VirtualQuery((PVOID)Address, &MemoryInformation, sizeof(MemoryInformation)))
			break;

		if (IsValidDelta((SIZE_T)Origin, Address, RangeSize) && (MemoryInformation.State == MEM_FREE) && (MemoryInformation.RegionSize >= BlockSize)) // Ищем свободную область памяти в пределах +-2гб
		{
			for (; Address < ((SIZE_T)MemoryInformation.BaseAddress + MemoryInformation.RegionSize); Address += SystemInfo.dwAllocationGranularity)
			{
				PVOID Result = VirtualAlloc((PVOID)Address, BlockSize, MEM_COMMIT | MEM_RESERVE, Protect); // Может вернуть ERROR_INVALID_ADDRESS

				if (Result)
				{
#ifdef _DEBUG
					printf_s("Allocated block at 0x%p\n", (PVOID)Address);

					//memset(Result, INT3, BlockSize);
#endif
					return Result;
				}
			}
		}
		Address = ((SIZE_T)MemoryInformation.BaseAddress + MemoryInformation.RegionSize);
	} 
	return NULL;
#else
	return VirtualAlloc(NULL, BlockSize, MEM_COMMIT | MEM_RESERVE, Protect);
#endif
}
*/

/*
static PMemoryBlock FindBlockInRange(_In_ PVOID Origin, _In_ SIZE_T RangeSize, _In_ SIZE_T BlockSize, _In_ BOOLEAN Reverse)
{
	if (!Origin || !RangeSize || !BlockSize)
		return NULL;

	for (PMemoryBlock Block = g_MemoryFirstBlock; Block != NULL; Block = Block->Next)
	{
#ifdef _M_X64
		BOOLEAN InRange = FALSE;

		if (Reverse)
			InRange = (RangeSize > ((SIZE_T)Origin - (SIZE_T)Block)); // -2гб
		else
			InRange = (RangeSize > ((SIZE_T)Block - (SIZE_T)Origin)); // +2гб

		if (InRange)
#endif
			if (Block->UsedBuffers < Block->MaxBuffers && (Block->BlockSize >= BlockSize)) // Ищем блок в котором имеется хоть один свободный буфер.
				return Block;
	}
	return FALSE;
}
*/

/*
*/
static PMemoryBlock GetFreeNextBlock(_In_ PVOID Origin, _In_ SIZE_T RangeSize, _In_ SIZE_T BlockSize)
{
	if (!Origin || !RangeSize || !BlockSize)
		return NULL;

	for (PMemoryBlock Block = g_MemoryFirstBlock; Block != NULL; Block = Block->Next)
	{
#ifdef _M_X64
		if (RangeSize > ((SIZE_T)Block - (SIZE_T)Origin)) // +2гб
#endif
			if (Block->UsedBuffers < Block->MaxBuffers && (Block->BlockSize >= BlockSize)) // Ищем блок в котором имеется хоть один свободный буфер.
				return Block;
	}
	return NULL;
}

/*
*/
static PMemoryBlock GetFreePrevBlock(_In_ PVOID Origin, _In_ SIZE_T RangeSize, _In_ SIZE_T BlockSize)
{
	if (!Origin || !RangeSize || !BlockSize)
		return NULL;

	for (PMemoryBlock Block = g_MemoryFirstBlock; Block != NULL; Block = Block->Next)
	{
#ifdef _M_X64
		if (RangeSize > ((SIZE_T)Origin - (SIZE_T)Block)) // -2гб
#endif
			if (Block->UsedBuffers < Block->MaxBuffers && (Block->BlockSize >= BlockSize))
				return Block;
	}
	return NULL;
}

/*
*/
static PMemoryBlock GetFreeBlock(_In_ PVOID Origin, _In_ SIZE_T RangeSize, _In_ SIZE_T BlockSize)
{
	if (!Origin || !BlockSize)
		return NULL;

	PMemoryBlock Block = GetFreeNextBlock(Origin, RangeSize, BlockSize);

	if (!Block)
		return GetFreePrevBlock(Origin, RangeSize, BlockSize);
	else
		return Block;
}

/*
*/
static PMemoryBlock RegisterBlock(_In_ PMemoryBlock NewBlock, _In_ SIZE_T BlockSize, _In_ SIZE_T BufferSize)
{
	if (!NewBlock || !BlockSize || !BufferSize)
		return NULL;

	SIZE_T Offset = sizeof(TMemoryBlock);

	SIZE_T MaxBuffers = (BlockSize - Offset) / BufferSize; // Максимальное количество буферов на один блок памяти.

	if (MaxBuffers)
	{
		NewBlock->BlockSize = BlockSize;

		NewBlock->MaxBuffers = MaxBuffers;

		NewBlock->Buffers = (PMemoryBuffer)((SIZE_T)NewBlock + Offset);

		if (!g_MemoryFirstBlock)
		{
			g_MemoryFirstBlock = NewBlock; // Первый блок.
		}
		else
		{
			PMemoryBlock LastBlock = g_MemoryFirstBlock;

			while (LastBlock->Next) // Ищем последний блок в списке.
			{
				LastBlock = LastBlock->Next;
			}
			LastBlock->Next = NewBlock;

			NewBlock->Prev = LastBlock;
		}
		return NewBlock;
	}
	return NULL;
}

/*
*/
static PMemoryBlock AllocateNewBlock(_In_ PVOID Origin, _In_ SIZE_T RangeSize, _In_ SIZE_T BlockSize, _In_ SIZE_T BufferSize)
{
	if (!Origin || !BlockSize || !BufferSize)
		return NULL;

	PMemoryBlock NewBlock = (PMemoryBlock)AllocMemory(Origin, RangeSize, BlockSize, PAGE_EXECUTE_READWRITE);

	if (NewBlock)
		return RegisterBlock(NewBlock, BlockSize, BufferSize);
	else
		return NULL;
}

/*
*/
#ifdef _M_X64
static PMemoryBlock GetNextBlock(_In_ PVOID Origin, _In_ SIZE_T RangeSize, _In_ SIZE_T BlockSize, _In_ SIZE_T BufferSize)
{
	if (!Origin) return NULL;

	PMemoryBlock Block = GetFreeNextBlock(Origin, RangeSize, BlockSize);

	if (!Block)
	{
		Block = (PMemoryBlock)AllocNextBlock(Origin, RangeSize, BlockSize);

		if (Block)
			return RegisterBlock(Block, BlockSize, BufferSize);
	}
	return Block;
}
#endif

/*
*/
#ifdef _M_X64
static PMemoryBlock GetPrevBlock(_In_ PVOID Origin, _In_ SIZE_T RangeSize, _In_ SIZE_T BlockSize, _In_ SIZE_T BufferSize)
{
	if (!Origin) return NULL;

	PMemoryBlock Block = GetFreePrevBlock(Origin, RangeSize, BlockSize);

	if (!Block)
	{
		Block = (PMemoryBlock)AllocPrevBlock(Origin, RangeSize, BlockSize);

		if (Block)
			return RegisterBlock(Block, BlockSize, BufferSize);
	}
	return Block;
}
#endif

/*
*/
static PMemoryBlock GetBlock(_In_ PVOID Origin, _In_ SIZE_T RangeSize, _In_ SIZE_T BlockSize, _In_ SIZE_T BufferSize)
{
	if (!Origin || !BlockSize) 
		return NULL;

	PMemoryBlock Block = GetFreeBlock(Origin, RangeSize, BlockSize);

	if (!Block)
		Block = AllocateNewBlock(Origin, RangeSize, BlockSize, BufferSize);

	return Block;
}

/*
*/
static BOOLEAN FreeBlock(_In_ PMemoryBlock Block)
{
	if (Block)
	{
		PMemoryBlock NextBlock = Block->Next, LastBlock = Block->Prev;

		if (g_MemoryFirstBlock == Block) // Если удаляем первый блок.
			g_MemoryFirstBlock = NextBlock;
		else
			LastBlock->Next = NextBlock;

		if (NextBlock) // Если последний.
			NextBlock->Prev = LastBlock;

		return FreeMemory(Block);
	}
	return FALSE;
}

/*
*/
static BOOLEAN FreeAllBlocks(_In_opt_ PMemoryBlock FirstBlock)
{
	BOOLEAN Result = FALSE;

	PMemoryBlock Block = (FirstBlock > 0) ? FirstBlock : g_MemoryFirstBlock;

	while (Block)
	{
		PMemoryBlock NextBlock = Block->Next;

		Result = FreeBlock(Block);

		if (Result)
			Block = NextBlock;
		else
			break;
	};
	return Result;
}

/*
*/
static PMemoryBlock GetBlockByBuffer(_In_ PMemoryBuffer Buffer)
{
	PMemoryBlock Block = g_MemoryFirstBlock;

	while (Block)
	{
		for (SIZE_T Count = 0; Count < Block->MaxBuffers; Count++)
		{
			if (&Block->Buffers[Count] == Buffer)
				return Block;
		}
		Block = Block->Next;
	}
	return NULL;
}

/*
*/
static PMemoryBuffer GetFreeBuffer(_In_ PMemoryBlock Block, _Out_opt_ PSIZE_T Number)
{
	if (!Block) return NULL;

	for (SIZE_T Count = 0; Count < Block->MaxBuffers; Count++)
	{
		if (!Block->Buffers[Count].Used)
		{
			if (Number)
				*Number = Count;

			return &Block->Buffers[Count];
		}
	}
	return NULL;
}

/*
*/
static PMemoryBuffer GetMemoryBuffer(_In_ PVOID Origin)
{
	if (!Origin) return NULL;

	PMemoryBlock Block = GetBlock(Origin, MAX_MEMORY_RANGE, MAX_BLOCK_SIZE, MAX_BUFFER_SIZE);

	if (Block)
	{
		PMemoryBuffer Buffer = GetFreeBuffer(Block, NULL);

		if (Buffer)
		{
			Buffer->Used = TRUE;

			Block->UsedBuffers++;

			return Buffer;
		}
	}
	return NULL;
}

/*
*/
static BOOLEAN FreeBuffer(_In_ PMemoryBuffer Buffer)
{
	if (!Buffer) return FALSE;

	PMemoryBlock Block = GetBlockByBuffer(Buffer);

	if (Block)
	{
		Buffer->Used = FALSE;

		Block->UsedBuffers--;

		RtlSecureZeroMemory(&Buffer->Data, sizeof(Buffer->Data));

		if (!Block->UsedBuffers) // Если все буферы свободны
			return FreeBlock(Block); // то удаляем ненужный блок.
	
		return TRUE;
	}
	return FALSE;
}

/*
*/
static PHookInfo GetHookInfo(_In_ PVOID Address, _Out_opt_ PMemoryBuffer* Buffer)
{
	if (!Address) return NULL;

	for (PMemoryBlock Block = g_MemoryFirstBlock; Block != NULL; Block = Block->Next)
	{
		for (SIZE_T Count = 0; Count < Block->MaxBuffers; Count++)
		{
			PMemoryBuffer MemoryBuffer = &Block->Buffers[Count];

			PHookInfo HookInfo = &MemoryBuffer->Data;

			if ((HookInfo->HookAddress == Address) || (HookInfo->OriginalAddress == Address) || 
				(HookInfo->BridgeCode == Address) || (HookInfo == Address))
			{
				if (Buffer) 
					*Buffer = MemoryBuffer;

				return HookInfo;
			}
		}
	}
	return NULL;
}

/*
*/
static PHookInfo GetHookBuffer(_In_ PVOID Origin, _Out_opt_ PMemoryBuffer *Buffer)
{
	if (!Origin) return NULL;

	PMemoryBuffer MemBuffer = GetMemoryBuffer(Origin);

	if (MemBuffer)
	{
		if (Buffer)
			*Buffer = MemBuffer;

		return &MemBuffer->Data;
	}
	return NULL;
}

/*
*/
static BOOLEAN FreeHookBuffer(_In_ PVOID Address)
{
	if (!Address) return FALSE;

	PMemoryBuffer Buffer = NULL;

	PHookInfo Hook = GetHookInfo(Address, &Buffer);

	if (Hook && Buffer)
		return FreeBuffer(Buffer);
	else
		return FALSE;
}

/*
*/
static BOOLEAN WriteJump(_In_ PVOID From, _In_ PVOID To, _In_ WORD Opcode)
{
	if (!From || !To) return FALSE;

	__try
	{
		if (Opcode == JUMP_ABS)
		{
			((PJumpAbs)From)->Opcode = JUMP_ABS; // jmp qword [rip + 0x00]
			((PJumpAbs)From)->Dummy = 0;
			((PJumpAbs)From)->Address = To;

			return TRUE;
		}
		else if (Opcode == JUMP_REL)
		{
			if (IsValidDelta((SIZE_T)From, (SIZE_T)To, TWO_GIGABYTES)) // Не более +-2гб.
			{
				((PJumpRel)From)->Opcode = JUMP_REL;
				((PJumpRel)From)->Address = (DWORD)GetJmpRelAddress(From, To, sizeof(TJumpRel));

				return TRUE;
			}
		}
		else if (Opcode == JUMP_SHORT)
		{
			if (IsValidDelta((SIZE_T)From, (SIZE_T)To, MAXBYTE)) // Не более +-255 байт.
			{
				((PJumpShort)From)->Opcode = JUMP_SHORT;
				((PJumpShort)From)->Address = (BYTE)GetJmpRelAddress(From, To, sizeof(TJumpShort));

				return TRUE;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return FALSE;
	}
	return FALSE;
}

/*
*/
static inline SSIZE_T AddressDisplacement(_In_ PLengthDisasm Data)
{
	switch (Data->DisplacementSize)
	{
	    case 1: return (int8_t)Data->AddressDisplacement.Displacement08;
			break;
	    case 2: return (int16_t)Data->AddressDisplacement.Displacement16;
			break;
	    case 4: return (int32_t)Data->AddressDisplacement.Displacement32;
			break;
	}
	return 0;
}

/*
*/
static inline SSIZE_T ImmediateData(_In_ PLengthDisasm Data)
{
	switch (Data->ImmediateDataSize)
	{
	    case 1: return (int8_t)Data->ImmediateData.ImmediateData08;
			break;
	    case 2: return (int16_t)Data->ImmediateData.ImmediateData16;
			break;
	    case 4: return (int32_t)Data->ImmediateData.ImmediateData32;
			break;
#ifdef _M_X64
	    case 8: return (int64_t)Data->ImmediateData.ImmediateData64;
			break;
#endif
	}
	return 0;
}

/*
*/
static BOOLEAN IsConditionalJump(_In_ PLengthDisasm Data)
{
	if (Data->Opcode[0] == 0x0F)
	{
		if ((Data->Opcode[1] & 0xF0) == 0x80) // jcc rel16/32
			return TRUE;
	}
	
	if ((Data->Opcode[0] & 0xF0) == 0x70) // jcc rel8
		return TRUE;

	if (Data->Opcode[0] == 0xE3) // jecxz
		return TRUE;

	return FALSE;
}

/*
*/
static BOOLEAN IsUnconditionalJump(_In_ PLengthDisasm Data)
{
	if ((Data->Opcode[0] == 0xEB) || // jmp rel8
		(Data->Opcode[0] == 0xE9))   // jmp rel16/32
	{
		return TRUE;
	}

	if (Data->Opcode[0] == 0xff && 
		Data->ModRMByte == 0x25) // jmp [imm32]
	{
		return TRUE;
	}
	return FALSE;
}

/*
*/
static SIZE_T ReadJumpAddressEx(_In_ PVOID Address, _In_ PLengthDisasm Data)
{
	if (!Address || !Data)
		return 0;

	SSIZE_T JmpAddress = 0;

	if (Data->Flags & F_DISP)
		JmpAddress = AddressDisplacement(Data);

	if (Data->Flags & F_IMM)
		JmpAddress = ImmediateData(Data);

	if (Data->Flags & F_RELATIVE)
		JmpAddress += (SSIZE_T)Address + Data->Length;

	if (Data->Opcode[0] == 0x0F)
	{
		if ((Data->Opcode[1] & 0xF0) == 0x80) // jcc rel16/32
			return JmpAddress;
	}
	if ((Data->Opcode[0] & 0xF0) == 0x70 || // jcc rel8
		(Data->Opcode[0] & 0xFC) == 0xE0 || // loopne, loope, loop, jecxz
		(Data->Opcode[0] & 0xF0) == 0xE0)   // call, jmp short
	{
		return JmpAddress;
	}
	if ((Data->Opcode[0] == 0xff && Data->ModRMByte == 0x25) || // jmp [Mem]
		(Data->Opcode[0] == 0xff && Data->ModRMByte == 0x15))   // call
	{
		if (JmpAddress)
			return *(PSIZE_T)JmpAddress;
	}
	return 0;
}

/*
*/
static uint8_t GetLengthCode(_In_ PVOID Address, _In_ PLengthDisasm Data)
{
	if (!Address) return 0;

	if (IsExecutableAddress(Address))
	{
#ifdef _M_X64
		uint8_t Size = LengthDisasm(Address, TRUE, Data);
#elif _M_IX86
		uint8_t Size = LengthDisasm(Address, FALSE, Data);
#endif
		return Size;
	}
	return 0;
}

/*
*/
static DWORD CalcCodeLength(_In_ PVOID Address, _In_ DWORD NeedSize)
{
	if (!Address || !NeedSize)
		return 0;

	DWORD CodeSize = 0;

	TLengthDisasm Data = { 0 };

	while (CodeSize < NeedSize)
	{
		GetLengthCode(Address, &Data);

		if (Data.Flags & F_INVALID)
			return 0;

		CodeSize += Data.Length;
	}
	return CodeSize;
}

/*
*/
static SIZE_T ReadJumpAddress(_In_ PVOID Address)
{
	if (!Address) return 0;

	TLengthDisasm Data = { 0 };

	uint8_t Size = GetLengthCode(Address, &Data);

	if (Size)
		return ReadJumpAddressEx(Address, &Data);
	else
		return 0;
}

/*
*/
static PVOID JumpWalk(_In_ PVOID Address, _In_ SIZE_T MaxJumps)
{
	if (!Address) return NULL;

	PVOID Result = 0;

	PVOID Jump = Address;

	for (SIZE_T Count = 0; Count < MaxJumps; Count++)
	{
		Jump = (PVOID)ReadJumpAddress(Jump);

		if (Jump)
			Result = Jump;
		else
			break;
	}
	return Result;
}

/*
*/
static PVOID GetImportedAddress(_In_ PVOID Address)
{
	if (!Address) return NULL;

	if (!IsExecutableAddress(Address))
		return NULL;

	TLengthDisasm Data = { 0 };

	if (!GetLengthCode(Address, &Data))
		return NULL;

	if (Data.Opcode[0] == 0xff && Data.ModRMByte == 0x25) // jmp [Mem]
	{
		PBYTE JmpAddress = (PBYTE)AddressDisplacement(&Data);

		if (JmpAddress)
		{
			if (Data.Flags & F_RELATIVE)
				JmpAddress += (SSIZE_T)Address + Data.Length;

			if (IsImportFunction(JmpAddress))
				return *(PVOID*)JmpAddress;
		}
	}
	return Address;
}

/*
*/
static BOOLEAN IsHookedProc(_In_ PVOID Address)
{
	if (!Address) return FALSE;

	PHookInfo HookInfo = GetHookInfo(Address, NULL);

	if (HookInfo)
	{
		if (HookInfo->Type == HookTypeSplice || HookInfo->Type == HookTypeHotpatch || HookInfo->Type == HookTypeExport)
		{
			return HookInfo->IsHooked;
		}
	}
	return FALSE;
}

/*
*/
static BOOLEAN IsSameHook(_In_ PVOID HookAddress)
{
	if (!HookAddress) return FALSE;

	PHookInfo HookInfo = GetHookInfo(HookAddress, NULL);

	if (HookInfo)
	{
		if (HookInfo->Type == HookTypeSplice || HookInfo->Type == HookTypeHotpatch || HookInfo->Type == HookTypeExport)
		{
			if (HookInfo->IsHooked)
			{
				if (HookInfo->HookAddress == HookAddress)
					return TRUE;
			}
		}
	}
	return FALSE;
}

/*
*/
static uint8_t ConvertInstruction(_In_ PVOID Address, _In_ DWORD NewSize, _Inout_ PLengthDisasm Data)
{
	if (!Address || !Data)
		return 0;

	if ((Data->Flags & F_RELATIVE) && (Data->Flags & F_IMM) && (Data->ImmediateDataSize <= 2)) // Обрабатываем только короткие прыжки.
	{
		if (((Data->Opcode[0] == 0x0F) && (Data->Opcode[1] & 0xF0) == 0x80) || (Data->Opcode[0] & 0xF0) == 0x70) // Условный прыжок. jcc rel8\16
		{
			uint8_t Condition = (Data->Opcode[0] != 0x0F ? Data->Opcode[0] : Data->Opcode[1]) & 0x0F;

			Data->Opcode[0] = 0x0F; // jcc rel32
			Data->Opcode[1] = 0x80 | Condition; // Условие.

			Data->OpcodeSize = 2;
			Data->ImmediateDataSize = 4;
			Data->ImmediateDataOffset = 2;
			Data->Length = sizeof(TJccRel);
		}
		else if (Data->Opcode[0] == 0xEB) // Безусловный короткий прыжок. jmp rel8
		{
			Data->Opcode[0] = 0xE9;

			Data->ImmediateDataSize = 4;
			Data->Length = sizeof(TJumpRel);
		}
		else if ((Data->Opcode[0] & 0xFC) == 0xE0) // loop, jecx
		{
			SSIZE_T Relative = ImmediateData(Data) + Data->Length;

			if (Relative > 0) 
				return 0; // Не поддерживаем прыжок во внутрь функции.

			SSIZE_T RestSize = MIN_HOOK_SIZE;

			if ((SSIZE_T)NewSize > RestSize)
				RestSize = NewSize;
			else
				RestSize -= NewSize;

			if (~Relative > RestSize)
				return 0;
		}
	}
	return Data->Length;
}

/*
*/
static uint8_t RelocateInstruction(_In_ PVOID Address, _In_ PVOID NewAddress, _In_ DWORD NewSize, _Inout_ PLengthDisasm Data)
{
	if (!Address || !NewAddress || !Data)
		return 0;

	if (Data->Flags & F_RELATIVE)
	{
		SSIZE_T NewRelative = (SSIZE_T)Address + Data->Length; //

		if (Data->Flags & F_DISP)
		{
			NewRelative += AddressDisplacement(Data);

			NewRelative -= (SSIZE_T)NewAddress + Data->Length;

			Data->AddressDisplacement.Displacement32 = (uint32_t)NewRelative;
		}
		else if (Data->Flags & F_IMM)
		{
			if (!ConvertInstruction(Address, NewSize, Data))
				return 0;

			if (Data->ImmediateDataSize >= 4)
			{
				NewRelative += ImmediateData(Data);

				NewRelative -= (SSIZE_T)NewAddress + Data->Length;

				Data->ImmediateData.ImmediateData64 = NewRelative;
			}
		}
	}
	return Data->Length;
}

/*
*/
static THookStatus CopyCodeEx(_In_ PVOID Source, _Inout_ PVOID Destination, _In_ BYTE NeedSize, _Out_ PBYTE ConvertedSize,  _Out_ PBYTE OriginalSize)
{
	if (!Source || !Destination || !ConvertedSize || !OriginalSize)
		return HookStatusError;

	TLengthDisasm Data = { 0 };

	PBYTE CodeAddress = (PBYTE)Source;

	PBYTE Buffer = (PBYTE)Destination;

	BYTE CodeSize = 0, NewSize = 0;

	while (CodeSize < NeedSize)
	{
		GetLengthCode(CodeAddress, &Data);

		if (Data.Flags & F_INVALID)
			return HookStatusInstructionError;

		if ((Data.Opcode[0] == 0xC3) || (Data.Opcode[0] == 0xC2))
			return HookStatusTooShortFunction;

		uint8_t OldLength = Data.Length;

		uint8_t ConvSize = RelocateInstruction(CodeAddress, Buffer, NewSize, &Data);

		if (!ConvSize) 
			return HookStatusInstructionError;

		if (ConvSize > OldLength)
			NewSize += ConvSize;
		else
			NewSize += OldLength;

		LengthAssemble(Buffer, &Data); // Собираем вновь инструкцию и копируем её в буфер.

		CodeAddress += OldLength; // Адрес следующей инструкции.
		CodeSize += OldLength; // Размер оригинального кода.
		Buffer += ConvSize; // Указатель на переходник.
	}
	if (ConvertedSize)
		*ConvertedSize = NewSize;

	if (OriginalSize)
		*OriginalSize = CodeSize;

	return HookStatusSuccess;
}

/*
*/
static uint8_t CopyCode(_In_ PVOID Source, _Inout_ PVOID Destination, _In_ BYTE NeedSize, _Out_ PBYTE OriginalSize)
{
	if (!Source || !Destination || !OriginalSize)
		return 0;

	uint8_t RelocatedSize = 0;

	if (CopyCodeEx(Source, Destination, NeedSize, &RelocatedSize, OriginalSize) == HookStatusSuccess)
		return RelocatedSize;
	else
		return 0;
}

/*
*/
PVOID GetBridgeAddress(_In_ PVOID Address)
{
	if (!Address) return NULL;

	PHookInfo HookInfo = GetHookInfo(Address, NULL);

	if (HookInfo)
		return HookInfo->BridgeCode;
	else
		return NULL;
}

/*
*/
PVOID GetOriginalAddress(_In_ PVOID Address)
{
	if (!Address) return NULL;

	PHookInfo HookInfo = GetHookInfo(Address, NULL);

	if (HookInfo)
		return HookInfo->OriginalAddress;
	else
		return NULL;
}

/*
*/
PVOID GetHookAddress(_In_ PVOID Address)
{
	if (!Address) return NULL;

	PHookInfo HookInfo = GetHookInfo(Address, NULL);

	if (HookInfo)
		return HookInfo->HookAddress;
	else
		return NULL;
}

/*
*/
static BOOLEAN ReplaceProcHook(_In_ PVOID OldAddress, _In_ PVOID NewAddress)
{
	if (!OldAddress || !NewAddress)
		return FALSE;

	PHookInfo HookInfo = GetHookInfo(OldAddress, NULL);

	if (HookInfo && HookInfo->Type == HookTypeSplice)
	{
		DWORD OldProtect = 0;

		PVOID OriginalAddress = HookInfo->OriginalAddress;

		if (VirtualProtect(OriginalAddress, HookInfo->OriginalSize, PAGE_EXECUTE_READWRITE, &OldProtect))
		{
#ifdef _M_X64
			((PJumpAbs)OriginalAddress)->Address = NewAddress;
#elif _M_IX86
			((PJumpRel)OriginalAddress)->Address = GetJmpRelAddress(OriginalAddress, NewAddress, sizeof(TJumpRel));
#endif
			VirtualProtect(OriginalAddress, HookInfo->OriginalSize, OldProtect, &OldProtect);

			HookInfo->HookAddress = NewAddress;

			return TRUE;
		}
	}
	return FALSE;
}

/*
*/
static THookStatus CreateHookBridge(_In_ PVOID Address, _In_ PVOID NewAddress, _In_ BYTE HookSize, _Out_ PHookInfo* Bridge)
{
	if (!Address || !NewAddress | !Bridge)
		return HookStatusError;

	PMemoryBuffer Buffer = NULL;

	PHookInfo HookInfo = GetHookBuffer(Address, &Buffer);

	if (!HookInfo)
		return HookStatusMemoryError;

	HookInfo->HookAddress = NewAddress;

	HookInfo->OriginalAddress = GetImportedAddress(Address);

#ifdef _DEBUG
	memset(HookInfo->BridgeCode, INT3, _countof(HookInfo->BridgeCode));

	memset(HookInfo->OriginalCode, INT3, _countof(HookInfo->OriginalCode));
#endif

	THookStatus Status = CopyCodeEx(Address, (PBYTE)HookInfo->BridgeCode, HookSize, &HookInfo->BridgeSize, &HookInfo->OriginalSize);

	if (Status == HookStatusSuccess)
	{
		if ((!HookInfo->BridgeSize) || (HookInfo->BridgeSize > _countof(HookInfo->BridgeCode)) || (HookInfo->OriginalSize > _countof(HookInfo->OriginalCode)))
		{
			Status = HookStatusInstructionError;
		}
		else if (Status == HookStatusSuccess)
		{
			memcpy_s(HookInfo->OriginalCode, _countof(HookInfo->OriginalCode), HookInfo->OriginalAddress, HookInfo->OriginalSize); // Сохраняем оригинальный код.

			WriteJump((PBYTE)HookInfo->BridgeCode + HookInfo->BridgeSize, (PBYTE)HookInfo->OriginalAddress + HookInfo->OriginalSize, JUMP_REL); // Пишем прыжок в оригинальный код.

#ifdef _DEBUG
			HookInfo->Jmp = (PJumpRel)((PBYTE)HookInfo->BridgeCode + HookInfo->BridgeSize);

			HookInfo->RetAddress = (PVOID)((PBYTE)HookInfo->OriginalAddress + HookInfo->OriginalSize);
#endif
			if (Bridge) *Bridge = HookInfo;
		}
	}
	if (Status != HookStatusSuccess)
	{
		FreeBuffer(Buffer);
	}
	return Status;
}

/*
*/
THookStatus HookSpliceEx(_In_ PVOID Address, _In_ PVOID NewAddress, _Out_ PHookInfo* Bridge)
{
	if (!Address || !NewAddress | !Bridge)
		return HookStatusError;

	if (!IsExecutableAddress(Address))
		return HookStatusError;

	if (IsHookedProc(Address))
		return HookStatusIsHooked;

	EnterCritSection();

	PHookInfo HookInfo = NULL;

	THookStatus Status = CreateHookBridge(Address, NewAddress, MIN_HOOK_SIZE, &HookInfo);

	if (Status == HookStatusSuccess)
	{
		DWORD OldProtect = 0;

		if (!VirtualProtect(HookInfo->OriginalAddress, HookInfo->OriginalSize, PAGE_EXECUTE_READWRITE, &OldProtect))
		{
			Status = HookStatusMemoryError;
		}
		else if (Status == HookStatusSuccess)
		{
			TProcessThreads Threads = { 0 };

			if (!EnumProcessThreads(GetCurrentProcessId(), &Threads)) // Получаем все потоки процесса
			{
				Status = HookStatusThreadsError;
			}
			else if (Status == HookStatusSuccess)
			{
				if (!SuspendResumeThreadsEx(TRUE, &Threads)) // Замараживаем их
				{
					Status = HookStatusThreadsError;
				}
				else if (Status == HookStatusSuccess)
				{
					if (!FixupThreadContextsEx(HookInfo, &Threads)) // Правим адрес выполнения, если нужно.
					{
						Status = HookStatusFixupThreadsError;
					}
					else if (Status == HookStatusSuccess)
					{
						memset(HookInfo->OriginalAddress, NOP, HookInfo->OriginalSize);
#ifdef _M_X64
						WriteJump(HookInfo->OriginalAddress, HookInfo->HookAddress, JUMP_ABS); // Прыжок в перехватчик.
#elif _M_IX86
						WriteJump(HookInfo->OriginalAddress, HookInfo->HookAddress, JUMP_REL);
#endif
						VirtualProtect(Address, HookInfo->OriginalSize, OldProtect, &OldProtect);

						FlushInstructionCache(GetCurrentProcess(), HookInfo->OriginalAddress, HookInfo->OriginalSize);

						FlushInstructionCache(GetCurrentProcess(), HookInfo->HookAddress, HookInfo->BridgeSize);

						if (!SuspendResumeThreadsEx(FALSE, &Threads)) // Размораживаем потоки.
						{
							Status = HookStatusThreadsError;
						}
						else if (Status == HookStatusSuccess)
						{
							HookInfo->IsHooked = TRUE;

							HookInfo->Type = HookTypeSplice;

							if (Bridge) 
								*Bridge = HookInfo;
						}
					}
				}
				ThreadsFree(&Threads);
			}
		}
		if (Status != HookStatusSuccess)
		{
			FreeHookBuffer(HookInfo);
		}
	}
	LeaveCritSection();

	return Status;
}

/*
*/
PVOID HookSplice(_In_ PVOID Address, _In_ PVOID NewAddress)
{
	if (!Address || !NewAddress)
		return NULL;

	PHookInfo Bridge = NULL;

	THookStatus Status = HookSpliceEx(Address, NewAddress, &Bridge);

	if (Status == HookStatusSuccess)
		return Bridge->BridgeCode;
	else
	{
#ifdef _DEBUG
		HookLog("Status: %s\n", HookStatusToString(Status));
#endif
		return NULL;
	}
}

/*
*/
THookStatus UnhookSpliceEx(_In_ PVOID OriginalAddress)
{
	if (!OriginalAddress)
		return HookStatusError;

	if (!IsExecutableAddress(OriginalAddress))
		return HookStatusError;

	EnterCritSection();

	THookStatus Status = HookStatusSuccess;

	PMemoryBuffer Buffer = NULL;

	//PHookInfo HookInfo = (PHookInfo)((PBYTE)OriginalAddress - offsetof(THookInfo, BridgeCode));

	PHookInfo HookInfo = GetHookInfo(GetImportedAddress(OriginalAddress), &Buffer);

	if (!HookInfo || !Buffer || HookInfo->Type != HookTypeSplice)
	{
		Status = HookStatusNotFound;
	}
	else if (Status == HookStatusSuccess)
	{
		TProcessThreads Threads = { 0 };

		if (!EnumProcessThreads(GetCurrentProcessId(), &Threads))
		{
			Status = HookStatusThreadsError;
		}
		if (Status == HookStatusSuccess)
		{
			if (!SuspendResumeThreadsEx(TRUE, &Threads))
			{
				Status = HookStatusThreadsError;
			}
			else if (Status == HookStatusSuccess)
			{
				DWORD OldProtect = 0;

				if (!VirtualProtect(HookInfo->OriginalAddress, HookInfo->OriginalSize, PAGE_EXECUTE_READWRITE, &OldProtect))
				{
					Status = HookStatusMemoryError;
				}
				else if (Status == HookStatusSuccess)
				{
					memcpy(HookInfo->OriginalAddress, HookInfo->OriginalCode, HookInfo->OriginalSize);

					VirtualProtect(HookInfo->OriginalAddress, HookInfo->OriginalSize, OldProtect, &OldProtect);

					FlushInstructionCache(GetCurrentProcess(), HookInfo->OriginalAddress, HookInfo->OriginalSize);
				}
				if (!SuspendResumeThreadsEx(FALSE, &Threads))
				{
					Status = HookStatusThreadsError;
				}
			}
			ThreadsFree(&Threads);
		}
		if (!FreeBuffer(Buffer))
		{
			Status = HookStatusMemoryError;
		}
	}
	LeaveCritSection();

	return Status;
}

/*
*/
BOOLEAN UnhookSplice(_In_ PVOID OriginalAddress)
{
	if (!OriginalAddress)
		return FALSE;

	THookStatus Status = UnhookSpliceEx(OriginalAddress);

	if (Status == HookStatusSuccess)
		return TRUE;
	else
	{
#ifdef _DEBUG
		HookLog("Status: %s\n", HookStatusToString(Status));
#endif
		return FALSE;
	}
}

/*
*/
static BOOLEAN IsHotpatch(_In_ PVOID Address, _In_ PVOID HookAddress)
{
	if (JumpWalk(Address, 2) == HookAddress)
		return TRUE;

	if (JumpWalk((PBYTE)Address - sizeof(TJumpShort), 2) == HookAddress)
		return TRUE;

	return FALSE;
}

/*
*/
static BOOLEAN IsHotpatchSupport(_In_ PVOID Address, _In_ BYTE NeedSize)
{
	if (!Address) return FALSE;

	PBYTE pCode = (PBYTE)Address;

#ifdef _M_IX86
	if (*(PWORD)pCode != 0xff8b) // mov edi, edi
		return FALSE;
#endif

	pCode -= NeedSize;

	for (BYTE i = 0; i < NeedSize; i++)
	{
		if (pCode[i] != 0xCC && pCode[i] != 0x90 && pCode[i] != 0x00) // int 3, nop
			return FALSE;
	}
	return TRUE;
}

/*
	Только для x32
*/
static PVOID Hotpatch32(_In_ PVOID Address, _In_ PVOID NewAddress)
{
#ifdef _M_IX86
	if (!Address || !NewAddress)
		return NULL;

	if (IsHotpatch(Address, NewAddress))
		return NULL;

	if (IsHotpatchSupport(Address, MIN_HOTPATCH_SIZE))
	{
		PBYTE Patch = (PBYTE)Address - sizeof(TJumpRel);

		DWORD OldProtect = 0;

		if (VirtualProtect(Patch, sizeof(TJumpRel), PAGE_EXECUTE_READWRITE, &OldProtect))
		{
			WriteJump(Address, Patch, JUMP_SHORT);

			WriteJump(Patch, NewAddress, JUMP_REL);

			VirtualProtect(Patch, sizeof(TJumpRel), OldProtect, &OldProtect);

			FlushInstructionCache(GetCurrentProcess(), Address, sizeof(TJumpRel));

			return (PVOID)((SIZE_T)Address + sizeof(TJumpShort));
		}
	}
#endif
	return NULL;
}

/*
*/
static BOOLEAN RemoveHotpatch32(_In_ PVOID Address, _In_ PVOID HookAddress)
{
#ifdef _M_IX86
	if (IsHotpatch(Address, HookAddress))
	{
		DWORD OldProtect = 0;

		BYTE NeedSize = MAX_HOTPATCH_SIZE;

		PBYTE OriginAddress = (PBYTE)Address;

		OriginAddress -= sizeof(TJumpShort);

		PBYTE Patch = (PBYTE)Address - NeedSize;

		if (VirtualProtect(Patch, NeedSize, PAGE_EXECUTE_READWRITE, &OldProtect))
		{
			*(PWORD)OriginAddress = 0xff8b;

			memset(Patch, INT3, NeedSize - sizeof(TJumpShort));

			VirtualProtect(Patch, NeedSize, OldProtect, &OldProtect);

			FlushInstructionCache(GetCurrentProcess(), OriginAddress, sizeof(TJumpShort));

			return IsHotpatchSupport(OriginAddress, MIN_HOTPATCH_SIZE);
		}
	}
#endif
	return FALSE;
}

/*
*/
static BOOLEAN ReplaceHotpatch(_In_ PVOID OldAddress, _In_ PVOID NewAddress)
{
	if (!OldAddress || !NewAddress)
		return FALSE;

	PHookInfo HookInfo = GetHookInfo(OldAddress, NULL);

	if (HookInfo && HookInfo->Type == HookTypeHotpatch)
	{
		if (IsHotpatch(HookInfo->OriginalAddress, HookInfo->HookAddress))
		{
			PBYTE PatchAddress = ((PBYTE)HookInfo->OriginalAddress - MIN_HOTPATCH_SIZE);

			DWORD OldProtect = 0;

			if (VirtualProtect(PatchAddress, MIN_HOTPATCH_SIZE, PAGE_EXECUTE_READWRITE, &OldProtect))
			{
#ifdef _M_X64
				((PJumpAbs)PatchAddress)->Address = NewAddress;
#elif _M_IX86
				((PJumpRel)PatchAddress)->Address = GetJmpRelAddress(PatchAddress, NewAddress, sizeof(TJumpRel));
#endif
				VirtualProtect(PatchAddress, MIN_HOTPATCH_SIZE, OldProtect, &OldProtect);

				HookInfo->HookAddress = NewAddress;

				return TRUE;
			}
		}
	}
	return FALSE;
}

/*
*/
static THookStatus HookHotpatchEx(_In_ PVOID Address, _In_ PVOID NewAddress, _Out_opt_ PHookInfo* Bridge)
{
	if (!Address || !NewAddress | !Bridge)
		return HookStatusError;

	if (!IsExecutableAddress(Address))
		return HookStatusError;

	if (IsHookedProc(Address))
		return HookStatusIsHooked;

	if (!IsHotpatchSupport(Address, MIN_HOTPATCH_SIZE))
		return HookStatusNotSupport;

	EnterCritSection();

	PHookInfo HookInfo = NULL;

	THookStatus Status = CreateHookBridge(Address, NewAddress, sizeof(TJumpShort), &HookInfo);

	if (Status == HookStatusSuccess)
	{
		DWORD OldProtect = 0;

		PBYTE PatchAddress = (PBYTE)HookInfo->OriginalAddress - MIN_HOTPATCH_SIZE;

		if (!VirtualProtect(PatchAddress, MAX_HOTPATCH_SIZE, PAGE_EXECUTE_READWRITE, &OldProtect))
		{
			Status = HookStatusMemoryError;
		}
		else if (Status == HookStatusSuccess)
		{
			TProcessThreads Threads = { 0 };

			if (!EnumProcessThreads(GetCurrentProcessId(), &Threads))
			{
				Status = HookStatusThreadsError;
			}
		    else if (Status == HookStatusSuccess)
			{
				SuspendResumeThreadsEx(TRUE, &Threads);

				memset(HookInfo->OriginalAddress, NOP, HookInfo->OriginalSize);

				WriteJump(HookInfo->OriginalAddress, PatchAddress, JUMP_SHORT);
#ifdef _M_X64
				WriteJump(PatchAddress, HookInfo->HookAddress, JUMP_ABS); // JUMP_REL
#elif _M_IX86
				WriteJump(PatchAddress, HookInfo->HookAddress, JUMP_REL);
#endif
				VirtualProtect(PatchAddress, MAX_HOTPATCH_SIZE, OldProtect, &OldProtect);

				FlushInstructionCache(GetCurrentProcess(), HookInfo->OriginalAddress, HookInfo->OriginalSize);

				FlushInstructionCache(GetCurrentProcess(), HookInfo->HookAddress, HookInfo->BridgeSize);

				SuspendResumeThreadsEx(FALSE, &Threads);

				if (Bridge) *Bridge = HookInfo;

				HookInfo->IsHooked = TRUE;

				HookInfo->Type = HookTypeHotpatch;

				ThreadsFree(&Threads);
			}
		}
		if (Status != HookStatusSuccess)
		{
			FreeHookBuffer(HookInfo);
		}
	}
	LeaveCritSection();

	return Status;
}

/*
*/
PVOID HookHotpatch(_In_ PVOID Address, _In_ PVOID NewAddress)
{
	if (!Address || !NewAddress)
		return NULL;

	PHookInfo Bridge = NULL;

	THookStatus Status = HookHotpatchEx(Address, NewAddress, &Bridge);

	if (Status == HookStatusSuccess)
		return Bridge->BridgeCode;
	else
	{
#ifdef _DEBUG
		HookLog("Status: %s\n", HookStatusToString(Status));
#endif
		return NULL;
	}
}

/*
*/
THookStatus UnhookHotpatchEx(_In_ PVOID OriginalAddress)
{
	if (!OriginalAddress)
		return HookStatusError;

	THookStatus Status = HookStatusSuccess;

	if (!IsExecutableAddress(OriginalAddress))
		return HookStatusError;

	EnterCritSection();

	PMemoryBuffer Buffer = NULL;

	PHookInfo HookInfo = GetHookInfo(GetImportedAddress(OriginalAddress), &Buffer);

	if (!HookInfo || !Buffer || HookInfo->Type != HookTypeHotpatch)
	{
		Status = HookStatusNotFound;
	}
	else if (Status == HookStatusSuccess)
	{
		PBYTE PatchAddress = (PBYTE)HookInfo->OriginalAddress - MIN_HOTPATCH_SIZE;

		DWORD OldProtect = 0;

		if (!VirtualProtect(PatchAddress, MAX_HOTPATCH_SIZE, PAGE_EXECUTE_READWRITE, &OldProtect))
		{
			Status = HookStatusMemoryError;
		}
		else if (Status == HookStatusSuccess)
		{
			TProcessThreads Threads = { 0 };

			if (!EnumProcessThreads(GetCurrentProcessId(), &Threads))
			{
				Status = HookStatusThreadsError;
			}
			else if (Status == HookStatusSuccess)
			{
				SuspendResumeThreadsEx(TRUE, &Threads);

				memcpy_s(HookInfo->OriginalAddress, HookInfo->OriginalSize, HookInfo->OriginalCode, HookInfo->OriginalSize);

				memset(PatchAddress, INT3, MIN_HOTPATCH_SIZE);

				VirtualProtect(PatchAddress, MAX_HOTPATCH_SIZE, OldProtect, &OldProtect);

				FlushInstructionCache(GetCurrentProcess(), HookInfo->OriginalAddress, HookInfo->OriginalSize);

				SuspendResumeThreadsEx(FALSE, &Threads);

				ThreadsFree(&Threads);
			}
		}
		if (!FreeBuffer(Buffer))
		{
			Status = HookStatusMemoryError;
		}
	}
	LeaveCritSection();

	return Status;
}

/*
*/
BOOLEAN UnhookHotpatch(_In_ PVOID OriginalAddress)
{
	if (!OriginalAddress) return FALSE;

	THookStatus Status = UnhookHotpatchEx(OriginalAddress);

	if (Status == HookStatusSuccess)
		return TRUE;
	else
	{
#ifdef _DEBUG
		HookLog("Status: %s\n", HookStatusToString(Status));
#endif
		return FALSE;
	}
}

/*
*/
THookStatus HookProcEx(_In_ PVOID Address, _In_ PVOID NewAddress, _Out_ PHookInfo* Bridge)
{
	if (!Address || !NewAddress || !Bridge)
		return HookStatusError;

	THookStatus Status = HookHotpatchEx(Address, NewAddress, Bridge);

	if (Status != HookStatusSuccess)
		Status = HookSpliceEx(Address, NewAddress, Bridge);

	return Status;
}

/*
*/
PVOID HookProc(_In_ PVOID Address, _In_ PVOID NewAddress)
{
	if (!Address || !NewAddress)
		return NULL;

	PHookInfo Bridge = NULL;

	THookStatus Status = HookProcEx(Address, NewAddress, &Bridge);

	if (Status == HookStatusSuccess)
		return Bridge->BridgeCode;
	else
	{
#ifdef _DEBUG
		HookLog("Status: %s\n", HookStatusToString(Status));
#endif
		return NULL;
	}
}

/*
*/
THookStatus UnhookProcEx(_In_ PVOID OriginalAddress)
{
	if (!OriginalAddress)
		return HookStatusError;

	PHookInfo HookInfo = GetHookInfo(OriginalAddress, NULL);

	if (!HookInfo)
		return HookStatusNotFound;

	if (HookInfo->Type == HookTypeSplice)
	{
		return UnhookSpliceEx(HookInfo->OriginalAddress);
	}
	else if (HookInfo->Type == HookTypeHotpatch)
	{
		return UnhookHotpatchEx(HookInfo->OriginalAddress);
	}
	return HookStatusError;
}

/*
*/
BOOLEAN UnhookProc(_In_ PVOID OriginalAddress)
{
	if (!OriginalAddress)
		return FALSE;

	THookStatus Status = UnhookProcEx(OriginalAddress);

	if (Status == HookStatusSuccess)
		return TRUE;
	else
	{
#ifdef _DEBUG
		HookLog("Status: %s\n", HookStatusToString(Status));
#endif
		return FALSE;
	}
}

/*
*/
BOOLEAN UnhookAllProc()
{
	PMemoryBlock Block = g_MemoryFirstBlock;

	while (Block)
	{
		PMemoryBlock NextBlock = Block->Next;

		SIZE_T CountHooks = Block->UsedBuffers;

		for (SIZE_T Count = 0; Count < Block->MaxBuffers; Count++)
		{
			PHookInfo HookInfo = &Block->Buffers[Count].Data;

			if (!HookInfo->IsHooked)
				continue;

			if (UnhookProc(HookInfo->OriginalAddress))
			{
				CountHooks--;

				if (!CountHooks) break;
			}
		}
		Block = NextBlock;
	}
	return TRUE;
}

/*
*/
PVOID HookImportEx(_In_ LPCSTR DllName, _In_ PVOID ProcAddress, _In_ PVOID NewAddress, _In_ BOOLEAN ImportByName)
{
	if (!DllName || !NewAddress)
		return NULL;

	PVOID ModuleHandle = GetModuleHandleW(NULL);

	PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)GetImageDirectoryEntry(ModuleHandle, IMAGE_DIRECTORY_ENTRY_IMPORT, NULL);

	if (ImportDescriptor)
	{
		while (ImportDescriptor->FirstThunk)
		{
			LPSTR ModuleName = (LPSTR)(ImportDescriptor->Name + (SIZE_T)ModuleHandle);

			if (CompareModulesA(DllName, ModuleName))
			{
				PIMAGE_THUNK_DATA OriginalFirstThunk = NULL, FirstThunk = NULL;

				FirstThunk = (PIMAGE_THUNK_DATA)(ImportDescriptor->FirstThunk + (SIZE_T)ModuleHandle);

				OriginalFirstThunk = (PIMAGE_THUNK_DATA)(ImportDescriptor->OriginalFirstThunk + (SIZE_T)ModuleHandle);

				while (OriginalFirstThunk->u1.AddressOfData)
				{
					SIZE_T Function = 0;

					SIZE_T Ordinal = OriginalFirstThunk->u1.Ordinal;

					if (FirstThunk->u1.Function == (SIZE_T)ProcAddress) // Поиск по адресу
					{
						Function = FirstThunk->u1.Function;
					}
					else if (IMAGE_SNAP_BY_ORDINAL(Ordinal)) // ординалу
					{
						if (IMAGE_ORDINAL(Ordinal) == IMAGE_ORDINAL((SIZE_T)ProcAddress))
						{
							Function = FirstThunk->u1.Function;
						}
					}
					else if (ImportByName) // имени.
					{
						PIMAGE_IMPORT_BY_NAME ImportedName = (PIMAGE_IMPORT_BY_NAME)(OriginalFirstThunk->u1.AddressOfData + (SIZE_T)ModuleHandle);

						if (strcmp((LPSTR)ProcAddress, ImportedName->Name) == 0)
						{
							Function = FirstThunk->u1.Function;
						}
					}
					if (Function)
					{
						if (Function == (SIZE_T)NewAddress) // Если повторный перехват.
							return FALSE;

						DWORD OldProtect = 0;

						if (VirtualProtect(FirstThunk, sizeof(FirstThunk), PAGE_READWRITE, &OldProtect))
						{
							SIZE_T OldAddress = Function; // Оригинальный адрес.

							FirstThunk->u1.Function = (SIZE_T)NewAddress; // Патчим импорт.

							VirtualProtect(FirstThunk, sizeof(FirstThunk), OldProtect, &OldProtect);

							return (PVOID)OldAddress;
						}
						return NULL;
					}
					FirstThunk++; 
					
					OriginalFirstThunk++;
				}
			}
			ImportDescriptor++;
		}
	}
	return NULL;
}

/*
*/
PVOID HookImportA(_In_ LPCSTR DllName, _In_ LPCSTR ProcedureName, _In_ PVOID NewAddress)
{
	return HookImportEx(DllName, (PVOID)ProcedureName, NewAddress, TRUE);
}

/*
*/
PVOID HookImportW(_In_ LPCWSTR DllName, _In_ LPCWSTR ProcedureName, _In_ PVOID NewAddress)
{
	LPSTR DllNameA = UnicodeToAnsi(DllName);

	LPSTR ProcedureNameA = UnicodeToAnsi(ProcedureName);

	PVOID Result = HookImportA(DllNameA, ProcedureNameA, NewAddress);

	FreeStringA(DllNameA);

	FreeStringA(ProcedureNameA);

	return Result;
}

/*
*/
BOOLEAN UnhookImportA(_In_ LPCSTR DllName, _In_ LPCSTR ProcedureName)
{
	if (!DllName || !ProcedureName)
		return FALSE;

	HMODULE DllHandle = GetModuleHandleA(DllName);

	if (DllHandle)
	{
		PVOID ProcAddress = GetProcAddress(DllHandle, ProcedureName);

		if (ProcAddress)
			return HookImportA(DllName, ProcedureName, ProcAddress) > 0;
	}
	return FALSE;
}

/*
*/
BOOLEAN UnhookImportW(_In_ LPCWSTR DllName, _In_ LPCWSTR ProcedureName)
{
	LPSTR DllNameA = UnicodeToAnsi(DllName);

	LPSTR ProcedureNameA = UnicodeToAnsi(ProcedureName);

	BOOLEAN Result = UnhookImportA(DllNameA, ProcedureNameA);

	FreeStringA(DllNameA);

	FreeStringA(ProcedureNameA);

	return Result;
}

/*
static PVOID FindEATFunction(_In_ PVOID ModuleHandle, _In_ LPCSTR ProcedureName, _Out_opt_ PDWORD *ForPatch)
{
	if (!ProcedureName) return NULL;

	PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)GetImageDirectoryEntry(ModuleHandle, IMAGE_DIRECTORY_ENTRY_EXPORT, NULL);

	if (ExportDirectory)
	{
		PDWORD AddressOfNames = (PDWORD)((SIZE_T)ModuleHandle + ExportDirectory->AddressOfNames);

		for (DWORD IndexName = 0; IndexName < ExportDirectory->NumberOfNames; IndexName++)
		{
			LPSTR ExportName = (LPSTR)((SIZE_T)ModuleHandle + AddressOfNames[IndexName]);

			if (strcmp(ProcedureName, ExportName) == 0)
			{
				PWORD AddressOfNameOrdinals = (PWORD)((SIZE_T)ModuleHandle + ExportDirectory->AddressOfNameOrdinals);

				PDWORD AddressOfFunctions = (PDWORD)((SIZE_T)ModuleHandle + ExportDirectory->AddressOfFunctions);

				DWORD FunctionIndex = AddressOfNameOrdinals[IndexName];

				PDWORD RelativeOffset = &AddressOfFunctions[FunctionIndex];

				DWORD ProcedureOffset = *RelativeOffset;

				if (!ProcedureOffset) return NULL;

				PVOID ProcedureAddress = (PVOID)(ProcedureOffset + (SIZE_T)ModuleHandle);

				if (ForPatch)
					*ForPatch = RelativeOffset;

				return ProcedureAddress;
			}
		}
	}
	return NULL;
}
*/

/*
*/
#ifdef _M_X64
static PHookInfo CreateEATBuffer(_In_ PVOID Origin)
{
	PMemoryBlock Block = GetNextBlock(Origin, TWO_GIGABYTES, MAX_BLOCK_SIZE, MAX_BUFFER_SIZE);

	if (Block)
	{
		PMemoryBuffer Buffer = GetFreeBuffer(Block, NULL);

		if (Buffer)
		{
			Buffer->Used = TRUE;

			Block->UsedBuffers++;

			return &Buffer->Data;
		}
		FreeHookBuffer(Buffer);
	}
	return NULL;
}
#endif

/*
*/
PVOID HookExportA(_In_opt_ LPCSTR ModuleName, _In_ LPCSTR ProcedureName, _In_opt_ PVOID NewAddress)
{
	if (!IsSameHook(NewAddress)) // Защита от повторного перехвата.
	{
		PVOID ModuleHandle = GetModuleHandleA(ModuleName);

		if (ModuleHandle)
		{
			DWORD SizeOfExport = 0;

			PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)GetImageDirectoryEntry(ModuleHandle, IMAGE_DIRECTORY_ENTRY_EXPORT, &SizeOfExport);

			if (ExportDirectory && SizeOfExport)
			{
				LONG FunctionIndex = -1;

				if (((SIZE_T)ProcedureName & 0xffff0000) == 0) // Поиск по ординалу
				{
					DWORD Ordinal = LOWORD(ProcedureName);

					if ((Ordinal < ExportDirectory->Base) || (Ordinal >= (ExportDirectory->Base + ExportDirectory->NumberOfFunctions))) // Если ординал меньше базого значения или больше количества экспортируемых функций.
						return NULL;
					else
						FunctionIndex = (Ordinal - ExportDirectory->Base);
				}
				else // По имени.
				{
					PDWORD AddressOfNames = (PDWORD)((SIZE_T)ModuleHandle + ExportDirectory->AddressOfNames);

					PWORD AddressOfNameOrdinals = (PWORD)((SIZE_T)ModuleHandle + ExportDirectory->AddressOfNameOrdinals);

					for (DWORD IndexName = 0; IndexName < ExportDirectory->NumberOfNames; IndexName++)
					{
						LPSTR ExportName = (LPSTR)((SIZE_T)ModuleHandle + AddressOfNames[IndexName]);

						if (strcmp(ProcedureName, ExportName) == 0) // _strcmpi
						{
							FunctionIndex = AddressOfNameOrdinals[IndexName];

							break;
						}
					}
				}
				if (FunctionIndex >= 0)
				{
					PDWORD AddressOfFunctions = (PDWORD)((SIZE_T)ModuleHandle + ExportDirectory->AddressOfFunctions);

					PDWORD pRelativeOffset = &AddressOfFunctions[FunctionIndex]; //

					DWORD ProcedureOffset = *pRelativeOffset; // Смещение оригинальной функции.

					if (!ProcedureOffset)
						return NULL;

					DWORD DeltaOffset = (DWORD)((SIZE_T)NewAddress - (SIZE_T)ModuleHandle); // Смещение к перехватчику.

					PVOID ProcedureAddress = (PVOID)(ProcedureOffset + (SIZE_T)ModuleHandle); // Оригинальный адрес функции..
#ifdef _M_X64
					PHookInfo HookInfo = GetHookInfo(ProcedureAddress, NULL); // Если функция уже перехвачена

					if (HookInfo && HookInfo->IsHooked)
					{
						ProcedureAddress = HookInfo->OriginalAddress; // то вернём оригинальный адрес.
						//ProcedureAddress = (PVOID)(DeltaOffset + (SIZE_T)ModuleHandle); 
					}
#endif
					if (((SIZE_T)ProcedureAddress >= (SIZE_T)ExportDirectory) &&
						((SIZE_T)ProcedureAddress < (SIZE_T)(ExportDirectory + SizeOfExport))) // Forwarded export.
					{
						CHAR ForwardName[_MAX_FNAME] = { 0 };

						strcpy_s(ForwardName, _countof(ForwardName), (LPSTR)ProcedureAddress);

						LPSTR pProcName = strchr(ForwardName, '.');

						*pProcName++ = '\0';

						if (*pProcName == '#')
						{
							*pProcName++ = '\0';

							pProcName = (PCHAR)(WORD)atoi(pProcName);
						}
						return HookExportA(ForwardName, pProcName, NewAddress);
					}

					if (!NewAddress)
						return ProcedureAddress;
#ifdef _M_X64
					// Из-за специфики экспорта адрес переходника должен быть всегда больше, чем адрес библиотеки, но не более +2гб.
					if (IsGreaterThan2Gb(ModuleHandle, NewAddress))
					{
						PHookInfo ExportBridge = CreateEATBuffer(ModuleHandle);

						if (!ExportBridge) return NULL;

						ExportBridge->IsHooked = TRUE;

						ExportBridge->BridgeSize = sizeof(TJumpAbs);

						ExportBridge->OriginalAddress = ProcedureAddress;

						ExportBridge->HookAddress = NewAddress;

						ExportBridge->Type = HookTypeExport;

						WriteJump(ExportBridge->BridgeCode, NewAddress, JUMP_ABS); // Прыжок в переходник.

						DeltaOffset = (DWORD)((SIZE_T)ExportBridge->BridgeCode - (SIZE_T)ModuleHandle);

						if (DeltaOffset > TWO_GIGABYTES)
						{
							FreeHookBuffer(ExportBridge);

							return NULL;
						}
					}
#endif
					DWORD OldProtect = 0;

					if (VirtualProtect((PVOID)pRelativeOffset, sizeof(DWORD), PAGE_READWRITE, &OldProtect))
					{
						*(PDWORD)pRelativeOffset = DeltaOffset; // Патчим экспорт.

						VirtualProtect(pRelativeOffset, sizeof(DWORD), OldProtect, &OldProtect);

						return ProcedureAddress;
					}
				}
			}
		}
	}
	return NULL;
}

/*
*/
PVOID HookExportW(_In_opt_ LPCWSTR ModuleName, _In_ LPCWSTR ProcedureName, _In_opt_ PVOID NewAddress)
{
	LPSTR ModuleNameA = UnicodeToAnsi(ModuleName);

	LPSTR ProcedureNameA = UnicodeToAnsi(ProcedureName);

	PVOID Result = HookExportA(ModuleNameA, ProcedureNameA, NewAddress);

	FreeStringA(ModuleNameA);

	FreeStringA(ProcedureNameA);

	return Result;
}

/*
*/
BOOLEAN UnhookExportA(_In_opt_ LPCSTR ModuleName, _In_ LPCSTR ProcedureName, _In_ PVOID OriginalAddress)
{
	if (!OriginalAddress) return FALSE;
#ifdef _M_X64
	PMemoryBuffer Buffer = NULL;

	PHookInfo HookInfo = GetHookInfo(OriginalAddress, &Buffer);

	if (HookInfo->Type == HookTypeExport)
	{	
		if (HookExportA(ModuleName, ProcedureName, HookInfo->OriginalAddress))
			return FreeBuffer(Buffer);
	}
	return FALSE;
#elif _M_IX86
	return HookExportA(ModuleName, ProcedureName, OriginalAddress) > 0;
#endif
}

/*
*/
BOOLEAN UnhookExportW(_In_ LPCWSTR ModuleName, _In_ LPCWSTR ProcedureName, _In_ PVOID OriginalAddress)
{
	LPSTR ModuleNameA = UnicodeToAnsi(ModuleName);

	LPSTR ProcedureNameA = UnicodeToAnsi(ProcedureName);

	BOOLEAN Result = UnhookExportA(ModuleNameA, ProcedureNameA, OriginalAddress);

	FreeStringA(ModuleNameA);

	FreeStringA(ProcedureNameA);

	return Result;
}

/*
*/
static PVOID FindEATFunction(_In_opt_ LPCSTR ModuleName, _In_ LPCSTR ProcedureName)
{
	if (ModuleName)
		return HookExportA(ModuleName, ProcedureName, NULL);
	else
		return NULL;
}

/*
*/
PVOID HookWinApiA(_In_ LPCSTR DllName, _In_ LPCSTR ProcedureName, _In_ PVOID NewAddress)
{
	if (!DllName || !ProcedureName || !NewAddress)
		return NULL;

	HMODULE ModuleHandle = GetModuleHandleA(DllName);

	if (ModuleHandle)
	{
		PVOID ProcAddress = GetProcAddress(ModuleHandle, ProcedureName);

		if (ProcAddress)
			return HookProc(ProcAddress, NewAddress);
	}
	return NULL;
}

/*
*/
PVOID HookWinApiW(_In_ LPCWSTR DllName, _In_ LPCWSTR ProcedureName, _In_ PVOID NewAddress)
{
	LPSTR DllNameA = UnicodeToAnsi(DllName);

	LPSTR ProcedureNameA = UnicodeToAnsi(ProcedureName);

	PVOID Result = HookWinApiA(DllNameA, ProcedureNameA, NewAddress);

	FreeStringA(DllNameA);

	FreeStringA(ProcedureNameA);

	return Result;
}

/*
*/
BOOLEAN UnhookWinApiA(_In_ LPCSTR DllName, _In_ LPCSTR ProcedureName)
{
	if (!DllName || !ProcedureName)
		return FALSE;

	HMODULE ModuleHandle = GetModuleHandleA(DllName);

	if (ModuleHandle)
	{
		PVOID ProcAddress = GetProcAddress(ModuleHandle, ProcedureName);

		if (ProcAddress)
			return UnhookProc(ProcAddress);
	}
	return FALSE;
}

/*
*/
BOOLEAN UnhookWinApiW(_In_ LPCWSTR DllName, _In_ LPCWSTR ProcedureName)
{
	LPSTR DllNameA = UnicodeToAnsi(DllName);

	LPSTR ProcedureNameA = UnicodeToAnsi(ProcedureName);

	BOOLEAN Result = UnhookWinApiA(DllNameA, ProcedureNameA);

	FreeStringA(DllNameA);

	FreeStringA(ProcedureNameA);

	return Result;
}

/*
*/
static void SetBits(PSIZE_T Base, int LowBit, int Bits, int NewValue)
{
	int Mask = (1 << Bits) - 1;
	*Base = (*Base & ~(Mask << LowBit)) | ((SIZE_T)NewValue << LowBit);
}

/*
*/
static int GetTriggeredDebugRegister(_In_ PCONTEXT Context)
{
	if (!Context) return -1;

	for (int RegIndex = 0; RegIndex < 4; RegIndex++)
	{
		if (Context->Dr6 & ((SIZE_T)1 << RegIndex))
			return RegIndex;
	}
	return -1;
}

/*
*/
static int GetFreeCountRegisters(_In_ PCONTEXT Context)
{
	int Result = -1;

	for (int RegIndex = 0; RegIndex < 4; RegIndex++)
	{
		if ((Context->Dr7 & ((SIZE_T)1 << (RegIndex * 2))) == 0)
			Result++;
	}
	return Result;
}

/*
*/
static int GetFreeDebugRegister(_In_ PCONTEXT Context)
{
	if (!Context) return -1;

	for (int RegIndex = 0; RegIndex < 4; RegIndex++)
	{
		if ((Context->Dr7 & ((SIZE_T)1 << (RegIndex * 2))) == 0)
			return RegIndex;
	}
	return -1;
}

/*
*/
static int GetDebugRegisterByAddress(_In_ PCONTEXT Context, _In_ PVOID Address)
{
	if (!Context || !Address)
		return -1;

	if (Context->Dr0 == (SIZE_T)Address)
		return 0;
	else if (Context->Dr1 == (SIZE_T)Address)
		return 1;
	else if (Context->Dr2 == (SIZE_T)Address)
		return 2;
	else if (Context->Dr3 == (SIZE_T)Address)
		return 3;

	return -1;
}

/*
*/
static PVOID GetAddressByDebugRegister(_In_ PCONTEXT Context, _In_ HBP_INDEX Index)
{
	if (!Context) return NULL;

	switch (Index)
	{
		case HBP_DR0: return (PVOID)Context->Dr0;
			break;
		case HBP_DR1: return (PVOID)Context->Dr1;
			break;
		case HBP_DR2: return (PVOID)Context->Dr2;
			break;
		case HBP_DR3: return (PVOID)Context->Dr3;
			break;
	}
	return NULL;
}

/*
*/
static int SetHardwareHookEx(_In_ HANDLE ThreadHandle, _In_ PVOID Address, _In_ HBP_INDEX Index, _In_ HBP_TYPE Type, _In_ HBP_SIZE Size)
{
	if (!Address || (Index > 3) || (Type > 3) || (Size > 3))
		return -1;

	CONTEXT Context = { 0 };

	Context.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if (GetThreadContext(ThreadHandle, &Context))
	{
		int NewIndex = Index;

		if (NewIndex == HBP_AUTO)
			NewIndex = GetFreeDebugRegister(&Context); // Получаем индекс свободного регистра.

		switch (NewIndex)
		{
			case HBP_DR0: Context.Dr0 = (SIZE_T)Address;
				break;
			case HBP_DR1: Context.Dr1 = (SIZE_T)Address;
				break;
			case HBP_DR2: Context.Dr2 = (SIZE_T)Address;
				break;
			case HBP_DR3: Context.Dr3 = (SIZE_T)Address;
				break;

			default:
				return -1;
		}

		SetBits(&Context.Dr7, 16 + (NewIndex * 4), 2, Type);  //
		SetBits(&Context.Dr7, 18 + (NewIndex * 4), 2, Size);  //
		SetBits(&Context.Dr7, NewIndex * 2, 1, 1); // Включаем отладочный регистр.

		if (SetThreadContext(ThreadHandle, &Context))
			return NewIndex;
	}
	return -1;
}

/*
*/
static BOOLEAN SetHardwareHook(_In_ DWORD ThreadID, _In_ PVOID Address, _Out_ PINT Index)
{
	if (!Address) return FALSE;

	HANDLE ThreadHandle = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, ThreadID);

	if (ThreadHandle)
	{
		BOOLEAN IsSuspended = FALSE;

		if (ThreadID != GetCurrentThreadId())
		{
			SuspendThread(ThreadHandle);

			IsSuspended = TRUE;
		}

		int RegIndex = SetHardwareHookEx(ThreadHandle, Address, HBP_AUTO, HBP_BREAK_ON_EXECUTION, HBP_BYTE);

		if (IsSuspended)
			ResumeThread(ThreadHandle);

		CloseHandle(ThreadHandle);

		if (Index) 
			*Index = RegIndex;

		if (RegIndex >= 0)
			return TRUE;
	}
	return FALSE;
}

/*
*/
static BOOLEAN RemoveHardwareHookEx(_In_ HANDLE ThreadHandle, _In_ PVOID Address)
{
	if (!Address) return FALSE;

	CONTEXT Context = { 0 };

	Context.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if (GetThreadContext(ThreadHandle, &Context))
	{
		int RegIndex = GetDebugRegisterByAddress(&Context, Address);

		if (RegIndex > 0 || RegIndex <= 3)
		{
			SetBits(&Context.Dr7, RegIndex * 2, 1, 0); // Выключаем

			if (SetThreadContext(ThreadHandle, &Context))
				return TRUE;
		}
	}
	return FALSE;
}

/*
*/
static BOOLEAN RemoveHardwareHook(_In_ DWORD ThreadID, _In_ PVOID Address)
{
	BOOLEAN Result = FALSE;

	HANDLE ThreadHandle = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, ThreadID);

	if (ThreadHandle)
	{
		Result = RemoveHardwareHookEx(ThreadHandle, Address);

		CloseHandle(ThreadHandle);
	}
	return Result;
}

/*
*/
static BOOLEAN SetThreadsHardwareHook(_In_ PVOID Address, _In_ BOOLEAN RemoveHooks)
{
	if (!Address) return FALSE;

	TProcessThreads Threads = { 0 };

	if (EnumProcessThreads(GetCurrentProcessId(), &Threads))
	{
		DWORD Count = 0;

		for (; Count < Threads.Count; Count++)
		{
			BOOLEAN Success = FALSE;

			DWORD ThreadID = Threads.ThreadsID[Count];

			if (RemoveHooks)
				Success = RemoveHardwareHook(ThreadID, Address);
			else
				Success = SetHardwareHook(ThreadID, Address, NULL);

			if (!Success) break;
		}
		MemFree(Threads.ThreadsID, 0);

		if (Count == Threads.Count)
			return TRUE;
	}
	return FALSE;
}

/*
*/
static BOOLEAN HookVEHInit(_In_ PVECTORED_EXCEPTION_HANDLER VEHandler)
{
	if (!VEHandler) return FALSE;

	if (!g_VectoredHandler)
	{
		g_VectoredHandler = AddVectoredExceptionHandler(CALL_FIRST, VEHandler);

		if (!g_VectoredHandler)
			return FALSE;
	}
	return TRUE;
}

/*
*/
static BOOLEAN RemoveVEH()
{
	if (RemoveVectoredExceptionHandler(g_VectoredHandler))
	{
		g_VectoredHandler = NULL;

		return TRUE;
	}
	return FALSE;
}

/*
*/
static PHookVEH GetHookVEHContext(_In_ PVOID Address, _Out_opt_ PDWORD Index)
{
	if (!Address) return NULL;

	for (DWORD Count = 0; Count < g_VEHList.Count; Count++)
	{
		PHookVEH Context = &g_VEHList.Ctx[Count];

		if (Context->OriginalAddress == Address || Context->HookAddress == Address || Context == Address)
		{
			if (Index)
				*Index = Count;

			return Context;
		}
	}
	return NULL;
}

/*
*/
BOOLEAN UpdateVEH(_In_ PVOID Address)
{
	if (!Address) return FALSE;

	PHookVEH Context = GetHookVEHContext(Address, NULL);

	if (Context)
	{
		if (!Context->IsHooked)
		{
			if (HookVEH(Context->OriginalAddress, Context->HookAddress, Context->Type))
				return TRUE;
		}
	}
	return FALSE;
}

/*
*/
static LONG CALLBACK HookVEHandler(PEXCEPTION_POINTERS Exception)
{
#ifdef _M_X64
	#define XIP Rip
#else
	#define XIP Eip
#endif
	// EXCEPTION_PRIV_INSTRUCTION, EXCEPTION_ACCESS_VIOLATION, EXCEPTION_BREAKPOINT, EXCEPTION_GUARD_PAGE, EXCEPTION_SINGLE_STEP
	DWORD ExceptionCode = Exception->ExceptionRecord->ExceptionCode;

	if (ExceptionCode == EXCEPTION_GUARD_PAGE)
	{
		for (DWORD Count = 0; Count < g_VEHList.Count; Count++)
		{
			if (g_VEHList.Ctx[Count].Type != HookGuardPage)
				continue;

			if (AreInSamePage((PVOID)Exception->ContextRecord->XIP, g_VEHList.Ctx[Count].OriginalAddress))
			{
				if (Exception->ContextRecord->XIP == (SIZE_T)g_VEHList.Ctx[Count].OriginalAddress)
				{
					g_VEHList.Ctx[Count].IsHooked = FALSE;

					Exception->ContextRecord->XIP = (SIZE_T)g_VEHList.Ctx[Count].HookAddress;
				}
			}
		}
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	else if (ExceptionCode == EXCEPTION_PRIV_INSTRUCTION)
	{
		for (DWORD Count = 0; Count < g_VEHList.Count; Count++)
		{
			if (g_VEHList.Ctx[Count].Type != HookPrivInstruction)
				continue;

			if (Exception->ContextRecord->XIP == (SIZE_T)g_VEHList.Ctx[Count].OriginalAddress)
			{
				DWORD OldProtect = 0;

				g_VEHList.Ctx[Count].IsHooked = FALSE;

				if (VirtualProtect(g_VEHList.Ctx[Count].OriginalAddress, sizeof(BYTE), PAGE_EXECUTE_READWRITE, &g_VEHList.Ctx[Count].OldProtect))
				{
					*g_VEHList.Ctx[Count].OriginalAddress = g_VEHList.Ctx[Count].StorageByte;

					Exception->ContextRecord->XIP = (SIZE_T)g_VEHList.Ctx[Count].HookAddress;

					VirtualProtect(g_VEHList.Ctx[Count].OriginalAddress, sizeof(BYTE), g_VEHList.Ctx[Count].OldProtect, &OldProtect);
				}
				return EXCEPTION_CONTINUE_EXECUTION;
			}
		}
	}
	else if (ExceptionCode == EXCEPTION_SINGLE_STEP)
	{
		for (DWORD Count = 0; Count < g_VEHList.Count; Count++)
		{
			if (g_VEHList.Ctx[Count].Type != HookHardwareBreakpoint)
				continue;

			if (Exception->ContextRecord->XIP == (SIZE_T)g_VEHList.Ctx[Count].OriginalAddress)
			{
				g_VEHList.Ctx[Count].IsHooked = FALSE;

				int RegIndex = GetTriggeredDebugRegister(Exception->ContextRecord);

				Exception->ContextRecord->Dr6 = 0;

				if (RegIndex >= 0)
				{
					SetBits(&Exception->ContextRecord->Dr7, RegIndex * 2, 1, 0);

					Exception->ContextRecord->XIP = (SIZE_T)g_VEHList.Ctx[Count].HookAddress;
				}
				return EXCEPTION_CONTINUE_EXECUTION;
			}
		}
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

/*
*/
static PHookVEH HookVectoredHandle(_In_ PVOID Address, _In_ PVOID NewAddress, _In_ TVEHType Type, _Inout_ PHookVEH Context)
{
	if (!Address || !NewAddress || !Context)
		return FALSE;

	if (HookVEHInit(&HookVEHandler))
	{
		Context->IsHooked = TRUE;

		Context->HookAddress = (PBYTE)NewAddress;

		Context->OriginalAddress = (PBYTE)Address;

		Context->Type = Type;

		DWORD OldProtect = 0;

		if (Context->Type == HookGuardPage)
		{
			MEMORY_BASIC_INFORMATION MemoryInformation = { 0 };

			if (VirtualQuery(Address, &MemoryInformation, sizeof(MemoryInformation)))
			{
				if (MemoryInformation.Protect & PAGE_NOACCESS)
					return NULL;

				if (!AreInSamePage(Address, NewAddress))
				{
					if (VirtualProtect(Address, sizeof(BYTE), PAGE_EXECUTE_READ | PAGE_GUARD, &Context->OldProtect))
						return Context;
				}
			}
		}
		else if (Context->Type == HookPrivInstruction)
		{
			if (VirtualProtect(Address, sizeof(BYTE), PAGE_EXECUTE_READWRITE, &Context->OldProtect))
			{
				Context->StorageByte = *(PBYTE)Address;

				*(PBYTE)Address = HLT; // Или INT3?

				VirtualProtect(Address, sizeof(BYTE), Context->OldProtect, &OldProtect);

				return Context;
			}
		}
		else if (Context->Type == HookHardwareBreakpoint)
		{
			INT RegIndex = -1;

			if (SetHardwareHook(GetCurrentThreadId(), Address, &RegIndex))
			{
				if (RegIndex >= 0)
				{
					//Context->StorageByte = RegIndex;

					return Context;
				}
			}
		}
	}
	return NULL;
}

/*
*/
PHookVEH HookVEH(_In_ PVOID Address, _In_ PVOID NewAddress, _In_ TVEHType Type)
{
	if (!Address || !NewAddress)
		return NULL;

	if (UnhookVEH(Address))
	{
		PHookVEH Context = (PHookVEH)MemReAlloc(g_VEHList.Ctx, ((SIZE_T)g_VEHList.Count + 1) * sizeof(THookVEH));

		if (Context)
		{
			g_VEHList.Ctx = Context; // Указатель на начало.

			Context = &g_VEHList.Ctx[g_VEHList.Count];

			g_VEHList.Count++;

			return HookVectoredHandle(Address, NewAddress, Type, Context);
		}
	}
	return NULL;
}

/*
*/
static BOOLEAN RemoveVEHEntry(_In_ DWORD Index)
{
	BOOLEAN Result = FALSE;

	if (g_VEHList.Count > Index)
	{
		Result = MemDeleteFromArray((PVOID*)&g_VEHList.Ctx, g_VEHList.Count - 1, Index, sizeof(THookVEH));

		g_VEHList.Count--;
	}
	return Result;
}

/*
*/
BOOLEAN UnhookVEH(_In_ PVOID Address)
{
	if (!Address) return FALSE;

	DWORD Index = -1;

	BOOLEAN Result = TRUE;

	PHookVEH Context = GetHookVEHContext(Address, &Index);

	if (Context)
	{
		DWORD OldProtect = 0;

		if (Context->Type == HookGuardPage)
		{
			//volatile BYTE GenerateExceptionRead = *Context->OriginalAddress; // Генерируем исключение, чтобы убрать флаг GUARD_PAGE 

			Result = VirtualProtect(Context->OriginalAddress, sizeof(BYTE), Context->OldProtect, &OldProtect);
		}
		else if (Context->Type == HookPrivInstruction)
		{
			if (VirtualProtect(Context->OriginalAddress, sizeof(BYTE), PAGE_EXECUTE_READWRITE, &OldProtect))
			{
				*Context->OriginalAddress = Context->StorageByte;

				Result = VirtualProtect(Context->OriginalAddress, sizeof(BYTE), OldProtect, &OldProtect);
			}
		}
		else if (Context->Type == HookHardwareBreakpoint)
		{
			Result = RemoveHardwareHook(GetCurrentThreadId(), Context->OriginalAddress);
		}
		Result = RemoveVEHEntry(Index);
	}
	return Result;
}

/*
*/
BOOLEAN FreeVEHHooks()
{
	for (int Count = g_VEHList.Count - 1; Count >= 0; Count--) // Освобождаем с конца.
	{
		PHookVEH Context = &g_VEHList.Ctx[Count];

		if (!UnhookVEH(Context->HookAddress))
			return FALSE;
	}
	return RemoveVEH();
}

/*
*/
PVOID GetVirtualAddress(_In_ PVOID VirtualTable, _In_ DWORD Index)
{
	if (!VirtualTable) return NULL;

	PVOID Method = ((PClassInstance)VirtualTable)->VFTable->Func[Index];

	if (IsExecutableAddress(Method))
		return Method;
	else
		return NULL;
}

/*
*/
PVOID PatchVFTable(_In_ PVOID VirtualTable, _In_ DWORD Index, _In_ PVOID NewMethod)
{
	if (!VirtualTable || !NewMethod)
		return NULL;

	PVOID Method = &((PClassInstance)VirtualTable)->VFTable->Func[Index]; // Смещение метода относительно начала таблицы.

	DWORD OldProtect = 0;

	if (VirtualProtect(Method, sizeof(Method), PAGE_READWRITE, &OldProtect))
	{
		PVOID Original = *(PVOID*)Method; // Адрес оригинального метода.

		*(PVOID*)Method = NewMethod; // Патчим таблицу.

		VirtualProtect(Method, sizeof(Method), OldProtect, &OldProtect);

		return Original;
	}
	return NULL;
}

/*
*/
PVOID HookVirtualMethod(_In_ PVOID VirtualTable, _In_ DWORD Index, _In_ PVOID NewMethod)
{
	if (!VirtualTable || !NewMethod)
		return NULL;

	PVOID Method = GetVirtualAddress(VirtualTable, Index);

	if (Method)
		return HookProc(Method, NewMethod);
	else
		return NULL;
}

/*
    Рекомендуется.
*/
PHookVEH HookVirtualMethodViaVEH(_In_ PVOID VirtualTable, _In_ DWORD Index, _In_ PVOID NewMethod)
{
	if (!VirtualTable || !NewMethod)
		return NULL;

	PVOID Method = GetVirtualAddress(VirtualTable, Index);

	if (Method)
		return HookVEH(Method, NewMethod, HookPrivInstruction);
	else
		return NULL;
}

/*
*/
BOOLEAN UnhookVirtualMethod(_In_ PVOID HookMethod)
{
	if (!HookMethod) return FALSE;

	BOOLEAN Result = UnhookProc(HookMethod);

	if (!Result)
		return UnhookVEH(HookMethod);
	else
		return Result;
}

/*
*/
BOOLEAN UpdateMethodViaVEH(_In_ PVOID HookMethod)
{
	if (HookMethod)
		return UpdateVEH(HookMethod);
	else
		return FALSE;
}

/*
*/
PVOID HookComInterface(_In_ IUnknown* Interface, _In_ DWORD Index, _In_ PVOID NewMethod)
{
	if (!Interface || !NewMethod) 
		return NULL;

	DWORD MethodIndex = Index + 3; // Пропускаем QueryInterface, AddRef, Release

	return HookVirtualMethod(Interface, MethodIndex, NewMethod);
}

/*
*/
BOOLEAN UnhookComInterface(_In_ PVOID HookMethod)
{
	if (!HookMethod) return FALSE;

	return UnhookVirtualMethod(HookMethod);
}

/*
*/
LPSTR HookStatusToString(_In_ THookStatus Status)
{
	switch (Status)
	{
	    case HookStatusError: return "Hook status error";
			break;
	    case HookStatusSuccess: return "Hook status success";
		    break;
		case HookStatusUnknown: return "Hook status unknown";
			break;
	    case HookStatusIsHooked: return "Hook status is hooked";
		    break;
		case HookStatusNotFound: return "Hook status not found";
			break;
		case HookStatusNotSupport: return "Hook status not support";
			break;
	    case HookStatusMemoryError: return "Hook status memory error";
		    break;
		case HookStatusThreadsError: return "Hook status threads error";
			break;
	    case HookStatusInstructionError: return "Hook status instruction error";
		    break;
		case HookStatusFixupThreadsError: return "Hook status fixup threads error";
			break;
		case HookStatusTooShortFunction: return "Hook status too short function";
			break;
	}
	return "";
}

/*
*/
void HookLog(_In_ LPCSTR Format, ...)
{
	va_list ArgList;

	va_start(ArgList, Format);

	SIZE_T NeedSize = _vsprintf_p(NULL, 0, Format, ArgList);

	if (NeedSize)
	{
		NeedSize++;

		PCHAR Buffer = (PCHAR)MemAlloc(NeedSize);

		if (Buffer)
		{
			_vsprintf_p(Buffer, NeedSize, Format, ArgList);

			//vprintf_s(Format, ArgList);

			OutputDebugStringA(Buffer);

			MemFree(Buffer, NeedSize);
		}
	}
	va_end(ArgList);
}