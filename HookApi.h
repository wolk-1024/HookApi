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

#pragma once

#include "LDASM\LengthDisasm.h"

#define JUMP_REL 0xE9
#define JUMP_SHORT 0xEB
#define JUMP_ABS 0x25FF
#define PUSH 0x68
#define RET 0xC3
#define NOP 0x90
#define INT3 0xCC
#define HLT 0xF4

#define PAGE_EXECUTE_FLAGS \
    (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)

#define HALF_GIGABYTE 0x20000000

#define ONE_GIGABYTE 0x40000000

#define TWO_GIGABYTES 0x80000000

#define MAX_HOOKS_PER_BLOCK 1024

#define MAX_BLOCK_SIZE 0x1000 * 8 // 32кб

#define MAX_MEMORY_RANGE TWO_GIGABYTES

#define MAX_HOOK_SIZE  MAX_INSTRUCTION_SIZE * 2

#define MAX_BRIDGE_SIZE MAX_HOOK_SIZE + sizeof(TJumpRel)

#define MAX_BUFFER_SIZE sizeof(TMemoryBuffer)

#ifdef _M_X64
#define MIN_HOTPATCH_SIZE sizeof(TJumpAbs)
#define MAX_HOTPATCH_SIZE MIN_HOTPATCH_SIZE + sizeof(TJumpShort)
#elif _M_IX86
#define MIN_HOTPATCH_SIZE sizeof(TJumpRel)
#define MAX_HOTPATCH_SIZE MIN_HOTPATCH_SIZE + sizeof(TJumpShort)
#endif

#ifdef _M_X64
#define MIN_HOOK_SIZE sizeof(TJumpAbs)
#elif _M_IX86
#define MIN_HOOK_SIZE sizeof(TJumpRel)
#endif

#ifdef _M_IX86
//#define GetClassMethod(Var, Method) { __asm push eax __asm mov eax, Method __asm mov Var, eax __asm pop eax}
#endif

#ifdef __cplusplus
/*
	Не будет работать с виртуальными методами!
*/
auto GetClassMethod = [](auto ClassMethod)
{
	auto Method = *&ClassMethod;

	return (void*&)Method;
};

auto UpdateMethodHook = [](auto ClassMethod)
{
	auto Address = GetClassMethod(ClassMethod);

	return UpdateMethodViaVEH(Address);
};

auto UnhookClassMethod = [](auto ClassMethod)
{
	auto Address = GetClassMethod(ClassMethod);

	return UnhookVirtualMethod(Address);
};
#endif

#define HookDebug(Message) \
{\
   HookLog("%s\n(%s)\n%s\n", __FUNCDNAME__, __FUNCTION__, Message); \
}

#pragma pack(push, 1) // Отрубаем выравнивание структур

typedef struct TJumpShort
{
	BYTE Opcode;
	BYTE Address;
} TJumpShort, *PJumpShort;

typedef struct TJumpRel
{
	BYTE Opcode;
	DWORD Address;
} TJumpRel, *PJumpRel;

typedef struct TJccRel
{
	BYTE Opcode;
	BYTE Cond;
	DWORD Address;
} TJccRel, * PJccRel;

typedef struct TJumpAbs
{
	WORD Opcode;
	DWORD Dummy;
	PVOID Address;
} TJumpAbs, *PJumpAbs;

#pragma pack(pop) // Включаем обратно.

typedef enum THookStatus
{
	HookStatusError = 0,
	HookStatusSuccess = 1,
	HookStatusUnknown = 2,
	HookStatusIsHooked = 3,
	HookStatusNotFound = 4,
	HookStatusNotSupport = 5,
	HookStatusMemoryError = 6,
	HookStatusThreadsError = 7,
	HookStatusInstructionError = 8,
	HookStatusTooShortFunction = 9,
	HookStatusFixupThreadsError = 10
} THookStatus;

typedef enum THookType
{
	HookTypeExport = 1,
	HookTypeImport = 2,
	HookTypeSplice = 3,
	HookTypeHotpatch = 4,
	HookTypeInterface = 5
} THookType;

typedef enum TVEHType
{
	HookGuardPage = 1, // Могут быть ошибки.
	HookPrivInstruction = 2, // Рекомендуется.
	HookHardwareBreakpoint = 3 // Не более четырёх перехватов.
} TVEHType;

typedef enum _HBP_SIZE
{
	HBP_BYTE = 0,
	HBP_WORD = 1,
	HBP_DWORD = 3,
#ifdef _WIN64
	HBP_QWORD = 2 // Нужно ли?
#endif
} HBP_SIZE;

typedef enum _HBP_INDEX
{
	HBP_AUTO = -1,
	HBP_DR0 = 0,
	HBP_DR1 = 1,
	HBP_DR2 = 2,
	HBP_DR3 = 3
}
HBP_INDEX;

typedef enum _HBP_TYPE
{
	HBP_BREAK_ON_EXECUTION = 0,
	HBP_BREAK_ON_WRITE = 1,
	HBP_BREAK_ON_READWRITE = 3
}
HBP_TYPE;

#define HBP_ERROR -1
#define HBP_NO_INDEX -2 // Нет свободных регистров.

#define CALL_FIRST 1 // Для AddVectoredExceptionHandler
#define CALL_LAST 0
#define EFLAGS_TF 0x100

typedef struct THookInfo
{
	BYTE BridgeCode[MAX_BRIDGE_SIZE]; // Релоцированный код.
	BYTE OriginalCode[MAX_HOOK_SIZE]; // Оригинальный.
	BYTE BridgeSize;
	BYTE OriginalSize;
	PVOID HookAddress;
	PVOID OriginalAddress;
	BOOLEAN IsHooked;
	THookType Type;
#ifdef _DEBUG
	PJumpRel Jmp;
	PVOID RetAddress;
#endif
} THookInfo, *PHookInfo;

typedef struct THookVEH
{
	BOOLEAN IsHooked;
	PBYTE OriginalAddress;
	PBYTE HookAddress;
	BYTE StorageByte;
	DWORD OldProtect;
	TVEHType Type;
} THookVEH, *PHookVEH;

typedef struct THookVEHList
{
	DWORD Count;
	PHookVEH Ctx;
} THookVEHList, *PHookVEHList;

typedef struct TMemoryBuffer
{
	BOOLEAN Used;
	THookInfo Data;
} TMemoryBuffer, *PMemoryBuffer;

typedef struct TMemoryBlock
{
	struct TMemoryBlock * Next;
	struct TMemoryBlock * Prev;
	SIZE_T BlockSize;
	SIZE_T MaxBuffers;
	SIZE_T UsedBuffers;
	PMemoryBuffer Buffers;
} TMemoryBlock, *PMemoryBlock;

typedef struct TProcessThreads
{
	DWORD Count;
	PDWORD ThreadsID;
} TProcessThreads, *PProcessThreads;

typedef struct TVFTable {
	PVOID Func[1];
} TVFTable, * PVFTable;

typedef struct TClassInstance {
	PVFTable VFTable;
} TClassInstance, * PClassInstance;

#ifdef __cplusplus
extern "C" {
#endif

	THookStatus HookSpliceEx(_In_ PVOID Address, _In_ PVOID NewAddress, _Out_ PHookInfo* Bridge);
	PVOID HookSplice(_In_ PVOID Address, _In_ PVOID NewAddress);

	THookStatus UnhookSpliceEx(_In_ PVOID OriginalAddress);
	BOOLEAN UnhookSplice(_In_ PVOID OriginalAddress);

	THookStatus HookHotpatchEx(_In_ PVOID Address, _In_ PVOID NewAddress, _Out_opt_ PHookInfo* Bridge);
	PVOID HookHotpatch(_In_ PVOID Address, _In_ PVOID NewAddress);

	THookStatus UnhookHotpatchEx(_In_ PVOID OriginalAddress);
	BOOLEAN UnhookHotpatch(_In_ PVOID OriginalAddress);

	THookStatus HookProcEx(_In_ PVOID Address, _In_ PVOID NewAddress, _Out_ PHookInfo* Bridge);
	PVOID HookProc(_In_ PVOID Address, _In_ PVOID NewAddress);

	THookStatus UnhookProcEx(_In_ PVOID OriginalAddress);
	BOOLEAN UnhookProc(_In_ PVOID OriginalAddress);

	BOOLEAN UnhookAllProc();

	PVOID GetBridgeAddress(_In_ PVOID Address);

	LPSTR HookStatusToString(_In_ THookStatus Status);

	PVOID HookImportEx(_In_ LPCSTR DllName, _In_ PVOID ProcAddress, _In_ PVOID NewAddress, _In_ BOOLEAN ImportByName);
	PVOID HookImportA(_In_ LPCSTR DllName, _In_ LPCSTR ProcedureName, _In_ PVOID NewAddress);
	PVOID HookImportW(_In_ LPCWSTR DllName, _In_ LPCWSTR ProcedureName, _In_ PVOID NewAddress);

	BOOLEAN UnhookImportA(_In_ LPCSTR DllName, _In_ LPCSTR ProcedureName);
	BOOLEAN UnhookImportW(_In_ LPCWSTR DllName, _In_ LPCWSTR ProcedureName);

	PVOID HookExportA(_In_opt_ LPCSTR ModuleName, _In_ LPCSTR ProcedureName, _In_opt_ PVOID NewAddress);
	PVOID HookExportW(_In_opt_ LPCWSTR ModuleName, _In_ LPCWSTR ProcedureName, _In_opt_ PVOID NewAddress);

	BOOLEAN UnhookExportA(_In_opt_ LPCSTR ModuleName, _In_ LPCSTR ProcedureName, _In_ PVOID OriginalAddress);
	BOOLEAN UnhookExportW(_In_opt_ LPCWSTR ModuleName, _In_ LPCWSTR ProcedureName, _In_ PVOID OriginalAddress);

	PVOID HookWinApiA(_In_ LPCSTR DllName, _In_ LPCSTR ProcedureName, _In_ PVOID NewAddress);
	PVOID HookWinApiW(_In_ LPCWSTR DllName, _In_ LPCWSTR ProcedureName, _In_ PVOID NewAddress);

	BOOLEAN UnhookWinApiA(_In_ LPCSTR DllName, _In_ LPCSTR ProcedureName);
	BOOLEAN UnhookWinApiW(_In_ LPCWSTR DllName, _In_ LPCWSTR ProcedureName);

	PHookVEH HookVEH(_In_ PVOID Address, _In_ PVOID NewAddress, _In_ TVEHType Type);
	BOOLEAN UnhookVEH(_In_ PVOID Address);
	BOOLEAN UpdateVEH(_In_ PVOID Address);
	BOOLEAN FreeVEHHooks();

	PVOID GetVirtualAddress(_In_ PVOID VirtualTable, _In_ DWORD Index);
	PVOID PatchVFTable(_In_ PVOID VirtualTable, _In_ DWORD Index, _In_ PVOID NewMethod);
	PVOID HookVirtualMethod(_In_ PVOID VirtualTable, _In_ DWORD Index, _In_ PVOID NewMethod);
	PHookVEH HookVirtualMethodViaVEH(_In_ PVOID VirtualTable, _In_ DWORD Index, _In_ PVOID NewMethod);
	BOOLEAN UpdateMethodViaVEH(_In_ PVOID HookMethod);
	BOOLEAN UnhookVirtualMethod(_In_ PVOID HookMethod);

	PVOID HookComInterface(_In_ IUnknown* Interface, _In_ DWORD Index, _In_ PVOID NewMethod);
	BOOLEAN UnhookComInterface(_In_ PVOID HookMethod);

	void HookLog(_In_ LPCSTR Format, ...);

#ifdef __cplusplus
}
#endif