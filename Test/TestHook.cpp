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
#include <stdlib.h>
#include <locale.h>
#include <functional>
#include <MMDeviceAPI.h>
#include <Functiondiscoverykeys_devpkey.h>

#include "..\HookApi.h"

#pragma comment(lib, "ntdll.lib")

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

extern "C"  
{
	NTSYSAPI NTSTATUS NTAPI NtGetContextThread(_In_ HANDLE ThreadHandle, _Inout_ PCONTEXT ThreadContext);
}

typedef int (WINAPI* pfnMessageBoxW)(
	_In_opt_ HWND hWnd,
	_In_opt_ LPCWSTR lpText,
	_In_opt_ LPCWSTR lpCaption,
	_In_ UINT uType
	);

typedef HANDLE(WINAPI* pfnCreateFileW)(
	_In_ LPCWSTR lpFileName,
	_In_ DWORD dwDesiredAccess,
	_In_ DWORD dwShareMode,
	_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	_In_ DWORD dwCreationDisposition,
	_In_ DWORD dwFlagsAndAttributes,
	_In_opt_ HANDLE hTemplateFile
	);

typedef void (WINAPI* pfnExitThread) (
	_In_ DWORD dwExitCode
	);

typedef NTSTATUS(NTAPI* pfnCloseHandle) (
	_In_ HANDLE hObject
	);

typedef NTSTATUS(NTAPI* pfnNtGetContextThread)(
	_In_ HANDLE ThreadHandle,
	_Inout_ PCONTEXT ThreadContext
	);

pfnMessageBoxW OldMessageBoxW = nullptr;

pfnCreateFileW OldCreateFileW = nullptr;

pfnExitThread OldExitThread = nullptr;

pfnCloseHandle OldCloseHandle = nullptr;

pfnNtGetContextThread OldNtGetContextThread = nullptr;

typedef HRESULT(STDMETHODCALLTYPE* pfnGetCount)(
	IMMDeviceCollection* This,
	_Out_ UINT* pcDevices
	);

typedef HRESULT(STDMETHODCALLTYPE* pfnGetId)(
	IMMDevice* This,
	_Outptr_ LPWSTR* ppstrId
	);

typedef HRESULT(STDMETHODCALLTYPE* pfnGetValue)(
	_In_ IPropertyStore* This,
	__RPC__in REFPROPERTYKEY key,
	__RPC__out PROPVARIANT* pv
	);

pfnGetCount OldGetCount = nullptr;

pfnGetId OldGetId = nullptr;

pfnGetValue OldGetValue = nullptr;

int __CRTDECL new_printf_s(_In_z_ _Printf_format_string_ char const* const _Format, ...)
{
	int Result = printf_s("printf_s hooked!\n");

	//UpdateVEH(&new_printf_s);

	return Result;
}

int __cdecl new_strcmp(_In_z_ char const* _Str1, _In_z_ char const* _Str2)
{
	printf_s("strcmp hooked!\n");

	int Result = strcmp(_Str1, _Str2);

	//UpdateVEH(&new_strcmp);

	return Result;
}

size_t __cdecl new_strlen(_In_z_ char const* _Str)
{
	printf_s("strlen hooked!\n");

	size_t Result = strlen(_Str);

	//UpdateVEH(&new_strlen);

	return Result;
}

int
WINAPI
NewMessageBoxW(
	_In_opt_ HWND hWnd,
	_In_opt_ LPCWSTR lpText,
	_In_opt_ LPCWSTR lpCaption,
	_In_ UINT uType
)
{
	//pfnMessageBoxW OldMessageBoxW = GetBridgeAddress(&NewMessageBoxW);

	int Result = OldMessageBoxW(hWnd, L"MessageBoxW hooked!", L"OK", uType);

	return Result;
}

HANDLE
WINAPI
NewCreateFileW(
	_In_ LPCWSTR lpFileName,
	_In_ DWORD dwDesiredAccess,
	_In_ DWORD dwShareMode,
	_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	_In_ DWORD dwCreationDisposition,
	_In_ DWORD dwFlagsAndAttributes,
	_In_opt_ HANDLE hTemplateFile)
{
	printf_s("CreateFileW hooked!\n");

	return OldCreateFileW(
		lpFileName,
		dwDesiredAccess,
		dwShareMode,
		lpSecurityAttributes,
		dwCreationDisposition,
		dwFlagsAndAttributes,
		hTemplateFile
	);
}

void WINAPI NewExitThread(_In_ DWORD dwExitCode)
{
	printf_s("ExitThread! hooked\n");

	OldExitThread(dwExitCode);
}

NTSTATUS NTAPI NewNtGetContextThread(_In_ HANDLE ThreadHandle, _Inout_ PCONTEXT ThreadContext)
{
	printf_s("NtGetContextThread hooked!\n");

	return OldNtGetContextThread(ThreadHandle, ThreadContext);
}

NTSTATUS NTAPI NewCloseHandle(_In_ HANDLE hObject)
{
	printf_s("CloseHandle hooked!\n");

	return OldCloseHandle(hObject);
}

bool TestImportHook()
{
	bool Result = false;

	OldCreateFileW = (pfnCreateFileW)HookImportA("kernel32", "CreateFileW", &NewCreateFileW);

	if (OldCreateFileW)
	{
		WCHAR FileName[MAX_PATH] = { 0 };

		GetModuleFileNameW(0, FileName, MAX_PATH);

		HANDLE hFile = CreateFileW(FileName, GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

		if (hFile != INVALID_HANDLE_VALUE)
		{
			OldCloseHandle = (pfnCloseHandle)HookImportA("kernel32", "CloseHandle", &NewCloseHandle);

			if (OldCloseHandle)
			{
				Result = CloseHandle(hFile);

				UnhookImportA("kernel32", "CloseHandle");
			}
		}
		UnhookImportA("kernel32", "CreateFileW");
	}
	return Result;
}

bool TestNtHook()
{
	bool Result = false;

	OldNtGetContextThread = (pfnNtGetContextThread)HookWinApiA("ntdll", "NtGetContextThread", &NewNtGetContextThread);

	if (OldNtGetContextThread)
	{
		CONTEXT Context = { 0 };

		Context.ContextFlags = CONTEXT_ALL;

		if (NtGetContextThread(GetCurrentThread(), &Context) == STATUS_SUCCESS)
		{
			Result = true;
		}
		UnhookWinApiA("ntdll", "NtGetContextThread");
	}
	return Result;
}

bool TestExportHook()
{
	OldExitThread = (pfnExitThread)HookExportW(L"kernel32", L"ExitThread", &NewExitThread); // RtlExitUserThread

	if (OldExitThread)
	{
		pfnExitThread TestExitThread = (pfnExitThread)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "ExitThread");

		//TestExitThread(123);

		UnhookExportW(L"kernel32", L"ExitThread", OldExitThread);

		TestExitThread = (pfnExitThread)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "ExitThread");

		if (OldExitThread == TestExitThread)
			return true;
	}
	return false;
}

bool TestSplice()
{
	PVOID ProcAddress = GetProcAddress(LoadLibraryW(L"user32.dll"), "MessageBoxW");

	if (ProcAddress)
	{
		OldMessageBoxW = (pfnMessageBoxW)HookSplice(ProcAddress, &NewMessageBoxW);

		MessageBoxW(GetDesktopWindow(), L"Test", L"Test", MB_ICONINFORMATION);

		return UnhookSplice(OldMessageBoxW);
	}
	return false;
}

bool TestVEH()
{
	HookVEH(&printf_s, &new_printf_s, HookPrivInstruction);

	printf_s("test ptrintf_s");

	HookVEH(&strcmp, &new_strcmp, HookHardwareBreakpoint);

	strcmp("strcmp", "strcmp");

	HookVEH(&strlen, &new_strlen, HookGuardPage);

	strlen("strlen");

	return FreeVEHHooks();
}

class CTestClass // Оригинальный класс.
{
public:

	virtual void PrintString(const char* String) // 0
	{
		printf_s("%s\n", String);
	}

	virtual void SetVar(int Val) // 1
	{
		m_TestInt = Val;
	}

	virtual int GetInt() // 2
	{
		return m_TestInt;
	}

	virtual int AddInt(int A, int B) // 3
	{
		return A + B;
	}
	int m_TestInt = 0;
};

class CHookClass
{
public:

	void PrintString(const char* String)
	{
		printf("Hooked method!\n");

		((CTestClass*)this)->PrintString(String); // Вызываем оригинальную функцию

		UpdateMethodHook(&CHookClass::PrintString); // Восстанавливаем перехват.
	}

	void SetVar(int Val)
	{
		((CTestClass*)this)->m_TestInt = Val; // Получаем доступ к переменным.
	}

	int GetInt()
	{
		return ((CTestClass*)this)->m_TestInt;
	}

	int AddInt(int A, int B)
	{
		return A + B;
	}
};

bool TestClassHook()
{
	CTestClass* TestClass = new CTestClass();

	HookVirtualMethodViaVEH(TestClass, 0, GetClassMethod(&CHookClass::PrintString));

	HookVirtualMethodViaVEH(TestClass, 1, GetClassMethod(&CHookClass::SetVar));

	HookVirtualMethodViaVEH(TestClass, 2, GetClassMethod(&CHookClass::GetInt));

	HookVirtualMethodViaVEH(TestClass, 3, GetClassMethod(&CHookClass::AddInt));

	TestClass->PrintString("Original method");

	int ClassVar = TestClass->AddInt(1, 2);

	TestClass->SetVar(ClassVar);

	ClassVar = TestClass->GetInt();

	UnhookAllProc();

	delete TestClass;

	return (ClassVar == 3);
}

HRESULT STDMETHODCALLTYPE NewGetCount(_In_ IMMDeviceCollection* This, _Out_ UINT* pcDevices)
{
	//printf_s("IMMDeviceCollection::GetCount hooked!\n");

	return OldGetCount(This, pcDevices);
}

HRESULT STDMETHODCALLTYPE NewGetId(_In_ IMMDevice* This, _Outptr_ LPWSTR* ppstrId)
{
	//printf_s("IMMDevice::GetId hooked!\n");

	return OldGetId(This, ppstrId);
}

HRESULT STDMETHODCALLTYPE NewGetValue(_In_ IPropertyStore* This, __RPC__in REFPROPERTYKEY key, __RPC__out PROPVARIANT* pv)
{
	//printf_s("IPropertyStore::GetValue hooked!\n");

	return OldGetValue(This, key, pv);
}

void TestComInterfaceHook()
{
	HRESULT hResult = CoInitialize(NULL);

	if (SUCCEEDED(hResult))
	{
		IMMDeviceEnumerator* Enumerator = NULL;

		hResult = CoCreateInstance(__uuidof(MMDeviceEnumerator), NULL, CLSCTX_INPROC_SERVER, __uuidof(IMMDeviceEnumerator), (void**)&Enumerator);

		if (SUCCEEDED(hResult))
		{
			IMMDeviceCollection* DeviceCollection = NULL;

			hResult = Enumerator->EnumAudioEndpoints(eRender, DEVICE_STATE_ACTIVE | DEVICE_STATE_UNPLUGGED, &DeviceCollection);

			if (SUCCEEDED(hResult))
			{
				OldGetCount = (pfnGetCount)HookComInterface(DeviceCollection, 0, &NewGetCount);

				UINT DeviceCount = 0;

				hResult = DeviceCollection->GetCount(&DeviceCount);

				if (SUCCEEDED(hResult))
				{
					printf_s("Count devices: %d\n\n", DeviceCount);

					IMMDevice* Device = NULL;

					IPropertyStore* PropertyStore = NULL;

					for (UINT DeviceIndex = 0; DeviceIndex < DeviceCount; DeviceIndex++) // Цикл перехватов.
					{
						hResult = DeviceCollection->Item(DeviceIndex, &Device);

						if (SUCCEEDED(hResult))
						{
							LPWSTR StrId = NULL;

							OldGetId = (pfnGetId)HookComInterface(Device, 2, &NewGetId);

							hResult = Device->GetId(&StrId);

							if (SUCCEEDED(hResult))
							{
								wprintf_s(L"Device id: %ws\n", StrId);

								hResult = Device->OpenPropertyStore(STGM_READ, &PropertyStore);

								if (SUCCEEDED(hResult))
								{
									PROPVARIANT DeviceName = { 0 };

									PropVariantInit(&DeviceName);

									OldGetValue = (pfnGetValue)HookComInterface(PropertyStore, 2, &NewGetValue);

									hResult = PropertyStore->GetValue(PKEY_Device_FriendlyName, &DeviceName);

									if (SUCCEEDED(hResult))
									{
										wprintf_s(L"Device name: %ws\n\n", DeviceName.pwszVal);

										UnhookComInterface(&NewGetValue);
									}
									PropVariantClear(&DeviceName);
								}
								UnhookComInterface(&NewGetId);
							}
						}
					}
					UnhookComInterface(&NewGetCount);
				}
			}
		}
		CoUninitialize();
	}
}

int main(int argc, char* argv[], char* envp[])
{
	setlocale(LC_CTYPE, "ru_RU.utf8");

	TestComInterfaceHook();

	TestExportHook();

	TestClassHook();

	TestSplice();

	TestVEH();

	TestImportHook();

	TestNtHook();

	system("pause");

	return 0;
}
