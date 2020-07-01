#include <Windows.h>
#include <d3d11_4.h>
#include <directxcolors.h>

#include "..\HookApi.h"

#pragma comment (lib, "d3d11.lib")

using namespace DirectX;

LPCWSTR MainWindowName = L"F1 - включить перехват, F2 - вернуть назад, Esc - выход";
LPCWSTR WindowClassName = L"TestDirectXHook";

HWND g_hMainWindow = nullptr;

ID3D11Device* g_d3dDevice = nullptr;
ID3D11DeviceContext* g_DeviceContext = nullptr;
IDXGISwapChain* g_SwapChain = nullptr;
ID3D11RenderTargetView* g_RenderTargetView = nullptr;

typedef void(STDMETHODCALLTYPE* pfnClearRenderTargetView) (ID3D11DeviceContext* This, ID3D11RenderTargetView* pRenderTargetView, _In_ const FLOAT ColorRGBA[4]);

pfnClearRenderTargetView pClearRenderTargetView = nullptr;

void STDMETHODCALLTYPE NewClearRenderTargetView(_In_ ID3D11DeviceContext* This, _In_ ID3D11RenderTargetView* pRenderTargetView, _In_ const FLOAT ColorRGBA[4])
{
	pClearRenderTargetView(This, pRenderTargetView, Colors::Tomato); // Меняем цвет)
}

bool SetD3D11Hooks()
{
	PVOID Result = HookComInterface(g_DeviceContext, 47, &NewClearRenderTargetView);

	if (Result)
	{
		pClearRenderTargetView = (pfnClearRenderTargetView)Result;

		return true;
	}
	return false;
}

bool UnhookD3D11()
{
	return UnhookComInterface(pClearRenderTargetView);
}

void Render()
{
	//float ClearColor[4] = { 0.0f, 1.0f, 0.0f, 1.0f }; // красный, зеленый, синий, альфа-канал 

	g_DeviceContext->ClearRenderTargetView(g_RenderTargetView, Colors::LightSeaGreen);

	g_SwapChain->Present(0, 0);
}

void ReleaseDevice()
{
	if (g_DeviceContext)
		g_DeviceContext->Release();

	if (g_RenderTargetView)
		g_RenderTargetView->Release();

	if (g_SwapChain)
		g_SwapChain->Release();

	if (g_d3dDevice)
		g_d3dDevice->Release();
}

HRESULT InitD3D11(HWND hWnd)
{
	RECT Rect = { 0 };

	GetClientRect(hWnd, &Rect);

	UINT Width = Rect.right - Rect.left;

	UINT Height = Rect.bottom - Rect.top;

	DXGI_SWAP_CHAIN_DESC SwapChain = { 0 };

	SwapChain.BufferCount = 1;
	SwapChain.BufferDesc.Width = Width;
	SwapChain.BufferDesc.Height = Height;
	SwapChain.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
	SwapChain.BufferDesc.RefreshRate.Numerator = 60;
	SwapChain.BufferDesc.RefreshRate.Denominator = 1;
	SwapChain.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
	SwapChain.OutputWindow = hWnd;
	SwapChain.SampleDesc.Count = 1;
	SwapChain.SampleDesc.Quality = 0;
	SwapChain.Windowed = TRUE;

	UINT Flags = 0;

#ifdef _DEBUG
	Flags = D3D11_CREATE_DEVICE_DEBUG;
#endif

	HRESULT hResult = D3D11CreateDeviceAndSwapChain(
		nullptr,
		D3D_DRIVER_TYPE_HARDWARE,
		nullptr,
		Flags,
		nullptr,
		0,
		D3D11_SDK_VERSION,
		&SwapChain,
		&g_SwapChain,
		&g_d3dDevice,
		nullptr,
		&g_DeviceContext);

	if (SUCCEEDED(hResult))
	{
		ID3D11Texture2D* BackBuffer = nullptr;

		hResult = g_SwapChain->GetBuffer(0, __uuidof(ID3D11Texture2D), (PVOID*)&BackBuffer);

		if (SUCCEEDED(hResult))
		{
			hResult = g_d3dDevice->CreateRenderTargetView(BackBuffer, nullptr, &g_RenderTargetView);

			if (SUCCEEDED(hResult))
			{
				BackBuffer->Release();

				g_DeviceContext->OMSetRenderTargets(1, &g_RenderTargetView, nullptr);

				D3D11_VIEWPORT Viewports = { 0 };

				Viewports.Width = (FLOAT)Width;
				Viewports.Height = (FLOAT)Height;
				Viewports.MinDepth = 0.0f;
				Viewports.MaxDepth = 1.0f;
				Viewports.TopLeftX = 0;
				Viewports.TopLeftY = 0;

				g_DeviceContext->RSSetViewports(1, &Viewports);

				return S_OK;
			}
		}
	}
	return S_FALSE;
}

void KeyboardInput(UINT Key)
{
	switch (Key)
	{
		case VK_F1:
		{
			SetD3D11Hooks();
			break;
		}
		case VK_F2:
		{
			UnhookD3D11();
			break;
		}
		case VK_ESCAPE:
		{
			ReleaseDevice();

			PostQuitMessage(0);
		}
	}
}

LRESULT CALLBACK WindowProc(HWND hWindow, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	PAINTSTRUCT Paint = { 0 };

	switch (uMsg)
	{
		case WM_KEYDOWN:
		{
			KeyboardInput((UINT)wParam);
			break;
		}
		case WM_PAINT:
		{
			BeginPaint(hWindow, &Paint);

			EndPaint(hWindow, &Paint);

			break;
		}
		case WM_DESTROY:
		{
			PostQuitMessage(0);

			break;
		}

		default:
			return DefWindowProcW(hWindow, uMsg, wParam, lParam);
	}
	return 0;
}

HWND InitWindow(HINSTANCE hInstance, LPCWSTR WindowName, LPCWSTR ClassName, int nCmdShow)
{
	WNDCLASSEXW WindowClass = { 0 };

	WindowClass.cbSize = sizeof(WindowClass);
	WindowClass.style = CS_HREDRAW | CS_VREDRAW;;
	WindowClass.lpfnWndProc = &WindowProc;
	WindowClass.cbClsExtra = 0;
	WindowClass.cbWndExtra = 0;
	WindowClass.hInstance = hInstance;
	WindowClass.hIcon = nullptr;
	WindowClass.hCursor = LoadCursorW(NULL, IDC_ARROW);
	WindowClass.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
	WindowClass.lpszMenuName = nullptr;
	WindowClass.lpszClassName = ClassName;
	WindowClass.hIconSm = LoadIconW(WindowClass.hInstance, IDI_APPLICATION);

	if (RegisterClassExW(&WindowClass))
	{
		RECT Rect = { 0, 0, 800, 600 };

		AdjustWindowRect(&Rect, WS_OVERLAPPEDWINDOW, FALSE);

		HWND hWindow = CreateWindowExW(
			0,
			ClassName,
			WindowName,
			WS_OVERLAPPEDWINDOW,
			CW_USEDEFAULT,
			CW_USEDEFAULT,
			Rect.right - Rect.left,
			Rect.bottom - Rect.top,
			nullptr,
			nullptr,
			hInstance,
			nullptr);

		if (hWindow)
		{
			ShowWindow(hWindow, nCmdShow);

			return hWindow;
		}
	}
	return nullptr;
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow)
{
	//HINSTANCE hInstance = GetModuleHandleW(nullptr);

	g_hMainWindow = InitWindow(hInstance, MainWindowName, WindowClassName, SW_NORMAL); // Создаём окно.

	if (g_hMainWindow)
	{
		if (InitD3D11(g_hMainWindow) == S_OK) // Заводим 11-й директ.
		{
			MSG Msg = { 0 };

			while (Msg.message != WM_QUIT)
			{
				if (PeekMessageW(&Msg, nullptr, 0, 0, PM_REMOVE))
				{
					TranslateMessage(&Msg);
					DispatchMessageW(&Msg);
				}
				else
					Render(); // Отрисовываем кадр.
			}
		}
		DestroyWindow(g_hMainWindow);

		UnregisterClassW(WindowClassName, hInstance);
	}
	return 0;
}