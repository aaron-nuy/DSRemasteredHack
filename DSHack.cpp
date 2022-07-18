// DSHack.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>
#include <WinUser.h>
#include <string>
#include <thread>
#include <string.h>
#include <TlHelp32.h>
#include <stdlib.h>

#define SOULS_POINTER_ADDRESS 0x1D00F50
#define SOULS_POINTER_ADDRESS_OFFSET 0xDA4

DWORD Win32ReturnProcessID(const std::wstring& pProcessName) {
	HANDLE hToolHelper = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0x0);
	PROCESSENTRY32 p32ProcessEntry = { 0 };
	p32ProcessEntry.dwSize = sizeof(PROCESSENTRY32);

	if (hToolHelper == NULL) {
		throw std::exception("Couldn't take snapchot of running processes\n");
	}

	if (!Process32First(hToolHelper, &p32ProcessEntry)) {
		CloseHandle(hToolHelper);
		throw std::exception("Unexpected error\n");
	}

	do {
		if (!wcscmp(p32ProcessEntry.szExeFile, pProcessName.c_str())) {
			CloseHandle(hToolHelper);
			return p32ProcessEntry.th32ProcessID;
		}
	} while (Process32Next(hToolHelper, &p32ProcessEntry));

	throw std::exception("Couldn't find process with that name\n");
}

LPVOID Win32ReturnModuleBaseAddress(DWORD dwProcessID, const std::wstring& lpszModuleName) {

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessID);
	LPVOID dwModuleBaseAddress;

	if (hSnapshot != INVALID_HANDLE_VALUE) {
		MODULEENTRY32 ModuleEntry32 = { 0 };
		ModuleEntry32.dwSize = sizeof(MODULEENTRY32);
		if (Module32First(hSnapshot, &ModuleEntry32)) {
			do
			{
				if (!wcscmp(ModuleEntry32.szModule, lpszModuleName.c_str()))
				{
					dwModuleBaseAddress = ModuleEntry32.modBaseAddr;
					CloseHandle(hSnapshot);
					return dwModuleBaseAddress;
				}
			} while (Module32Next(hSnapshot, &ModuleEntry32));
		}
	}

	return 0;

}


int main()
{
	LPVOID soulsAdress = 0;
	UINT32 soulsNeeded = 9999999;

	try {
		

		DWORD processID = Win32ReturnProcessID(L"DarkSoulsRemastered.exe");
		LPVOID moduleBaseAdr = Win32ReturnModuleBaseAddress(processID, L"DarkSoulsRemastered.exe");


		HANDLE hProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
		if (!hProcessHandle) {
			std::cout << "Couldn't open process Failed with error: " << GetLastError() << "\n";
			return 1;
		}
	
		if (!ReadProcessMemory(hProcessHandle, (LPCTSTR)((UINT64)SOULS_POINTER_ADDRESS + (UINT64)moduleBaseAdr), &soulsAdress, sizeof(LPVOID), NULL)) {
			std::cout << "Couldn't read process memory. Failed with error: " << GetLastError() << "\n";
			return 1;
		}


		std::cout << soulsAdress << "\n";

		if (!WriteProcessMemory(hProcessHandle, (LPVOID)((UINT64)soulsAdress + SOULS_POINTER_ADDRESS_OFFSET), &soulsNeeded, sizeof(soulsNeeded), NULL)) {
			std::cout << "Couldn't write to process memory. Failed with error: " << GetLastError() << "\n";
			return 1;
		}

		std::cout << "Written successfully!";
		return 0;

	}
	catch (std::exception& e) {
		std::cout << e.what();
	}
}

