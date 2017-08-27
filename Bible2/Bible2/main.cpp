#include <Windows.h>
#include <iostream>
#include <string>
#include <TlHelp32.h>

char Dll[32];

unsigned char shellcode[] = {
	0x9C,
	0x60,
	0x68, 0x42, 0x42, 0x42, 0x42,
	0xB8, 0x42, 0x42, 0x42, 0x42,
	0xFF, 0xD0,
	0x61,
	0x9D,
	0xC3
};

void Shell(HANDLE hProcess, FARPROC llAddr, LPVOID dllAddr)
{
	HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	THREADENTRY32 te32;
	te32.dwSize = sizeof(THREADENTRY32);
	Thread32First(hThreadSnap, &te32);

	DWORD TID = 0;
	HANDLE hThread;
	do
	{
		if (te32.th32OwnerProcessID == GetProcessId(hProcess))
		{
			if (TID == 0)
				TID = te32.th32ThreadID;

			hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
			SuspendThread(hThread);
			CloseHandle(hThread);
		}
	} while (Thread32Next(hThreadSnap, &te32));
	CloseHandle(hThreadSnap);

	CONTEXT lpContext;
	lpContext.ContextFlags = CONTEXT_FULL;
	HANDLE targetThread = NULL;

	targetThread = OpenThread(THREAD_ALL_ACCESS, FALSE, TID);

	GetThreadContext(targetThread, &lpContext);

	lpContext.Esp -= sizeof(unsigned int);
	WriteProcessMemory(hProcess, (LPVOID)lpContext.Esp, (LPCVOID)&lpContext.Eip, sizeof(unsigned int), NULL);

	shellcode[3] = ((unsigned int)dllAddr & 0xFF);
	shellcode[4] = (((unsigned int)dllAddr >> 8) & 0xFF);
	shellcode[5] = (((unsigned int)dllAddr >> 16) & 0xFF);
	shellcode[6] = (((unsigned int)dllAddr >> 24) & 0xFF);
	shellcode[8] = ((unsigned int)llAddr & 0xFF);
	shellcode[9] = (((unsigned int)llAddr >> 8) & 0xFF);
	shellcode[10] = (((unsigned int)llAddr >> 16) & 0xFF);
	shellcode[11] = (((unsigned int)llAddr >> 24) & 0xFF);

	LPVOID shellcodeAddress;
	shellcodeAddress = VirtualAllocEx(hProcess, NULL, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	WriteProcessMemory(hProcess, shellcodeAddress, (LPCVOID)shellcode, sizeof(shellcode), NULL);

	lpContext.Eip = (DWORD)shellcodeAddress;
	SetThreadContext(targetThread, &lpContext);

	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	te32.dwSize = sizeof(THREADENTRY32);

	Thread32First(hThreadSnap, &te32);

	do
	{
		if (te32.th32OwnerProcessID == GetProcessId(hProcess))
		{
			hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
			ResumeThread(hThread);

			if (te32.th32ThreadID == TID)
				WaitForSingleObject(hThread, 5000);

			CloseHandle(hThread);
		}
	} while (Thread32Next(hThreadSnap, &te32));
	CloseHandle(hThreadSnap);
}

int CALLBACK WinMain(HINSTANCE something, HINSTANCE somethingelse, LPSTR cmd, int cmdshow)
{
	DWORD pID;
	GetWindowThreadProcessId(FindWindow(0, L"Counter-Strike: Global Offensive"), &pID);

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pID);

	FARPROC LoadLibAddr = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

	GetFullPathNameA("module.dll", MAX_PATH, Dll, NULL);

	LPVOID allocDllName = VirtualAllocEx(hProcess, NULL, strlen(Dll), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	WriteProcessMemory(hProcess, allocDllName, Dll, strlen(Dll), NULL);

	Shell(hProcess, LoadLibAddr, allocDllName);

	VirtualFreeEx(hProcess, allocDllName, strlen(Dll), MEM_RELEASE);

	CloseHandle(hProcess);

	return true;
}
