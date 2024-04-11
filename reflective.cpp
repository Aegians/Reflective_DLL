//#include "stdafx.h"
#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
//#include <stdio.h>
//#include <stdlib.h>
#include "LoadLibraryR.h"
#include "NtCreateThreadEx.h"
 
void createShellcode(int ret, int str, unsigned char** shellcode, int* shellcodeSize)
{
	unsigned char* retChar = (unsigned char*)&ret;
	unsigned char* strChar = (unsigned char*)&str;
	//The part where I dont understand what to do with GetReflectiveLoaderOffset()
	int api = (int)GetProcAddress(LoadLibraryA("kernel32.dll"), "LoadLibraryA");
	unsigned char* apiChar = (unsigned char*)&api;
	unsigned char sc[] = {
		// Push ret
		0x68, retChar[0], retChar[1], retChar[2], retChar[3],
		// Push all flags
		0x9C,
		// Push all register
		0x60,
		// Push address of DLL
		0x68, strChar[0], strChar[1], strChar[2], strChar[3],
		// Mov eax (LoadLibrary adress)
		0xB8, apiChar[0], apiChar[1], apiChar[2], apiChar[3],
		// Call eax
		0xFF, 0xD0,
		// Pop all register
		0x61,
		// Pop all flags
		0x9D,
		// Ret
		0xC3
	};
 
	*shellcodeSize = 22;
	*shellcode = (unsigned char*)malloc(22);
	memcpy(*shellcode, sc, 22);
}
 
HANDLE FindThread(DWORD dwPID)
{
	THREADENTRY32 te32 = { 0 };
	HANDLE ret = INVALID_HANDLE_VALUE;
	HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
 
	te32.dwSize = sizeof(THREADENTRY32);
 
	do
	{
		if (!Thread32First(hThreadSnap, &te32))
			break;
 
		do
		{
			if (te32.th32OwnerProcessID == dwPID)
			{
				if (!(ret = OpenThread(THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT | THREAD_GET_CONTEXT, FALSE, te32.th32ThreadID)))
					ret = INVALID_HANDLE_VALUE;
				break;
			}
		} while (Thread32Next(hThreadSnap, &te32));
	} while (0);
 
	CloseHandle(hThreadSnap);
 
	return ret;
}
 
DWORD FindProcessId(std::string processName)
{
	PROCESSENTRY32 processInfo;
	processInfo.dwSize = sizeof(processInfo);
 
	HANDLE processSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (processSnapshot == INVALID_HANDLE_VALUE)
		return 0;
 
	Process32First(processSnapshot, &processInfo);
	if (!processName.compare(processInfo.szExeFile))
	{
		CloseHandle(processSnapshot);
		return processInfo.th32ProcessID;
	}
 
	while (Process32Next(processSnapshot, &processInfo))
	{
		if (!processName.compare(processInfo.szExeFile))
		{
			CloseHandle(processSnapshot);
			return processInfo.th32ProcessID;
		}
	}
 
	CloseHandle(processSnapshot);
	return 0;
}
 
auto HandleReceiver(HANDLE *io_port) {
	DWORD nOfBytes;
	ULONG_PTR cKey;
	LPOVERLAPPED pid;
 
	DWORD dwBytesRead = 0;
	DWORD dwReflectiveLoaderOffset = 0;
	HANDLE hLoadThread = NULL;
 
	//THREADENTRY32 te32;
	CONTEXT ctx;
	unsigned char* shellcode;
	int shellcodeLen;
	//PVOID pRemoteCtx = NULL;
	//static const DWORD REFLECTIVE_STACK_SIZE = 0x2000;
 
	while (GetQueuedCompletionStatus(*io_port, &nOfBytes, &cKey, &pid, -1))
		if (nOfBytes == 6) {
			auto race_handle = OpenProcess(PROCESS_ALL_ACCESS, false, (DWORD)pid);
			printf("Stolen handle : %08x for %d\n", race_handle, pid);
			//insert injection conditions here
			DWORD ProcessId = FindProcessId("ArmA2OA.exe");
			printf("Process ID: %d\n", ProcessId);
			if (ProcessId == (DWORD)pid)
				{
				printf("Found target process!!!!\n");
				// path to our dll
				LPCSTR DllPath = "C:\\Users\\Username\\Desktop\\reflective_dll.dll";
				
				//suspend thread
				HANDLE hThread = FindThread(ProcessId);
				SuspendThread(hThread);
 
				auto hFile = CreateFileA(DllPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
				auto dllFileLength = GetFileSize(hFile, NULL);
				auto remoteDllAddr = VirtualAllocEx(race_handle, NULL, dllFileLength, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
				
				auto lpBuffer = HeapAlloc(GetProcessHeap(), 0, dllFileLength);
				ReadFile(hFile, lpBuffer, dllFileLength, &dwBytesRead, NULL);
				WriteProcessMemory(race_handle, remoteDllAddr, lpBuffer, dllFileLength, NULL);
 
				//registers
				ctx.ContextFlags = CONTEXT_FULL;
				GetThreadContext(hThread, &ctx);
				createShellcode(ctx.Eip, (int)remoteDllAddr, &shellcode, &shellcodeLen);
 
				printf("Created Shellcode: \n");
				for (int i = 0; i<shellcodeLen; i++)
					printf("%X ", shellcode[i]);
				printf("\n");
 
				//yea reflective injection imported function
				//I don't understand how to properly replace LoadLibraryA with GetReflectiveLoaderOffset() in shellcode
				dwReflectiveLoaderOffset = GetReflectiveLoaderOffset(lpBuffer);
				HeapFree(GetProcessHeap(), 0, lpBuffer);
 
				//virtualalloc and wpm for the shellcode
				auto remote_shellcodePtr = VirtualAllocEx(race_handle, NULL, shellcodeLen, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
				WriteProcessMemory(race_handle, remote_shellcodePtr, shellcode, shellcodeLen, NULL);
				
				//resume thread
				ctx.Eip = (DWORD)remote_shellcodePtr;
				SetThreadContext(hThread, &ctx);
 
				ResumeThread(hThread);
 
				Sleep(8000);
 
				//hLoadThread = CreateRemoteThread(race_handle, 0, 0, (LPTHREAD_START_ROUTINE)((ULONG_PTR)remoteDllAddr + dwReflectiveLoaderOffset), NULL, 0, NULL);
				//WaitForSingleObject(hLoadThread, INFINITE);
				
				CloseHandle(race_handle);
				}			
		}
}
 
int main()
{
	auto pid = 0UL;
	//auto desk_hwnd = GetShellWindow();
	auto desk_hwnd = FindWindow(0, "Steam");
	auto ret = GetWindowThreadProcessId(desk_hwnd, &pid);
	auto exp_handle = OpenProcess(PROCESS_ALL_ACCESS, true, pid);
	auto io_port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, 0, 0, 0);
	auto job_object = CreateJobObjectW(0, 0);
	auto job_io_port = JOBOBJECT_ASSOCIATE_COMPLETION_PORT{ 0, io_port };
	auto result = SetInformationJobObject(job_object, JobObjectAssociateCompletionPortInformation, &job_io_port, sizeof(job_io_port));
	result = AssignProcessToJobObject(job_object, exp_handle);
	auto threadHandle = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)HandleReceiver, &io_port, 0, 0);
	WaitForSingleObject(threadHandle, -1);
	CloseHandle(exp_handle);
	return 0;
}
