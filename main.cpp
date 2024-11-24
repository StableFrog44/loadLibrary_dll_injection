#include <Windows.h>
#include <cstdio>
#include <cstring>
#include <TlHelp32.h>
#include <string>
#include <filesystem>

// printing macros, actually pretty nice to use.
#define Error(content, ...) fprintf(stderr, "[Error] " content "\n", ##__VA_ARGS__);
#define Debug(content, ...) printf("[Debug] " content "\n", ##__VA_ARGS__)

namespace fileSystem = std::filesystem;

DWORD ObtainProcessId(const char* processName)
{
    // create snapshot of processes
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot == INVALID_HANDLE_VALUE || !hSnapshot)
    {
        // using unsigned int for the format type because even though GetLastError() returns a DWORD 
        // (32 bit unsigned long) 64 bit systems (the common now) treat this as an unsigned int.
        Error("Failed creating snapshot of proccesses. Error: %u", GetLastError());
        return 1;
    }

    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnapshot, &entry))
    {
        Error("Failed obtaining the first process. Error: %u", GetLastError());
        CloseHandle(hSnapshot);
        return 1;
    }

    // begin looping now
    while (Process32Next(hSnapshot, &entry))
    {
        if (!_strcmpi(entry.szExeFile, processName)) // _strcmpi for case insensitive results
        {

            CloseHandle(hSnapshot);
            return entry.th32ProcessID;
        }
    }

    CloseHandle(hSnapshot);
    return 0;
}

int main()
{
    // proof of concept project, can be changed as needed (case-insensitive aswell :D)
    const char* processName = "notepad.exe";

    // can change as needed
    std::string dllPath = fileSystem::current_path().string() + "\\concept_dll.dll";

    const DWORD pid = ObtainProcessId(processName);

    if (!pid)
    {
        Error("Failed to obtain process id. Process name: %s, Error: %u", processName, GetLastError());
        return 1;
    }

    HANDLE hProcHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    if (!hProcHandle)
    {
        Error("Failed to obtain handle. PID: %u, Process name: %s, Error: %u", pid, processName, GetLastError());
        return 1;
    }

    // here we add 1 to compensate for null terminator
    LPVOID alloc = VirtualAllocEx(hProcHandle, NULL, dllPath.size() + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    if (!alloc)
    {
        Error("Failed to allocate memory. Handle: 0x%p, Error: %u", hProcHandle, GetLastError());
        CloseHandle(hProcHandle);
        return 1;
    }

    // finally time to write mem
    if (!WriteProcessMemory(hProcHandle, alloc, dllPath.c_str(), dllPath.size() + 1, nullptr))
    {
        ERROR("Failed to write memory. PID: %u, Error: %u", pid, GetLastError());
        VirtualFreeEx(hProcHandle, alloc, 0, MEM_RELEASE);
        CloseHandle(hProcHandle);
        return 1;
    }

    // create thread =D, we also call LoadLibraryA from here, not needing to call it manually.
    HANDLE hThread = CreateRemoteThread(hProcHandle, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibraryA, alloc, NULL, NULL);

    if (!hThread)
    {
        Error("Failed to create thread. :(");
        VirtualFreeEx(hProcHandle, alloc, 0, MEM_RELEASE);
        CloseHandle(hProcHandle);
        return 1;
    }

    // atp we have successfully created the thread and injected.
    // this will wait until the thread is finished, and then clean up.
    Debug("Thread created. PID: %u, Handle: 0x%p, Process name: %s", pid, hProcHandle, processName);
    Debug("Waiting for thread to finish...");

    WaitForSingleObject(hThread, INFINITE);
    VirtualFreeEx(hProcHandle, alloc, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcHandle);

    Debug("Cleaned up.");

    return 0;
}