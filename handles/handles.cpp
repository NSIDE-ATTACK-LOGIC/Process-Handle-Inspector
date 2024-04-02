#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
#include <TlHelp32.h>

typedef NTSTATUS(NTAPI* NTQUERYOBJECT)(HANDLE Handle, OBJECT_INFORMATION_CLASS Info, PVOID Buffer, ULONG BufferSize, PULONG ReturnLength);

BOOL EnableDebugPrivilege()
{
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tkp;
    BOOL success;

    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);

    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = luid;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    success = AdjustTokenPrivileges(hToken, false, &tkp, sizeof(tkp), NULL, NULL);
    CloseHandle(hToken);

    return success;
}

DWORD GetPID(LPCWSTR processName)
{
    DWORD pid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &entry) == TRUE)
    {
        do {
            if (wcscmp(entry.szExeFile, processName) == 0)
            {
                pid = entry.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &entry) == TRUE);
    }

    CloseHandle(hSnapshot);
    return pid;
}

DWORD PrintHandlePermissions(HANDLE hHandle)
{
    NTQUERYOBJECT pNtQueryObject = (NTQUERYOBJECT)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryObject");

    BYTE objectInfoBuffer[0x1000] = { 0 };
    PUBLIC_OBJECT_BASIC_INFORMATION* objectInfo = (PUBLIC_OBJECT_BASIC_INFORMATION*)objectInfoBuffer;

    NTSTATUS status = pNtQueryObject(hHandle, ObjectBasicInformation, objectInfo, sizeof(PUBLIC_OBJECT_BASIC_INFORMATION), NULL);

    if (status != 0) {
        printf("[-] Failed to query the handle's access mask: 0x%x", status);
        return FALSE;
    }

    printf("[+] Handle Permissions: %d\n", objectInfo->GrantedAccess);
    printf("[*] PROCESS_ALL_ACCESS: %d\n", (objectInfo->GrantedAccess & PROCESS_ALL_ACCESS) != 0);
    printf("[*] PROCESS_CREATE_PROCESS: %d\n", (objectInfo->GrantedAccess & PROCESS_CREATE_PROCESS) != 0);
    printf("[*] PROCESS_CREATE_THREAD: %d\n", (objectInfo->GrantedAccess & PROCESS_CREATE_THREAD) != 0);
    printf("[*] PROCESS_DUP_HANDLE: %d\n", (objectInfo->GrantedAccess & PROCESS_DUP_HANDLE) != 0);
    printf("[*] PROCESS_QUERY_INFORMATION: %d\n", (objectInfo->GrantedAccess & PROCESS_QUERY_INFORMATION) != 0);
    printf("[*] PROCESS_QUERY_LIMITED_INFORMATION: %d\n", (objectInfo->GrantedAccess & PROCESS_QUERY_LIMITED_INFORMATION) != 0);
    printf("[*] PROCESS_SET_INFORMATION: %d\n", (objectInfo->GrantedAccess & PROCESS_SET_INFORMATION) != 0);
    printf("[*] PROCESS_SET_QUOTA: %d\n", (objectInfo->GrantedAccess & PROCESS_SET_QUOTA) != 0);
    printf("[*] PROCESS_SUSPEND_RESUME: %d\n", (objectInfo->GrantedAccess & PROCESS_SUSPEND_RESUME) != 0);
    printf("[*] PROCESS_TERMINATE: %d\n", (objectInfo->GrantedAccess & PROCESS_TERMINATE) != 0);
    printf("[*] PROCESS_VM_OPERATION: %d\n", (objectInfo->GrantedAccess & PROCESS_VM_OPERATION) != 0);
    printf("[*] PROCESS_VM_READ: %d\n", (objectInfo->GrantedAccess & PROCESS_VM_READ) != 0);
    printf("[*] PROCESS_VM_WRITE: %d\n", (objectInfo->GrantedAccess & PROCESS_VM_WRITE) != 0);
    printf("[*] SYNCHRONIZE: %d\n", (objectInfo->GrantedAccess & SYNCHRONIZE) != 0);
    return objectInfo->GrantedAccess;
}

void main(void)
{
    if (!EnableDebugPrivilege())  // Required to obtain a handle to LSASS
    {
        printf("[-] Failed to enable SeDebugPrivilege: %d\n", GetLastError());
        return;
    }
    printf("[+] Enabled SeDebugPrivilege\n");

    DWORD lsassPid = GetPID(L"lsass.exe");
    printf("[+] Found lsass with PID %d\n", lsassPid);

    HANDLE hLsass = OpenProcess(PROCESS_ALL_ACCESS, FALSE, lsassPid);
    if (hLsass == NULL) {
        printf("[-] Failed to obtain a handle to lsass: %d\n", GetLastError());
        CloseHandle(hLsass);
        return;
    }
    printf("[+] Obtained handle to lsass\n\n");

    PrintHandlePermissions(hLsass);
}
