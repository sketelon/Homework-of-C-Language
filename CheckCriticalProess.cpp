#include <windows.h>
#include <stdio.h>
#pragma comment(lib,"Advapi32.lib") 

#define ProcessBreakOnTermination 29
typedef int ProcessInformationClass;
typedef NTSTATUS(NTAPI * _NtQueryInformationProcess)(
    HANDLE ProcessHandle,
    ProcessInformationClass  informationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
    );

/*
NTSTATUS
RtlSetProcessIsCritical (
   BOOLEAN bNew,       // new setting for process
   BOOLEAN *pbOld,     // pointer which receives old setting (can be null)
   BOOLEAN bNeedScb);      // need system critical breaks
*/

typedef NTSTATUS(NTAPI * RtlSetProcessIsCritical)(
    BOOLEAN bNew,       // new setting for process
    BOOLEAN *pbOld,     // pointer which receives old setting (can be null)
    BOOLEAN bNeedScb);      // need system critical breaks

BOOL EnableDebugPrivilege(BOOL fEnable)
{
    BOOL fOk = FALSE;
    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
    {
        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
        tp.Privileges[0].Attributes = fEnable ? SE_PRIVILEGE_ENABLED : 0;
        AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
        fOk = (GetLastError() == ERROR_SUCCESS);
        CloseHandle(hToken);
    }
    return(fOk);
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        printf("\nCheck the selected process is critical or not.\n");
        printf("Usage:\n");
        printf("     %s <pid>\n", argv[0]);
        return 0;
    }

    if (!EnableDebugPrivilege(TRUE))
    {
        printf("[!]AdjustTokenPrivileges Failed.<%d>\n", GetLastError());
    }

    DWORD pid;
    sscanf_s(argv[1], "%d", &pid);
    
    // 若 PID = -1，设置进程临界
    if (-1 == pid)
    {
        RtlSetProcessIsCritical fSetCritical = (RtlSetProcessIsCritical)GetProcAddress(GetModuleHandleA("NtDll.dll"), "RtlSetProcessIsCritical");
        if (!fSetCritical)
        {
            printf("[!]Could not find RtlSetProcessIsCritical entry point in NTDLL.DLL\n");
            return 0;
        }
        fSetCritical(1, 0, 0);

        // 运行程序
        while (true)
        {
            printf("\rRunning.");
            Sleep(500);
            printf("\rRunning..");
            Sleep(500);
            printf("\rRunning...");
            Sleep(500);
            printf("\b\b   ");
        }
    }
    



    HANDLE hProcess;
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL)
    {
        printf("[!]OpenProcess Failed.<%d>\n", GetLastError());
        return 0;
    }
    _NtQueryInformationProcess NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("NtDll.dll"), "NtQueryInformationProcess");
    if (!NtQueryInformationProcess)
    {
        printf("[!]Could not find NtQueryInformationProcess entry point in NTDLL.DLL\n");
        return 0;
    }
    NTSTATUS status;
    ULONG breakOnTermination;
    status = NtQueryInformationProcess(hProcess, ProcessBreakOnTermination, &breakOnTermination, sizeof(ULONG), NULL);
    if (status < 0)
        printf("[!]NtQueryInformationProcess error\n");

    // 若进程为 critical 状态，强制结束进程将会发生蓝屏
    if (breakOnTermination == 1)

        printf("[+]The process is critical\n");
    else
        printf("[!]The process is not critical\n");
    return 0;
}
