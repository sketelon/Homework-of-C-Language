#include <windows.h>
#include <stdio.h>
#include <conio.h>
#include <tchar.h>
#pragma comment(lib,"Advapi32.lib") 

#define BUF_SIZE 256

/*???没明白*/

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        printf("\nCreateFileMapping\n\n");
        printf("Usage:\n");
        printf("%s <string>\n", argv[0]);
        return 0;
    }

    HANDLE hMapFile1, hMapFile2;
    char *pBuf;
    char *pBuf2;
    char szName1[] = "Global\\SharedMappingObject1";
    char szName2[] = "Global\\SharedMappingObject2";
    DWORD EventRecordID = 32;
    DWORD offset = 0x11;

    char szOffset[8];
    sprintf_s(szOffset, "%d", offset);

    printf("[*]Try to set SecurityDescriptor... ");

    // 没看懂这段设置安全描述符啥意思
    /*
    当把程序放到服务器上并运行,然后用远程桌面连接服务器时的用户身份作为了另一用户,这时运行访问共享内存的程序将产生错误[代码是2]。
    根据错误代码认为是权限问题,通常会去添加安全描述符,也就是设置CreateFileMapping的LPSECURITY_ATTRIBUTES参数,会这样做：
    */
    PSECURITY_DESCRIPTOR pSec = (PSECURITY_DESCRIPTOR)LocalAlloc(LMEM_FIXED, SECURITY_DESCRIPTOR_MIN_LENGTH);
    if (!pSec)
    {
        return GetLastError();
    }
    if (!InitializeSecurityDescriptor(pSec, SECURITY_DESCRIPTOR_REVISION))
    {
        LocalFree(pSec);
        return GetLastError();
    }
    if (!SetSecurityDescriptorDacl(pSec, TRUE, NULL, TRUE))
    {
        LocalFree(pSec);
        return GetLastError();
    }
    SECURITY_ATTRIBUTES attr;
    attr.bInheritHandle = FALSE;
    attr.lpSecurityDescriptor = pSec;
    attr.nLength = sizeof(SECURITY_ATTRIBUTES);
    printf("Done\n");
    
    printf("[*]Try to CreateFileMapping1... ");
    // INVALID_HANDLE_VALUE 表示创建内存空间
    hMapFile1 = CreateFileMapping(INVALID_HANDLE_VALUE, &attr, PAGE_READWRITE, 0, BUF_SIZE, szName1);
    if (hMapFile1 == NULL)
    {
        printf("\n[!]Could not create file mapping object1 (%d).\n", GetLastError());
        return 0;
    }
    pBuf = (char *)MapViewOfFile(hMapFile1, FILE_MAP_ALL_ACCESS, 0, 0, BUF_SIZE);
    if (pBuf == NULL)
    {
        printf("\n[!]Could not map view of file1 (%d).\n", GetLastError());
        CloseHandle(hMapFile1);
        return 1;
    }
    CopyMemory((PVOID)pBuf, argv[1], strlen(argv[1]));

    printf("Done\n");

    printf("[*]Try to CreateFileMapping2... ");

    hMapFile2 = CreateFileMapping(INVALID_HANDLE_VALUE, &attr, PAGE_READWRITE, 0, BUF_SIZE, szName2);
    if (hMapFile2 == NULL)
    {
        printf("\n[!]Could not create file mapping object2 (%d).\n", GetLastError());
        return 0;
    }
    pBuf2 = (char *)MapViewOfFile(hMapFile2, FILE_MAP_ALL_ACCESS, 0, 0, BUF_SIZE);
    if (pBuf2 == NULL)
    {
        printf("\n[!]Could not map view of file2 (%d).\n", GetLastError());
        CloseHandle(hMapFile2);
        return 1;
    }
    CopyMemory((PVOID)pBuf2, szOffset, strlen(szOffset));

    printf("Done\n");

    printf("Waiting...\n");
    printf("[+]You can input something to stop waiting\n");
    _getch();

    printf("[*]Free\n");
    LocalFree(pSec);
    UnmapViewOfFile(pBuf);
    CloseHandle(hMapFile1);
    UnmapViewOfFile(pBuf2);
    CloseHandle(hMapFile2);

    return 0;
}
