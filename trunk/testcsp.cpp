#include "stdafx.h"
#include <windows.h>
#include <wincrypt.h>

typedef HCRYPTPROV (WINAPI *pI_CryptGetDefaultCryptProv)(ALG_ID algid);
HCRYPTPROV        hProv = NULL;

typedef int (__stdcall *def_CryptExtOpenCER)(
    HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow);
def_CryptExtOpenCER CryptExtOpenCER;

typedef int (__stdcall *def_MyProc)(void);
def_MyProc MyProc;

#define PATCH_NUM 2
char *patch_list[2*PATCH_NUM]={
    "ADVAPI32.dll","SystemFunction035",            //i=0
    "CRYPT32.dll","I_CryptGetDefaultCryptProv"     //i=1
};

void WriteMem(int pos, char *patch, int len)
{
    DWORD my_id = GetCurrentProcessId();
    HANDLE p_hand = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, NULL, my_id);
    if (WriteProcessMemory(p_hand, (LPDWORD)pos, patch, len, NULL)==0) {
        printf("Error write to memory\nHint: run from Administrator rigths");
    }
    CloseHandle(p_hand);
}

HCRYPTPROV PASCAL old_I_CryptGetDefaultCryptProv(int AlgID) //call MS Provider
{
    __asm mov eax,0; //достаточно 10 байт
    __asm mov eax,0;
    return NULL;
}

HCRYPTPROV PASCAL my_I_CryptGetDefaultCryptProv(int AlgID)
{
    if (AlgID!=0 && AlgID!=0x2036) 
        return old_I_CryptGetDefaultCryptProv(AlgID); //old MS
    return hProv;
}

int StartPatch(void)
{
    BYTE *p;
    HMODULE h_dll;
    char buf[10];
    DWORD new_addr;
    for(int i=0;i<PATCH_NUM;i++)
    {
        h_dll = LoadLibrary(patch_list[i*2]);
        if (h_dll==NULL) 
        {
            printf("Error! Can not LoadLibrary(%s)\n", patch_list[i*2]);
            return 1;
        }
        MyProc = (def_MyProc)GetProcAddress(h_dll, patch_list[i*2+1]);
        if (MyProc==NULL)
        {
            printf("Error! Can not GetProcAddress(%s)\n", patch_list[i*2+1]);
            return 1;
        }

        p = (BYTE*)MyProc;
        if (i==1)
        {
            memcpy(buf, p, 5);

            buf[5]=0xe9;
            new_addr = (DWORD)p;
            new_addr -= (DWORD)old_I_CryptGetDefaultCryptProv;
            new_addr -= 5;
            memcpy(buf+6, &new_addr, 4);
            WriteMem((DWORD)old_I_CryptGetDefaultCryptProv, buf, 10);

            buf[0]=0xe9;
            new_addr = (DWORD)my_I_CryptGetDefaultCryptProv;
            new_addr -= (DWORD)MyProc;
            new_addr -= 5;
            memcpy(buf+1, &new_addr, 4);
            WriteMem((DWORD)MyProc, buf, 5);
        }
        else
        {
            WriteMem((int)p, "\xb8\x01\x00\x00\x00\xC2\x04\x00", 8); //mov ax,1 - ret 4
        }
    }
    return 0;
}

int RunCert(char *certName)
{
    HMODULE h_dll;
    h_dll = LoadLibrary("C:\\windows\\system32\\CRYPTEXT.dll");
    if (h_dll==NULL) return 1;
    CryptExtOpenCER = (def_CryptExtOpenCER)GetProcAddress(h_dll, "CryptExtOpenCER");
    if (CryptExtOpenCER==NULL) return 2;
       CryptExtOpenCER(NULL, NULL, certName, SW_SHOW);
    FreeLibrary(h_dll);
    return 0;
}

int _tmain(int argc, _TCHAR* argv[])
{
    if (StartPatch())
    {
        printf("Error Patch\n");
        return 1;
    }

    if (RCRYPT_FAILED(CryptAcquireContext(&hProv, "test", NULL, 123, 0)))
    {
        printf("CryptAcquireConext returned error %x\n", GetLastError());
        printf("FAILED\n");
        return 1;
    }
    printf("SUCCEED\n");

    RunCert("gnivc_2006.cer");
    RunCert("rootsber.cer");
    
    return 0;
}
