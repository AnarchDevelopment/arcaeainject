#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>

std::string WCharToString(const WCHAR* wstr) {
    if (!wstr) return "";
    int size = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
    if (size <= 0) return "";
    std::string result(size - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &result[0], size, NULL, NULL);
    return result;
}
std::wstring StringToWString(const std::string& str) {
    if (str.empty()) return L"";
    int size = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, NULL, 0);
    if (size <= 0) return L"";
    std::wstring result(size - 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &result[0], size);
    return result;
}
DWORD GetProcId(const char *procName) {
    DWORD procId = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W procEntry;
        procEntry.dwSize = sizeof(procEntry);
        if (Process32FirstW(hSnap, &procEntry)) {
            do {
                std::string currentProcName = WCharToString(procEntry.szExeFile);
                std::string searchName = procName;
                std::transform(currentProcName.begin(), currentProcName.end(), currentProcName.begin(), ::tolower);
                std::transform(searchName.begin(), searchName.end(), searchName.begin(), ::tolower);
                if (currentProcName == searchName || currentProcName.find(searchName) != std::string::npos) {
                    procId = procEntry.th32ProcessID;
                    break;
                }
            } while (Process32NextW(hSnap, &procEntry));
        }
    }
    CloseHandle(hSnap);
    return procId;
}
bool performInjection(DWORD procId, const wchar_t *dllPath) {
    HANDLE hProc = OpenProcess(
        PROCESS_CREATE_THREAD | 
        PROCESS_QUERY_INFORMATION | 
        PROCESS_VM_OPERATION | 
        PROCESS_VM_WRITE | 
        PROCESS_VM_READ, 
        0, 
        procId
    );
    if (!hProc || hProc == INVALID_HANDLE_VALUE) {
        std::cerr << "[!] Failed to open process. Error: " << GetLastError() << std::endl;
        return false;
    }
    size_t dllPathSize = (wcslen(dllPath) + 1) * sizeof(wchar_t);
    void *loc = VirtualAllocEx(hProc, NULL, dllPathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!loc) {
        std::cerr << "[!] Failed to allocate memory in target process. Error: " << GetLastError() << std::endl;
        CloseHandle(hProc);
        return false;
    }
    if (!WriteProcessMemory(hProc, loc, dllPath, dllPathSize, NULL)) {
        std::cerr << "[!] Failed to write memory in target process. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProc, loc, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }
    LPVOID pLoadLibrary = (LPVOID)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    if (!pLoadLibrary) {
        std::cerr << "[!] Failed to get LoadLibraryW address. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProc, loc, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }
    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibrary, loc, 0, NULL);
    
    if (!hThread) {
        std::cerr << "[!] Failed to create remote thread. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProc, loc, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }
    WaitForSingleObject(hThread, 5000);
    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    
    CloseHandle(hThread);
    VirtualFreeEx(hProc, loc, 0, MEM_RELEASE);
    CloseHandle(hProc);
    
    return exitCode != 0;
}
int main(int argc, char* argv[]) {
    BOOL fIsRunAsAdmin = FALSE;
    PSID pAdministratorsGroup = NULL;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(
        &NtAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0, &pAdministratorsGroup))
    {
        CheckTokenMembership(NULL, pAdministratorsGroup, &fIsRunAsAdmin);
        FreeSid(pAdministratorsGroup);
    }
    if (!fIsRunAsAdmin) {
        std::cerr << "You must run the current shell as an administrator." << std::endl;
        return 1;
    }

    if (argc != 3) {
        std::string exeName = argv[0];
        size_t lastSlash = exeName.find_last_of("\\/");
        if (lastSlash != std::string::npos) {
            exeName = exeName.substr(lastSlash + 1);
        }
        std::cout << "Usage: " << exeName << " (proc_name) (dll_path)" << std::endl;
        return 1;
    }
    const char* processName = argv[1];
    const char* dllPath = argv[2];
    DWORD dwAttrib = GetFileAttributesA(dllPath);
    if (dwAttrib == INVALID_FILE_ATTRIBUTES) {
        std::cerr << "Error: DLL file not found: " << dllPath << std::endl;
        return 1;
    }
    if (dwAttrib & FILE_ATTRIBUTE_DIRECTORY) {
        std::cerr << "Error: Path is a directory, not a DLL: " << dllPath << std::endl;
        return 1;
    }
    char fullPathA[MAX_PATH];
    if (!GetFullPathNameA(dllPath, MAX_PATH, fullPathA, NULL)) {
        std::cerr << "Error: Failed to get full path of DLL" << std::endl;
        return 1;
    }
    std::cout << "[*] Looking for process: " << processName << std::endl;
    DWORD procId = GetProcId(processName);
    if (!procId) {
        std::cerr << "Error: Process '" << processName << "' not found." << std::endl;
        return 1;
    }
    std::cout << "[+] Found process PID: " << procId << std::endl;
    std::cout << "[*] DLL full path: " << fullPathA << std::endl;  
    BOOL isWow64 = FALSE;
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, procId);
    if (hProcess) {
        typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
        LPFN_ISWOW64PROCESS fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandleW(L"kernel32"), "IsWow64Process");
        if (fnIsWow64Process) {
            fnIsWow64Process(hProcess, &isWow64);
            std::cout << "[*] Target process architecture: " << (isWow64 ? "32-bit (running on 64-bit)" : 
#ifdef _WIN64
            "64-bit"
#else
            "32-bit"
#endif
            ) << std::endl;
        }
        CloseHandle(hProcess);
    }
    std::wstring wDllPath = StringToWString(fullPathA);   
    std::wcout << L"[*] Injecting DLL into process..." << std::endl;   
    if (performInjection(procId, wDllPath.c_str())) {
        std::wcout << L"[*] Succesfully injected " << wDllPath << L" | PID: " << procId << std::endl;
        return 0;
    } else {
        std::cerr << "[-] Failed to inject DLL" << std::endl;
        std::cerr << "Possible reasons:" << std::endl;
        std::cerr << "  - DLL architecture mismatch (32-bit vs 64-bit)" << std::endl;
        std::cerr << "  - DLL has missing dependencies" << std::endl;
        std::cerr << "  - Process protected by PPL (Protected Process Light)" << std::endl;
        std::cerr << "  - Anti-cheat software blocking injection" << std::endl;
        return 1;
    }
}