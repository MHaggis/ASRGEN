//Block credential stealing from the Windows local security authority subsystem (lsass.exe)
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>

DWORD FindLsassProcess() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, &pe32)) {
            do {
                WCHAR wText[260];
                MultiByteToWideChar(CP_ACP, 0, pe32.szExeFile, -1, wText, 260);

                if (_wcsicmp(wText, L"lsass.exe") == 0) {
                    CloseHandle(hSnapshot);
                    return pe32.th32ProcessID;
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
    return 0;
}

int main() {
    DWORD lsassPID = FindLsassProcess();
    if (lsassPID) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, lsassPID);
        if (hProcess != NULL) {
            std::cout << "Successfully opened a handle to LSASS." << std::endl;
            CloseHandle(hProcess);
        } else {
            std::cout << "Failed to open a handle to LSASS." << std::endl;
        }
    } else {
        std::cout << "LSASS process not found." << std::endl;
    }

    return 0;
}
