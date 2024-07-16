#include <windows.h>
#include <tlhelp32.h>
#include <iostream>

using namespace std;

void ListProcesses() {
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;
    cout << "[+] Retrieving all informations from the current process" << endl;
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "CreateToolhelp32Snapshot failed." << std::endl;
        return;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hProcessSnap, &pe32)) {
        CloseHandle(hProcessSnap);
        std::cerr << "Process32First failed." << std::endl;
        return;
    }

    cout << "[+] Listing all process name : " << endl;

    do {
        wcout << "   - Process [ID], \"name\": [" << pe32.th32ProcessID << "] " << pe32.szExeFile  << endl;
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
}

int main() {
    ListProcesses();
    return 0;
}
