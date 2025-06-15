#include <windows.h>
#include <iostream>
#include <string>
#include <vector>

#include "Shared.h" 

void ShowUsage() {
    std::wcout << L"Usage: Controller.exe <command> [options]" << std::endl;
    std::wcout << L"Commands:" << std::endl;
    std::wcout << L"  resume_all        - Resumes all suspended processes." << std::endl;
    std::wcout << L"  resume <pid>      - Resumes a specific process by its ID." << std::endl;
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        ShowUsage();
        return 1;
    }

    HANDLE hDevice = CreateFileW(L"\\\\.\\StartSuspended", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hDevice == INVALID_HANDLE_VALUE) {
        std::wcerr << L"Failed to open device. Error: " << GetLastError() << std::endl;
        std::wcerr << L"(Is the driver loaded? Are you running as Administrator?)" << std::endl;
        return 1;
    }

    std::wstring command = argv[1];
    BOOL success = FALSE;
    DWORD bytesReturned = 0;

    if (command == L"resume_all") {
        success = DeviceIoControl(hDevice, IOCTL_STARTSUSPENDED_RESUME_ALL, nullptr, 0, nullptr, 0, &bytesReturned, nullptr);
        if (success) {
            std::wcout << L"Resume all request sent successfully." << std::endl;
        }
    }
    else if (command == L"resume" && argc > 2) {
        ULONG pid = _wtoi(argv[2]);
        if (pid == 0) {
            std::wcerr << L"Invalid PID." << std::endl;
        }
        else {
            success = DeviceIoControl(hDevice, IOCTL_STARTSUSPENDED_RESUME_BY_PID, &pid, sizeof(pid), nullptr, 0, &bytesReturned, nullptr);
            if (success) {
                std::wcout << L"Resume request for PID " << pid << " sent successfully." << std::endl;
            }
        }
    }
    else {
        ShowUsage();
    }

    if (!success) {
        std::wcerr << L"DeviceIoControl failed. Error: " << GetLastError() << std::endl;
    }

    CloseHandle(hDevice);
    return success ? 0 : 1;
}