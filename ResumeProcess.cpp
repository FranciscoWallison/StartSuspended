#include <windows.h>
#include <iostream>

#define IOCTL_STARTSUSPENDED_RESUME CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

int wmain() {
    HANDLE h = CreateFileW(L"\\\\.\\StartSuspended", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        std::wcerr << L"Failed to open device" << std::endl;
        return 1;
    }

    DWORD bytes = 0;
    BOOL ok = DeviceIoControl(h, IOCTL_STARTSUSPENDED_RESUME, nullptr, 0, nullptr, 0, &bytes, nullptr);
    if (!ok) {
        std::wcerr << L"DeviceIoControl failed: " << GetLastError() << std::endl;
        CloseHandle(h);
        return 1;
    }

    std::wcout << L"Resume request sent" << std::endl;
    CloseHandle(h);
    return 0;
}
