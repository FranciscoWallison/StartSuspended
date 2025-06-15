#include <iostream>
#define WIN32_NO_STATUS
#include <windows.h>
#include <ntstatus.h>
#include <winternl.h> // Necessário para UNICODE_STRING

// Constante para verificar colisao de nome ao carregar o driver
#ifndef STATUS_OBJECT_NAME_COLLISION
#define STATUS_OBJECT_NAME_COLLISION ((NTSTATUS)0xC0000035L)
#endif

#ifndef STATUS_IMAGE_ALREADY_LOADED
#define STATUS_IMAGE_ALREADY_LOADED ((NTSTATUS)0xc000010E)
#endif

// --- Definições e Protótipos para a API Nativa ---

// Protótipo da função NtLoadDriver
typedef NTSTATUS(NTAPI* pNtLoadDriver)(IN PUNICODE_STRING DriverService);
// Protótipo da função NtUnloadDriver
typedef NTSTATUS(NTAPI* pNtUnloadDriver)(IN PUNICODE_STRING DriverService);

// Função para inicializar uma UNICODE_STRING
void RtlInitUnicodeString(PUNICODE_STRING destination, PCWSTR source) {
    if (source) {
        destination->Length = (USHORT)wcslen(source) * sizeof(WCHAR);
        destination->MaximumLength = destination->Length + sizeof(WCHAR);
    }
    else {
        destination->Length = 0;
        destination->MaximumLength = 0;
    }
    destination->Buffer = (PWSTR)source;
}

// Função para habilitar o privilégio SeLoadDriverPrivilege
BOOL EnablePrivilege(const wchar_t* privilegeName) {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        std::cerr << "OpenProcessToken failed. Error: " << GetLastError() << std::endl;
        return FALSE;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!LookupPrivilegeValue(NULL, privilegeName, &tp.Privileges[0].Luid)) {
        std::cerr << "LookupPrivilegeValue failed. Error: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return FALSE;
    }

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        std::cerr << "AdjustTokenPrivileges failed. Error: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        std::cerr << "The token does not have the specified privilege." << std::endl;
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);
    return TRUE;
}


int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2 || (wcscmp(argv[1], L"load") != 0 && wcscmp(argv[1], L"unload") != 0)) {
        std::wcout << L"Usage: NtLoader.exe <load | unload>" << std::endl;
        return 1;
    }

    std::wcout << L"Attempting to enable SeLoadDriverPrivilege..." << std::endl;
    if (!EnablePrivilege(SE_LOAD_DRIVER_NAME)) {
        std::cerr << "Failed to enable SeLoadDriverPrivilege. Please run as Administrator." << std::endl;
        return 1;
    }
    std::wcout << L"Privilege enabled successfully." << std::endl;

    // Carrega a ntdll e obtém o endereço das funções
    HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
    if (hNtdll == NULL) {
        std::cerr << "Failed to get handle to ntdll.dll" << std::endl;
        return 1;
    }

    // Prepara o nome do serviço no formato que a API Nativa espera
    UNICODE_STRING driverService;
    RtlInitUnicodeString(&driverService, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\StartSuspended");

    NTSTATUS status;

    if (wcscmp(argv[1], L"load") == 0) {
        pNtLoadDriver NtLoadDriver = (pNtLoadDriver)GetProcAddress(hNtdll, "NtLoadDriver");
        if (NtLoadDriver == NULL) {
            std::cerr << "Failed to get address of NtLoadDriver" << std::endl;
            return 1;
        }

        std::wcout << L"Calling NtLoadDriver..." << std::endl;
        status = NtLoadDriver(&driverService);

        if (status == STATUS_OBJECT_NAME_COLLISION || status == STATUS_IMAGE_ALREADY_LOADED) {
            std::wcout << L"Driver already loaded. Attempting to unload and reload..." << std::endl;
            pNtUnloadDriver NtUnloadDriver = (pNtUnloadDriver)GetProcAddress(hNtdll, "NtUnloadDriver");
            if (NtUnloadDriver) {
                NtUnloadDriver(&driverService);
                status = NtLoadDriver(&driverService);
            }
        }

        if (status == 0) { // STATUS_SUCCESS
            std::wcout << L"Driver loaded successfully!" << std::endl;
        }
        else {
            std::wcerr << L"NtLoadDriver failed with status: 0x" << std::hex << status << std::endl;
        }
    }
    else { // "unload"
        pNtUnloadDriver NtUnloadDriver = (pNtUnloadDriver)GetProcAddress(hNtdll, "NtUnloadDriver");
        if (NtUnloadDriver == NULL) {
            std::cerr << "Failed to get address of NtUnloadDriver" << std::endl;
            return 1;
        }

        std::wcout << L"Calling NtUnloadDriver..." << std::endl;
        status = NtUnloadDriver(&driverService);

        if (status == 0) { // STATUS_SUCCESS
            std::wcout << L"Driver unloaded successfully!" << std::endl;
        }
        else {
            std::wcerr << L"NtUnloadDriver failed with status: 0x" << std::hex << status << std::endl;
        }
    }

    return (status == 0) ? 0 : 1;
}