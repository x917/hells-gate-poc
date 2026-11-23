# hells-gate-poc

*created while sleep deprived*

resolves `ntdll!NtYieldExecution` syscall number from ntdll at runtime, builds an 11-byte syscall stub, injects it into notepad.exe, and runs it via `CreateRemoteThread`. the stub calls the syscall directly so it skips the ntdll stub user-mode hooks get bypassed.

the stub gets placed at a deliberately high address (>= 0x7001_0000_0000) instead of letting the OS pick. lands outside the heap/DLL ranges EDRs walk most heavily; the loop tries 4 GB-spaced candidates in case one is taken.

`NtYieldExecution` is a no-op so nothing visible happens in notepad. this just proves the path works.

x64 only. process-injection PoC only run in a VM you own, against processes you own.
