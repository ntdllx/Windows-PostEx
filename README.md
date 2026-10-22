# Windows-PostEx

**English** | [简体中文](README.zh.md) | [繁體中文](README.zh-Hant.md) | [日本語](README.ja.md) | [Français](README.fr.md) | [Deutsch](README.de.md) | [Español](README.es.md)

This project is aimed at security professionals with some background. It is "semi-weaponized": it sits between a toy demo and a real threat. Every tool runs on real Windows, but I deliberately leave some flaws so it is not treated as a finished product. **I make no guarantees about the robustness of any of this code; the point is to demonstrate ideas, not to create threats.**

Most of the functionality was extracted from my own C2. The plan is to cover the main parts of the Windows post-exploitation chain, including but not limited to Execution, Lateral Movement, Privilege Escalation, Persistence, and Credential Theft. Whether all of it gets implemented depends on risk and time; I make no actual promises.

## Execution

Run code in the current process without going through the normal DLL loading path. Payloads are read into memory and are not written to disk again.

- `Execution/coffldr`: maps an AMD64 COFF object into the current process, resolves symbols, applies relocations, sets page permissions, then calls the entry point. Detection surface: RX pages with no module record. Deliberately no exception table, so objects that use SEH do not work, and a crash in the entry point takes down the host.

- `Execution/refldr`: the host places the DLL in an executable buffer in file layout and calls the payload's own ReflectiveLoad; mapping, imports, and the other tables are handled inside the payload. The image is MEM_PRIVATE and absent from the loader list; unload only does DETACH and removes the function table, it does not free the image. Handle with care.

- `Execution/peloader`: host-side mapping. Image mode uses SEC_IMAGE to bypass LdrLoadDll; stomp mode writes the payload into an executable section of an already loaded module. Detection: image mode is MEM_IMAGE but absent from the loader list; in stomp mode the host section no longer matches the file on disk. Deliberately no CFG / load config handling, and the stomp host cannot be chosen arbitrarily.

- `Execution/clrldr`: loads a .NET Framework 4 assembly into a private AppDomain, and can also run Windows PowerShell 5.1 through the SMA in the GAC without starting powershell.exe. Detection surface: mscoree/clr/mscorlib are loaded, and AMSI/ETW see the activity. Deliberately .NET Framework 4 only, no AMSI/ETW patching, no automatic dependency resolution from the payload directory, and the domain stays resident.

clrldr's CLR host and COM vtable layout are based on [Havoc](https://github.com/HavocFramework/Havoc)'s Clr.h, with my own changes.

## Size

The repository does not include build scripts. Built for x64 Release without the CRT, the native binaries target roughly:

- coffldr: ~15 KB
- refldr: ~9 KB
- peloader: ~15 KB
- clrldr: ~21 KB (including the embedded managed runner)

Actual sizes vary with compiler and optimization settings. Development builds include selftest, inspect, and readable errors, so they are much larger and are not listed here.

## Usage

The examples below assume you have built the native binaries into `Execution/bin` and that payloads are in the current directory, or use real paths.

```bat
REM COFF: map the object and call its entry point; --args is comma-separated
bin\coffldr.exe run hello.obj
bin\coffldr.exe run hello.obj --args alpha,42 --entry go

REM Reflective DLL: call the payload's ReflectiveLoad
bin\refldr.exe run payload.dll --export Run

REM Host-side mapping: SEC_IMAGE, or write into an executable section of a loaded module
bin\peloader.exe map payload.dll --mode image --export Run
bin\peloader.exe map payload.dll --mode stomp --host winhttp.dll --export Run

REM CLR: an assembly, or Windows PowerShell 5.1
bin\clrldr.exe run tool.dll --args "alpha beta"
bin\clrldr.exe ps "Get-Process | Select-Object -First 3"
```

Native builds only print results; check the exit code on failure. Use the matching `*-dev.exe` when you need readable errors, `selftest`, or `inspect`. `--args` is comma-separated for coffldr and space-separated for clrldr.

## Notes

These are dual-use offensive techniques. Use them only in environments you own or are authorized to test. The flaws described above are intentional boundaries, not oversights.
