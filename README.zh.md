# Windows-PostEx

[English](README.md) | **简体中文** | [繁體中文](README.zh-Hant.md) | [日本語](README.ja.md) | [Français](README.fr.md) | [Deutsch](README.de.md) | [Español](README.es.md)

本项目面向有一定基础的安全专业人员，定位是“半武器化”：在玩具 demo 和真实威胁之间找一个平衡点。每个工具都能在真实 Windows 上跑通，但我会刻意留下一些缺陷，避免它被直接当成成品使用。**我不对其中任何代码的健壮性做保证，本意在于体现思路，而非制造威胁。**

功能基本是从我自研的 C2 里独立拆出来的。计划覆盖 Windows 后渗透的主要核心环节，包括但不限于 Execution、Lateral Movement、Privilege Escalation、Persistence、Credential Theft 等；是否全部实现取决于风险和精力，在此不做任何实际的承诺。

## Execution

在当前进程里执行代码，不经过常规的 DLL 加载路径。payload 读进内存后不再写盘。

- `Execution/coffldr`：把 AMD64 COFF 对象映射进当前进程，解析符号、做重定位、按页设权限，然后调用入口。检测面是进程里出现没有模块记录的 RX 页；刻意不注册异常表，所以带 SEH 的对象不能用，入口崩溃也会带走宿主。

- `Execution/refldr`：宿主把 DLL 按文件布局放进可执行缓冲，调用 payload 自带的 ReflectiveLoad，映射、导入等表都在 payload 里完成。映像是 MEM_PRIVATE、不在加载器链表；卸载只做 DETACH 和删表，不释放映像，自行注意。

- `Execution/peloader`：宿主侧映射，image 模式用 SEC_IMAGE 绕过 LdrLoadDll，stomp 模式把 payload 写进已加载模块的可执行节。前者是 MEM_IMAGE 但不在加载器链表，后者是宿主节内容和磁盘文件对不上；刻意不处理 CFG / load config，stomp 的宿主也不能随便选。

- `Execution/clrldr`：把 .NET Framework 4 程序集读进私有 AppDomain 执行，也能通过 GAC 里的 SMA 跑 Windows PowerShell 5.1，不启动 powershell.exe。检测面是 mscoree/clr/mscorlib 的加载、AMSI 和 ETW；刻意只支持 .NET Framework 4，不 patch AMSI/ETW，不自动解析同目录依赖，域常驻不卸载。

clrldr 的 CLR 宿主和 COM vtable 布局参考了 [Havoc](https://github.com/HavocFramework/Havoc) 的 Clr.h，我在此基础上做了改造。

## 体积

仓库不附带构建脚本。按 x64 Release、不链接 CRT 的方式编译时，原生版的目标体积大致是：

- coffldr：约 15 KB
- refldr：约 9 KB
- peloader：约 15 KB
- clrldr：约 21 KB（含内嵌的托管 runner）

具体大小会随编译器和优化选项浮动。开发版带 selftest、inspect 和可读错误，体积会大很多，不在这里列。

## 用法

下面假设你已经把原生版编译到 `Execution/bin`，payload 放在当前目录，或者换成实际路径。

```bat
REM COFF：映射对象并调用入口，--args 是逗号分隔
bin\coffldr.exe run hello.obj
bin\coffldr.exe run hello.obj --args alpha,42 --entry go

REM 反射 DLL：调用 payload 内的 ReflectiveLoad
bin\refldr.exe run payload.dll --export Run

REM 宿主映射：SEC_IMAGE，或者写进已加载模块的可执行节
bin\peloader.exe map payload.dll --mode image --export Run
bin\peloader.exe map payload.dll --mode stomp --host winhttp.dll --export Run

REM CLR：程序集，或者 Windows PowerShell 5.1
bin\clrldr.exe run tool.dll --args "alpha beta"
bin\clrldr.exe ps "Get-Process | Select-Object -First 3"
```

原生版只输出结果，失败时看退出码；需要可读错误、`selftest` 或 `inspect` 时用对应的 `*-dev.exe`。`--args` 在 coffldr 里是逗号分隔，在 clrldr 里是空格分隔。

## 说明

这些是双用途的攻击技术，只在你拥有或获授权的环境中使用。上面写到的缺陷不是遗漏，是刻意留下的边界。
