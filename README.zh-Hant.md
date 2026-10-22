# Windows-PostEx

[English](README.md) | [简体中文](README.zh.md) | **繁體中文** | [日本語](README.ja.md) | [Français](README.fr.md) | [Deutsch](README.de.md) | [Español](README.es.md)

本專案面向具備一定基礎的資安專業人員，定位是「半武器化」：在玩具 demo 與真實威脅之間取得平衡。每個工具都能在真實 Windows 上跑通，但我會刻意留下一些缺陷，避免它被直接當成成品使用。**我不對其中任何程式碼的健壯性做保證，本意是體現思路，而非製造威脅。**

功能基本上是從我自行開發的 C2 中獨立拆出來的。計畫涵蓋 Windows 後滲透的主要核心環節，包括但不限於 Execution、Lateral Movement、Privilege Escalation、Persistence、Credential Theft 等；是否全部實作取決於風險與精力，在此不做任何實際承諾。

## Execution

在目前行程內執行程式碼，不經過常規的 DLL 載入路徑。payload 讀進記憶體後不再寫入磁碟。

- `Execution/coffldr`：把 AMD64 COFF 物件映射進目前行程，解析符號、做重定位、依頁面設定權限，然後呼叫進入點。偵測面是行程中出現沒有模組記錄的 RX 頁面；刻意不註冊例外表，所以使用 SEH 的物件無法運作，進入點崩潰也會帶走宿主。

- `Execution/refldr`：宿主把 DLL 依檔案佈局放進可執行緩衝區，呼叫 payload 自帶的 ReflectiveLoad，映射、匯入等表都在 payload 內完成。映像是 MEM_PRIVATE、不在載入器清單中；卸載只做 DETACH 和刪表，不釋放映像，請自行注意。

- `Execution/peloader`：宿主端映射，image 模式用 SEC_IMAGE 繞過 LdrLoadDll，stomp 模式把 payload 寫進已載入模組的可執行節區。前者是 MEM_IMAGE 但不在載入器清單，後者是宿主節區內容與磁碟檔案不一致；刻意不處理 CFG / load config，stomp 的宿主也不能隨便選。

- `Execution/clrldr`：把 .NET Framework 4 組件讀進私有 AppDomain 執行，也能透過 GAC 裡的 SMA 執行 Windows PowerShell 5.1，不啟動 powershell.exe。偵測面是 mscoree/clr/mscorlib 的載入、AMSI 和 ETW；刻意只支援 .NET Framework 4，不 patch AMSI/ETW，不自動解析同目錄相依性，網域常駐不卸載。

clrldr 的 CLR 宿主與 COM vtable 佈局參考了 [Havoc](https://github.com/HavocFramework/Havoc) 的 Clr.h，我在此基礎上做了改造。

## 體積

倉庫不附帶建置腳本。以 x64 Release、不連結 CRT 的方式編譯時，原生版的目標體積大致是：

- coffldr：約 15 KB
- refldr：約 9 KB
- peloader：約 15 KB
- clrldr：約 21 KB（含內嵌的受管理 runner）

具體大小會隨編譯器與最佳化選項浮動。開發版包含 selftest、inspect 與可讀錯誤，體積會大很多，不在此列出。

## 用法

以下假設你已把原生版編譯到 `Execution/bin`，payload 放在目前目錄，或換成實際路徑。

```bat
REM COFF：映射物件並呼叫進入點，--args 以逗號分隔
bin\coffldr.exe run hello.obj
bin\coffldr.exe run hello.obj --args alpha,42 --entry go

REM 反射 DLL：呼叫 payload 內的 ReflectiveLoad
bin\refldr.exe run payload.dll --export Run

REM 宿主端映射：SEC_IMAGE，或寫入已載入模組的可執行節區
bin\peloader.exe map payload.dll --mode image --export Run
bin\peloader.exe map payload.dll --mode stomp --host winhttp.dll --export Run

REM CLR：組件，或 Windows PowerShell 5.1
bin\clrldr.exe run tool.dll --args "alpha beta"
bin\clrldr.exe ps "Get-Process | Select-Object -First 3"
```

原生版只輸出結果，失敗時看結束代碼；需要可讀錯誤、`selftest` 或 `inspect` 時用對應的 `*-dev.exe`。`--args` 在 coffldr 裡是逗號分隔，在 clrldr 裡是空格分隔。

## 說明

這些是雙用途的攻擊技術，只在你擁有或獲授權的環境中使用。上面寫到的缺陷不是遺漏，是刻意留下的邊界。
