# Windows-PostEx

[English](README.md) | [简体中文](README.zh.md) | [繁體中文](README.zh-Hant.md) | **日本語** | [Français](README.fr.md) | [Deutsch](README.de.md) | [Español](README.es.md)

本プロジェクトは、ある程度の基礎を持つセキュリティ専門家を対象としています。「セミウェポナイズド」、つまりおもちゃのデモと現実の脅威の中間を狙ったものです。各ツールは実際の Windows 上で動作しますが、完成品として扱われないよう、意図的にいくつか欠陥を残しています。**コードの堅牢性は一切保証しません。目的はアイデアを示すことであり、脅威を作ることではありません。**

機能のほとんどは自作の C2 から切り出したものです。Windows ポストエクスプロイトの主要な要素、具体的には Execution、Lateral Movement、Privilege Escalation、Persistence、Credential Theft などを網羅する予定ですが、実装するかどうかはリスクと手間に依存します。ここでは具体的な約束はしません。

## Execution

通常の DLL 読み込み経路を通さず、現在のプロセス内でコードを実行します。payload はメモリに読み込まれ、その後ディスクに書き戻されることはありません。

- `Execution/coffldr`: AMD64 COFF オブジェクトを現在のプロセスにマップし、シンボル解決、リロケーション、ページ権限の設定を行ってからエントリポイントを呼び出します。検知面は、モジュール記録のない RX ページです。例外テーブルを登録しないため SEH を使うオブジェクトは動作せず、エントリポイントがクラッシュするとホストごと落ちます。

- `Execution/refldr`: ホストは DLL をファイルレイアウトのまま実行可能バッファに置き、payload 自身の ReflectiveLoad を呼び出します。マッピング、インポートなどのテーブルは payload 側で処理します。イメージは MEM_PRIVATE で、ローダーリストには載りません。アンロードは DETACH と関数テーブルの削除だけで、イメージは解放しません。扱いには注意してください。

- `Execution/peloader`: ホスト側でのマッピングです。image モードは SEC_IMAGE で LdrLoadDll を迂回し、stomp モードは読み込み済みモジュールの実行可能セクションに payload を書き込みます。検知面は、image モードでは MEM_IMAGE なのにローダーリストにないこと、stomp モードではホストのセクション内容がディスク上のファイルと一致しないことです。CFG / load config は意図的に処理せず、stomp のホストも任意には選べません。

- `Execution/clrldr`: .NET Framework 4 のアセンブリをプライベート AppDomain に読み込み、GAC の SMA 経由で Windows PowerShell 5.1 も powershell.exe を起動せずに実行できます。検知面は mscoree/clr/mscorlib の読み込み、AMSI、ETW です。意図的に .NET Framework 4 のみに対応し、AMSI/ETW はパッチせず、payload のディレクトリからの依存関係の自動解決も行わず、ドメインは常駐したままです。

clrldr の CLR ホストと COM vtable のレイアウトは、[Havoc](https://github.com/HavocFramework/Havoc) の Clr.h を参考にし、独自の変更を加えています。

## サイズ

リポジトリにビルドスクリプトは含まれていません。x64 Release、CRT 非リンクでビルドした場合のネイティブバイナリの目標サイズは、おおよそ次のとおりです。

- coffldr: 約 15 KB
- refldr: 約 9 KB
- peloader: 約 15 KB
- clrldr: 約 21 KB（埋め込まれたマネージド runner を含む）

実際のサイズはコンパイラや最適化オプションによって変動します。開発版は selftest、inspect、読みやすいエラーを含むため、はるかに大きくなり、ここには記載していません。

## 使い方

以下では、ネイティブバイナリを `Execution/bin` にビルド済みで、payload がカレントディレクトリにあるか、実際のパスを指定するものとします。

```bat
REM COFF: オブジェクトをマップしてエントリポイントを呼び出す。--args はカンマ区切り
bin\coffldr.exe run hello.obj
bin\coffldr.exe run hello.obj --args alpha,42 --entry go

REM リフレクティブ DLL: payload 内の ReflectiveLoad を呼び出す
bin\refldr.exe run payload.dll --export Run

REM ホスト側マッピング: SEC_IMAGE、または読み込み済みモジュールの実行可能セクションに書き込む
bin\peloader.exe map payload.dll --mode image --export Run
bin\peloader.exe map payload.dll --mode stomp --host winhttp.dll --export Run

REM CLR: アセンブリ、または Windows PowerShell 5.1
bin\clrldr.exe run tool.dll --args "alpha beta"
bin\clrldr.exe ps "Get-Process | Select-Object -First 3"
```

ネイティブ版は結果だけを出力します。失敗時は終了コードを確認してください。読みやすいエラー、`selftest`、`inspect` が必要な場合は、対応する `*-dev.exe` を使ってください。`--args` は coffldr ではカンマ区切り、clrldr では空白区切りです。

## 注意

これらはデュアルユースの攻撃技術です。自分が所有している環境、またはテストを許可された環境でのみ使用してください。上記の欠陥は見落としではなく、意図的に残した境界です。
