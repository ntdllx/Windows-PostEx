# Windows-PostEx

[English](README.md) | [简体中文](README.zh.md) | [繁體中文](README.zh-Hant.md) | [日本語](README.ja.md) | [Français](README.fr.md) | **Deutsch** | [Español](README.es.md)

Dieses Projekt richtet sich an Sicherheitsfachleute mit Grundkenntnissen. Es ist „halb weaponisiert“: angesiedelt zwischen einer Spielzeug-Demo und einer echten Bedrohung. Jedes Tool läuft auf echtem Windows, aber ich lasse absichtlich einige Schwächen, damit es nicht als fertiges Produkt behandelt wird. **Ich übernehme keine Garantie für die Robustheit dieses Codes; es geht darum, Ideen zu zeigen, nicht Bedrohungen zu erzeugen.**

Der Großteil der Funktionalität wurde aus meinem eigenen C2 herausgelöst. Geplant ist, die wesentlichen Teile der Windows-Post-Exploitation-Kette abzudecken, darunter Execution, Lateral Movement, Privilege Escalation, Persistence und Credential Theft. Ob alles umgesetzt wird, hängt von Risiko und Zeit ab; konkrete Zusagen mache ich hier nicht.

## Execution

Code im aktuellen Prozess ausführen, ohne den normalen DLL-Ladepfad zu verwenden. Payloads werden in den Speicher gelesen und nicht erneut auf die Festplatte geschrieben.

- `Execution/coffldr`: bildet ein AMD64-COFF-Objekt in den aktuellen Prozess ab, löst Symbole auf, wendet Relocations an, setzt den Seitenschutz und ruft den Einstiegspunkt auf. Erkennung: RX-Seiten ohne Moduleintrag. Bewusst keine Exception-Tabelle: Objekte mit SEH funktionieren nicht, und ein Absturz im Einstiegspunkt reißt den Host mit.

- `Execution/refldr`: Der Host legt die DLL im Dateilayout in einen ausführbaren Puffer und ruft das ReflectiveLoad des Payloads auf; Mapping, Importe und die übrigen Tabellen erledigt der Payload. Das Image ist MEM_PRIVATE und steht nicht in der Loader-Liste; beim Entladen wird nur DETACH ausgeführt und die Funktionstabelle entfernt, das Image aber nicht freigegeben. Mit Vorsicht behandeln.

- `Execution/peloader`: Mapping auf der Host-Seite. Der Image-Modus nutzt SEC_IMAGE, um LdrLoadDll zu umgehen; der Stomp-Modus schreibt den Payload in eine ausführbare Sektion eines bereits geladenen Moduls. Erkennung: Im Image-Modus ist es MEM_IMAGE, steht aber nicht in der Loader-Liste; im Stomp-Modus stimmt der Inhalt der Host-Sektion nicht mehr mit der Datei überein. CFG / Load Config werden bewusst nicht behandelt, und der Stomp-Host lässt sich nicht beliebig wählen.

- `Execution/clrldr`: lädt eine .NET-Framework-4-Assembly in eine private AppDomain und kann über die SMA aus dem GAC auch Windows PowerShell 5.1 ausführen, ohne powershell.exe zu starten. Erkennung: mscoree/clr/mscorlib werden geladen, AMSI und ETW sehen die Aktivität. Bewusst nur .NET Framework 4, kein AMSI/ETW-Patching, keine automatische Auflösung von Abhängigkeiten aus dem Payload-Verzeichnis, und die Domain bleibt resident.

CLR-Host und COM-vtable-Layout von clrldr basieren auf Clr.h von [Havoc](https://github.com/HavocFramework/Havoc), mit meinen eigenen Änderungen.

## Größe

Das Repository enthält keine Build-Skripte. Für x64 Release ohne CRT liegen die nativen Binärdateien ungefähr bei:

- coffldr: ca. 15 KB
- refldr: ca. 9 KB
- peloader: ca. 15 KB
- clrldr: ca. 21 KB (inklusive des eingebetteten Managed Runners)

Tatsächliche Größen hängen von Compiler und Optimierungsoptionen ab. Entwicklungsbuilds enthalten selftest, inspect und lesbare Fehler; sie sind deutlich größer und werden hier nicht aufgeführt.

## Verwendung

Die Beispiele unten gehen davon aus, dass die nativen Binärdateien nach `Execution/bin` gebaut wurden und die Payloads im aktuellen Verzeichnis liegen oder echte Pfade verwendet werden.

```bat
REM COFF: Objekt mappen und Einstiegspunkt aufrufen; --args ist kommagetrennt
bin\coffldr.exe run hello.obj
bin\coffldr.exe run hello.obj --args alpha,42 --entry go

REM Reflective DLL: das ReflectiveLoad des Payloads aufrufen
bin\refldr.exe run payload.dll --export Run

REM Mapping auf der Host-Seite: SEC_IMAGE oder in eine ausführbare Sektion eines geladenen Moduls schreiben
bin\peloader.exe map payload.dll --mode image --export Run
bin\peloader.exe map payload.dll --mode stomp --host winhttp.dll --export Run

REM CLR: eine Assembly oder Windows PowerShell 5.1
bin\clrldr.exe run tool.dll --args "alpha beta"
bin\clrldr.exe ps "Get-Process | Select-Object -First 3"
```

Native Builds geben nur das Ergebnis aus; bei einem Fehler den Exit-Code prüfen. Für lesbare Fehler sowie für `selftest` oder `inspect` die passende `*-dev.exe` verwenden. `--args` ist bei coffldr kommagetrennt und bei clrldr durch Leerzeichen getrennt.

## Hinweise

Dies sind Dual-Use-Angriffstechniken. Verwende sie nur in Umgebungen, die dir gehören oder für die du eine Testfreigabe hast. Die oben beschriebenen Schwächen sind absichtliche Grenzen, keine Versehen.
