# Windows-PostEx

[English](README.md) | [简体中文](README.zh.md) | [繁體中文](README.zh-Hant.md) | [日本語](README.ja.md) | [Français](README.fr.md) | [Deutsch](README.de.md) | **Español**

Este proyecto está dirigido a profesionales de seguridad con conocimientos básicos. Es «semi-armado»: se sitúa entre una demo de juguete y una amenaza real. Cada herramienta funciona en Windows real, pero dejo fallos a propósito para que no se trate como un producto terminado. **No garantizo la robustez de este código; la intención es mostrar ideas, no crear amenazas.**

La mayor parte de la funcionalidad se extrajo de mi propio C2. El plan es cubrir los principales elementos de la cadena de post-explotación de Windows, incluidos, entre otros, Execution, Lateral Movement, Privilege Escalation, Persistence y Credential Theft. Que se implemente todo depende del riesgo y del tiempo; aquí no hago promesas concretas.

## Execution

Ejecutar código en el proceso actual sin pasar por la ruta normal de carga de DLL. Los payloads se leen en memoria y no se vuelven a escribir en disco.

- `Execution/coffldr`: mapea un objeto COFF AMD64 en el proceso actual, resuelve símbolos, aplica reubicaciones, ajusta los permisos de página y llama al punto de entrada. Superficie de detección: páginas RX sin registro de módulo. A propósito no registra una tabla de excepciones, así que los objetos que usan SEH no funcionan, y un fallo en el punto de entrada también hace caer al host.

- `Execution/refldr`: el host coloca la DLL con el diseño de archivo en un búfer ejecutable y llama al ReflectiveLoad del propio payload; el mapeo, las importaciones y las demás tablas se resuelven dentro del payload. La imagen es MEM_PRIVATE y no aparece en la lista del cargador; la descarga solo hace DETACH y elimina la tabla de funciones, no libera la imagen. Manipular con cuidado.

- `Execution/peloader`: mapeo del lado del host. El modo image usa SEC_IMAGE para evitar LdrLoadDll; el modo stomp escribe el payload en una sección ejecutable de un módulo ya cargado. Detección: en image es MEM_IMAGE pero no está en la lista del cargador; en stomp, el contenido de la sección del host ya no coincide con el archivo. A propósito no se manejan CFG / load config, y el host del stomp no se puede elegir al azar.

- `Execution/clrldr`: carga un ensamblado de .NET Framework 4 en un AppDomain privado, y también puede ejecutar Windows PowerShell 5.1 mediante la SMA del GAC sin iniciar powershell.exe. Superficie de detección: carga de mscoree/clr/mscorlib, AMSI y ETW. A propósito solo .NET Framework 4, sin parchear AMSI/ETW, sin resolución automática de dependencias desde el directorio del payload, y el dominio queda residente.

El host CLR y el diseño de vtables COM de clrldr se basan en Clr.h de [Havoc](https://github.com/HavocFramework/Havoc), con mis propios cambios.

## Tamaño

El repositorio no incluye scripts de compilación. Compilados para x64 Release sin CRT, los binarios nativos apuntan aproximadamente a:

- coffldr: ~15 KB
- refldr: ~9 KB
- peloader: ~15 KB
- clrldr: ~21 KB (incluido el runner administrado embebido)

El tamaño real varía según el compilador y las opciones de optimización. Las versiones de desarrollo incluyen selftest, inspect y errores legibles; son mucho más grandes y no se listan aquí.

## Uso

Los ejemplos siguientes suponen que los binarios nativos se compilaron en `Execution/bin` y que los payloads están en el directorio actual, o usan rutas reales.

```bat
REM COFF: mapear el objeto y llamar a su punto de entrada; --args va separado por comas
bin\coffldr.exe run hello.obj
bin\coffldr.exe run hello.obj --args alpha,42 --entry go

REM DLL reflexiva: llamar al ReflectiveLoad del payload
bin\refldr.exe run payload.dll --export Run

REM Mapeo del lado del host: SEC_IMAGE, o escribir en una sección ejecutable de un módulo cargado
bin\peloader.exe map payload.dll --mode image --export Run
bin\peloader.exe map payload.dll --mode stomp --host winhttp.dll --export Run

REM CLR: un ensamblado, o Windows PowerShell 5.1
bin\clrldr.exe run tool.dll --args "alpha beta"
bin\clrldr.exe ps "Get-Process | Select-Object -First 3"
```

Los binarios nativos solo imprimen el resultado; revisa el código de salida si falla. Usa el `*-dev.exe` correspondiente cuando necesites errores legibles, `selftest` o `inspect`. `--args` va separado por comas en coffldr y por espacios en clrldr.

## Notas

Estas son técnicas ofensivas de doble uso. Úsalas solo en entornos que poseas o para los que tengas autorización de prueba. Los fallos descritos arriba son límites intencionales, no descuidos.
