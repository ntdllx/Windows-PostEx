# Windows-PostEx

[English](README.md) | [简体中文](README.zh.md) | [繁體中文](README.zh-Hant.md) | [日本語](README.ja.md) | **Français** | [Deutsch](README.de.md) | [Español](README.es.md)

Ce projet s'adresse à des professionnels de la sécurité ayant déjà des bases. Il est « semi-armé » : il se situe entre une démo jouet et une menace réelle. Chaque outil fonctionne sur un vrai Windows, mais je laisse volontairement des défauts pour qu'il ne soit pas pris pour un produit fini. **Je ne garantis pas la robustesse de ce code ; le but est de montrer des idées, pas de créer des menaces.**

L'essentiel des fonctionnalités a été extrait de mon propre C2. Le projet prévoit de couvrir les principaux éléments de la chaîne de post-exploitation Windows, notamment Execution, Lateral Movement, Privilege Escalation, Persistence et Credential Theft. Leur implémentation dépendra du risque et du temps disponible ; je ne prends ici aucun engagement concret.

## Execution

Exécuter du code dans le processus courant sans passer par le chemin de chargement DLL habituel. Les payloads sont lus en mémoire et ne sont pas réécrits sur le disque.

- `Execution/coffldr` : mappe un objet COFF AMD64 dans le processus courant, résout les symboles, applique les relocations, règle les protections de pages, puis appelle le point d'entrée. Surface de détection : des pages RX sans module associé. Pas de table d'exceptions : les objets qui utilisent SEH ne fonctionnent pas, et un crash du point d'entrée emporte le processus hôte.

- `Execution/refldr` : l'hôte place la DLL au format fichier dans un tampon exécutable et appelle le ReflectiveLoad fourni par le payload ; le mapping, les imports et les autres tables sont gérés dans le payload. L'image est MEM_PRIVATE et absente de la liste des modules ; le déchargement ne fait que DETACH et supprime la table de fonctions, sans libérer l'image. À manipuler avec précaution.

- `Execution/peloader` : mapping côté hôte. Le mode image utilise SEC_IMAGE pour contourner LdrLoadDll ; le mode stomp écrit le payload dans une section exécutable d'un module déjà chargé. Détection : en mode image, MEM_IMAGE mais absent de la liste des modules ; en mode stomp, le contenu de la section hôte ne correspond plus au fichier. Pas de gestion CFG / load config, et l'hôte du stomp ne peut pas être choisi au hasard.

- `Execution/clrldr` : charge un assembly .NET Framework 4 dans un AppDomain privé, et peut aussi exécuter Windows PowerShell 5.1 via la SMA du GAC sans lancer powershell.exe. Surface de détection : chargement de mscoree/clr/mscorlib, AMSI et ETW. Volontairement limité à .NET Framework 4, pas de patch AMSI/ETW, pas de résolution automatique des dépendances du dossier du payload, et le domaine reste résident.

L'hôte CLR et la disposition des vtables COM de clrldr s'appuient sur Clr.h de [Havoc](https://github.com/HavocFramework/Havoc), avec mes propres modifications.

## Taille

Le dépôt ne contient pas de scripts de compilation. Compilés en x64 Release sans CRT, les binaires natifs visent environ :

- coffldr : ~15 Ko
- refldr : ~9 Ko
- peloader : ~15 Ko
- clrldr : ~21 Ko (runner managé embarqué inclus)

La taille réelle varie selon le compilateur et les options d'optimisation. Les versions de développement incluent selftest, inspect et des erreurs lisibles ; elles sont bien plus grosses et ne sont pas listées ici.

## Utilisation

Les exemples ci-dessous supposent que les binaires natifs sont compilés dans `Execution/bin` et que les payloads sont dans le répertoire courant, ou utilisent des chemins réels.

```bat
REM COFF : mapper l'objet et appeler son point d'entrée ; --args est séparé par des virgules
bin\coffldr.exe run hello.obj
bin\coffldr.exe run hello.obj --args alpha,42 --entry go

REM DLL réflexive : appeler le ReflectiveLoad du payload
bin\refldr.exe run payload.dll --export Run

REM Mapping côté hôte : SEC_IMAGE, ou écrire dans une section exécutable d'un module chargé
bin\peloader.exe map payload.dll --mode image --export Run
bin\peloader.exe map payload.dll --mode stomp --host winhttp.dll --export Run

REM CLR : un assembly, ou Windows PowerShell 5.1
bin\clrldr.exe run tool.dll --args "alpha beta"
bin\clrldr.exe ps "Get-Process | Select-Object -First 3"
```

Les binaires natifs n'affichent que le résultat ; vérifiez le code de sortie en cas d'échec. Utilisez le `*-dev.exe` correspondant pour obtenir des erreurs lisibles, ou pour `selftest` / `inspect`. `--args` est séparé par des virgules pour coffldr et par des espaces pour clrldr.

## Remarques

Ce sont des techniques offensives à double usage. Utilisez-les uniquement dans des environnements que vous possédez ou pour lesquels vous êtes autorisé à effectuer des tests. Les défauts décrits ci-dessus sont des limites intentionnelles, pas des oublis.
