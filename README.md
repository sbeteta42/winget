# winget
Installation automatisé de WinGet sans passer par le Windows Store

# Objectif :
Cet utilitaire est une simplifaction de l'installation de WinGet sur toutes version de Windows, y compris Server sans passer par le Windows Store.

# Installation
Vous devez lancer PowerShell ou Windows Terminal en tant qu'ADMINISTRATEUR ! La méthode recommandée consiste à cliquer avec le bouton droit sur le menu Démarrer et à sélectionner (PowerShell en tant qu'administrateur Windows 10 - Terminal Windows en tant qu'administrateur Windows 11)

```bash
iwr -useb https://raw.githubusercontent.com/sbeteta42/winget/main/winget-install.ps1 | iex
```
 ou alors 

```bash
 irm https://raw.githubusercontent.com/sbeteta42/winget/main/winget-install.ps1 | iex
```
