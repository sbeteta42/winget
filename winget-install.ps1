<#PSScriptInfo

.VERSION 1.0

<#
.SYNOPSIS
	Télécharge et installe la dernière version de winget et ses dépendances. Met à  jour la variable PATH si nécessaire.
.DESCRIPTION
	Télécharge et installe la dernière version de winget et ses dépendances. Met à  jour la variable PATH si nécessaire

Ce script est conçu pour ètre simple et facile à  utiliser, éliminant les tracas liés au téléchargement, à  l'installation et à  la configuration manuels de Winget. Pour rendre le Winget nouvellement installé disponible, un redémarrage du système peut ètre nécessaire après avoir exécuté le
Cette fonction doit ètre exécutée avec des privilèges administratifs.
.EXEMPLE
installation d'ailes
.PARAMETER Mode débogage
     Active le mode débogage, qui affiche des informations supplémentaires pour le débogage.
.PARAMETER Désactiver le nettoyage
     Désactive le nettoyage du script et des prérequis après l'installation.
.PARAMETRE Forcer
     Assure l'installation de Winget et de ses dépendances, mème si déjà  présentes.
.PARAMETER CheckForUpdate
     Vérifie si une mise à  jour est disponible pour le script.
Version .PARAMETRE
     Affiche la version du script.
Aide .PARAMETER
     Affiche les informations d'aide complètes pour le script.
.REMARQUES
Version : 1.0
Créé par : sbeteta@beteta.org
.LIEN
Site du projet : https://github.com/sbeteta42/winget-install
#>
[CmdletBinding()]
param (
    [switch]$Version,
    [switch]$Help,
    [switch]$CheckForUpdate,
    [switch]$DisableCleanup,
    [switch]$DebugMode,
    [switch]$Force
)

# Version
$CurrentVersion = '1.0'
$RepoOwner = 'sbeteta42'
$RepoName = 'winget-install'
$PowerShellGalleryName = 'winget-install'

# Versions
$ProgressPreference = 'SilentlyContinue' # Supprimer la barre de progression (rend le téléchargement ultra rapide)
$ConfirmPreference = 'None' # Supprimer les invites de confirmation

# Afficher la version si -Version est spécifié
if ($Version.IsPresent) {
    $CurrentVersion
    exit 0
}

# Afficher l'aide complète si -Help est spécifié
if ($Help) {
    Get-Help -Name $MyInvocation.MyCommand.Source -Full
    exit 0
}

# Afficher $PSVersionTable et Get-Host si -Verbose est spécifié
if ($PSBoundParameters.ContainsKey('Verbose') -and $PSBoundParameters['Verbose']) {
    $PSVersionTable
    Get-Host
}

function Get-TempFolder {
    <#
        .SYNOPSIS
        Obtient le chemin du dossier temporaire de l'utilisateur actuel.

        .DESCRIPTION
        Cette fonction récupère le chemin du dossier temporaire de l'utilisateur actuel.

        .EXAMPLE
        Get-TempFolder
    #>
    return [System.IO.Path]::GetTempPath()
}

function Get-OSInfo {
    <#
        .SYNOPSIS
        Récupère des informations détaillées sur la version et lÂ’architecture du système dÂ’exploitation.

        .DESCRIPTION
        Cette fonction interroge à  la fois le registre Windows et la classe Win32_OperatingSystem pour collecter des informations complètes sur le système d'exploitation. Il renvoie des détails tels que l'ID de version, la version d'affichage, le nom, le type (poste de travail/serveur), la version numérique, l'ID d'édition, la version (objet qui inclut les numéros majeurs, mineurs et de build) et l'architecture (architecture du système d'exploitation, pas architecture du processeur). ).
        
        .EXAMPLE
        Get-OSInfo

        Cet exemple récupère les détails de la version du système d'exploitation actuel et renvoie un objet avec des propriétés telles que ReleaseId, DisplayVersion, Name, Type, NumericVersion, EditionId, Version et Architecture.
        
        .EXAMPLE
        (Get-OSInfo).Version.Major

        Cet exemple récupère le numéro de version majeure du système d'exploitation. La fonction Get-OSInfo renvoie un objet avec une propriété Version, qui est elle-mème un objet contenant les propriétés Major, Minor et Build. Vous pouvez accéder à  ces sous-propriétés en utilisant la notation par points.
        
        .EXAMPLE
        $osDetails = Get-OSInfo
        Write-Output "OS Name: $($osDetails.Name)"
        Write-Output "OS Type: $($osDetails.Type)"
        Write-Output "OS Architecture: $($osDetails.Architecture)"

        Cet exemple récupère le numéro de version majeure du système d'exploitation. 
        La fonction Get-OSInfo renvoie un objet avec une propriété Version, qui est elle-mème un objet contenant les propriétés Major, Minor et Build.
        Vous pouvez accéder à  ces sous-propriétés en utilisant la notation par points.
        Cet exemple stocke le résultat de Get-OSInfo dans une variable, puis accède à  diverses propriétés pour imprimer des détails sur le système d'exploitation.

    #>
    [CmdletBinding()]
    param ()

    try {
        # Get registry values
        $registryValues = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        $releaseIdValue = $registryValues.ReleaseId
        $displayVersionValue = $registryValues.DisplayVersion
        $nameValue = $registryValues.ProductName
        $editionIdValue = $registryValues.EditionId

        # Supprimez "Server" de $editionIdValue s'il existe
        $editionIdValue = $editionIdValue -replace "Server", ""

        # Obtenez les détails du système d'exploitation à  l'aide de Get-CimInstance car la clé de registre pour Name n'est pas toujours correcte avec Windows 11
        $osDetails = Get-CimInstance -ClassName Win32_OperatingSystem
        $nameValue = $osDetails.Caption

        # Obtenez les détails de l'architecture du système d'exploitation (pas du processeur)
        # Obtenez uniquement les chiffres
        $architecture = ($osDetails.OSArchitecture -replace "[^\d]").Trim()

        # Si 32 bits ou 64 bits, remplacez par x32 et x64
        if ($architecture -eq "32") {
            $architecture = "x32"
        } elseif ($architecture -eq "64") {
            $architecture = "x64"
        }

        # Obtenez le détails de la version du système d'exploitation (en tant qu'objet de version)
        $versionValue = [System.Environment]::OSVersion.Version

        # Déterminer le type de produit Microsoft
        # Reference: https://learn.microsoft.com/en-us/dotnet/api/microsoft.powershell.commands.producttype?view=powershellsdk-1.1.0
        if ($osDetails.ProductType -eq 1) {
            $typeValue = "Workstation"
        } elseif ($osDetails.ProductType -eq 2 -or $osDetails.ProductType -eq 3) {
            $typeValue = "Server"
        } else {
            $typeValue = "Unknown"
        }

        # Extraire la valeur numérique du Name
        $numericVersion = ($nameValue -replace "[^\d]").Trim()

        # Créer et renvoyer un objet personnalisé avec les propriétés requises
        $result = [PSCustomObject]@{
            ReleaseId      = $releaseIdValue
            DisplayVersion = $displayVersionValue
            Name           = $nameValue
            Type           = $typeValue
            NumericVersion = $numericVersion
            EditionId      = $editionIdValue
            Version        = $versionValue
            Architecture   = $architecture
        }

        return $result
    } catch {
        Write-Error "Impossible d'obtenir les détails de la version du système d'exploitation.`nError: $_"
        exit 1
    }
}

function Get-GitHubRelease {
    <#
        .SYNOPSIS
        récupère les dernières informations de version d'un référentiel GitHub.

        .DESCRIPTION
        This function uses the GitHub API to get information about the latest release of a specified repository, including its version and the date it was published.

        .PARAMETER Owner
        The GitHub username of the repository owner.

        .PARAMETER Repo
        The name of the repository.

        .EXAMPLE
        Get-GitHubRelease -Owner "sbeteta42" -Repo "winget-install"
        This command retrieves the latest release version and published datetime of the winget-install repository owned by sbeteta42.
    #>
    [CmdletBinding()]
    param (
        [string]$Owner,
        [string]$Repo
    )
    try {
        $url = "https://api.github.com/repos/$Owner/$Repo/releases/latest"
        $response = Invoke-RestMethod -Uri $url -ErrorAction Stop

        $latestVersion = $response.tag_name
        $publishedAt = $response.published_at

        # Convert UTC time string to local time
        $UtcDateTime = [DateTime]::Parse($publishedAt, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind)
        $PublishedLocalDateTime = $UtcDateTime.ToLocalTime()

        [PSCustomObject]@{
            LatestVersion     = $latestVersion
            PublishedDateTime = $PublishedLocalDateTime
        }
    } catch {
        Write-Error "Unable to check for updates.`nError: $_"
        exit 1
    }
}

function CheckForUpdate {
    param (
        [string]$RepoOwner,
        [string]$RepoName,
        [version]$CurrentVersion,
        [string]$PowerShellGalleryName
    )

    $Data = Get-GitHubRelease -Owner $RepoOwner -Repo $RepoName

    if ($Data.LatestVersion -gt $CurrentVersion) {
        Write-Output "`nA new version of $RepoName is available.`n"
        Write-Output "Current version: $CurrentVersion."
        Write-Output "Latest version: $($Data.LatestVersion)."
        Write-Output "Published at: $($Data.PublishedDateTime).`n"
        Write-Output "You can download the latest version from https://github.com/$RepoOwner/$RepoName/releases`n"
        if ($PowerShellGalleryName) {
            Write-Output "Or you can run the following command to update:"
            Write-Output "Install-Script $PowerShellGalleryName -Force`n"
        }
    } else {
        Write-Output "`n$RepoName is up to date.`n"
        Write-Output "Current version: $CurrentVersion."
        Write-Output "Latest version: $($Data.LatestVersion)."
        Write-Output "Published at: $($Data.PublishedDateTime)."
        Write-Output "`nRepository: https://github.com/$RepoOwner/$RepoName/releases`n"
    }
    exit 0
}

function Write-Section($text) {
    <#
        .SYNOPSIS
        Imprime un bloc de texte entouré d'un séparateur de section pour une meilleure lisibilité de la sortie.

        .DESCRIPTION
        Cette fonction prend une entrée de chaà®ne et l'imprime sur la console, entourée d'un séparateur de section composé de caractères de hachage.
        Il est conçu pour améliorer la lisibilité de la sortie de la console.

        .PARAMETER text
        Le texte à  imprimer dans le séparateur de section.

        .EXAMPLE
        Write-Section "Téléchargement de fichiers..."
       Cette commande imprime le texte "Téléchargement de fichiers..." entouré d'un séparateur de section.
    #>
    Write-Output ""
    Write-Output ("#" * ($text.Length + 4))
    Write-Output "# $text #"
    Write-Output ("#" * ($text.Length + 4))
    Write-Output ""
}

function Get-WingetDownloadUrl {
    <#
        .SYNOPSIS
        Récupère l'URL de téléchargement de la dernière ressource de version qui correspond à  un modèle spécifié à  partir du référentiel GitHub.

        .DESCRIPTION
        Cette fonction utilise l'API GitHub pour obtenir des informations sur la dernière version du référentiel winget-cli.
        Il récupère ensuite l'URL de téléchargement de la ressource de version qui correspond à  un modèle spécifié.
      
        .PARAMETER Match
        Le modèle à  faire correspondre dans les noms dâ€™actifs.

        .EXAMPLE
        Get-WingetDownloadUrl "msixbundle"
        Cette commande récupère l'URL de téléchargement de la dernière version de la ressource dont le nom contient Â« msixbundle Â».
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Match
    )

    $uri = "https://api.github.com/repos/microsoft/winget-cli/releases"
    Write-Debug "Getting information from $uri"
    $releases = Invoke-RestMethod -uri $uri -Method Get -ErrorAction stop

    Write-Debug "Getting latest release..."
    foreach ($release in $releases) {
        if ($release.name -match "preview") {
            continue
        }
        $data = $release.assets | Where-Object name -Match $Match
        if ($data) {
            return $data.browser_download_url
        }
    }

    Write-Debug "Falling back to the latest release..."
    $latestRelease = $releases | Select-Object -First 1
    $data = $latestRelease.assets | Where-Object name -Match $Match
    return $data.browser_download_url
}

function Get-WingetStatus {
    <#
        .SYNOPSIS
        Vérifions si Winget est installé.

        .DESCRIPTION
        Cette fonction vérifie si Winget est installé.

        .EXAMPLE
        Get-WingetStatus
    #>

    # Vérifions si Winget est installé.
    $winget = Get-Command -Name winget -ErrorAction SilentlyContinue

    # If winget is installed, return $true
    if ($null -ne $winget) {
        return $true
    }

    # Si Winget n'est pas installé, return $false
    return $false
}

function Update-PathEnvironmentVariable {
    <#
        .SYNOPSIS
        Met à  jour la variable d'environnement PATH avec un nouveau chemin pour les niveaux Utilisateur et Machine.

        .DESCRIPTION
        La fonction ajoutera un nouveau chemin à  la variable d'environnement PATH, en s'assurant qu'il ne s'agit pas d'un doublon.
        Si le nouveau chemin est déjà  dans la variable PATH, la fonction ignorera son ajout.
        Cette fonction fonctionne aux niveaux utilisateur et machine.

        .PARAMETER NewPath
        Le nouveau chemin du répertoire à  ajouter à  la variable d'environnement PATH.

        .EXAMPLE
        Update-PathEnvironmentVariable -NewPath "C:\NewDirectory"
        Cette commande ajoutera le répertoire "C:\NewDirectory" à  la variable PATH aux niveaux utilisateur et machine.
    #>
    param(
        [string]$NewPath
    )

    foreach ($Level in "Machine", "User") {
        # Get the current PATH variable
        $path = [Environment]::GetEnvironmentVariable("PATH", $Level)

        # Check if the new path is already in the PATH variable
        if (!$path.Contains($NewPath)) {
            if ($DebugMode) {
                Write-Output "Adding $NewPath to PATH variable for $Level..."
            } else {
                Write-Output "Adding PATH variable for $Level..."
            }

            # Add the new path to the PATH variable
            $path = ($path + ";" + $NewPath).Split(';') | Select-Object -Unique
            $path = $path -join ';'

            # Set the new PATH variable
            [Environment]::SetEnvironmentVariable("PATH", $path, $Level)
        } else {
            if ($DebugMode) {
                Write-Output "$NewPath already present in PATH variable for $Level, skipping."
            } else {
                Write-Output "PATH variable already present for $Level, skipping."
            }
        }
    }
}

function Handle-Error {
    <#
        .SYNOPSIS
            Gère les erreurs courantes pouvant survenir lors dâ€™un processus dâ€™installation.

        .DESCRIPTION
            Cette fonction prend un objet ErrorRecord et vérifie certains codes d'erreur connus.
            En fonction du code d'erreur, il écrit des messages d'avertissement appropriés ou renvoie l'erreur.

        .PARAMETER ErrorRecord
            Objet ErrorRecord qui représente lâ€™erreur détectée. Cet objet contient des informations sur l'erreur, y compris l'exception levée.

        .EXAMPLE
            try {
                # Some code that may throw an error...
            } catch {
                Handle-Error $_
            }
            Cet exemple montre comment vous pouvez utiliser la fonction Handle-Error dans un bloc try-catch.
            Si une erreur se produit dans le bloc try, le bloc catch l'attrape et appelle Handle-Error,
            passer l'erreur (représentée par la variable $_) à  la fonction.
    #>
    param($ErrorRecord)

    # Stocker la valeur actuelle
    $OriginalErrorActionPreference = $ErrorActionPreference

    # Prèt à  continuer silencieusement
    $ErrorActionPreference = 'SilentlyContinue'

    if ($ErrorRecord.Exception.Message -match '0x80073D06') {
        Write-Warning "Version supérieure déjà  installée."
        Write-Warning "ça va, je continue..."
    } elseif ($ErrorRecord.Exception.Message -match '0x80073CF0') {
        Write-Warning "Mème version déjà  installée."
        Write-Warning "ça va, je continue..."
    } elseif ($ErrorRecord.Exception.Message -match '0x80073D02') {
        # Arrètez l'exécution et renvoyez le ErrorRecord afin que le bloc try/catch appelant renvoie l'erreur
        Write-Warning "Resources modified are in-use. Try closing Windows Terminal / PowerShell / Command Prompt and try again."
        Write-Warning "Si le problème persiste, redémarrez votre ordinateur."
        return $ErrorRecord
    } elseif ($ErrorRecord.Exception.Message -match 'Unable to connect to the remote server') {
        Write-Warning "Impossible de se connecter à  Internet pour télécharger les fichiers requis."
        Write-Warning "Essayez à  nouveau d'exécuter le script et assurez-vous que vous ètes connecté à  Internet.."
        Write-Warning "Parfois, le serveur nuget.org est en panne, vous devrez peut-ètre réessayer plus tard.."
        return $ErrorRecord
    } elseif ($ErrorRecord.Exception.Message -match "The remote name could not be resolved") {
        Write-Warning "Impossible de se connecter à  Internet pour télécharger les fichiers requis."
        Write-Warning "Essayez à  nouveau d'exécuter le script et assurez-vous que vous ètes connecté à  Internet."
        Write-Warning "Assurez-vous que DNS fonctionne correctement sur votre ordinateur."
    } else {
        # Pour les autres erreurs, nous devons arrèter l'exécution et renvoyer le ErrorRecord afin que le bloc try/catch appelant renvoie l'erreur
        return $ErrorRecord
    }

    # Réinitialiser à  la valeur d'origine
    $ErrorActionPreference = $OriginalErrorActionPreference
}

function Cleanup {
    <#
        .SYNOPSIS
            Supprime un fichier ou un répertoire spécifié sans demander de confirmation ni afficher d'erreurs.

        .DESCRIPTION
            Cette fonction prend un chemin vers un fichier ou un répertoire et le supprime sans demander de confirmation ni afficher d'erreurs.
            Si le chemin est un répertoire, la fonction supprimera le répertoire et tout son contenu.

        .PARAMETER Path
            Le chemin du fichier ou du répertoire à  supprimer.

        .PARAMETER Recurse
           Si le chemin est un répertoire, ce commutateur spécifie s'il faut supprimer le répertoire et tout son contenu.

        .EXAMPLE
            Cleanup -Path "C:\Temp"
            Cet exemple supprime le répertoire "C:\Temp" et tout son contenu.

        .EXAMPLE
            Cleanup -Path "C:\Temp" -Recurse
            Cet exemple supprime le répertoire "C:\Temp" et tout son contenu.

        .EXAMPLE
            Cleanup -Path "C:\Temp\file.txt"
            Cet exemple supprime le fichier Â« C:\Temp\file.txt Â».
    #>
    param (
        [string]$Path,
        [switch]$Recurse
    )

    try {
        if (Test-Path -Path $Path) {
            if ($Recurse -and (Get-Item -Path $Path) -is [System.IO.DirectoryInfo]) {
                Get-ChildItem -Path $Path -Recurse | Remove-Item -Force -Recurse
                Remove-Item -Path $Path -Force -Recurse
            } else {
                Remove-Item -Path $Path -Force
            }
        }
        if ($DebugMode) {
            Write-Output "Deleted: $Path"
        }
    } catch {
        # Errors are ignored
    }
}

function Install-Prerequisite {
    <#
        .SYNOPSIS
        Télécharge et installe un prérequis pour Winget.

        .DESCRIPTION
        Cette fonction prend un nom, une version, une URL, une URL alternative, un type de contenu et un corps, puis télécharge et installe le prérequis.

        .PARAMETER Name
        Le nom du prérequis.

        .PARAMETER Version
        La version du prérequis.

        .PARAMETER Url
        L'URL du prérequis.

        .PARAMETER AlternateUrl
        Lâ€™URL alternative du prérequis.

        .PARAMETER ContentType
        Le type de contenu du prérequis..

        .PARAMETER Body
        Le corps du prérequis.

        .PARAMETER NupkgVersion
        La version nupkg du prérequis.

        .PARAMETER AppxFileVersion
        La version du fichier appx du prérequis.

        .EXAMPLE
        Install-Prerequisite -Name "VCLibs" -Version "14.00" -Url "https://store.rg-adguard.net/api/GetFiles" -AlternateUrl "https://aka.ms/Microsoft.VCLibs.$arch.14.00.Desktop.appx" -ContentType "application/x-www-form-urlencoded" -Body "type=PackageFamilyName&url=Microsoft.VCLibs.140.00_8wekyb3d8bbwe&ring=RP&lang=en-US"

        Where $arch est le type d'architecture du système actuel.
    #>
    param (
        [string]$Name,
        [string]$Url,
        [string]$AlternateUrl,
        [string]$ContentType,
        [string]$Body,
        [string]$NupkgVersion,
        [string]$AppxFileVersion
    )

    $osVersion = Get-OSInfo
    $arch = $osVersion.Architecture

    Write-Section "Téléchargement et installation ${arch} ${Name}..."

    $ThrowReason = @{
        Message = ""
        Code    = 0
    }
    try {
        # ============================================================================ #
        # Windows 10 / Server 2022 detection
        # ============================================================================ #

        # Fonction pour extraire le domaine de l'URL
        function Get-DomainFromUrl($url) {
            $uri = [System.Uri]$url
            $domain = $uri.Host -replace "^www\."
            return $domain
        }

        # Si Server 2022 ou Windows 10, forcer la version hors magasin de VCLibs (return true)
        $messageTemplate = "{OS} detected. Using {DOMAIN} version of {NAME}."

        # Déterminer les informations spécifiques au système d'exploitation
        $osType = $osVersion.Type
        $osNumericVersion = $osVersion.NumericVersion

        if (($osType -eq "Server" -and $osNumericVersion -eq 2022) -or ($osType -eq "Workstation" -and $osNumericVersion -eq 10)) {
            if ($osType -eq "Server") {
                $osName = "Server 2022"
            } else {
                $osName = "Windows 10"
            }
            $domain = Get-DomainFromUrl $AlternateUrl
            $ThrowReason.Message = ($messageTemplate -replace "{OS}", $osName) -replace "{NAME}", $Name -replace "{DOMAIN}", $domain
            $ThrowReason.Code = 1
            throw
        }

        # ============================================================================ #
        # Méthode principale
        # ============================================================================ #

        $url = Invoke-WebRequest -Uri $Url -Method "POST" -ContentType $ContentType -Body $Body -UseBasicParsing | ForEach-Object Links | Where-Object outerHTML -match "$Name.+_${arch}__8wekyb3d8bbwe.appx" | ForEach-Object href

        # Si l'URL est vide, essayez la méthode alternative
        if ($url -eq "") {
            $ThrowReason.Message = "URL is empty"
            $ThrowReason.Code = 2
            throw
        }

        if ($DebugMode) {
            Write-Output "URL: ${url}`n"
        }
        Write-Output "Installing ${arch} ${Name}..."
        Add-AppxPackage $url -ErrorAction Stop
        Write-Output "`n$Name installed successfully."
    } catch {
        # Méthode alternative
        if ($_.Exception.Message -match '0x80073D02') {
            # If resources in use exception, fail immediately
            Handle-Error $_
            throw
        }

        try {
            $url = $AlternateUrl

            # Throw reason si une autre méthode est requise
            if ($ThrowReason.Code -eq 0) {
                Write-Warning "Erreur lors de la tentative de téléchargement ou d'installation $Name. Essayer une autre méthode..."
            } else {
                Write-Warning $ThrowReason.Message
            }
            Write-Output ""

            # If the URL is empty, throw error
            if ($url -eq "") {
                throw "L'URL est vide"
            }

            # Logique spécifique pour la méthode alternative VCLibs
            if ($Name -eq "VCLibs") {
                if ($DebugMode) {
                    Write-Output "URL: $($url)`n"
                }
                Write-Output "Installing ${arch} ${Name}..."
                Add-AppxPackage $url -ErrorAction Stop
                Write-Output "`n$Name installed successfully."
            }

            # Specific logic for UI.Xaml
            if ($Name -eq "UI.Xaml") {
                $TempFolder = Get-TempFolder

                $uiXaml = @{
                    url           = $url
                    appxFolder    = "tools/AppX/$arch/Release/"
                    appxFilename  = "Microsoft.UI.Xaml.$AppxFileVersion.appx"
                    nupkgFilename = Join-Path -Path $TempFolder -ChildPath "Microsoft.UI.Xaml.$NupkgVersion.nupkg"
                    nupkgFolder   = Join-Path -Path $TempFolder -ChildPath "Microsoft.UI.Xaml.$NupkgVersion"
                }

                # Debug
                if ($DebugMode) {
                    $formattedDebugOutput = ($uiXaml | ConvertTo-Json -Depth 10 -Compress) -replace '\\\\', '\'
                    Write-Output "uiXaml:"
                    Write-Output $formattedDebugOutput
                    Write-Output ""
                }

                # Downloading
                Write-Output "Downloading UI.Xaml..."
                if ($DebugMode) {
                    Write-Output "URL: $($uiXaml.url)"
                }
                Invoke-WebRequest -Uri $uiXaml.url -OutFile $uiXaml.nupkgFilename

                # Vérifiez si le dossier existe et supprimez-le si nécessaire (cela se produira si DisableCleanup est $true or $false)
                Cleanup -Path $uiXaml.nupkgFolder -Recurse

                # Extracting
                Write-Output "Extracting...`n"
                if ($DebugMode) {
                    Write-Output "Into folder: $($uiXaml.nupkgFolder)`n"
                }
                Add-Type -Assembly System.IO.Compression.FileSystem
                [IO.Compression.ZipFile]::ExtractToDirectory($uiXaml.nupkgFilename, $uiXaml.nupkgFolder)

                # Preparation pour l'install...
                Write-Output "Installing ${arch} ${Name}..."
                $XamlAppxFolder = Join-Path -Path $uiXaml.nupkgFolder -ChildPath $uiXaml.appxFolder
                $XamlAppxPath = Join-Path -Path $XamlAppxFolder -ChildPath $uiXaml.appxFilename

                # Debugging
                if ($DebugMode) { Write-Output "Installing appx Packages in: $XamlAppxFolder" }

                # Install
                Get-ChildItem -Path $XamlAppxPath -Filter *.appx | ForEach-Object {
                    if ($DebugMode) { Write-Output "Installing appx Package: $($_.Name)" }
                    Add-AppxPackage $_.FullName -ErrorAction Stop
                }
                Write-Output "`nUI.Xaml installed successfully."

                # Cleanup
                if ($DisableCleanup -eq $false) {
                    if ($DebugMode) { Write-Output "" } # Extra line break for readability if DebugMode is enabled
                    Cleanup -Path $uiXaml.nupkgFilename
                    Cleanup -Path $uiXaml.nupkgFolder -Recurse $true
                }
            }
        } catch {
            # Si vous ne parvenez pas à  vous connecter au serveur distant et à  Windows 10 ou Server 2022, afficher un message d'avertissement
            $ShowOldVersionMessage = $False
            if ($_.Exception.Message -match "Unable to connect to the remote server") {
                # Determine the correct Windows caption and set $ShowOutput to $True if conditions are met
                if ($osVersion.Type -eq "Workstation" -and $osVersion.NumericVersion -eq 10) {
                    $WindowsCaption = "Windows 10"
                    $ShowOldVersionMessage = $True
                } elseif ($osVersion.Type -eq "Server" -and $osVersion.NumericVersion -eq 2022) {
                    $WindowsCaption = "Server 2022"
                    $ShowOldVersionMessage = $True
                }

                # Output the warning message if $ShowOldVersionMessage is $True, otherwise output the generic error message
                if ($ShowOldVersionMessage) {
                    $OldVersionMessage = "There is an issue connecting to the server to download $Name. Unfortunately this is a known issue with the prerequisite server URLs - sometimes they are down. Since you're using $WindowsCaption you must use the non-store versions of the prerequisites, the prerequisites from the Windows store will not work, so you may need to try again later or install manually."
                    Write-Warning $OldVersionMessage
                } else {
                    Write-Warning "Error when trying to download or install $Name. Please try again later or manually install $Name."
                }
            }

            $errorHandled = Handle-Error $_
            if ($null -ne $errorHandled) {
                throw $errorHandled
            }
            $errorHandled = $null
        }
    }
}

# ============================================================================ #
# Initial checks
# ============================================================================ #

# Check for updates if -CheckForUpdate is specified
if ($CheckForUpdate) {
    CheckForUpdate -RepoOwner $RepoOwner -RepoName $RepoName -CurrentVersion $CurrentVersion -PowerShellGalleryName $PowerShellGalleryName
}

# Heading
Write-Output "winget-install $CurrentVersion"
Write-Output "TPour vérifier les mises à  jour, run winget-install -CheckForUpdate"

# Définir la version du système d'exploitation
$osVersion = Get-OSInfo

# Définir le type d'architecture
$arch = $osVersion.Architecture

# S'il s'agit d'un poste de travail, assurez-vous qu'il s'agit de Windows 10+
if ($osVersion.Type -eq "Workstation" -and $osVersion.NumericVersion -lt 10) {
    Write-Error "Winget est uniquement compatible avec Windows 10 ou supérieur."
    exit 1
}

# S'il s'agit d'un poste de travail avec Windows 10, assurez-vous qu'il s'agit de la version 1809 ou supérieure
if ($osVersion.Type -eq "Workstation" -and $osVersion.NumericVersion -eq 10 -and $osVersion.ReleaseId -lt 1809) {
    Write-Error "Winget est uniquement compatible avec Windows 10 version 1809 ou supérieure."
    exit 1
}

# Si c'est un serveur, il doit ètre 2022+
if ($osVersion.Type -eq "Server" -and $osVersion.NumericVersion -lt 2022) {
    Write-Error "Winget est uniquement compatible avec Windows Server 2022+."
    exit 1
}

# Vérifiez si Winget est déjà  installé
if (Get-WingetStatus) {
    if ($Force -eq $false) {
        Write-Output "winget is already installed, exiting..."
        exit 0
    }
}

# ============================================================================ #
# Début du processus d'installation
# ============================================================================ #

try {
    # ============================================================================ #
    # Conditions préalables à  l'installation
    # ============================================================================ #

    # VCLibs
    Install-Prerequisite -Name "VCLibs" -Version "14.00" -Url "https://store.rg-adguard.net/api/GetFiles" -AlternateUrl "https://aka.ms/Microsoft.VCLibs.$arch.14.00.Desktop.appx" -ContentType "application/x-www-form-urlencoded" -Body "type=PackageFamilyName&url=Microsoft.VCLibs.140.00_8wekyb3d8bbwe&ring=RP&lang=en-US"

    # UI.Xaml
    Install-Prerequisite -Name "UI.Xaml" -Version "2.7.3" -Url "https://store.rg-adguard.net/api/GetFiles" -AlternateUrl "https://www.nuget.org/api/v2/package/Microsoft.UI.Xaml/2.7.3" -ContentType "application/x-www-form-urlencoded" -Body "type=ProductId&url=9P5VK8KZB5QZ&ring=RP&lang=en-US" -NupkgVersion "2.7.3" -AppxFileVersion "2.7"

    # ============================================================================ #
    # Installation de winget
    # ============================================================================ #

    $TempFolder = Get-TempFolder

    # Output
    Write-Section "Téléchargement et installation de winget..."

    Write-Output "Récupération de l'URL de téléchargement de Winget depuis GitHub......"
    $wingetUrl = Get-WingetDownloadUrl -Match "msixbundle"
    $wingetPath = Join-Path -Path $tempFolder -ChildPath "winget.msixbundle"
    $wingetLicenseUrl = Get-WingetDownloadUrl -Match "License1.xml"
    $wingetLicensePath = Join-Path -Path $tempFolder -ChildPath "license1.xml"

    # If the URL is empty, throw error
    if ($wingetUrl -eq "") {
        throw "URL is empty"
    }

    Write-Output "Téléchargement de winget..."
    if ($DebugMode) {
        Write-Output "`nURL: $wingetUrl"
        Write-Output "Saving as: $wingetPath"
    }
    Invoke-WebRequest -Uri $wingetUrl -OutFile $wingetPath

    Write-Output "Téléchargement de la  license..."
    if ($DebugMode) {
        Write-Output "`nURL: $wingetLicenseUrl"
        Write-Output "Saving as: $wingetLicensePath"
    }
    Invoke-WebRequest -Uri $wingetLicenseUrl -OutFile $wingetLicensePath

    Write-Output "`nInstallation de winget..."

    # Debugging
    if ($DebugMode) {
        Write-Output "wingetPath: $wingetPath"
        Write-Output "wingetLicensePath: $wingetLicensePath"
    }

    # Try to install winget
    try {
        # Add-AppxPackage will throw an error if the app is already installed or higher version installed, so we need to catch it and continue
        Add-AppxProvisionedPackage -Online -PackagePath $wingetPath -LicensePath $wingetLicensePath -ErrorAction SilentlyContinue | Out-Null
        Write-Output "`nwinget installed successfully."
    } catch {
        $errorHandled = Handle-Error $_
        if ($null -ne $errorHandled) {
            throw $errorHandled
        }
        $errorHandled = $null
    }

    # Cleanup
    if ($DisableCleanup -eq $false) {
        if ($DebugMode) { Write-Output "" } # Extra line break for readability if DebugMode is enabled
        Cleanup -Path $wingetPath
        Cleanup -Path $wingetLicensePath
    }

    # ============================================================================ #
    # PATH environment variable
    # ============================================================================ #

    # Add the WindowsApps directory to the PATH variable
    Write-Section "Checking and adding WindowsApps directory to PATH variable for current user if not present..."
    $WindowsAppsPath = [IO.Path]::Combine([Environment]::GetEnvironmentVariable("LOCALAPPDATA"), "Microsoft", "WindowsApps")
    Update-PathEnvironmentVariable -NewPath $WindowsAppsPath

    # ============================================================================ #
    # Fini ! end ! lol !
    # ============================================================================ #

    Write-Section "Installation complète!"

    # Timeout for 5 seconds to check winget
    Write-Output "Vérifions si Winget est installé et fonctionne..."
    Start-Sleep -Seconds 3

    # Vérifiez si Winget est installé
    if (Get-WingetStatus -eq $true) {
        Write-Output "Winget est installé et fonctionne maintenant, vous pouvez continuer et l'utiliser."
    } else {
        Write-Warning "winget est installé mais n'est pas détecté comme une commande. Essayez d'utiliser Winget maintenant. Si cela ne fonctionne pas, attendez environ 1 minute et réessayez (c'est parfois retardé). Essayez également de redémarrer votre ordinateur"
        Write-Warning "Si vous redémarrez votre ordinateur et que la commande n'est toujours pas reconnue, veuillez lire la section Dépannage du README: https://github.com/sbeteta42/winget-install#troubleshooting`n"
        Write-Warning "Assurez-vous d'avoir la dernière version du script en exécutant cette commande: $PowerShellGalleryName -CheckForUpdate"
    }
} catch {
    # ============================================================================ #
    # Gestion des erreurs
    # ============================================================================ #

    Write-Section "AVERTISSEMENT! Une erreur s'est produite lors de l'installation!"
    Write-Warning "Si les messages ci-dessus ne vous aident pas et que le problème persiste, veuillez lire la section Dépannage du README: https://github.com/sbeteta42/winget-install#troubleshooting"
    Write-Warning "Assurez-vous d'avoir la dernière version du script en exécutant cette commande: $PowerShellGalleryName -CheckForUpdate"

    # If it's not 0x80073D02 (resources in use), show error
    if ($_.Exception.Message -notmatch '0x80073D02') {
        if ($DebugMode) {
            Write-Warning "Line number : $($_.InvocationInfo.ScriptLineNumber)"
        }
        Write-Warning "Error: $($_.Exception.Message)`n"
    }
}