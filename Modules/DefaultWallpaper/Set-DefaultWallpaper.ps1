<#
.SYNOPSIS
    Feature Update Controller script module for setting a default wallpaper during a Windows feature update.

.DESCRIPTION
    This script module downloads the defined wallpaper image file and sets it as the default wallpaper during the feature update process.

.EXAMPLE
    .\Set-DefaultWallpaper.ps1

.NOTES
    FileName:    Set-DefaultWallpaper.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2024-08-27
    Updated:     2024-08-27

    Version history:
    1.0.0 - (2024-08-27) Script created
#>
Begin {
    # Declare the script module name
    $ScriptModuleName = "DefaultWallpaper"
    $ScriptLogFileName = "SetupComplete.log"
}
Process {
    # Functions
    function Write-LogEntry {
        param (
            [parameter(Mandatory = $true, HelpMessage = "Value added to the log file.")]
            [ValidateNotNullOrEmpty()]
            [string]$Value,
    
            [parameter(Mandatory = $true, HelpMessage = "Severity for the log entry. 1 for Informational, 2 for Warning and 3 for Error.")]
            [ValidateNotNullOrEmpty()]
            [ValidateSet("1", "2", "3")]
            [string]$Severity,
    
            [parameter(Mandatory = $false, HelpMessage = "Name of the log file that the entry will written to.")]
            [ValidateNotNullOrEmpty()]
            [string]$FileName = $ScriptLogFileName
        )
        # Check if the script is running as SYSTEM, else use the user's temp folder for the log file location
        if ([Security.Principal.WindowsIdentity]::GetCurrent().IsSystem -eq $true) {
            $LogFilePath = Join-Path -Path (Join-Path -Path $env:ProgramData -ChildPath "Microsoft\IntuneManagementExtension\Logs") -ChildPath $FileName
        }
        else {
            $LogFilePath = Join-Path -Path $env:TEMP -ChildPath $FileName
        }

        # Create log folder path if it does not exist
        try {
            $LogFolderPath = Split-Path -Path $LogFilePath -Parent
            if (-not(Test-Path -Path $LogFolderPath)) {
                New-Item -ItemType "Directory" -Path $LogFolderPath -Force -ErrorAction "Stop" | Out-Null
            }
        }
        catch [System.Exception] {
            Write-Warning -Message "An error occurred while attempting to create the log folder path. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
        }
        
        # Construct time stamp for log entry
        $Time = -join @((Get-Date -Format "HH:mm:ss.fff"), "+", (Get-WmiObject -Class Win32_TimeZone | Select-Object -ExpandProperty Bias))
        
        # Construct date for log entry
        $Date = (Get-Date -Format "MM-dd-yyyy")
        
        # Construct context for log entry
        $Context = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
        
        # Construct final log entry
        $LogText = "<![LOG[$($Value)]LOG]!><time=""$($Time)"" date=""$($Date)"" component=""$($ScriptModuleName)"" context=""$($Context)"" type=""$($Severity)"" thread=""$($PID)"" file="""">"
        
        # Add value to log file
        try {
            Out-File -InputObject $LogText -Append -NoClobber -Encoding Default -FilePath $LogFilePath -ErrorAction Stop
        }
        catch [System.Exception] {
            Write-Warning -Message "Unable to append log entry $($ScriptLogFileName).log file. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
        }
    }

    function Remove-WallpaperFile {
        param(
            [parameter(Mandatory = $true, HelpMessage = "Full path to the image file to be removed.")]
            [ValidateNotNullOrEmpty()]
            [string]$FilePath
        )
        try {
            # Take ownership of the wallpaper file
            Write-LogEntry -Value "- Determining if ownership needs to be changed for file: $($FilePath)" -Severity 1
            $CurrentOwner = Get-Item -Path $FilePath | Get-NTFSOwner
            if ($CurrentOwner.Owner -notlike $LocalAdministratorsPrincipal) {
                Write-LogEntry -Value "- Amending owner as '$($LocalAdministratorsPrincipal)' temporarily for: $($FilePath)" -Severity 1
                Set-NTFSOwner -Path $FilePath -Account $LocalAdministratorsPrincipal -ErrorAction Stop
            }

            try {
                # Grant local Administrators group and system full control
                Write-LogEntry -Value "- Granting '$($LocalSystemPrincipal)' Full Control on: $($FilePath)" -Severity 1
                Add-NTFSAccess -Path $FilePath -Account $LocalSystemPrincipal -AccessRights "FullControl" -AccessType "Allow" -ErrorAction Stop
                Write-LogEntry -Value "- Granting '$($LocalAdministratorsPrincipal)' Full Control on: $($FilePath)" -Severity 1
                Add-NTFSAccess -Path $FilePath -Account $LocalAdministratorsPrincipal -AccessRights "FullControl" -AccessType "Allow" -ErrorAction Stop

                try {
                    # Remove existing local default wallpaper file
                    Write-LogEntry -Value "- Removing existing default wallpaper image file: $($FilePath)" -Severity 1
                    Remove-Item -Path $FilePath -Force -ErrorAction Stop
                }
                catch [System.Exception] {
                    Write-LogEntry -Value "- Failed to remove wallpaper image file '$($FilePath)'. Error message: $($_.Exception.Message)" -Severity 3
                }                    
            }
            catch [System.Exception] {
                Write-LogEntry -Value "- Failed to grant Administrators and local system with full control for wallpaper image file. Error message: $($_.Exception.Message)" -Severity 3
            }
        }
        catch [System.Exception] {
            Write-LogEntry -Value "- Failed to take ownership of '$($FilePath)'. Error message: $($_.Exception.Message)" -Severity 3
        }
    }

    # Initial logging details for detection script
    Write-LogEntry -Value "[$($ScriptModuleName)-Module] - Initializing" -Severity 1

    # Declare manifest and Azure storage account container variables
    $StorageAccountName = "<storage_account_name>"
    $StorageAccountContainer = "<storage_account_container_name>"

    # Declare variable for company name
    $CompanyName = "<company_name>"

    # Declare wallpaper image file name to be used to replace all the existing wallpaper files
    $WallpaperImageFileName = "img0.jpg"

    # Determine the localized name of the principals required for the functionality of this script
    $LocalAdministratorsPrincipal = "BUILTIN\Administrators"
    $LocalUsersPrincipal = "BUILTIN\Users"
    $LocalSystemPrincipal = "NT AUTHORITY\SYSTEM"
    $TrustedInstallerPrincipal = "NT SERVICE\TrustedInstaller"
    $RestrictedApplicationPackagesPrincipal = "ALL RESTRICTED APPLICATION PACKAGES"
    $ApplicationPackagesPrincipal = "ALL APPLICATION PACKAGES"

    try {
        # Construct the storage account context
        $StorageAccountContext = New-AzStorageContext -StorageAccountName $StorageAccountName -Anonymous -ErrorAction "Stop" -Verbose:$false

        try {
            # Declare the wallpaper image file path
            $WallpaperImageFile = Join-Path -Path $PSScriptRoot -ChildPath $WallpaperImageFileName
            if (Test-Path -Path $WallpaperImageFile) {
                Write-LogEntry -Value "- Found wallpaper image file: $($WallpaperImageFile)" -Severity 1
            }
            else {
                Write-LogEntry -Value "- Wallpaper image file not found: $($WallpaperImageFile)" -Severity 3

                try {
                    # Download the wallpaper image file from the Azure storage account
                    Write-LogEntry -Value "- Downloading wallpaper image file from Azure storage account." -Severity 1
                    $WallpaperImageDownload = Get-AzStorageBlobContent -Container $StorageAccountContainer -Blob $WallpaperImageFileName -Destination $PSScriptRoot -Context $StorageAccountContext -Force -ErrorAction "Stop" -Verbose:$false
                    Write-LogEntry -Value "- Successfully downloaded wallpaper image file to: $($WallpaperImageFile)" -Severity 1
                }
                catch [System.Exception] {
                    Write-LogEntry -Value "- Failed to download the wallpaper image file. Error message: $($_.Exception.Message)" -Severity 3
                }
            }

            if (Test-Path -Path $WallpaperImageFile) {
                # Process both Web and 4K wallpaper image paths and replace the existing wallpaper image files with the downloaded wallpaper image file
                $WallpaperFolders = @("$($env:SystemRoot)\Web\Wallpaper\Windows", "$($env:SystemRoot)\Web\4K\Wallpaper\Windows")
                foreach ($WallpaperFolder in $WallpaperFolders) {
                    Write-LogEntry -Value "- Processing wallpaper folder: $($WallpaperFolder)" -Severity 1

                    try {
                        # Determine the file name of the img*.jpg file in the Windows\Web\Wallpaper\Windows directory
                        $ExistingWallpaperImageFiles = Get-ChildItem -Path $WallpaperFolder -Filter "img*.jpg" -ErrorAction "Stop"
                        if ($ExistingWallpaperImageFiles -ne $null) {
                            foreach ($ExistingWallpaperImageFile in $ExistingWallpaperImageFiles) {
                                # Declare variables for the existing wallpaper image file
                                $CurrentWallpaperImageFilePath = $ExistingWallpaperImageFile.FullName
    
                                try {
                                    # Remove the existing wallpaper image file
                                    Remove-WallpaperFile -FilePath $CurrentWallpaperImageFilePath -ErrorAction "Stop"
    
                                    try {
                                        # Copy the downloaded wallpaper image file to the default wallpaper location
                                        Write-LogEntry -Value "- Copying downloaded wallpaper image file to: $($CurrentWallpaperImageFilePath)" -Severity 1
                                        Copy-Item -Path $WallpaperImageFile -Destination $CurrentWallpaperImageFilePath -Force -ErrorAction "Stop"
                
                                        try {
                                            # Grant non-inherited permissions for wallpaper item
                                            Write-LogEntry -Value "- Granting '$($LocalSystemPrincipal)' Read and Execute on: $($CurrentWallpaperImageFilePath)" -Severity 1
                                            Add-NTFSAccess -Path $CurrentWallpaperImageFilePath -Account $LocalSystemPrincipal -AccessRights "ReadAndExecute" -ErrorAction "Stop"
                                            Write-LogEntry -Value "- Granting '$($LocalAdministratorsPrincipal)' Read and Execute on: $($CurrentWallpaperImageFilePath)" -Severity 1
                                            Add-NTFSAccess -Path $CurrentWallpaperImageFilePath -Account $LocalAdministratorsPrincipal -AccessRights "ReadAndExecute" -ErrorAction "Stop"
                                            Write-LogEntry -Value "- Granting '$($LocalUsersPrincipal)' Read and Execute on: $($CurrentWallpaperImageFilePath)" -Severity 1
                                            Add-NTFSAccess -Path $CurrentWallpaperImageFilePath -Account $LocalUsersPrincipal -AccessRights "ReadAndExecute" -ErrorAction "Stop"
                                            Write-LogEntry -Value "- Granting '$($ApplicationPackagesPrincipal)' Read and Execute on: $($CurrentWallpaperImageFilePath)" -Severity 1
                                            Add-NTFSAccess -Path $CurrentWallpaperImageFilePath -Account $ApplicationPackagesPrincipal -AccessRights "ReadAndExecute" -ErrorAction "Stop"
                                            Write-LogEntry -Value "- Granting '$($RestrictedApplicationPackagesPrincipal)' Read and Execute on: $($CurrentWallpaperImageFilePath)" -Severity 1
                                            Add-NTFSAccess -Path $CurrentWallpaperImageFilePath -Account $RestrictedApplicationPackagesPrincipal -AccessRights "ReadAndExecute" -ErrorAction "Stop"
                                            Write-LogEntry -Value "- Granting '$($TrustedInstallerPrincipal)' Full Control on: $($CurrentWallpaperImageFilePath)" -Severity 1
                                            Add-NTFSAccess -Path $CurrentWallpaperImageFilePath -Account $TrustedInstallerPrincipal -AccessRights "FullControl" -ErrorAction "Stop"
                                            Write-LogEntry -Value "- Disabling inheritance on: $($CurrentWallpaperImageFilePath)" -Severity 1
                                            Disable-NTFSAccessInheritance -Path $CurrentWallpaperImageFilePath -RemoveInheritedAccessRules -ErrorAction "Stop"
                            
                                            try {
                                                # Set owner to trusted installer for new wallpaper file
                                                Write-LogEntry -Value "- Setting ownership for '$($TrustedInstallerPrincipal)' on wallpaper image file: $($CurrentWallpaperImageFilePath)" -Severity 1
                                                Set-NTFSOwner -Path $CurrentWallpaperImageFilePath -Account $TrustedInstallerPrincipal -ErrorAction "Stop"
                                            }
                                            catch [System.Exception] {
                                                Write-LogEntry -Value "- Failed to set ownership for '$($TrustedInstallerPrincipal)' on wallpaper image file: $($CurrentWallpaperImageFilePath). Error message: $($_.Exception.Message)" -Severity 3
                                            }
                                        }
                                        catch [System.Exception] {
                                            Write-LogEntry -Value "- Failed to revert permissions for wallpaper image file. Error message: $($_.Exception.Message)" -Severity 3
                                        }
                                    }
                                    catch [System.Exception] {
                                        Write-LogEntry -Value "- Failed to copy the downloaded wallpaper image file to the default wallpaper location. Error message: $($_.Exception.Message)" -Severity 3
                                    }
                                }
                                catch [System.Exception] {
                                    Write-LogEntry -Value "- Failed to remove existing wallpaper image file: $($CurrentWallpaperImageFilePath). Error message: $($_.Exception.Message)" -Severity 3
                                }
                            }
                        }
                    }
                    catch [System.Exception] {
                        Write-LogEntry -Value "- Failed to enumerate existing wallpaper image files. Error message: $($_.Exception.Message)" -Severity 3
                    }
                }
            }
            else {
                Write-LogEntry -Value "- Failed to download the wallpaper image file." -Severity 3
            }
        }
        catch [System.Exception] {
            Write-LogEntry -Value "- Failed to download the wallpaper image file. Error message: $($_.Exception.Message)" -Severity 3
        }
    }
    catch [System.Exception] {
        Write-LogEntry -Value "- Failed to construct the storage account context. Error message: $($_.Exception.Message)" -Severity 3
    }

    # Handle final logging details for script module
    Write-LogEntry -Value "[$($ScriptModuleName)-Module] - Completed" -Severity 1
}