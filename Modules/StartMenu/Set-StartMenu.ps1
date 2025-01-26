<#
.SYNOPSIS
    Feature Update Controller script module for handling Start menu layout during a Windows feature update.

.DESCRIPTION
    This script module downloads the start2.bin Start menu layout file that's prepared as a default layout. Each user profile will have the layout imported during the feature update process.

.EXAMPLE
    .\Set-StartMenu.ps1

.NOTES
    FileName:    Set-StartMenu.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2024-08-27
    Updated:     2024-08-27

    Version history:
    1.0.0 - (2024-08-27) Script created
#>
Begin {
    # Declare the script module name
    $ScriptModuleName = "StartMenu"
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

    # Initial logging details for detection script
    Write-LogEntry -Value "[$($ScriptModuleName)-Module] - Initializing" -Severity 1

    # Declare manifest and Azure storage account container variables
    $StorageAccountName = "<storage_account_name>"
    $StorageAccountContainer = "<storage_account_container_name>"

    # Declare variable for company name
    $CompanyName = "<company_name>"

    # Declare the start menu layout file name to be downloaded
    $StartMenuFileName = "start2.bin"

    # Declare the feature update controller root directory in ProgramData
    $ProgramDataFeatureUpdateControllerRootPath = Join-Path -Path $env:SystemDrive -ChildPath "ProgramData\$($CompanyName)\FeatureUpdateController"

    # Declare temporary download destinations
    $TemporaryDownloadPath = Join-Path -Path $ProgramDataFeatureUpdateControllerRootPath -ChildPath "Temp"

    # Declare variable for user profile block list
    $BlockedUserProfiles = @("Public", "defaultuser0")

    try {
        # Construct the storage account context
        $StorageAccountContext = New-AzStorageContext -StorageAccountName $StorageAccountName -Anonymous -ErrorAction "Stop" -Verbose:$false

        try {
            # Declare the start menu layout file name
            $StartMenuFile = Join-Path -Path $PSScriptRoot -ChildPath $StartMenuFileName
            if (Test-Path -Path $StartMenuFile) {
                Write-LogEntry -Value "- Found start menu layout file: $($StartMenuFile)" -Severity 1
            }
            else {
                Write-LogEntry -Value "- Start menu layout file not found: $($StartMenuFile)" -Severity 3

                try {
                    # Download the Start menu layout file from the Azure storage account
                    Write-LogEntry -Value "- Downloading Start menu layout file from Azure storage account" -Severity 1
                    $StartMenuFileDownload = Get-AzStorageBlobContent -Container $StorageAccountContainer -Blob $StartMenuFileName -Destination $PSScriptRoot -Context $StorageAccountContext -Force -ErrorAction "Stop" -Verbose:$false
                    Write-LogEntry -Value "- Successfully downloaded the start menu layout file to: $($StartMenuFile)" -Severity 1
                }
                catch [System.Exception] {
                    Write-LogEntry -Value "- Failed to download the start menu layout file. Error message: $($_.Exception.Message)" -Severity 3
                }
            }

            # Check if download was successful and file is present
            if (Test-Path -Path $StartMenuFile) {
                # Declare the start menu layout file path variable
                $StartMenuLayoutFilePath = Join-Path -Path $PSScriptRoot -ChildPath $StartMenuFileName

                # Loop through all user profiles and copy the start2.bin to the StartMenuExperienceHost LocalState folder
                $UserProfiles = Get-ChildItem -Path (Join-Path -Path $env:SystemDrive -ChildPath "Users") -Directory -ErrorAction "SilentlyContinue"
                foreach ($UserProfile in $UserProfiles) {
                    Write-LogEntry -Value "- Current user profile path: $($UserProfile)" -Severity 1

                    # Check if the current user profile is in the blocked list
                    if ($UserProfile.Name -in $BlockedUserProfiles) {
                        Write-LogEntry -Value "- Skipping user profile due to block list: $($UserProfile.Name)" -Severity 1
                    }
                    else {
                        try {
                            # Check if the LocalState folder exists, if not create it
                            $CurrentUserProfileLocalStatePath = Join-Path -Path $UserProfile.FullName -ChildPath "AppData\Local\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState"
                            if (-not(Test-Path -Path $CurrentUserProfileLocalStatePath)) {
                                Write-LogEntry -Value "- LocalState folder does not exist, creating: $($CurrentUserProfileLocalStatePath)" -Severity 1
                                New-Item -Path $CurrentUserProfileLocalStatePath -ItemType Directory -Force -ErrorAction "Stop" | Out-Null
                            }
    
                            try {
                                # Copy the start2.bin file to the LocalState folder
                                Write-LogEntry -Value "- Importing layout: $($StartMenuLayoutFilePath)" -Severity 1
                                Write-LogEntry -Value "- Destination path: $($CurrentUserProfileLocalStatePath)" -Severity 1
                                Copy-Item -Path $StartMenuLayoutFilePath -Destination $CurrentUserProfileLocalStatePath -Force -ErrorAction "Stop" | Out-Null
                                Write-LogEntry -Value "- Successfully imported the start menu layout file" -Severity 1
                            }
                            catch [System.Exception] {
                                Write-LogEntry -Value "- Failed to import the start menu layout file. Error message: $($_.Exception.Message)" -Severity 3
                            }
                        }
                        catch [System.Exception] {
                            Write-LogEntry -Value "- Failed to create the LocalState directory. Error message: $($_.Exception.Message)" -Severity 3
                        }
                    }
                }
            }
            else {
                Write-LogEntry -Value "- Failed to download the start menu layout file. File not present in temporary download destination" -Severity 3
            }
        }
        catch [System.Exception] {
            Write-LogEntry -Value "- Failed to download the start menu layout file. Error message: $($_.Exception.Message)" -Severity 3
        }
    }
    catch [System.Exception] {
        Write-LogEntry -Value "- Failed to construct the storage account context. Error message: $($_.Exception.Message)" -Severity 3
    }

    # Handle final logging details for script module
    Write-LogEntry -Value "[$($ScriptModuleName)-Module] - Completed" -Severity 1
}