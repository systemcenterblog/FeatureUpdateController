<#
.SYNOPSIS
    Proaction Remediation script for staging and controlling required files for feature updates of Windows.

.DESCRIPTION
    This is the detection script for a Proactive Remediation in Endpoint Analytics used control the feature update automation aspects around Windows setup.

.EXAMPLE
    .\Detection.ps1

.NOTES
    FileName:    Detection.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2024-08-26
    Updated:     2024-08-26

    Version history:
    1.0.0 - (2024-08-26) Script created
#>
Begin {
    # Define the proactive remediation name
    $ProactiveRemediationName = "FeatureUpdateController"

    # Define if any modules must be present on the device for this proactive remediation to execute properly
    # Set to $null if no modules are to be installed
    $Modules = @("Az.Storage", "Az.Resources", "NTFSSecurity")

    # Enable TLS 1.2 support for downloading modules from PSGallery
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # Install required modules for script execution
    if ($Modules -ne $null) {
        foreach ($Module in $Modules) {
            try {
                $CurrentModule = Get-InstalledModule -Name $Module -ErrorAction "Stop" -Verbose:$false
                if ($CurrentModule -ne $null) {
                    $LatestModuleVersion = (Find-Module -Name $Module -ErrorAction "Stop" -Verbose:$false).Version
                    if ($LatestModuleVersion -gt $CurrentModule.Version) {
                        $UpdateModuleInvocation = Update-Module -Name $Module -Force -ErrorAction "Stop" -Confirm:$false -Verbose:$false
                    }
                }
            }
            catch [System.Exception] {
                try {
                    # Install NuGet package provider
                    $PackageProvider = Install-PackageProvider -Name "NuGet" -Force -Verbose:$false
            
                    # Install current missing module
                    Install-Module -Name $Module -Force -ErrorAction "Stop" -Confirm:$false -Verbose:$false
                }
                catch [System.Exception] {
                    Write-Warning -Message "An error occurred while attempting to install $($Module) module. Error message: $($_.Exception.Message)"
                }
            }
        }
    }
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
            [string]$FileName = "$($ProactiveRemediationName).log"
        )
        # Check if the script is running as SYSTEM, else use the user's temp folder for the log file location
        if ([Security.Principal.WindowsIdentity]::GetCurrent().IsSystem -eq $true) {
            $LogFilePath = Join-Path -Path (Join-Path -Path $env:ProgramData -ChildPath "Microsoft\IntuneManagementExtension\Logs") -ChildPath $FileName
        }
        else {
            $LogFilePath = Join-Path -Path (Join-Path -Path $env:TEMP -ChildPath "RemediationScript\Logs") -ChildPath $FileName
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
        $LogText = "<![LOG[$($Value)]LOG]!><time=""$($Time)"" date=""$($Date)"" component=""$($ProactiveRemediationName)"" context=""$($Context)"" type=""$($Severity)"" thread=""$($PID)"" file="""">"
        
        # Add value to log file
        try {
            Out-File -InputObject $LogText -Append -NoClobber -Encoding Default -FilePath $LogFilePath -ErrorAction Stop
        }
        catch [System.Exception] {
            Write-Warning -Message "Unable to append log entry $($ProactiveRemediationName).log file. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
        }
    }

    function Out-SetupConfigIniFile {
        param(
            [parameter(Mandatory = $true, HelpMessage = "Path to the INI file to be created.")]
            [ValidateNotNullOrEmpty()]
            [string]$Path,
    
            [parameter(Mandatory = $true, HelpMessage = "Data to be written to the INI file.")]
            [ValidateNotNullOrEmpty()]
            [System.Collections.Specialized.OrderedDictionary]$Value
        )
        Process {
            # Add the default section header
            $Data = "[SetupConfig]"
    
            # Loop through each key and value in the ordered dictionary and insert into the data string
            foreach ($DataKey in $Value.Keys) {
                # Add the key and value to the data string
                $Data += "`r`n$($DataKey)=$($Value[$DataKey])"
            }
            
            try {
                # Write the data to the INI file
                Out-File -FilePath $Path -InputObject $Data -Encoding "ascii" -ErrorAction "Stop"
            }
            catch [System.Exception] {
                throw "$($MyInvocation.MyCommand): Error message: $($_.Exception.Message)"
            }
        }
    }

    # Check if the script is running as SYSTEM, else declare the user's temp folder for the log file location used to rotation check
    if ([Security.Principal.WindowsIdentity]::GetCurrent().IsSystem -eq $true) {
        $LogFilePath = Join-Path -Path (Join-Path -Path $env:ProgramData -ChildPath "Microsoft\IntuneManagementExtension\Logs") -ChildPath $FileName
    }
    else {
        $LogFilePath = Join-Path -Path (Join-Path -Path $env:TEMP -ChildPath "RemediationScript\Logs") -ChildPath $FileName
    }

    # Check if the log file is larger than 3MB, if true, rotate the log file
    $LogFile = Join-Path -Path $LogFilePath -ChildPath "$($ProactiveRemediationName).log"
    if (Test-Path -Path $LogFile) {
        # Get log file size
        $LogFileSize = (Get-Item -Path $LogFile).Length
        
        # Rotate log file if it is larger than 3MB
        if ($LogFileSize -gt 3145728) { 
            $LogFileName = [System.IO.Path]::GetFileNameWithoutExtension($LogFile)
            $LogFileExtension = [System.IO.Path]::GetExtension($LogFile)
            $LogFileDateTime = (Get-Date).ToString("yyyyMMddHHmmss")
            $LogFileNewPath = Join-Path -Path $LogFilePath -ChildPath "$($LogFileName)_$($LogFileDateTime)$($LogFileExtension)"
            
            try {
                # Copy existing log file to new path, remove the existing log file and create a new empty log file
                Copy-Item -Path $LogFile -Destination $LogFileNewPath -Force -ErrorAction "Stop" | Out-Null
                Remove-Item -Path $LogFile -ErrorAction "Stop" | Out-Null
                New-Item -Path $LogFile -ItemType "File" -Force -ErrorAction "Stop" | Out-Null
            }
            catch [System.Exception] {
                Write-Warning -Message "An error occurred while attempting to rotate the log file. Error message: $($_.Exception.Message)"
            }

            # Keep only the last 2 rotated log files, remove the rest
            $LogFiles = Get-ChildItem -Path $LogFilePath | Sort-Object -Property CreationTime -Descending
            if ($LogFiles.Count -gt 2) {
                $LogFiles | Select-Object -Skip 2 | Remove-Item -Force -ErrorAction "Stop" | Out-Null
            }
        }
    }

    # Initial logging details for detection script
    Write-LogEntry -Value "[$($ProactiveRemediationName)-Detection] - Initializing" -Severity 1

    # Declare variable for company name
    $CompanyName = "<company_name>"

    # Declare manifest and Azure storage account container variables
    $StorageAccountName = "<storage_account_name>"
    $StorageAccountContainer = "<storage_account_container_name>"
    $ManifestFileName = "manifest.json"

    # Declare registry root path for version control of each modules (scripts to be executed)
    $RegistryRootKey = "HKLM:\SOFTWARE\$($CompanyName)\FeatureUpdateController"

    # Declare the feature update controller root directory in ProgramData
    $ProgramDataFeatureUpdateControllerRootPath = Join-Path -Path $env:SystemDrive -ChildPath "ProgramData\$($CompanyName)\FeatureUpdateController"

    # Declare temporary download destinations
    $TemporaryDownloadPath = Join-Path -Path $ProgramDataFeatureUpdateControllerRootPath -ChildPath "Temp"

    # Declare directory path for modules to be installed
    $ModulesDirectoryPath = Join-Path -Path $ProgramDataFeatureUpdateControllerRootPath -ChildPath "Modules"

    # Declare directory path for modules to be installed
    $CustomActionScriptsDirectoryPath = Join-Path -Path $ProgramDataFeatureUpdateControllerRootPath -ChildPath "CustomActions"

    # Declare variables for Windows setup files and paths
    $WindowsSetupConfigFilePath = Join-Path -Path $env:SystemDrive -ChildPath "Users\Default\AppData\Local\Microsoft\Windows\WSUS\SetupConfig.ini"

    # Declare variable for prerequisities to continue script operation
    $ScriptOperationPrerequisites = $true

    # Declare error message variable
    $ErrorMessage = $null

    # Output script paths
    Write-LogEntry -Value "- These environment paths and registry locations will be used" -Severity 1
    Write-LogEntry -Value "- Company name: $($CompanyName)" -Severity 1
    Write-LogEntry -Value "- Feature Update Controller registry root key: $($RegistryRootKey)" -Severity 1
    Write-LogEntry -Value "- Feature Update Controller directory root path: $($ProgramDataFeatureUpdateControllerRootPath)" -Severity 1
    Write-LogEntry -Value "- Temporary download path: $($TemporaryDownloadPath)" -Severity 1
    Write-LogEntry -Value "- Windows setup config file path: $($WindowsSetupConfigFilePath)" -Severity 1

    # Test if registry key exists
    if (-not(Test-Path -Path $RegistryRootKey)) {
        Write-LogEntry -Value "- Registry key does not exist, creating: $($RegistryRootKey)" -Severity 1
        
        try {
            # Create registry key
            New-Item -Path $RegistryRootKey -Force -ErrorAction "Stop" | Out-Null
        }
        catch [System.Exception] {
            $ErrorMessage = "Failed to create registry key. Error message: $($_.Exception.Message)"
            Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
            $ScriptOperationPrerequisites = $false
        }
    }

    # Test if feature update controller root path exists
    if (-not(Test-Path -Path $ProgramDataFeatureUpdateControllerRootPath)) {
        Write-LogEntry -Value "- Feature update controller root path does not exist, creating: $($ProgramDataFeatureUpdateControllerRootPath)" -Severity 1
        
        try {
            # Create feature update controller root path
            New-Item -Path $ProgramDataFeatureUpdateControllerRootPath -ItemType "Directory" -Force -ErrorAction "Stop" | Out-Null
        }
        catch [System.Exception] {
            $ErrorMessage = "Failed to create feature update controller root path. Error message: $($_.Exception.Message)"
            Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
            $ScriptOperationPrerequisites = $false
        }
    }

    # Test if temporary download path exists
    if (-not(Test-Path -Path $TemporaryDownloadPath)) {
        Write-LogEntry -Value "- Temporary download path does not exist, creating: $($TemporaryDownloadPath)" -Severity 1
        
        try {
            # Create temporary download path
            New-Item -Path $TemporaryDownloadPath -ItemType "Directory" -Force -ErrorAction "Stop" | Out-Null
        }
        catch [System.Exception] {
            $ErrorMessage = "Failed to create temporary download path. Error message: $($_.Exception.Message)"
            Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
            $ScriptOperationPrerequisites = $false
        }
    }

    # Test if the Custom Actions directory path exists
    if (-not(Test-Path -Path $CustomActionScriptsDirectoryPath)) {
        Write-LogEntry -Value "- Custom Actions directory path does not exist, creating: $($CustomActionScriptsDirectoryPath)" -Severity 1
        
        try {
            # Create Custom Actions directory path
            New-Item -Path $CustomActionScriptsDirectoryPath -ItemType "Directory" -Force -ErrorAction "Stop" | Out-Null
        }
        catch [System.Exception] {
            $ErrorMessage = "Failed to create Custom Actions directory path. Error message: $($_.Exception.Message)"
            Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
            $ScriptOperationPrerequisites = $false
        }
    }

    # Test if Windows setup config file parent path exists
    $WindowsSetupConfigPath = Split-Path -Path $WindowsSetupConfigFilePath -Parent
    if (-not(Test-Path -Path $WindowsSetupConfigPath)) {
        Write-LogEntry -Value "- Windows setup config file parent path does not exist, creating: $($WindowsSetupConfigPath)" -Severity 1
        
        try {
            # Create Windows setup config file parent path
            New-Item -Path $WindowsSetupConfigPath -ItemType "Directory" -Force -ErrorAction "Stop" | Out-Null
        }
        catch [System.Exception] {
            $ErrorMessage = "Failed to create Windows setup config file parent path. Error message: $($_.Exception.Message)"
            Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
            $ScriptOperationPrerequisites = $false
        }
    }

    # Test if modules directory path exists
    if (-not(Test-Path -Path $ModulesDirectoryPath)) {
        Write-LogEntry -Value "- Modules directory path does not exist, creating: $($ModulesDirectoryPath)" -Severity 1
        
        try {
            # Create modules directory path
            New-Item -Path $ModulesDirectoryPath -ItemType "Directory" -Force -ErrorAction "Stop" | Out-Null
        }
        catch [System.Exception] {
            $ErrorMessage = "Failed to create modules directory path. Error message: $($_.Exception.Message)"
            Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
            $ScriptOperationPrerequisites = $false
        }
    }

    #
    # TODO: Add support for install drivers
    #

    # Check if prerequisites for script operation are met, if true continue script operation
    if ($ScriptOperationPrerequisites -eq $true) {
        try {
            # Construct the storage account context
            $StorageAccountContext = New-AzStorageContext -StorageAccountName $StorageAccountName -Anonymous -ErrorAction "Stop" -Verbose:$false
    
            try {
                # Download the latest version manifest file from storage account to the temporary download destination
                $LatestVersionManifest = Get-AzStorageBlobContent -Container $StorageAccountContainer -Blob $ManifestFileName -Destination $TemporaryDownloadPath -Context $StorageAccountContext -ClientTimeoutPerRequest 30 -Force -ErrorAction "Stop" -Verbose:$false
    
                # Test that the manifest file was downloaded successfully
                $ManifestFilePath = Join-Path -Path $TemporaryDownloadPath -ChildPath $ManifestFileName
                if (Test-Path -Path $ManifestFilePath) {
                    Write-LogEntry -Value "- Successfully downloaded the latest version manifest file" -Severity 1

                    try {
                        # Parse the manifest file to get the latest version details of each script modules
                        $ManifestContent = Get-Content -Path $ManifestFilePath -Raw -ErrorAction "Stop" | ConvertFrom-Json
                        Write-LogEntry -Value "- Successfully parsed the latest version manifest file" -Severity 1

                        # Handle output of UpdateNotifications prerequisites
                        Write-LogEntry -Value "[UpdateNotifications] - Initializing" -Severity 1

                        # Parse the manifest file to check if any UpdateNotifications instructions are present to be configure locally on the device
                        if ($ManifestContent.UpdateNotifications) {
                            Write-LogEntry -Value "- Update notification instructions are present in the manifest file" -Severity 1
                            foreach ($UpdateNotification in $ManifestContent.UpdateNotifications) {
                                Write-LogEntry -Value "- Processing current update notification configuration: $($UpdateNotification.Name)" -Severity 1

                                # Validate that current update notification contains required properties
                                if (-not($UpdateNotification.Name -and $UpdateNotification.KeyPath -and $UpdateNotification.DataValue -and $UpdateNotification.Type)) {
                                    $ErrorMessage = "Update notification configuration is missing required properties. Required properties: Name, KeyPath, DataValue, Type"
                                    Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
                                    $ScriptOperationPrerequisites = $false
                                    break
                                }

                                # Check if the update notification registry key exists
                                if (Test-Path -Path $UpdateNotification.KeyPath) {
                                    Write-LogEntry -Value "- Update notification registry key already exists: $($UpdateNotification.KeyPath)" -Severity 1
                                }
                                else {
                                    Write-LogEntry -Value "- Update notification registry key does not exist, creating: $($UpdateNotification.KeyPath)" -Severity 1

                                    try {
                                        # Create the update notification registry key
                                        New-Item -Path $UpdateNotification.KeyPath -Force -ErrorAction "Stop" | Out-Null
                                        Write-LogEntry -Value "- Successfully created update notification registry key" -Severity 1
                                    }
                                    catch [System.Exception] {
                                        $ErrorMessage = "Failed to create update notification registry key. Error message: $($_.Exception.Message)"
                                        Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
                                        $ScriptOperationPrerequisites = $false
                                    }
                                }

                                # Check if the update notification registry key value exists
                                Write-LogEntry -Value "- Checking if update notification registry value '$($UpdateNotification.Name)' exists in: $($UpdateNotification.KeyPath)" -Severity 1
                                $UpdateNotificationKeyValuePresence = Get-ItemProperty -Path $UpdateNotification.KeyPath -Name $UpdateNotification.Name -ErrorAction "SilentlyContinue"
                                if ($UpdateNotificationKeyValuePresence -eq $null) {
                                    Write-LogEntry -Value "- Update notification registry value does not exist, creating registry value '$($UpdateNotification.Name)' with data value '$($UpdateNotification.DataValue)' in: $($UpdateNotification.KeyPath)" -Severity 1

                                    try {
                                        # Create the update notification registry key
                                        New-ItemProperty -Path $UpdateNotification.KeyPath -Name $UpdateNotification.Name -PropertyType $UpdateNotification.Type -Value $UpdateNotification.DataValue -Force -ErrorAction "Stop" | Out-Null
                                        Write-LogEntry -Value "- Successfully created update notification registry value" -Severity 1
                                    }
                                    catch [System.Exception] {
                                        $ErrorMessage = "Failed to create update notification registry key. Error message: $($_.Exception.Message)"
                                        Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
                                        $ScriptOperationPrerequisites = $false
                                    }
                                }
                                else {
                                    Write-LogEntry -Value "- Update notification registry value '$($UpdateNotification.Name)' exists in: $($UpdateNotification.KeyPath)" -Severity 1

                                    # Check if registry data value conforms with the manifest file
                                    Write-LogEntry -Value "- Checking if update notification registry value '$($UpdateNotification.Name)' data value matches value from manifest file: $($UpdateNotification.DataValue)" -Severity 1
                                    $UpdateNotificationRegistryValueData = Get-ItemPropertyValue -Path $UpdateNotification.KeyPath -Name $UpdateNotification.Name
                                    if ($UpdateNotificationRegistryValueData -ne $UpdateNotification.DataValue) {
                                        Write-LogEntry -Value "- Current value of update notification '$($UpdateNotification.Name)' registry value: $($UpdateNotificationRegistryValueData)" -Severity 1
                                        Write-LogEntry -Value "- Update notification registry value '$($UpdateNotification.Name)' data value does not match value from manifest file, updating to: $($UpdateNotification.DataValue)" -Severity 1

                                        try {
                                            # Update the update notification registry key value
                                            Set-ItemProperty -Path $UpdateNotification.KeyPath -Name $UpdateNotification.Name -Value $UpdateNotification.DataValue -ErrorAction "Stop" | Out-Null
                                            Write-LogEntry -Value "- Successfully updated update notification registry value" -Severity 1
                                        }
                                        catch [System.Exception] {
                                            $ErrorMessage = "Failed to update update notification registry key. Error message: $($_.Exception.Message)"
                                            Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
                                            $ScriptOperationPrerequisites = $false
                                        }
                                    }
                                    else {
                                        Write-LogEntry -Value "- Update notification registry value '$($UpdateNotification.Name)' data value matches value from manifest file: $($UpdateNotification.DataValue)" -Severity 1
                                    }
                                }
                            }
                        }
                        else {
                            Write-LogEntry -Value "- No update notification instructions are present in the manifest file" -Severity 1
                        }

                        # Handle output of UpdateNotifications prerequisites
                        Write-LogEntry -Value "[UpdateNotifications] - Completed" -Severity 1

                        if ($ScriptOperationPrerequisites -eq $true) {
                            # Construct hashtable for SetupConfig parameters from manifest file
                            $WindowsSetupManifestParametersTable = @{}
                            foreach ($KeyValuePair in $ManifestContent.SetupConfig) {
                                $WindowsSetupManifestParametersTable.Add($KeyValuePair.Name, $KeyValuePair.Value)
                            }

                            # Handle output of Windows setup engine script prerequisites
                            Write-LogEntry -Value "[WindowsSetupEngine-Prerequisites] - Initializing" -Severity 1

                            # Detect if manifest file contains any paths to directories that must be created prior to script execution
                            $WindowsSetupParametersList = @("PostOOBE", "PostRollback", "CopyLogs")
                            foreach ($WindowsSetupParameter in $WindowsSetupParametersList) {
                                if ($WindowsSetupManifestParametersTable.ContainsKey($WindowsSetupParameter)) {
                                    Write-LogEntry -Value "- Found Windows setup parameter '$($WindowsSetupParameter)' in manifest file, check if defined path exists" -Severity 1
                                    $WindowsSetupParameterParentPath = Split-Path -Path $WindowsSetupManifestParametersTable[$WindowsSetupParameter] -Parent
                                    Write-LogEntry -Value "- Checking if parent path '$($WindowsSetupParameterParentPath)' for '$($WindowsSetupParameter)' exists" -Severity 1
                                    if (-not(Test-Path -Path $WindowsSetupParameterParentPath)) {
                                        Write-LogEntry -Value "- Path '$($WindowsSetupParameterParentPath)' does not exist, creating: $($WindowsSetupParameterParentPath)" -Severity 1
                                        try {
                                            New-Item -Path $WindowsSetupParameterParentPath -ItemType "Directory" -Force -ErrorAction "Stop" | Out-Null
                                        }
                                        catch [System.Exception] {
                                            $ErrorMessage = "Failed to create path '$($WindowsSetupParameterParentPath)'. Error message: $($_.Exception.Message)"
                                            Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
                                            $ScriptOperationPrerequisites = $false
                                        }
                                    }
                                }
                            }

                            if ($ScriptOperationPrerequisites -eq $true) {
                                try {
                                    # Generate SetupConfig.ini file with data from the manifest file
                                    Write-LogEntry -Value "- Generating the SetupConfig.ini file" -Severity 1
                                    $SetupConfigData = [System.Collections.Specialized.OrderedDictionary]::new()
                                    foreach ($KeyValuePair in $ManifestContent.SetupConfig) {
                                        Write-LogEntry -Value "- Adding key '$($KeyValuePair.Name)' with value: $($KeyValuePair.Value)" -Severity 1
                                        $SetupConfigData.Add($KeyValuePair.Name, $KeyValuePair.Value)
                                    }
                                    Write-LogEntry -Value "- Successfully added all keys and values to the SetupConfig.ini data construct" -Severity 1
                                    Out-SetupConfigIniFile -Path $WindowsSetupConfigFilePath -Value $SetupConfigData -ErrorAction "Stop"
                                    Write-LogEntry -Value "- Successfully generated the SetupConfig.ini file" -Severity 1

                                    # Determine if manifest file contains specifications to for the SetupComplete script files to be created, where POSTOOBE as setup parameter is defined in the SetupConfig data
                                    if ($SetupConfigData["POSTOOBE"]) {
                                        Write-LogEntry -Value "- POSTOOBE setup parameter is defined in the manifest file, check if SetupComplete script have been defined" -Severity 1
                                        foreach ($SetupConfigScriptFile in $ManifestContent.SetupConfigScriptFiles) {
                                            if ($SetupConfigScriptFile.Type -eq "POSTOOBE") {
                                                $SetupCompleteCmdFilePath = Join-Path -Path $ProgramDataFeatureUpdateControllerRootPath -ChildPath "SetupComplete.cmd"
                                                Write-LogEntry -Value "- Found POSTOOBE script file in manifest file, check if SetupComplete script file exists in: $($ProgramDataFeatureUpdateControllerRootPath)" -Severity 1

                                                # Determine the SetupComplete script file name
                                                $SetupConfigScriptFileName = $ManifestContent.SetupConfigScriptFiles | Where-Object { $PSItem.Type -eq "POSTOOBE" } | Select-Object -ExpandProperty "ScriptFile"
                                                if ($SetupConfigScriptFileName -ne $null) {
                                                    # Construct the SetupComplete.cmd file in the ProgramData directory
                                                    if (-not(Test-Path -Path $SetupCompleteCmdFilePath)) {
                                                        Write-LogEntry -Value "- SetupComplete.cmd file does not exist, creating: $($SetupCompleteCmdFilePath)" -Severity 1

                                                        try {
                                                            # Create the SetupComplete.cmd file
                                                            New-Item -Path $SetupCompleteCmdFilePath -ItemType File -Force -ErrorAction "Stop" | Out-Null
                                                            Write-LogEntry -Value "- Successfully created SetupComplete.cmd file" -Severity 1
                                                        }
                                                        catch [System.Exception] {
                                                            $ErrorMessage = "Failed to create SetupComplete.cmd file. Error message: $($_.Exception.Message)"
                                                            Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
                                                            $ScriptOperationPrerequisites = $false
                                                        }
                                                        
                                                        try {
                                                            # Add the command to be executed to the SetupComplete.cmd file
                                                            $SetupCompleteCmdFileContent = "powershell.exe -ExecutionPolicy Bypass -NoProfile -File ""$($ProgramDataFeatureUpdateControllerRootPath)\$($SetupConfigScriptFileName)"" -WindowStyle Hidden"
                                                            Write-LogEntry -Value "- Adding command to SetupComplete.cmd file: $($SetupCompleteCmdFileContent)" -Severity 1
                                                            Add-Content -Path $SetupCompleteCmdFilePath -Value $SetupCompleteCmdFileContent -ErrorAction "Stop"
                                                            Write-LogEntry -Value "- Successfully added command to SetupComplete.cmd file" -Severity 1
                                                        }
                                                        catch [System.Exception] {
                                                            $ErrorMessage = "Failed to add powershell.exe command to SetupComplete.cmd file. Error message: $($_.Exception.Message)"
                                                            Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
                                                            $ScriptOperationPrerequisites = $false
                                                        }
                                                    }
                                                    else {
                                                        Write-LogEntry -Value "- SetupComplete.cmd file already exists, but command line update may be required" -Severity 1

                                                        # Check if the script file name in the SetupComplete.cmd file is the same as the one in the manifest file
                                                        $SetupCompleteCmdFileContent = Get-Content -Path $SetupCompleteCmdFilePath -ErrorAction "Stop"
                                                        $SetupCompleteCmdFileContent = $SetupCompleteCmdFileContent | Where-Object { $PSItem -match "powershell.exe" }
                                                        $SetupCompleteCmdFileContent = $SetupCompleteCmdFileContent -replace "[^\\]+(?=\.ps1$)", [System.IO.Path]::GetFileNameWithoutExtension($SetupConfigScriptFileName)

                                                        try {
                                                            # Update the command to be executed in the SetupComplete.cmd file
                                                            Write-LogEntry -Value "- Updating SetupComplete.cmd command line to: $($SetupCompleteCmdFileContent)" -Severity 1
                                                            Set-Content -Path $SetupCompleteCmdFilePath -Value $SetupCompleteCmdFileContent -ErrorAction "Stop"
                                                        }
                                                        catch [System.Exception] {
                                                            $ErrorMessage = "Failed to update SetupComplete.cmd file. Error message: $($_.Exception.Message)"
                                                            Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
                                                            $ScriptOperationPrerequisites = $false
                                                        }
                                                    }

                                                    try {
                                                        # Download SetupComplete script file from storage account to the feature update controller root directory
                                                        $SetupCompletePs1FilePath = Join-Path -Path $ProgramDataFeatureUpdateControllerRootPath -ChildPath $SetupConfigScriptFileName
                                                        Write-LogEntry -Value "- Downloading '$($SetupConfigScriptFileName)' file from storage account to: $($SetupCompletePs1FilePath)" -Severity 1
                                                        $SetupCompletePs1File = Get-AzStorageBlobContent -Container $StorageAccountContainer -Blob $SetupConfigScriptFileName -Destination $ProgramDataFeatureUpdateControllerRootPath -Context $StorageAccountContext -ClientTimeoutPerRequest 30 -Force -ErrorAction "Stop" -Verbose:$false
                                                    }
                                                    catch [System.Exception] {
                                                        $ErrorMessage = "Failed to download $($SetupConfigScriptFileName) file. Error message: $($_.Exception.Message)"
                                                        Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
                                                        $ScriptOperationPrerequisites = $false
                                                    }
                                                }
                                                else {
                                                    Write-LogEntry -Value "- Script file name for type POSTOOBE is not defined in the manifest file, skipping file creation and download process" -Severity 1
                                                }
                                            }
                                            else {
                                                Write-LogEntry -Value "- POSTOOBE type was not defined in SetupConfig parameters in manifest file, skipping" -Severity 1
                                            }
                                        }
                                    }

                                    # Determine if manifest file contains specifications to for the SetupComplete script files to be created, where PostRollback as setup parameter is defined in the SetupConfig data
                                    if ($SetupConfigData["PostRollback"]) {
                                        Write-LogEntry -Value "- PostRollback setup parameter is defined in the manifest file, check if SetupRollback script have been defined" -Severity 1
                                        foreach ($SetupConfigScriptFile in $ManifestContent.SetupConfigScriptFiles) {
                                            if ($SetupConfigScriptFile.Type -eq "PostRollback") {
                                                $SetupRollbackCmdFilePath = Join-Path -Path $ProgramDataFeatureUpdateControllerRootPath -ChildPath "SetupRollback.cmd"
                                                Write-LogEntry -Value "- Found PostRollback script file in manifest file, check if SetupRollback script file exists in: $($ProgramDataFeatureUpdateControllerRootPath)" -Severity 1

                                                # Determine the PostRollback script file name
                                                $SetupConfigScriptFileName = $ManifestContent.SetupConfigScriptFiles | Where-Object { $PSItem.Type -eq "PostRollback" } | Select-Object -ExpandProperty "ScriptFile"
                                                if ($SetupConfigScriptFileName -ne $null) {
                                                    # Construct the PostRollback associated command file in the ProgramData directory
                                                    if (-not(Test-Path -Path $SetupRollbackCmdFilePath)) {
                                                        Write-LogEntry -Value "- SetupRollback.cmd file does not exist, creating: $($SetupRollbackCmdFilePath)" -Severity 1

                                                        try {
                                                            # Create the PostRollback associated command file
                                                            New-Item -Path $SetupRollbackCmdFilePath -ItemType File -Force -ErrorAction "Stop" | Out-Null
                                                            Write-LogEntry -Value "- Successfully created SetupRollback.cmd file" -Severity 1
                                                        }
                                                        catch [System.Exception] {
                                                            $ErrorMessage = "Failed to create SetupRollback.cmd file. Error message: $($_.Exception.Message)"
                                                            Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
                                                            $ScriptOperationPrerequisites = $false
                                                        }
                                                        
                                                        try {
                                                            # Add the command to be executed to the SetupRollback.cmd file
                                                            $SetupRollbackCmdFileContent = "powershell.exe -ExecutionPolicy Bypass -NoProfile -File ""$($ProgramDataFeatureUpdateControllerRootPath)\$($SetupConfigScriptFileName)"" -WindowStyle Hidden"
                                                            Write-LogEntry -Value "- Adding command to SetupRollback.cmd file: $($SetupRollbackCmdFileContent)" -Severity 1
                                                            Add-Content -Path $SetupRollbackCmdFilePath -Value $SetupRollbackCmdFileContent -ErrorAction "Stop"
                                                            Write-LogEntry -Value "- Successfully added command to SetupRollback.cmd file" -Severity 1
                                                        }
                                                        catch [System.Exception] {
                                                            $ErrorMessage = "Failed to add powershell.exe command to SetupRollback.cmd file. Error message: $($_.Exception.Message)"
                                                            Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
                                                            $ScriptOperationPrerequisites = $false
                                                        }
                                                    }
                                                    else {
                                                        Write-LogEntry -Value "- SetupRollback.cmd file already exists, but command line update may be required" -Severity 1

                                                        # Check if the script file name in the SetupRollback.cmd file is the same as the one in the manifest file
                                                        $SetupRollbackCmdFileContent = Get-Content -Path $SetupRollbackCmdFilePath -ErrorAction "Stop"
                                                        $SetupRollbackCmdFileContent = $SetupRollbackCmdFileContent | Where-Object { $PSItem -match "powershell.exe" }
                                                        $SetupRollbackCmdFileContent = $SetupRollbackCmdFileContent -replace "[^\\]+(?=\.ps1$)", [System.IO.Path]::GetFileNameWithoutExtension($SetupConfigScriptFileName)
                                                        
                                                        try {
                                                            # Update the command to be executed in the SetupRollback.cmd file
                                                            Write-LogEntry -Value "- Updating SetupRollback.cmd command line to: $($SetupRollbackCmdFileContent)" -Severity 1
                                                            Set-Content -Path $SetupRollbackCmdFilePath -Value $SetupRollbackCmdFileContent -ErrorAction "Stop"
                                                        }
                                                        catch [System.Exception] {
                                                            $ErrorMessage = "Failed to update SetupRollback.cmd file. Error message: $($_.Exception.Message)"
                                                            Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
                                                            $ScriptOperationPrerequisites = $false
                                                        }
                                                    }

                                                    try {
                                                        # Download SetupRollback script file from storage account to the feature update controller root directory
                                                        $SetupConfigScriptFileName = $ManifestContent.SetupConfigScriptFiles | Where-Object { $PSItem.Type -eq "PostRollback" } | Select-Object -ExpandProperty "ScriptFile"
                                                        $SetupRollbackPs1FilePath = Join-Path -Path $ProgramDataFeatureUpdateControllerRootPath -ChildPath $SetupConfigScriptFileName
                                                        Write-LogEntry -Value "- Downloading '$($SetupConfigScriptFileName)' file from storage account to: $($SetupRollbackPs1FilePath)" -Severity 1
                                                        $SetupRollbackPs1File = Get-AzStorageBlobContent -Container $StorageAccountContainer -Blob $SetupConfigScriptFileName -Destination $ProgramDataFeatureUpdateControllerRootPath -Context $StorageAccountContext -ClientTimeoutPerRequest 30 -Force -ErrorAction "Stop" -Verbose:$false
                                                    }
                                                    catch [System.Exception] {
                                                        $ErrorMessage = "Failed to download $($SetupConfigScriptFileName) file. Error message: $($_.Exception.Message)"
                                                        Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
                                                        $ScriptOperationPrerequisites = $false
                                                    }
                                                }
                                                else {
                                                    Write-LogEntry -Value "- Script file name for type PostRollback is not defined in the manifest file, skipping file creation and download process" -Severity 1
                                                }
                                            }
                                            else {
                                                Write-LogEntry -Value "- PostRollback type was not defined in SetupConfig parameters in manifest file, skipping" -Severity 1
                                            }
                                        }
                                    }

                                    # Handle output of Windows setup engine script prerequisites
                                    Write-LogEntry -Value "[WindowsSetupEngine-Prerequisites] - Completed" -Severity 1

                                    # Handle output of custom actions prerequisites
                                    Write-LogEntry -Value "[CustomActions-Install] - Initializing" -Severity 1

                                    # Create and download the required custom actions in the manifest file section named CustomActions
                                    if ($ManifestContent.CustomActions.Count -ge 1) {
                                        Write-LogEntry -Value "- Found $($ManifestContent.CustomActions.Count) custom actions in the manifest file" -Severity 1

                                        # Declare variable path for custom actions directory
                                        $CustomActionsRootPath = Join-Path -Path $env:Windir -ChildPath "System32\update"

                                        # Check if the custom actions are set to force update, if true delete existing custom actions
                                        if ($ManifestContent.CustomActionsConfig.ForceUpdate -eq $true) {
                                            Write-LogEntry -Value "- Custom actions are set to force update, deleting existing custom actions" -Severity 1
                                            
                                            try {
                                                # Remove custom actions unique folder registry key
                                                $CustomActionRootRegistryKey = Join-Path -Path $RegistryRootKey -ChildPath "CustomActions"
                                                if (Test-Path -Path $CustomActionRootRegistryKey) {
                                                    Write-LogEntry -Value "- Removing custom action registry root key: $($CustomActionRootRegistryKey)" -Severity 1
                                                    Remove-Item -Path $CustomActionRootRegistryKey -Recurse -Force -ErrorAction "Stop" | Out-Null
                                                }
                                                else {
                                                    Write-LogEntry -Value "- Custom action registry root key does not exist, skipping removal" -Severity 1
                                                }
                                            }
                                            catch [System.Exception] {
                                                $ErrorMessage = "Failed to remove custom action registry key. Error message: $($_.Exception.Message)"
                                                Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
                                                $ScriptOperationPrerequisites = $false
                                            }
                                            
                                            try {
                                                # Cleanup the System32\update directory
                                                Write-LogEntry -Value "- Cleaning up the custom actions directory: $($CustomActionsRootPath)" -Severity 1
                                                if (Test-Path -Path $CustomActionsRootPath) {
                                                    Remove-Item -Path "$($CustomActionsRootPath)\*" -Recurse -Force -ErrorAction "Stop" | Out-Null
                                                }
                                                else {
                                                    Write-LogEntry -Value "- Custom actions directory does not exist, skipping cleanup" -Severity 1
                                                }
                                            }
                                            catch [System.Exception] {
                                                $ErrorMessage = "Failed to cleanup the custom actions directory. Error message: $($_.Exception.Message)"
                                                Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
                                                $ScriptOperationPrerequisites = $false
                                            }

                                            try {
                                                # Cleanup the feature update controller custom actions directory
                                                Write-LogEntry -Value "- Cleaning up the custom actions directory: $($CustomActionScriptsDirectoryPath)" -Severity 1
                                                if (Test-Path -Path $CustomActionScriptsDirectoryPath) {
                                                    Remove-Item -Path "$($CustomActionScriptsDirectoryPath)\*" -Recurse -Force -ErrorAction "Stop" | Out-Null
                                                }
                                                else {
                                                    Write-LogEntry -Value "- Custom actions directory does not exist, skipping cleanup" -Severity 1
                                                }
                                            }
                                            catch [System.Exception] {
                                                $ErrorMessage = "Failed to cleanup the custom actions directory. Error message: $($_.Exception.Message)"
                                                Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
                                                $ScriptOperationPrerequisites = $false
                                            }
                                        }

                                        # Register the unique folder name in the registry
                                        $CustomActionRootRegistryKey = Join-Path -Path $RegistryRootKey -ChildPath "CustomActions"
                                        if (-not(Test-Path -Path $CustomActionRootRegistryKey)) {
                                            Write-LogEntry -Value "- Custom action unique folder registry key does not exist, creating: $($CustomActionRootRegistryKey)" -Severity 1

                                            try {
                                                # Create custom action unique folder registry key
                                                Write-LogEntry -Value "- Creating custom action root registry key: $($CustomActionRootRegistryKey)" -Severity 1
                                                New-Item -Path $CustomActionRootRegistryKey -Force -ErrorAction "Stop" | Out-Null
                                            }
                                            catch [System.Exception] {
                                                $ErrorMessage = "Failed to create custom action root registry key. Error message: $($_.Exception.Message)"
                                                Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
                                                $ScriptOperationPrerequisites = $false
                                            }
                                        }
                                        else {
                                            Write-LogEntry -Value "- Custom action registry key already exists: $($CustomActionRootRegistryKey)" -Severity 1
                                        }

                                        # Loop through each custom action in the manifest file
                                        foreach ($CustomAction in $ManifestContent.CustomActions) {
                                            Write-LogEntry -Value "- Processing custom action: $($CustomAction.Name)" -Severity 1

                                            # Declare variable for custom action type
                                            $CustomActionType = $CustomAction.Type.ToLower()

                                            # Declare variable for custom action name
                                            $CustomActionName = $CustomAction.Name

                                            # Check if the custom action registry root key contains a a sub-key with a known unique folder name in GUID format
                                            Write-LogEntry -Value "- Checking if custom action registry root key contains a sub-key with a known unique folder name in GUID format" -Severity 1
                                            $UniqueFolderName = Get-ChildItem -Path $CustomActionRootRegistryKey -ErrorAction "SilentlyContinue" | Where-Object { $PSItem.PSChildName -match "^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$" }
                                            if ($UniqueFolderName -ne $null) {
                                                $UniqueFolderName = $UniqueFolderName.PSChildName
                                                Write-LogEntry -Value "- Found unique folder name in custom action registry root key: $($UniqueFolderName)" -Severity 1
                                            }
                                            else {
                                                Write-LogEntry -Value "- No unique folder name found in custom action registry root key" -Severity 1
                                                $UniqueFolderName = (New-Guid).Guid
                                                Write-LogEntry -Value "- Generated unique folder name for custom action type of : $($UniqueFolderName)" -Severity 1
                                            }

                                            # Check if the custom action unique folder registry key exists for current custom action
                                            $CustomActionUniqueFolderRegistryKey = Join-Path -Path $CustomActionRootRegistryKey -ChildPath $UniqueFolderName
                                            if (-not(Test-Path -Path $CustomActionUniqueFolderRegistryKey)) {
                                                Write-LogEntry -Value "- Custom action unique folder registry key does not exist, creating: $($CustomActionUniqueFolderRegistryKey)" -Severity 1

                                                try {
                                                    # Create custom action unique folder registry key
                                                    Write-LogEntry -Value "- Creating custom action unique folder registry key: $($CustomActionUniqueFolderRegistryKey)" -Severity 1
                                                    New-Item -Path $CustomActionUniqueFolderRegistryKey -Force -ErrorAction "Stop" | Out-Null
                                                    Write-LogEntry -Value "- Successfully created custom action unique folder registry key" -Severity 1
                                                }
                                                catch [System.Exception] {
                                                    $ErrorMessage = "Failed to create custom action unique folder registry key. Error message: $($_.Exception.Message)"
                                                    Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
                                                    $ScriptOperationPrerequisites = $false
                                                }
                                            }
                                            else {
                                                Write-LogEntry -Value "- Custom action unique folder registry key already exists: $($CustomActionUniqueFolderRegistryKey)" -Severity 1
                                            }

                                            # Check if the custom action type registry key exists for current custom action
                                            $CustomActionTypeRegistryKey = Join-Path -Path $CustomActionUniqueFolderRegistryKey -ChildPath $CustomActionType
                                            if (-not(Test-Path -Path $CustomActionTypeRegistryKey)) {
                                                Write-LogEntry -Value "- Custom action type registry key does not exist, creating: $($CustomActionTypeRegistryKey)" -Severity 1

                                                try {
                                                    # Create custom action type registry key
                                                    Write-LogEntry -Value "- Creating custom action type registry key: $($CustomActionTypeRegistryKey)" -Severity 1
                                                    New-Item -Path $CustomActionTypeRegistryKey -Force -ErrorAction "Stop" | Out-Null
                                                    Write-LogEntry -Value "- Successfully created custom action type registry key" -Severity 1
                                                }
                                                catch [System.Exception] {
                                                    $ErrorMessage = "Failed to create custom action type registry key. Error message: $($_.Exception.Message)"
                                                    Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
                                                    $ScriptOperationPrerequisites = $false
                                                }
                                            }
                                            else {
                                                Write-LogEntry -Value "- Custom action type registry key already exists: $($CustomActionTypeRegistryKey)" -Severity 1
                                            }

                                            # Check if the custom action type registry key contains the required registry key for the custom action name
                                            $CustomActionNameRegistryKey = Join-Path -Path $CustomActionTypeRegistryKey -ChildPath $CustomActionName.ToLower()
                                            if (-not(Test-Path -Path $CustomActionNameRegistryKey)) {
                                                Write-LogEntry -Value "- Custom action name registry key does not exist, creating: $($CustomActionNameRegistryKey)" -Severity 1

                                                try {
                                                    # Create custom action name registry key
                                                    New-Item -Path $CustomActionNameRegistryKey -Force -ErrorAction "Stop" | Out-Null
                                                    Write-LogEntry -Value "- Successfully created custom action name registry key" -Severity 1
                                                }
                                                catch [System.Exception] {
                                                    $ErrorMessage = "Failed to create custom action name registry key. Error message: $($_.Exception.Message)"
                                                    Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
                                                    $ScriptOperationPrerequisites = $false
                                                }
                                            }
                                            else {
                                                Write-LogEntry -Value "- Custom action name registry key already exists: $($CustomActionNameRegistryKey)" -Severity 1
                                            }

                                            # Check if the custom action registry key contains the required registry ScriptFile value
                                            Write-LogEntry -Value "- Checking if custom action registry key contains the required registry ScriptFile value" -Severity 1
                                            $CustomActionScriptFileValue = Get-ItemProperty -Path $CustomActionNameRegistryKey -Name "ScriptFile" -ErrorAction "SilentlyContinue"
                                            if ($CustomActionScriptFileValue -eq $null) {
                                                Write-LogEntry -Value "- No custom action registry value was found with name: ScriptFile" -Severity 1

                                                try {
                                                    # Set the custom action name registry value
                                                    $CustomActionScriptFilePath = Join-Path -Path $CustomActionScriptsDirectoryPath -ChildPath $CustomAction.ScriptFile
                                                    Write-LogEntry -Value "- Setting custom action registry value 'ScriptFile' with value: $($CustomActionScriptFilePath)" -Severity 1
                                                    New-ItemProperty -Path $CustomActionNameRegistryKey -Name "ScriptFile" -Value $CustomActionScriptFilePath -ErrorAction "Stop" | Out-Null
                                                    Write-LogEntry -Value "- Successfully added custom action registry value" -Severity 1
                                                }
                                                catch [System.Exception] {
                                                    $ErrorMessage = "Failed to add custom action registry value. Error message: $($_.Exception.Message)"
                                                    Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
                                                    $ScriptOperationPrerequisites = $false
                                                }
                                            }
                                            else {
                                                Write-LogEntry -Value "- Custom action registry value already exists with value: $($CustomActionScriptFilePath)" -Severity 1
                                            }

                                            # Declare variable for custom action directory path based on type
                                            $CustomActionFolderPath = Join-Path -Path (Join-Path -Path $CustomActionsRootPath -ChildPath $CustomActionType) -ChildPath $UniqueFolderName

                                            # Declare variables for ScriptWrapperFile and path
                                            $CustomActionScriptWrapperFileName = ("$($CustomActionName).cmd").ToLower()
                                            $CustomActionScriptWrapperFilePath = Join-Path -Path $CustomActionFolderPath -ChildPath $CustomActionScriptWrapperFileName

                                            # Check if the custom action registry key contains the required registry ScriptWrapperFile value
                                            Write-LogEntry -Value "- Checking if custom action registry key contains the required registry ScriptWrapperFile value" -Severity 1
                                            $CustomActionScriptWrapperFileValue = Get-ItemProperty -Path $CustomActionNameRegistryKey -Name "ScriptWrapperFile" -ErrorAction "SilentlyContinue"
                                            if ($CustomActionScriptWrapperFileValue -eq $null) {
                                                Write-LogEntry -Value "- No custom action registry value was found with name: ScriptWrapperFile" -Severity 1

                                                try {
                                                    # Set the custom action name registry value
                                                    Write-LogEntry -Value "- Setting custom action registry value 'ScriptWrapperFile' with value: $($CustomActionScriptWrapperFilePath)" -Severity 1
                                                    New-ItemProperty -Path $CustomActionNameRegistryKey -Name "ScriptWrapperFile" -Value $CustomActionScriptWrapperFilePath -ErrorAction "Stop" | Out-Null
                                                    Write-LogEntry -Value "- Successfully added custom action registry value" -Severity 1
                                                }
                                                catch [System.Exception] {
                                                    $ErrorMessage = "Failed to add custom action registry value. Error message: $($_.Exception.Message)"
                                                    Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
                                                    $ScriptOperationPrerequisites = $false
                                                }
                                            }
                                            else {
                                                Write-LogEntry -Value "- Custom action registry value already exists with value: $($CustomActionScriptWrapperFilePath)" -Severity 1
                                            }

                                            # Check if the custom action directory path exists
                                            if (-not(Test-Path -Path $CustomActionFolderPath)) {
                                                Write-LogEntry -Value "- Custom action directory path does not exist, creating: $($CustomActionFolderPath)" -Severity 1
                                                try {
                                                    # Create custom action directory path
                                                    New-Item -Path $CustomActionFolderPath -ItemType "Directory" -Force -ErrorAction "Stop" | Out-Null
                                                }
                                                catch [System.Exception] {
                                                    $ErrorMessage = "Failed to create custom action directory path. Error message: $($_.Exception.Message)"
                                                    Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
                                                    $ScriptOperationPrerequisites = $false
                                                }
                                            }

                                            # Continue if the custom action directory path exists
                                            if (Test-Path -Path $CustomActionFolderPath) {
                                                Write-LogEntry -Value "- Custom action directory path exists: $($CustomActionFolderPath)" -Severity 1

                                                # Construct the custom action script wrapper command file
                                                $CustomActionScriptWrapperFileName = ("$($CustomActionName).cmd").ToLower()
                                                $CustomActionScriptWrapperFilePath = Join-Path -Path $CustomActionFolderPath -ChildPath $CustomActionScriptWrapperFileName

                                                # Check if the custom action script wrapper command file exists
                                                if (-not(Test-Path -Path $CustomActionScriptWrapperFilePath)) {
                                                    Write-LogEntry -Value "- Custom action script wrapper command file '$($CustomActionScriptWrapperFileName)' does not exist, creating: $($CustomActionScriptWrapperFilePath)" -Severity 1
                                                    try {
                                                        # Create custom action script wrapper command file
                                                        New-Item -Path $CustomActionScriptWrapperFilePath -ItemType "File" -Force -ErrorAction "Stop" | Out-Null
                                                    }
                                                    catch [System.Exception] {
                                                        $ErrorMessage = "Failed to create custom action script wrapper command file. Error message: $($_.Exception.Message)"
                                                        Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
                                                        $ScriptOperationPrerequisites = $false
                                                    }

                                                    try {
                                                        # Add the custom action script wrapper command to the custom action script wrapper command file
                                                        $CustomActionScriptWrapperCommand = "powershell.exe -ExecutionPolicy Bypass -NoProfile -File ""$($CustomActionScriptsDirectoryPath)\$($CustomAction.ScriptFile)"" -WindowStyle Hidden"
                                                        Write-LogEntry -Value "- Adding custom action script wrapper command to: $($CustomActionScriptWrapperCommand)" -Severity 1
                                                        Add-Content -Path $CustomActionScriptWrapperFilePath -Value $CustomActionScriptWrapperCommand -ErrorAction "Stop"
                                                        Write-LogEntry -Value "- Successfully added custom action script wrapper command to: $($CustomActionScriptWrapperFilePath)" -Severity 1
                                                    }
                                                    catch [System.Exception] {
                                                        $ErrorMessage = "Failed to add custom action script wrapper command to custom action script wrapper command file. Error message: $($_.Exception.Message)"
                                                        Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
                                                        $ScriptOperationPrerequisites = $false
                                                    }
                                                }
                                                else {
                                                    Write-LogEntry -Value "- Custom action script wrapper command file '$($CustomActionScriptWrapperFileName)' already exists, but command line update may be required" -Severity 1

                                                    # Check if the script file name in the Custom Action command file is the same as the one in the manifest file
                                                    $CustomActionScriptWrapperFileContent = Get-Content -Path $CustomActionScriptWrapperFilePath -ErrorAction "Stop"
                                                    $CustomActionScriptWrapperFileContent = $CustomActionScriptWrapperFileContent | Where-Object { $PSItem -match "powershell.exe" }
                                                    $CustomActionScriptWrapperFileContent = $CustomActionScriptWrapperFileContent -replace "[^\\]+(?=\.ps1$)", [System.IO.Path]::GetFileNameWithoutExtension($CustomAction.ScriptFile)

                                                    try {
                                                        # Update the command to be executed in the custom action script wrapper command file
                                                        Write-LogEntry -Value "- Updating custom action script wrapper command line to: $($CustomActionScriptWrapperFileContent)" -Severity 1
                                                        Set-Content -Path $CustomActionScriptWrapperFilePath -Value $CustomActionScriptWrapperFileContent -ErrorAction "Stop"
                                                    }
                                                    catch [System.Exception] {
                                                        $ErrorMessage = "Failed to update custom action script wrapper command file. Error message: $($_.Exception.Message)"
                                                        Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
                                                        $ScriptOperationPrerequisites = $false
                                                    }
                                                }

                                                try {
                                                    # Download the custom action script file from the storage account to the custom action directory
                                                    Write-LogEntry -Value "- Downloading custom action script '$($CustomAction.ScriptFile)' from storage account to: $($CustomActionScriptsDirectoryPath)" -Severity 1
                                                    $CustomActionScriptFile = Get-AzStorageBlobContent -Container $StorageAccountContainer -Blob $CustomAction.ScriptFile -Destination $CustomActionScriptsDirectoryPath -Context $StorageAccountContext -ClientTimeoutPerRequest 30 -Force -ErrorAction "Stop" -Verbose:$false
                                                }
                                                catch [System.Exception] {
                                                    $ErrorMessage = "Failed to download custom action script '$($CustomAction.ScriptFile)'. Error message: $($_.Exception.Message)"
                                                    Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
                                                    $ScriptOperationPrerequisites = $false
                                                }
                                            }
                                            else {
                                                Write-LogEntry -Value "- Custom action directory path does not exist, skipping custom action script wrapper command file creation" -Severity 1
                                                $ScriptOperationPrerequisites = $false
                                            }
                                        }
                                    }
                                    else {
                                        # No custom actions defined in the manifest file
                                        Write-LogEntry -Value "- No custom actions defined in the manifest file" -Severity 1
                                    }

                                    # Handle output of custom actions prerequisites
                                    Write-LogEntry -Value "[CustomActions-Install] - Completed" -Severity 1

                                    if ($ScriptOperationPrerequisites -eq $true) {
                                        Write-LogEntry -Value "[ScriptModule-Install] - Initializing" -Severity 1

                                        if ($ManifestContent.Modules.Count -ge 1) {
                                            Write-LogEntry -Value "- Found '$($ManifestContent.Modules.Count)' script modules in the manifest file" -Severity 1

                                            try {
                                                # Process each script module from the manifest file
                                                foreach ($ScriptModule in $ManifestContent.Modules) {
                                                    # Construct the current module directory path
                                                    $ModuleDirectoryPath = Join-Path -Path $ModulesDirectoryPath -ChildPath $ScriptModule.Name

                                                    # Construct the current module registry key
                                                    $ModuleRegistryKey = Join-Path -Path $RegistryRootKey -ChildPath (Join-Path -Path "Modules" -ChildPath $ScriptModule.Name)

                                                    # Check if the current script module is already installed, by checking for the presence of the version registry value
                                                    Write-LogEntry -Value "- Checking if script module '$($ScriptModule.Name)' is installed" -Severity 1
                                                    if (-not(Test-Path -Path $ModuleRegistryKey)) {
                                                        Write-LogEntry -Value "- Script module '$($ScriptModule.Name)' is not installed, installing module" -Severity 1

                                                        try {
                                                            # Check if module specific directory exists in the modules directory path
                                                            if (-not(Test-Path -Path $ModuleDirectoryPath)) {
                                                                Write-LogEntry -Value "- Module directory path does not exist, creating: $($ModuleDirectoryPath)" -Severity 1
                                                                try {
                                                                    # Create module directory path
                                                                    New-Item -Path $ModuleDirectoryPath -ItemType "Directory" -Force -ErrorAction "Stop" | Out-Null
                                                                }
                                                                catch [System.Exception] {
                                                                    $ErrorMessage = "Failed to create module directory path. Error message: $($_.Exception.Message)"
                                                                    Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
                                                                }
                                                            }

                                                            try {
                                                                # Download the script module from the storage account to the module specific directory
                                                                Write-LogEntry -Value "- Downloading script module '$($ScriptModule.Name)' from storage account to: $($ModuleDirectoryPath)" -Severity 1
                                                                $ModuleScriptFile = Get-AzStorageBlobContent -Container $StorageAccountContainer -Blob $ScriptModule.ScriptFile -Destination $ModuleDirectoryPath -Context $StorageAccountContext -ClientTimeoutPerRequest 30 -Force -ErrorAction "Stop" -Verbose:$false
                                                            }
                                                            catch [System.Exception] {
                                                                $ErrorMessage = "Failed to download script module '$($ScriptModule.Name)'. Error message: $($_.Exception.Message)"
                                                                Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
                                                            }

                                                            try {
                                                                # Download the support file from the storage account to the module specific directory, if defined
                                                                if (($ScriptModule.SupportFile) -and (-not([string]::IsNullOrEmpty($ScriptModule.SupportFile)))) {
                                                                    Write-LogEntry -Value "- Downloading support file '$($ScriptModule.SupportFile)' from storage account to: $($ModuleDirectoryPath)" -Severity 1
$ModuleSupportFilePath = Join-Path -Path $ModuleDirectoryPath -ChildPath $ScriptModule.SupportFile
$ModuleSupportUrl = "$GitHubBaseUrl$ScriptModule.SupportFile"
Invoke-WebRequest -Uri $ModuleSupportUrl -OutFile $ModuleSupportFilePath -UseBasicParsing -ErrorAction Stop
                                                                    $ModuleSupportFile = Get-AzStorageBlobContent -Container $StorageAccountContainer -Blob $ScriptModule.SupportFile -Destination $ModuleDirectoryPath -Context $StorageAccountContext -ClientTimeoutPerRequest 30 -Force -ErrorAction "Stop" -Verbose:$false
                                                                }
                                                            }
                                                            catch [System.Exception] {
                                                                $ErrorMessage = "Failed to download support file '$($ScriptModule.SupportFile)'. Error message: $($_.Exception.Message)"
                                                                Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
                                                            }

                                                            # Create a sub-key in the registry for the script module
                                                            New-Item -Path $ModuleRegistryKey -Force -ErrorAction "Stop" | Out-Null

                                                            # Create a registry key for the version of the installed script module
                                                            New-ItemProperty -Path $ModuleRegistryKey -Name "Version" -Value $ScriptModule.Version -PropertyType "String" -Force -ErrorAction "Stop" | Out-Null

                                                            # Create a registry key for the script file name of the installed script module
                                                            New-ItemProperty -Path $ModuleRegistryKey -Name "Name" -Value $ScriptModule.ScriptFile -PropertyType "String" -Force -ErrorAction "Stop" | Out-Null

                                                            # Create a registry key for the script module directory path
                                                            New-ItemProperty -Path $ModuleRegistryKey -Name "Path" -Value $ModuleDirectoryPath -PropertyType "String" -Force -ErrorAction "Stop" | Out-Null
                                                            Write-LogEntry -Value "- Successfully installed script module: '$($ScriptModule.Name)'" -Severity 1
                                                        }
                                                        catch [System.Exception] {
                                                            $ErrorMessage = "Failed to install script module '$($ScriptModule.Name)'. Error message: $($_.Exception.Message)"
                                                            Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
                                                        }
                                                    }
                                                    else {
                                                        Write-LogEntry -Value "- Script module '$($ScriptModule.Name)' is already installed, perform update checks" -Severity 1

                                                        # Check if version of the current module from the manifest file is higher than the installed version
                                                        Write-LogEntry -Value "- Checking if script module '$($ScriptModule.Name)' requires update" -Severity 1
                                                        $InstalledModuleVersion = (Get-ItemProperty -Path $ModuleRegistryKey -Name "Version").Version
                                                        $LatestModuleVersion = $ScriptModule.Version
                                                        Write-LogEntry -Value "- Installed version of script module '$($ScriptModule.Name)': $($InstalledModuleVersion)" -Severity 1
                                                        Write-LogEntry -Value "- Latest version of script module '$($ScriptModule.Name)': $($ScriptModule.Version)" -Severity 1

                                                        if ([System.Version]$LatestModuleVersion -gt [System.Version]$InstalledModuleVersion) {
                                                            Write-LogEntry -Value "- Installed version of script module '$($ScriptModule.Name)' is lower than the latest version, update required" -Severity 1

                                                            try {
                                                                try {
                                                                    # Download the script module from the storage account to the module specific directory
                                                                    Write-LogEntry -Value "- Downloading script module '$($ScriptModule.Name)' from storage account to: $($ModuleDirectoryPath)" -Severity 1
                                                                    $ModuleScriptFile = Get-AzStorageBlobContent -Container $StorageAccountContainer -Blob $ScriptModule.ScriptFile -Destination $ModuleDirectoryPath -Context $StorageAccountContext -ClientTimeoutPerRequest 30 -Force -ErrorAction "Stop" -Verbose:$false
                                                                }
                                                                catch [System.Exception] {
                                                                    $ErrorMessage = "Failed to download script module '$($ScriptModule.Name)'. Error message: $($_.Exception.Message)"
                                                                    Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
                                                                }

                                                                try {
                                                                    # Download the support file from the storage account to the module specific directory, if defined
                                                                    if (($ScriptModule.SupportFile) -and (-not([string]::IsNullOrEmpty($ScriptModule.SupportFile)))) {
                                                                        Write-LogEntry -Value "- Downloading support file '$($ScriptModule.SupportFile)' from storage account to: $($ModuleDirectoryPath)" -Severity 1
                                                                        $ModuleSupportFile = Get-AzStorageBlobContent -Container $StorageAccountContainer -Blob $ScriptModule.SupportFile -Destination $ModuleDirectoryPath -Context $StorageAccountContext -ClientTimeoutPerRequest 30 -Force -ErrorAction "Stop" -Verbose:$false
                                                                    }
                                                                }
                                                                catch [System.Exception] {
                                                                    $ErrorMessage = "Failed to download support file '$($ScriptModule.SupportFile)'. Error message: $($_.Exception.Message)"
                                                                    Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
                                                                }

                                                                # Update the version of the installed script module
                                                                Set-ItemProperty -Path $ModuleRegistryKey -Name "Version" -Value $ScriptModule.Version -ErrorAction "Stop"

                                                                # Update the script file name of the installed script module
                                                                Set-ItemProperty -Path $ModuleRegistryKey -Name "Name" -Value $ScriptModule.ScriptFile -ErrorAction "Stop"
                                                                Write-LogEntry -Value "- Successfully updated script module: '$($ScriptModule.Name)'" -Severity 1
                                                            }
                                                            catch [System.Exception] {
                                                                $ErrorMessage = "Failed to update script module '$($ScriptModule.Name)'. Error message: $($_.Exception.Message)"
                                                                Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
                                                            }
                                                        }
                                                        else {
                                                            Write-LogEntry -Value "- Installed version of script module '$($ScriptModule.Name)' is up to date" -Severity 1
                                                        }

                                                        # Check if module update enforcment is required
                                                        if ($ScriptModule.ForceUpdate -eq $true) {
                                                            Write-LogEntry -Value "- Update enforcement is required for script module '$($ScriptModule.Name)'" -Severity 1

                                                            try {
                                                                # Download the script module from the storage account to the module specific directory
                                                                Write-LogEntry -Value "- Downloading script module '$($ScriptModule.Name)' from storage account to: $($ModuleDirectoryPath)" -Severity 1
                                                                $ModuleScriptFile = Get-AzStorageBlobContent -Container $StorageAccountContainer -Blob $ScriptModule.ScriptFile -Destination $ModuleDirectoryPath -Context $StorageAccountContext -ClientTimeoutPerRequest 30 -Force -ErrorAction "Stop" -Verbose:$false
                                                            }
                                                            catch [System.Exception] {
                                                                $ErrorMessage = "Failed to download script module '$($ScriptModule.Name)'. Error message: $($_.Exception.Message)"
                                                                Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
                                                            }

                                                            try {
                                                                # Download the support file from the storage account to the module specific directory, if defined
                                                                if (($ScriptModule.SupportFile) -and (-not([string]::IsNullOrEmpty($ScriptModule.SupportFile)))) {
                                                                    Write-LogEntry -Value "- Downloading support file '$($ScriptModule.SupportFile)' from storage account to: $($ModuleDirectoryPath)" -Severity 1
                                                                    $ModuleSupportFile = Get-AzStorageBlobContent -Container $StorageAccountContainer -Blob $ScriptModule.SupportFile -Destination $ModuleDirectoryPath -Context $StorageAccountContext -ClientTimeoutPerRequest 30 -Force -ErrorAction "Stop" -Verbose:$false
                                                                }
                                                            }
                                                            catch [System.Exception] {
                                                                $ErrorMessage = "Failed to download support file '$($ScriptModule.SupportFile)'. Error message: $($_.Exception.Message)"
                                                                Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            catch [System.Exception] {
                                                $ErrorMessage = "Failed to process script module '$($ScriptModule.Name)' from the manifest file. Error message: $($_.Exception.Message)"
                                                Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
                                            }

                                            # Handle output of script module installation
                                            Write-LogEntry -Value "[ScriptModule-Install] - Completed" -Severity 1
                                        }
                                        else {
                                            Write-LogEntry -Value "- No script modules defined in the manifest file" -Severity 1
                                        }

                                        Write-LogEntry -Value "[ScriptModule-Uninstall] - Initializing" -Severity 1

                                        # Check if the manifest file contains script modules
                                        if ($ManifestContent.Modules.Count -ge 1) {
                                            # Determine what script modules are installed based on registry keys presence
                                            $InstalledModules = Get-ChildItem -Path (Join-Path -Path $RegistryRootKey -ChildPath "Modules") -ErrorAction "SilentlyContinue"
                                            if ($InstalledModules -ne $null) {
                                                Write-LogEntry -Value "- Found '$($InstalledModules.Count)' script modules installed on the device" -Severity 1

                                                # Process each installed script module and check if it's present in the manifest file, if not, uninstall the script module
                                                foreach ($InstalledModule in $InstalledModules) {
                                                    $InstalledModuleName = $InstalledModule | Select-Object -ExpandProperty "PSChildName"
                                                    Write-LogEntry -Value "- Checking if installed script module '$($InstalledModuleName)' is present in the manifest file" -Severity 1
                                                    $ManifestModule = $ManifestContent.Modules | Where-Object { $PSItem.Name -eq $InstalledModuleName }
                                                    if ($ManifestModule -eq $null) {
                                                        Write-LogEntry -Value "- Installed script module '$($InstalledModuleName)' is not present in the manifest file, uninstalling" -Severity 1

                                                        try {
                                                            # Remove the module directory path
                                                            $ScriptModuleDirectoryPath = (Get-ItemProperty -Path $InstalledModule.PSPath -Name "Path").Path
                                                            Write-LogEntry -Value "- Removing module directory path for installed script module '$($InstalledModuleName)' in path: $($ScriptModuleDirectoryPath)" -Severity 1
                                                            Remove-Item -Path $ScriptModuleDirectoryPath -Force -Recurse -ErrorAction "Stop"
                                                        }
                                                        catch [System.Exception] {
                                                            $ErrorMessage = "Failed to remove module directory path for script module '$($InstalledModuleName)'. Error message: $($_.Exception.Message)"
                                                            Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
                                                        }
                                                        
                                                        try {
                                                            # Remove the registry key for the script module
                                                            Write-LogEntry -Value "- Removing registry key for installed script module '$($InstalledModuleName)' in path: $($InstalledModule.PSPath)" -Severity 1
                                                            Remove-Item -Path $InstalledModule.PSPath -Force -Recurse -ErrorAction "Stop"
                                                        }
                                                        catch [System.Exception] {
                                                            $ErrorMessage = "Failed to uninstall script module '$($InstalledModuleName)'. Error message: $($_.Exception.Message)"
                                                            Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
                                                        }
                                                    }
                                                    else {
                                                        Write-LogEntry -Value "- Installed script module '$($InstalledModuleName)' is present in the manifest file, skipping uninstallation" -Severity 1
                                                    }
                                                }
                                            }
                                            else {
                                                Write-LogEntry -Value "- No script modules are installed on the device based on registry discovery" -Severity 1
                                            }
                                        }
                                        else {
                                            # No script modules defined in the manifest file, but installed modules are present, uninstall all installed script modules
                                            Write-LogEntry -Value "- No script modules are defined in the manifest file, uninstalling all installed script modules if present locally on device" -Severity 1

                                            try {
                                                # Retrieve all sub-keys of installed modules from the registry
                                                $RegistryInstalledModules = Get-ChildItem -Path (Join-Path -Path $RegistryRootKey -ChildPath "Modules") -ErrorAction "Stop"
                                                if ($RegistryInstalledModules -ne $null) {
                                                    Write-LogEntry -Value "- Found '$($RegistryInstalledModules.Count)' script modules installed on the device" -Severity 1

                                                    # Process each installed script module and uninstall it
                                                    foreach ($RegistryInstalledModule in $RegistryInstalledModules) {
                                                        try {
                                                            # Remove the module directory path
                                                            $ScriptModuleDirectoryPath = (Get-ItemProperty -Path $InstalledModule.PSPath -Name "Path").Path
                                                            Write-LogEntry -Value "- Removing module directory path for installed script module '$($RegistryInstalledModule.PSChildName)' in path: $($ScriptModuleDirectoryPath)" -Severity 1
                                                            Remove-Item -Path $ScriptModuleDirectoryPath -Force -Recurse -ErrorAction "Stop"
                                                        }
                                                        catch [System.Exception] {
                                                            $ErrorMessage = "Failed to remove module directory path for script module '$($RegistryInstalledModule.PSChildName)'. Error message: $($_.Exception.Message)"
                                                            Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
                                                        }
                                                        
                                                        try {
                                                            # Remove the registry key for the script module
                                                            Write-LogEntry -Value "- Removing registry key for installed script module '$($RegistryInstalledModule.PSChildName)' in path: $($RegistryInstalledModule.PSPath)" -Severity 1
                                                            Remove-Item -Path $RegistryInstalledModule.PSPath -Force -Recurse -ErrorAction "Stop"                                                            
                                                        }
                                                        catch [System.Exception] {
                                                            $ErrorMessage = "Failed to uninstall script module '$($RegistryInstalledModule.PSChildName)'. Error message: $($_.Exception.Message)"
                                                            Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
                                                        }                                                                                                            
                                                    }
                                                }
                                                else {
                                                    Write-LogEntry -Value "- No script modules are installed on the device based on registry discovery" -Severity 1
                                                }
                                            }
                                            catch [System.Exception] {
                                                $ErrorMessage = "Failed to process uninstall operation of script modules. Error message: $($_.Exception.Message)"
                                                Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
                                            }
                                        }

                                        # Handle output of script module uninstallation
                                        Write-LogEntry -Value "[ScriptModule-Uninstall] - Completed" -Severity 1

                                        # Handle output for custom action uninstallation
                                        Write-LogEntry -Value "[CustomActions-Uninstall] - Initializing" -Severity 1

                                        # Determine the unique folder name for custom actions to be cleaned up
                                        $CustomActionRootRegistryKey = Join-Path -Path $RegistryRootKey -ChildPath "CustomActions"
                                        Write-LogEntry -Value "- Retrieving custom action unique folder name sub-key from registry key: $($CustomActionRootRegistryKey)" -Severity 1
                                        $UniqueFolderName = Get-ChildItem -Path $CustomActionRootRegistryKey -ErrorAction "SilentlyContinue" | Where-Object { $PSItem.PSChildName -match "^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$" }
                                        if ($UniqueFolderName -ne $null) {
                                            $UniqueFolderName = $UniqueFolderName.PSChildName
                                            Write-LogEntry -Value "- Found unique folder name in custom action registry root key: $($UniqueFolderName)" -Severity 1

                                            # Cleanup custom actions that are not present in the manifest file
                                            if ($ManifestContent.CustomActions.Count -ge 1) {
                                                # Construct list to contain custom actions present on the device
                                                $CustomActionsInstalledList = New-Object -TypeName "System.Collections.Generic.List[System.Object]"

                                                # Construct list to contain custom actions present in the manifest file
                                                $CustomActionsManifestList = New-Object -TypeName "System.Collections.Generic.List[System.Object]"

                                                # Declare variable path for custom actions directory
                                                $CustomActionsRootPath = Join-Path -Path $env:Windir -ChildPath "System32\update"

                                                # Declare variable for custom actions unique folder registry path
                                                $CustomActionUniqueFolderRegistryPath = Join-Path -Path $CustomActionRootRegistryKey -ChildPath $UniqueFolderName

                                                # Loop through each custom action item in the manifest and add custom object to the custom actions manifest list
                                                Write-LogEntry -Value "- Processing custom actions defined in the manifest file" -Severity 1
                                                foreach ($CustomAction in $ManifestContent.CustomActions) {
                                                    # Construct custom object to store custom action details
                                                    $CustomActionObject = [PSCustomObject]@{
                                                        Name = $CustomAction.Name.ToLower()
                                                        Type = $CustomAction.Type
                                                        ScriptFile = $CustomAction.ScriptFile
                                                    }

                                                    # Add the custom action object to the custom actions manifest list
                                                    $CustomActionsManifestList.Add($CustomActionObject)
                                                }

                                                # Read custom action registry key to determine what's currently installed on the device, add installed custom actions to the custom actions installed list
                                                Write-LogEntry -Value "- Processing custom actions details from registry: $($CustomActionUniqueFolderRegistryPath)" -Severity 1
                                                $CustomActionsRegistryKeyItems = Get-ChildItem -Path $CustomActionUniqueFolderRegistryPath -ErrorAction "SilentlyContinue"
                                                if ($CustomActionsRegistryKeyItems -ne $null) {
                                                    foreach ($CustomActionRegistryKeyItem in $CustomActionsRegistryKeyItems) {
                                                        # Determine the custom action type name from the registry key name
                                                        $CustomActionType = $CustomActionRegistryKeyItem.PSChildName.ToLower()

                                                        # Retrieve all sub-keys, if present in the custom action type registry key
                                                        $CustomActionTypeRegistryKey = Join-Path -Path $CustomActionUniqueFolderRegistryPath -ChildPath $CustomActionType
                                                        $CustomActionTypeRegistryKeyItems = Get-ChildItem -Path $CustomActionTypeRegistryKey -ErrorAction "SilentlyContinue"
                                                        if ($CustomActionTypeRegistryKeyItems -ne $null) {
                                                            foreach ($CustomActionTypeRegistryKeyItem in $CustomActionTypeRegistryKeyItems) {
                                                                # Declare variable for the custom action name from the registry key name
                                                                $CustomActionName = $CustomActionTypeRegistryKeyItem.PSChildName.ToLower()

                                                                # Get all custom actions for the current custom action type
                                                                $CustomActionNameRegistryKey = Join-Path -Path $CustomActionTypeRegistryKey -ChildPath $CustomActionName
                                                                if (Test-Path -Path $CustomActionNameRegistryKey) {
                                                                    # Construct custom object to store custom action details
                                                                    $CustomActionObject = [PSCustomObject]@{
                                                                        Name = $CustomActionName
                                                                        Type = $CustomActionType
                                                                        RegistryPath = $CustomActionNameRegistryKey
                                                                        ScriptFile = (Get-ItemProperty -Path $CustomActionNameRegistryKey -Name "ScriptFile").ScriptFile
                                                                        ScriptWrapperFile = (Get-ItemProperty -Path $CustomActionNameRegistryKey -Name "ScriptWrapperFile").ScriptWrapperFile
                                                                    }

                                                                    # Add the custom action object to the custom actions installed list
                                                                    $CustomActionsInstalledList.Add($CustomActionObject)
                                                                } 
                                                            }
                                                        }
                                                        else {
                                                            Write-LogEntry -Value "- No custom actions defined in the custom action type registry key: $($CustomActionTypeRegistryKey)" -Severity 2
                                                            Write-LogEntry -Value "- Consider forcing an update to rebuild the custom actions, as this is unexpected" -Severity 2
                                                        }
                                                    }
                                                }

                                                # Compare custom actions installed on the device with custom actions defined in the manifest file
                                                Write-LogEntry -Value "- Comparing custom actions installed on the device with custom actions defined in the manifest file" -Severity 1
                                                if ($CustomActionsInstalledList.Count -ge 1) {
                                                    Write-LogEntry -Value "- Found '$($CustomActionsInstalledList.Count)' custom actions installed on the device based on registry details" -Severity 1

                                                    # Loop through each custom action item in the custom actions installed list
                                                    foreach ($CustomActionItem in $CustomActionsInstalledList) {
                                                        $CustomActionManifest = $CustomActionsManifestList | Where-Object { $PSItem.Name.ToLower() -eq $CustomActionItem.Name.ToLower() }
                                                        if ($CustomActionManifest -eq $null) {
                                                            Write-LogEntry -Value "- Custom action '$($CustomActionItem.Name)' is not present in the manifest file, cleanup required" -Severity 1
    
                                                            # Check if the custom action script wrapper command file exists, remove if present
                                                            if (Test-Path -Path $CustomActionItem.ScriptWrapperFile) {
                                                                Write-LogEntry -Value "- Custom action script wrapper command file '$($CustomActionItem.ScriptWrapperFile)' exists, attempting to remove" -Severity 1
                                                                
                                                                try {
                                                                    # Remove the custom action script wrapper command file
                                                                    Remove-Item -Path $CustomActionItem.ScriptWrapperFile -Force -ErrorAction "Stop"
                                                                    Write-LogEntry -Value "- Successfully removed custom action script wrapper command file" -Severity 1
                                                                }
                                                                catch [System.Exception] {
                                                                    $ErrorMessage = "Failed to remove custom action script wrapper command file. Error message: $($_.Exception.Message)"
                                                                    Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
                                                                }
                                                            }
                                                            else {
                                                                Write-LogEntry -Value "- Custom action script wrapper command file '$($CustomActionItem.ScriptWrapperFile)' does not exist" -Severity 1
                                                            }
    
                                                            # Check if the custom action script file exists, remove if present
                                                            if (Test-Path -Path $CustomActionItem.ScriptFile) {
                                                                Write-LogEntry -Value "- Custom action script file '$($CustomActionItem.ScriptFile)' exists, attempting to remove" -Severity 1
    
                                                                try {
                                                                    # Remove the custom action script file
                                                                    Remove-Item -Path $CustomActionItem.ScriptFile -Force -ErrorAction "Stop"
                                                                    Write-LogEntry -Value "- Successfully removed custom action script file" -Severity 1
                                                                }
                                                                catch [System.Exception] {
                                                                    $ErrorMessage = "Failed to remove custom action script file. Error message: $($_.Exception.Message)"
                                                                    Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
                                                                }
                                                            }
                                                            else {
                                                                Write-LogEntry -Value "- Custom action script file '$($CustomActionItem.ScriptFile)' does not exist" -Severity 1
                                                            }
    
                                                            # Check if the custom action unique folder directory is empty, remove if empty
                                                            $CustomActionTypeUniqueFolderDirectoryPath = Join-Path -Path $CustomActionsRootPath -ChildPath (Join-Path -Path $CustomActionItem.Type -ChildPath $UniqueFolderName)
                                                            $CustomActionTypeUniqueFolderDirectoryItems = Get-ChildItem -Path $CustomActionTypeUniqueFolderDirectoryPath -Recurse -ErrorAction "SilentlyContinue"
                                                            if ($CustomActionTypeUniqueFolderDirectoryItems -eq $null) {
                                                                Write-LogEntry -Value "- Custom action type unique folder directory '$($CustomActionTypeUniqueFolderDirectoryPath)' is empty, remove directory" -Severity 1
    
                                                                try {
                                                                    # Remove the custom action type unique folder directory
                                                                    Remove-Item -Path $CustomActionTypeUniqueFolderDirectoryPath -Force -ErrorAction "Stop"
                                                                    Write-LogEntry -Value "- Successfully removed custom action type unique folder directory" -Severity 1
                                                                }
                                                                catch [System.Exception] {
                                                                    $ErrorMessage = "Failed to remove custom action type unique folder directory. Error message: $($_.Exception.Message)"
                                                                    Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
                                                                }
                                                            }
                                                            else {
                                                                Write-LogEntry -Value "- Custom action type unique folder directory '$($CustomActionTypeUniqueFolderDirectoryPath)' contains files, no action required" -Severity 1
                                                            }
    
                                                            # Check if the custom action type directory is empty, remove if empty
                                                            $CustomActionTypeDirectoryPath = Join-Path -Path $CustomActionsRootPath -ChildPath $CustomActionItem.Type
                                                            $CustomActionTypeDirectoryItems = Get-ChildItem -Path $CustomActionTypeDirectoryPath -Recurse -ErrorAction "SilentlyContinue"
                                                            if ($CustomActionTypeDirectoryItems -eq $null) {
                                                                Write-LogEntry -Value "- Custom action type directory '$($CustomActionTypeDirectoryPath)' is empty, remove directory" -Severity 1
    
                                                                try {
                                                                    # Remove the custom action type directory
                                                                    Remove-Item -Path $CustomActionTypeDirectoryPath -Force -ErrorAction "Stop"
                                                                    Write-LogEntry -Value "- Successfully removed custom action type directory" -Severity 1
                                                                }
                                                                catch [System.Exception] {
                                                                    $ErrorMessage = "Failed to remove custom action type directory. Error message: $($_.Exception.Message)"
                                                                    Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
                                                                }
                                                            }
                                                            else {
                                                                Write-LogEntry -Value "- Custom action type directory '$($CustomActionTypeDirectoryPath)' contains files, no action required" -Severity 1
                                                            }
    
                                                            # Check if the custom action name registry sub-key exists, remove if present
                                                            if (Test-Path -Path $CustomActionItem.RegistryPath) {
                                                                Write-LogEntry -Value "- Removing custom action name registry key: $($CustomActionItem.RegistryPath)" -Severity 1
    
                                                                try {
                                                                    # Remove the custom action name registry key
                                                                    Remove-Item -Path $CustomActionItem.RegistryPath -Force -ErrorAction "Stop"
                                                                    Write-LogEntry -Value "- Successfully removed custom action name registry key" -Severity 1
                                                                }
                                                                catch [System.Exception] {
                                                                    $ErrorMessage = "Failed to remove custom action name registry key. Error message: $($_.Exception.Message)"
                                                                    Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
                                                                }
                                                            }
                                                            else {
                                                                Write-LogEntry -Value "- Custom action name registry key does not exist, no action required" -Severity 1
                                                            }
    
                                                            # Check if the custom action type registry key contains any sub-keys, remove if empty
                                                            $CustomActionTypeRegistryKeyPath = Join-Path -Path $CustomActionUniqueFolderRegistryPath -ChildPath $CustomActionItem.Type
                                                            $CustomActionTypeRegistryKeyItems = Get-ChildItem -Path $CustomActionTypeRegistryKeyPath -ErrorAction "SilentlyContinue"
                                                            if ($CustomActionTypeRegistryKeyItems -eq $null) {
                                                                Write-LogEntry -Value "- Custom action type registry key '$($CustomActionTypeRegistryKeyPath)' is empty, remove registry key" -Severity 1
    
                                                                try {
                                                                    # Remove the custom action type registry key
                                                                    Remove-Item -Path $CustomActionTypeRegistryKeyPath -Force -ErrorAction "Stop"
                                                                    Write-LogEntry -Value "- Successfully removed custom action type registry key" -Severity 1
                                                                }
                                                                catch [System.Exception] {
                                                                    $ErrorMessage = "Failed to remove custom action type registry key. Error message: $($_.Exception.Message)"
                                                                    Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
                                                                }
                                                            }
                                                            else {
                                                                Write-LogEntry -Value "- Custom action type registry key '$($CustomActionTypeRegistryKeyPath)' contains sub-keys, no action required" -Severity 1
                                                            }
                                                        }
                                                        else {
                                                            Write-LogEntry -Value "- Custom action '$($CustomActionItem.Name)' is present in the manifest file, no cleanup required" -Severity 1
                                                        }
                                                    }
                                                }
                                                else {
                                                    Write-LogEntry -Value "- No custom actions are installed on the device based on registry details" -Severity 1
                                                    Write-LogEntry -Value "- Consider forcing an update to rebuild the custom actions, if lingering files are present" -Severity 1
                                                }

                                                # Check if the custom action unique folder registry key contains any sub-keys, remove if empty
                                                $CustomActionUniqueFolderRegistryKeyItems = Get-ChildItem -Path $CustomActionUniqueFolderRegistryPath -ErrorAction "SilentlyContinue"
                                                if ($CustomActionUniqueFolderRegistryKeyItems -eq $null) {
                                                    Write-LogEntry -Value "- Custom action unique folder registry key '$($CustomActionUniqueFolderRegistryPath)' is empty, remove registry key" -Severity 1

                                                    try {
                                                        # Remove the custom action unique folder registry key
                                                        Remove-Item -Path $CustomActionUniqueFolderRegistryPath -Force -ErrorAction "Stop"
                                                        Write-LogEntry -Value "- Successfully removed custom action unique folder registry key" -Severity 1
                                                    }
                                                    catch [System.Exception] {
                                                        $ErrorMessage = "Failed to remove custom action unique folder registry key. Error message: $($_.Exception.Message)"
                                                        Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
                                                    }
                                                }
                                                else {
                                                    Write-LogEntry -Value "- Custom action unique folder registry key '$($CustomActionUniqueFolderRegistryPath)' contains sub-keys, no action required" -Severity 1
                                                }
                                            }
                                            else {
                                                Write-LogEntry -Value "- No custom actions defined in the manifest file, perform full cleanup of all related custom actions on device" -Severity 1

                                                # Declare variable path for custom actions directory
                                                $CustomActionsDirectoryRootPath = Join-Path -Path $env:Windir -ChildPath "System32\update"

                                                # Check if the custom actions directory contains any files, if so remove them
                                                if ((Get-ChildItem -Path $CustomActionsDirectoryRootPath).Count -gt 0) {
                                                    Write-LogEntry -Value "- Custom actions directory '$($CustomActionsDirectoryRootPath)' contains files, attempting to remove them" -Severity 1

                                                    try {
                                                        # Remove all files in the custom actions directory
                                                        Remove-Item -Path $CustomActionsDirectoryRootPath\* -Recurse -Force -ErrorAction "Stop"
                                                        Write-LogEntry -Value "- Successfully removed all files in custom actions directory" -Severity 1
                                                    }
                                                    catch [System.Exception] {
                                                        $ErrorMessage = "Failed to remove all files in custom actions directory. Error message: $($_.Exception.Message)"
                                                        Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
                                                    }
                                                }
                                                else {
                                                    Write-LogEntry -Value "- Custom actions directory is empty, no files to remove" -Severity 1
                                                }

                                                # Check if feature update controller specific custom actions directory contains any files, if so remove them
                                                if ((Get-ChildItem -Path $CustomActionScriptsDirectoryPath).Count -gt 0) {
                                                    Write-LogEntry -Value "- Custom actions directory '$($CustomActionScriptsDirectoryPath)' contains files, attempting to remove them" -Severity 1

                                                    try {
                                                        # Remove all files in the custom actions directory
                                                        Remove-Item -Path $CustomActionScriptsDirectoryPath\* -Force -ErrorAction "Stop"
                                                        Write-LogEntry -Value "- Successfully removed all files in custom actions directory" -Severity 1
                                                    }
                                                    catch [System.Exception] {
                                                        $ErrorMessage = "Failed to remove all files in custom actions directory. Error message: $($_.Exception.Message)"
                                                        Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
                                                    }
                                                }
                                                else {
                                                    Write-LogEntry -Value "- Custom actions directory is empty, no files to remove" -Severity 1
                                                }

                                                # Check if the custom actions root registry key contains any sub-keys
                                                $CustomActionUniqueFolderRegistryPath = Join-Path -Path $CustomActionRootRegistryKey -ChildPath $UniqueFolderName
                                                $CustomActionRootRegistryKeyItems = Get-ChildItem -Path $CustomActionRootRegistryKey -ErrorAction "SilentlyContinue"
                                                if ($CustomActionRootRegistryKeyItems -ne $null) {
                                                    try {
                                                        # Remove custom action unique folder registry key
                                                        Write-LogEntry -Value "- Removing custom action unique folder registry key: $($CustomActionUniqueFolderRegistryPath)" -Severity 1
                                                        Remove-Item -Path $CustomActionUniqueFolderRegistryPath -Recurse -Force -ErrorAction "Stop"
                                                    }
                                                    catch [System.Exception] {
                                                        $ErrorMessage = "Failed to remove custom action unique folder registry key. Error message: $($_.Exception.Message)"
                                                        Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
                                                    }
                                                }
                                                else {
                                                    Write-LogEntry -Value "- No custom action unique folder registry keys found in: $($CustomActionRootRegistryKey)" -Severity 1
                                                }
                                            }
                                        }
                                        else {
                                            Write-LogEntry -Value "- No unique folder name found in custom action registry root key, skipping custom action cleanup" -Severity 1
                                        }

                                        # Handle output for custom action uninstallation
                                        Write-LogEntry -Value "[CustomActions-Uninstall] - Completed" -Severity 1
                                    }
                                    else {
                                        $ErrorMessage = "Prerequisites for script operation were not met. Reason: Failure occurred prior to script module installation, see log for more details"
                                        Write-LogEntry -Value "- $($ErrorMessage)" -Severity 2
                                    }
                                }
                                catch [System.Exception] {
                                    $ErrorMessage = "Failed to generate the SetupConfig.ini file. Error message: $($_.Exception.Message)"
                                    Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
                                }
                            }
                            else {
                                $ErrorMessage = "Prerequisites for script operation were not met. Reason: Failure occurred while creating required directory paths for defined Setup parameters in manifest file"
                                Write-LogEntry -Value "- $($ErrorMessage)" -Severity 2
                            }
                        }
                        else {
                            Write-LogEntry -Value "- Script operation prerequisites were not met. Reason: Update notification configuration failure occured, see previous errors" -Severity 3
                        }
                    }
                    catch [System.Exception] {
                        $ErrorMessage = "Failed to parse the latest version manifest file. Error message: $($_.Exception.Message)"
                        Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
                    }
                }
                else {
                    $ErrorMessage = "Failed to download the latest version manifest file"
                    Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
                }
            }
            catch [System.Exception] {
                $ErrorMessage = "Failed to download the latest version manifest file. Error message: $($_.Exception.Message)"
                Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
            }
        }
        catch [System.Exception] {
            $ErrorMessage = "Failed to construct the storage account context. Error message: $($_.Exception.Message)"
            Write-LogEntry -Value "- $($ErrorMessage)" -Severity 3
        }
    }
    else {
        $ErrorMessage = "Prerequisites for script operation were not met. Reason: Failure occurred while creating necessary root directory paths and registry keys"
        Write-LogEntry -Value "- $($ErrorMessage)" -Severity 2
    }

    # Final logging details for detection script reporting to Intune
    Write-LogEntry -Value "[$($ProactiveRemediationName)-Detection] - Completed" -Severity 1
    if ($ErrorMessage -ne $null) {
        Write-Output -InputObject $ErrorMessage
    }
    else {
        Write-Output -InputObject "Success"
    }
}