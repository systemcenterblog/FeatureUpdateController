<#
.SYNOPSIS
    Main script for the Feature Update Controller responsible for running each script modules prestaged in the Feature Update Controller folder.

.DESCRIPTION
    Main script for the Feature Update Controller responsible for running each script modules prestaged in the Feature Update Controller folder.

.EXAMPLE
    .\SetupComplete.ps1

.NOTES
    FileName:    SetupComplete.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2024-08-26
    Updated:     2024-08-26

    Version history:
    1.0.0 - (2024-08-26) Script created
#>
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
            [string]$FileName = "SetupComplete.log"
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

    # Declare variable for company name
    $CompanyName = "<company_name>"

    # Declare registry root path for version control of each modules (scripts to be executed)
    $RegistryRootKey = "HKLM:\SOFTWARE\$($CompanyName)\FeatureUpdateController\Modules"

    # Get all installed script modules from registry key
    $InstalledModules = Get-ChildItem -Path $RegistryRootKey -ErrorAction "SilentlyContinue"
    foreach ($ScriptModule in $InstalledModules) {
        # Declare variables for current script module
        $ScriptModuleName = $ScriptModule.PSChildName
        $ScriptModuleVersion = $ScriptModule.GetValue("Version")
        $ScriptModulePath = $ScriptModule.GetValue("Path")
        $ScriptModuleFileName = $ScriptModule.GetValue("Name")
        $ScriptModuleFilePath = Join-Path -Path $ScriptModulePath -ChildPath $ScriptModuleFileName

        # Check if the script module is installed and ready for execution
        Write-LogEntry -Value "Initiating checks for script module '$($ScriptModuleName)' with version '$($ScriptModuleVersion)' and script file path: $($ScriptModuleFilePath)" -Severity 1

        # Check if the script module is installed and that the script file exists, if not log an error
        if (-not(Test-Path -Path $ScriptModuleFilePath)) {
            Write-LogEntry -Value "Script module '$($ScriptModuleName)' with version '$($ScriptModuleVersion)' is installed, but script file could not be found." -Severity 3
        }
        else {
            Write-LogEntry -Value "Script module '$($ScriptModuleName)' with version '$($ScriptModuleVersion)' is installed." -Severity 1

            try {
                # Run each script module
                Write-LogEntry -Value "Executing script module: $($ScriptModuleFilePath)" -Severity 1
                . $ScriptModuleFilePath
                Write-LogEntry -Value "Script module '$($ScriptModuleName)' executed successfully." -Severity 1
            }
            catch [System.Exception] {
                Write-LogEntry -Value "An error occurred while attempting to run $($ScriptFile.Name). Error message: $($_.Exception.Message)" -Severity 3
            }
        }
    }
}