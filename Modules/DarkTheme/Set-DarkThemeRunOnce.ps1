<#
.SYNOPSIS
    Feature Update Controller script module for configuring dark theme for the first time for the users that logs in.

.DESCRIPTION
    This script module configures dark theme per user. The script module will apply the dark theme and wait for the SystemSettings.exe process to launch, then close the process.

.EXAMPLE
    .\Set-DarkThemeRunOnce.ps1

.NOTES
    FileName:    Set-DarkThemeRunOnce.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2024-08-27
    Updated:     2024-08-27

    Version history:
    1.0.0 - (2024-08-27) Script created
#>
Begin {
    # Declare the script module name
    $ScriptModuleName = "DarkTheme"
    $ScriptLogFileName = "DarkTheme.log"
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

    # Apply dark theme
    $WindowsThemeFolderPath = Join-Path -Path $env:SystemRoot -ChildPath "Resources\Themes"
    $WindowsThemeFileName = "dark.theme"
    $WindowsThemeFilePath = Join-Path -Path $WindowsThemeFolderPath -ChildPath $WindowsThemeFileName
    Write-LogEntry -Value "Applying dark theme from: $($WindowsThemeFilePath)" -Severity 1
    Start-Process -FilePath $WindowsThemeFilePath -Wait

    # Wait until the SystemSettings.exe process launches, then close the process
    do {
        Start-Sleep -Milliseconds 1
        $SystemSettingsProcess = Get-Process -Name "SystemSettings" -ErrorAction SilentlyContinue
    }
    until ($SystemSettingsProcess)
    Write-LogEntry -Value "SystemSettings.exe process found, closing process" -Severity 1
    Stop-Process -Name "SystemSettings" -Force

    # Handle final logging details for script module
    Write-LogEntry -Value "[$($ScriptModuleName)-Module] - Completed" -Severity 1
}