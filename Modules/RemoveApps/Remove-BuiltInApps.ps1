<#
.SYNOPSIS
    Feature Update Controller script module for handling removal of unwanted built-in apps during a Windows feature update.

.DESCRIPTION
    This script module removes unwanted built-in apps during a Windows feature update. The script module will remove AppxPackage and AppxProvisioningPackage for each app that is not whitelisted.

.EXAMPLE
    .\Remove-BuiltInApps.ps1

.NOTES
    FileName:    Remove-BuiltInApps.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2024-08-27
    Updated:     2024-08-27

    Version history:
    1.0.0 - (2024-08-27) Script created
#>
Begin {
    # Declare the script module name
    $ScriptModuleName = "RemoveBuiltInApps"
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

    # White list of appx packages to keep installed
    $WhiteListedApps = New-Object -TypeName System.Collections.ArrayList
    $WhiteListedApps.AddRange(@(
        "Microsoft.DesktopAppInstaller",
        "Microsoft.MSPaint",
        "Microsoft.Windows.Photos",
        "Microsoft.StorePurchaseApp",
        "Microsoft.CompanyPortal",
        "Microsoft.WindowsAlarms",
        "Microsoft.WindowsCalculator",
        "Microsoft.WindowsStore",
        "Microsoft.Windows.ShellExperienceHost", # Added since Windows 10 version 1809
        "Microsoft.ScreenSketch",
        "Microsoft.HEIFImageExtension",
        "Microsoft.VP9VideoExtensions",
        "Microsoft.WebMediaExtensions",
        "Microsoft.WebpImageExtension", # Added since Windows 10 version 1909
        "Microsoft.Outlook.DesktopIntegrationServicess", # Added since Windows 10 version 2004
        "Microsoft.MicrosoftEdge.Stable", # Added since Windows 10 version 20H2
        "Microsoft.WindowsTerminal",
        "Microsoft.SecHealthUI",
        "Microsoft.OneDriveSync",
        "MicrosoftWindows.Client.WebExperience",
        "MicrosoftWindows.CrossDevice",
        "Microsoft.WindowsNotepad",
        "Microsoft.Paint",
        "Microsoft.PowerAutomateDesktop"
    ))

    # Determine provisioned apps
    $AppArrayList = Get-AppxProvisionedPackage -Online | Where-Object { $PSItem.PublisherId -in @("8wekyb3d8bbwe", "kzf8qxf38zg5c", "yxz26nhyzhsrt", "cw5n1h2txyewy") } | Select-Object -ExpandProperty DisplayName

    # Loop through the list of appx packages
    foreach ($App in $AppArrayList) {
        Write-LogEntry -Value "- Processing appx package: $($App)" -Severity 1

        # If application name not in appx package white list, remove AppxPackage and AppxProvisioningPackage
        if (($App -in $WhiteListedApps)) {
            Write-LogEntry -Value "- Skipping excluded application package: $($App)" -Severity 1
        }
        else {
            # Gather package names
            $AppPackageFullName = Get-AppxPackage -Name $App | Select-Object -ExpandProperty PackageFullName -First 1
            $AppProvisioningPackageName = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like $App } | Select-Object -ExpandProperty PackageName -First 1

            # Attempt to remove AppxPackage
            if ($AppPackageFullName -ne $null) {
                try {
                    Write-LogEntry -Value "- Removing AppxPackage: $($AppPackageFullName)" -Severity 1
                    Remove-AppxPackage -Package $AppPackageFullName -ErrorAction Stop | Out-Null
                }
                catch [System.Exception] {
                    Write-LogEntry -Value "- Removing AppxPackage '$($AppPackageFullName)' failed: $($_.Exception.Message)" -Severity 3
                }
            }
            else {
                Write-LogEntry -Value "- Unable to locate AppxPackage for current app: $($App)" -Severity 1
            }

            # Attempt to remove AppxProvisioningPackage
            if ($AppProvisioningPackageName -ne $null) {
                try {
                    Write-LogEntry -Value "- Removing AppxProvisioningPackage: $($AppProvisioningPackageName)" -Severity 1
                    Remove-AppxProvisionedPackage -PackageName $AppProvisioningPackageName -Online -ErrorAction Stop | Out-Null
                }
                catch [System.Exception] {
                    Write-LogEntry -Value "- Removing AppxProvisioningPackage '$($AppProvisioningPackageName)' failed: $($_.Exception.Message)" -Severity 3
                }
            }
            else {
                Write-LogEntry -Value "- Unable to locate AppxProvisioningPackage for current app: $($App)" -Severity 1
            }
        }
    }

    Write-LogEntry -Value "- Starting Features on Demand V2 removal process" -Severity 1

    # Get Features On Demand that should be removed
    $FeatureOnDemandList = @("ContactSupport")
    try {
        $OSBuildNumber = Get-WmiObject -Class "Win32_OperatingSystem" | Select-Object -ExpandProperty BuildNumber

        foreach ($Feature in $FeatureOnDemandList) {
            try {
                Write-LogEntry -Value "- Removing Feature on Demand V2 package: $($Feature)" -Severity 1
                Get-WindowsCapability -Online -LimitAccess -ErrorAction Stop | Where-Object { ($_.Name -like $Feature) -and ($_.State -like "Installed") } | Remove-WindowsCapability -Online -ErrorAction Stop | Out-Null
            }
            catch [System.Exception] {
                Write-LogEntry -Value "- Removing Feature on Demand V2 package failed: $($_.Exception.Message)" -Severity 3
            }
        }    
    }
    catch [System.Exception] {
        Write-LogEntry -Value "- Attempting to list Feature on Demand V2 packages failed: $($_.Exception.Message)" -Severity 3
    }

    # Complete
    Write-LogEntry -Value "- Completed built-in AppxPackage, AppxProvisioningPackage and Feature on Demand V2 removal process" -Severity 1

    # Handle final logging details for script module
    Write-LogEntry -Value "[$($ScriptModuleName)-Module] - Completed" -Severity 1
}