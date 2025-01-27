<#
.SYNOPSIS
    Feature Update Controller custom action script to be executed in the event that the feature update process fails.

.DESCRIPTION
    This custom action script is intended to be executed in the event that the feature update process fails. The script will gather device information and send a log payload to an Azure Function App for log ingestion handling.

.EXAMPLE
    .\Failure.ps1

.NOTES
    FileName:    Failure.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2024-08-27
    Updated:     2024-08-27

    Version history:
    1.0.0 - (2024-08-27) Script created
#>
Begin {
    try {
        # Add required assemblies
        Add-Type -AssemblyName "System.Device" -ErrorAction "Stop"
    }
    catch [System.Exception] {
        Write-Warning -Message "Failed to add required assemblies. Error message: $($_.Exception.Message)"
    }

    # Declare the script module name
    $ScriptName = "UpgradeFailed"
    $ScriptLogFileName = "UpgradeFailed.log"
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
        $LogText = "<![LOG[$($Value)]LOG]!><time=""$($Time)"" date=""$($Date)"" component=""$($ScriptName)"" context=""$($Context)"" type=""$($Severity)"" thread=""$($PID)"" file="""">"
        
        # Add value to log file
        try {
            Out-File -InputObject $LogText -Append -NoClobber -Encoding Default -FilePath $LogFilePath -ErrorAction Stop
        }
        catch [System.Exception] {
            Write-Warning -Message "Unable to append log entry $($ScriptLogFileName).log file. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
        }
    }

    function Get-GeoCoordinate {
        # Construct return value object
        $Coordinates = [PSCustomObject]@{
            Latitude = $null
            Longitude = $null
        }

        Write-LogEntry -Value "Attempting to start resolving the current device coordinates" -Severity 1
        $GeoCoordinateWatcher = New-Object -TypeName "System.Device.Location.GeoCoordinateWatcher"
        $GeoCoordinateWatcher.Start()

        # Wait until watcher resolves current location coordinates
        $GeoCounter = 0
        while (($GeoCoordinateWatcher.Status -notlike "Ready") -and ($GeoCoordinateWatcher.Permission -notlike "Denied") -and ($GeoCounter -le 60)) {
            Start-Sleep -Seconds 1
            $GeoCounter++
        }

        # Break operation and return empty object since permission was denied
        if ($GeoCoordinateWatcher.Permission -like "Denied") {
            Write-LogEntry -Value "Permission was denied accessing coordinates from location services" -Severity 3

            # Stop and dispose of the GeCoordinateWatcher object
            $GeoCoordinateWatcher.Stop()
            $GeoCoordinateWatcher.Dispose()

            # Handle return error
            return $Coordinates
        }

        # Set coordinates for return value
        $Coordinates.Latitude = ($GeoCoordinateWatcher.Position.Location.Latitude).ToString().Replace(",", ".")
        $Coordinates.Longitude = ($GeoCoordinateWatcher.Position.Location.Longitude).ToString().Replace(",", ".")

        # Stop and dispose of the GeCoordinateWatcher object
        $GeoCoordinateWatcher.Stop()
        $GeoCoordinateWatcher.Dispose()

        # Handle return value
        return $Coordinates
    }

    # Initial logging details for detection script
    Write-LogEntry -Value "[$($ScriptName)] - Initializing" -Severity 1

    # Get coordinates for device
    Write-LogEntry -Value "- Retrieving device coordinates" -Severity 1
    $Coordinates = Get-GeoCoordinate

    # Get operating system details
    Write-LogEntry -Value "- Retrieving operating system details" -Severity 1
    $ComputerOSDetails = Get-CimInstance -ClassName "Win32_OperatingSystem"

    # Perform additional actions based on what should happen in your environment in the event that the feature update failed
    # ...
}
End {
    # Handle final logging details for script module
    Write-LogEntry -Value "[$($ScriptName)] - Completed" -Severity 1
}