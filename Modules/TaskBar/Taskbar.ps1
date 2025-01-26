<#
.SYNOPSIS
    Feature Update Controller script module for configuring elements on the Taskbar during a Windows feature update.

.DESCRIPTION
    This script module configures Taskbar related settings during the feature update process.

.EXAMPLE
    .\Set-Taskbar.ps1

.NOTES
    FileName:    Set-Taskbar.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2024-08-27
    Updated:     2024-08-27

    Version history:
    1.0.0 - (2024-08-27) Script created
#>
Begin {
    # Declare the script module name
    $ScriptModuleName = "Taskbar"
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

    function Invoke-HKCUScriptBlockAllUserProfiles {
        param(
            [parameter(Mandatory = $true, HelpMessage = "Script block to execute for each user profile.")]
            [ValidateNotNullOrEmpty()]
            [scriptblock]$ScriptBlock
        )
        Begin {
            # Declare list to store user profiles
            $UserProfileList = New-Object -TypeName "System.Collections.Generic.List[System.Object]"

            # Declare variable to store system specific profiles
            $SystemProfiles = "S-1-5-18", "S-1-5-19", "S-1-5-20"
        }
        Process {
            # Retrieve all user profiles, exclude system specific profiles
            $RegistryUserProfileListKey = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
            Write-LogEntry -Value "- Reading list of user profiles from: $($RegistryUserProfileListKey)" -Severity 1
            
            try {
                $UserProfiles = Get-ChildItem -Path $RegistryUserProfileListKey -ErrorAction "Stop"
                foreach ($UserProfile in $UserProfiles) {
                    Write-LogEntry -Value "- Found user profile: $($UserProfile.PSChildName)" -Severity 1

                    # Convert current user profile SID to NTAccount
                    $NTAccountSID = New-Object -TypeName "System.Security.Principal.SecurityIdentifier" -ArgumentList $UserProfile.PSChildName
                    $NTAccount = $NTAccountSID.Translate([Security.Principal.NTAccount])
    
                    # Get user profile properties
                    $ProfileProperties = Get-ItemProperty -Path $UserProfile.PSPath | Where-Object { ($PSItem.ProfileImagePath) }
    
                    # Determine if user profile is a local account
                    $LocalAccount = Get-CimInstance -ClassName "Win32_Account" -Filter "SID like '$($UserProfile.PSChildName)'"

                    # Add user profile to list if it is not a system profile and matches the corporate domain name
                    if ($UserProfile.PSChildName -notin $SystemProfiles) {
                        if ($LocalAccount -eq $null) {
                            Write-LogEntry -Value "- User profile is not a local account, adding to user list" -Severity 1
                            $UserProfileList.Add([PSCustomObject]@{
                                SID = $UserProfile.PSChildName
                                NTAccount = $NTAccount.Value
                                ProfileImagePath = $ProfileProperties.ProfileImagePath
                            })
                        }
                        else {
                            Write-LogEntry -Value "- User profile is a local account, skipping" -Severity 2
                        }
                    }
                }

                # Handle user profile list construction completion output
                Write-LogEntry -Value "- User profile list construction completed" -Severity 1
            }
            catch [System.Exception] {
                Write-LogEntry -Value "Failed to construct list of user profiles. Error message: $($_.Exception.Message)" -Severity 3
            }

            # Continue if user profiles were found
            if ($UserProfileList.Count -ge 1) {
                Write-LogEntry -Value "- Total count of '$($UserProfileList.Count)' user profiles to be processed" -Severity 1

                # Process each user profile in list and load user registry hive
                foreach ($UserProfile in $UserProfileList) {
                    Write-LogEntry -Value "- Loading user registry hive: $($UserProfile.NTAccount)" -Severity 1

                    # Load user registry hive
                    $UserRegistryHiveFilePath = Join-Path -Path $UserProfile.ProfileImagePath -ChildPath "NTUSER.DAT"
                    Write-LogEntry -Value "- User registry hive local file path: $($UserRegistryHiveFilePath)" -Severity 1
                    
                    # Check if user registry hive exists
                    $UserRegistryPath = "Registry::HKEY_USERS\$($UserProfile.SID)"
                    Write-LogEntry -Value "- Check if user registry hive registry path exist: $($UserRegistryPath)" -Severity 1
                    if (-not(Test-Path -Path $UserRegistryPath)) {
                        # Load user registry hive from local file path
                        if (Test-Path -Path $UserRegistryHiveFilePath -PathType "Leaf") {
                            # Declare variable for reg.exe executable path
                            $RegExecutable = Join-Path -Path $env:Windir -ChildPath "System32\reg.exe"

                            # Declare arguments for reg.exe to load the current user profile registry hive
                            $RegArguments = "load ""HKEY_USERS\$($UserProfile.SID)"" ""$($UserRegistryHiveFilePath)"""
                            
                            try {
                                # Load current user profile registry hive
                                Write-LogEntry -Value "- Invoking command: $($RegExecutable) $($RegArguments)" -Severity 1
                                Start-Process -FilePath $RegExecutable -ArgumentList $RegArguments -Wait -ErrorAction "Stop"
                                Write-LogEntry -Value "- Successfully loaded user registry hive: $($UserRegistryHiveFilePath)" -Severity 1

                                try {
                                    # Execute script block for current user profile
                                    Write-LogEntry -Value "- Executing script block for user: $($UserProfile.NTAccount)" -Severity 1
                                    Invoke-Command -ScriptBlock $ScriptBlock -ErrorAction "Stop"
                                    Write-LogEntry -Value "- Successfully executed script block for user: $($UserProfile.NTAccount)" -Severity 1
                                }
                                catch [System.Exception] {
                                    Write-LogEntry -Value "- Failed to execute script block for user: $($UserProfile.NTAccount)" -Severity 3
                                }
                            }
                            catch [System.Exception] {
                                Write-LogEntry -Value "- Failed to load user registry hive: $($UserRegistryHiveFilePath)" -Severity 3
                            }

                            try {
                                # Initiate garbage collection to release user registry hive
                                Write-LogEntry -Value "- Initiating garbage collection before user hive unload command" -Severity 1
                                [GC]::Collect()
                                [GC]::WaitForPendingFinalizers()
                                Start-Sleep -Seconds 5

                                # Unload current user profile registry hive
                                $RegArguments = "unload ""HKEY_USERS\$($UserProfile.SID)"""
                                Write-LogEntry -Value "- Invoking command: $($RegExecutable) $($RegArguments)" -Severity 1
                                Start-Process -FilePath $RegExecutable -ArgumentList $RegArguments -Wait -ErrorAction "Stop"
                                Write-LogEntry -Value "- Successfully unloaded user registry hive: $($UserRegistryHiveFilePath)" -Severity 1
                            }
                            catch [System.Exception] {
                                Write-LogEntry -Value "- Failed to unload user registry hive: $($UserRegistryHiveFilePath)" -Severity 3
                            }
                        }
                        else {
                            Write-LogEntry -Value "- User registry hive file could not be found: $($UserRegistryHiveFilePath)" -Severity 3
                        }
                    }
                    else {
                        Write-LogEntry -Value "- User registry hive could not be found: $($UserRegistryPath)" -Severity 3
                    }
                }
            }
            else {
                Write-LogEntry -Value "- No user profiles found" -Severity 2
            }
        }
    }

    # Initial logging details for detection script
    Write-LogEntry -Value "[$($ScriptModuleName)-Module] - Initializing" -Severity 1

    # Declare script block to run for each user profile
    [scriptblock]$HKCURegistrySettings = {
        Write-LogEntry -Value "- [ScriptBlock] - Initializing" -Severity 1

        # Example to remove the Copilot button from the Taskbar
        New-ItemProperty -Path "Registry::HKEY_USERS\$($UserProfile.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCopilotButton" -Value "0" -PropertyType Dword -Force

        Write-LogEntry -Value "- [ScriptBlock] - Completed" -Severity 1
    }

    # Invoke script block for each user profile
    Invoke-HKCUScriptBlockAllUserProfiles -ScriptBlock $HKCURegistrySettings

    # Handle final logging details for script module
    Write-LogEntry -Value "[$($ScriptModuleName)-Module] - Completed" -Severity 1
}