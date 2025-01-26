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

    function Get-EntraIDDeviceID {
        <#
        .SYNOPSIS
            Get the Entra ID device ID from the local device.
        
        .DESCRIPTION
            Get the Entra ID device ID from the local device.
        
        .NOTES
            Author:      Nickolaj Andersen
            Contact:     @NickolajA
            Created:     2021-05-26
            Updated:     2024-01-08
        
            Version history:
            1.0.0 - (2021-05-26) Function created
            1.0.1 - (2022-15.09) Updated to support CloudPC (Different method to find EntraID DeviceID)
            1.0.2 - (2024-01-08) Improved function to find the correct certificate instance by including the issuer in the critiera filtering
        #>
        Process {
            # Define Cloud Domain Join information registry path
            $EntraIDJoinInfoRegistryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"
            
            # Retrieve the child key name that is the thumbprint of the machine certificate containing the device identifier guid
            $EntraIDJoinInfoKey = Get-ChildItem -Path $EntraIDJoinInfoRegistryKeyPath | Select-Object -ExpandProperty "PSChildName"
            if ($EntraIDJoinInfoKey -ne $null) {
                # Retrieve the machine certificate based on thumbprint from registry key
                
                if ($EntraIDJoinInfoKey -ne $null) {
                    # Match key data against GUID regex
                    if ([guid]::TryParse($EntraIDJoinInfoKey, $([ref][guid]::Empty))) {
                        $EntraIDJoinCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { ($PSItem.Issuer -like "*MS-Organization-Access*") -and ($PSItem.Subject -like "CN=$($EntraIDJoinInfoKey)") }
                    }
                    else {
                        $EntraIDJoinCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { ($PSItem.Issuer -like "*MS-Organization-Access*") -and ($PSItem.Thumbprint -eq $EntraIDJoinInfoKey) }
                    }
                }
                if ($EntraIDJoinCertificate -ne $null) {
                    # Determine the device identifier from the subject name
                    $EntraIDDeviceID = ($EntraIDJoinCertificate | Select-Object -ExpandProperty "Subject") -replace "CN=", ""
                    # Handle return value
                    return $EntraIDDeviceID
                }
            }
        }
    }
    function Get-EntraTenantID {
        # Cloud Join information registry path
        $EntraTenantInfoRegistryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\TenantInfo"
        # Retrieve the child key name that is the tenant id for AzureAD
        $EntraTenantID = Get-ChildItem -Path $EntraTenantInfoRegistryKeyPath | Select-Object -ExpandProperty "PSChildName"
        return $EntraTenantID
    }      

    function Get-IntuneDeviceID {
        <#
        .SYNOPSIS
            Get the Intune device ID from the local device.
        
        .DESCRIPTION
            Get the Intune device ID from the local device.
        
        .NOTES
            Author:      Nickolaj Andersen
            Contact:     @NickolajA
            Created:     2024-09-02
            Updated:     2024-09-02
        
            Version history:
            1.0.0 - (2024-09-02) Function created
        #>
        Process {
            # Define Intune enrollment information registry path
            $IntuneEnrollmentInfoRegistryKeyPath = "HKLM:\SOFTWARE\Microsoft\Enrollments\"
            
            # Retrieve the child key name that is the thumbprint of the machine certificate containing the device identifier guid
            $IntuneEnrollmentInfoKey = Get-ChildItem -Path $IntuneEnrollmentInfoRegistryKeyPath -Recurse | Where-Object { $_.PSChildName -like "MS DM Server" }
            if ($IntuneEnrollmentInfoKey -ne $null) {
                # Retrieve the machine certificate based on thumbprint from registry key
                $IntuneEnrollmentInfo = Get-ItemProperty -Path $IntuneEnrollmentInfoKey.PSPath
                if ($IntuneEnrollmentInfo -ne $null) {
                    # Handle return value
                    return $IntuneEnrollmentInfo.EntDMID
                }
            }
        }
    }

    function Get-EntraIDRegistrationCertificateThumbprint {
        <#
        .SYNOPSIS
            Get the thumbprint of the certificate used for Entra ID device registration.
        
        .DESCRIPTION
            Get the thumbprint of the certificate used for Entra ID device registration.
        
        .NOTES
            Author:      Nickolaj Andersen
            Contributor: @JankeSkanke
            Contact:     @NickolajA
            Created:     2021-06-03
            Updated:     2024-01-08
        
            Version history:
            1.0.0 - (2021-06-03) Function created
            1.1.0 - (2022-26-10) Added support for finding thumbprint for Cloud PCs @JankeSkanke
            1.1.1 - (2024-01-08) Improved function to find the correct certificate instance by including the issuer in the critiera filtering
        #>
        Process {
            # Define Cloud Domain Join information registry path
            $EntraIDJoinInfoRegistryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"

            # Retrieve the child key name that is the thumbprint of the machine certificate containing the device identifier guid
            $EntraIDJoinInfoKey = Get-ChildItem -Path $EntraIDJoinInfoRegistryKeyPath | Select-Object -ExpandProperty "PSChildName"

             # Retrieve the machine certificate based on thumbprint from registry key or Certificate (CloudPC)        
            if ($EntraIDJoinInfoKey -ne $null) {
                # Match key data against GUID regex for CloudPC Support 
                if ([guid]::TryParse($EntraIDJoinInfoKey, $([ref][guid]::Empty))) {
                    # This is for CloudPC
                    $EntraIDJoinCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { ($PSItem.Issuer -like "*MS-Organization-Access*") -and ($PSItem.Subject -like "CN=$($EntraIDJoinInfoKey)") }
                    $EntraIDJoinInfoThumbprint = $EntraIDJoinCertificate.Thumbprint
                }
                else {
                    # Retrieve the child key name that is the thumbprint of the machine certificate containing the device identifier guid (non-CloudPC)
                    $EntraIDJoinInfoThumbprint = Get-ChildItem -Path $EntraIDJoinInfoRegistryKeyPath | Select-Object -ExpandProperty "PSChildName"
                }
            }
            # Handle return value
            return $EntraIDJoinInfoThumbprint
        }
    }

    function New-RSACertificateSignature {
        <#
        .SYNOPSIS
            Creates a new signature based on content passed as parameter input using the private key of a certificate determined by it's thumbprint, to sign the computed hash of the content.
        
        .DESCRIPTION
            Creates a new signature based on content passed as parameter input using the private key of a certificate determined by it's thumbprint, to sign the computed hash of the content.
            The certificate used must be available in the LocalMachine\My certificate store, and must also contain a private key.
    
        .PARAMETER Content
            Specify the content string to be signed.
    
        .PARAMETER Thumbprint
            Specify the thumbprint of the certificate.
        
        .NOTES
            Author:      Nickolaj Andersen / Thomas Kurth
            Contact:     @NickolajA
            Created:     2021-06-03
            Updated:     2021-06-03
        
            Version history:
            1.0.0 - (2021-06-03) Function created
    
            Credits to Thomas Kurth for sharing his original C# code.
        #>
        param(
            [parameter(Mandatory = $true, HelpMessage = "Specify the content string to be signed.")]
            [ValidateNotNullOrEmpty()]
            [string]$Content,
    
            [parameter(Mandatory = $true, HelpMessage = "Specify the thumbprint of the certificate.")]
            [ValidateNotNullOrEmpty()]
            [string]$Thumbprint
        )
        Process {
            # Determine the certificate based on thumbprint input
            $Certificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Thumbprint -eq $CertificateThumbprint }
            if ($Certificate -ne $null) {
                if ($Certificate.HasPrivateKey -eq $true) {
                    # Read the RSA private key
                    $RSAPrivateKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
                    
                    if ($RSAPrivateKey -ne $null) {
                        if ($RSAPrivateKey -is [System.Security.Cryptography.RSACng]) {
                            # Construct a new SHA256Managed object to be used when computing the hash
                            $SHA256Managed = New-Object -TypeName "System.Security.Cryptography.SHA256Managed"
    
                            # Construct new UTF8 unicode encoding object
                            $UnicodeEncoding = [System.Text.UnicodeEncoding]::UTF8
    
                            # Convert content to byte array
                            [byte[]]$EncodedContentData = $UnicodeEncoding.GetBytes($Content)
    
                            # Compute the hash
                            [byte[]]$ComputedHash = $SHA256Managed.ComputeHash($EncodedContentData)
    
                            # Create signed signature with computed hash
                            [byte[]]$SignatureSigned = $RSAPrivateKey.SignHash($ComputedHash, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    
                            # Convert signature to Base64 string
                            $SignatureString = [System.Convert]::ToBase64String($SignatureSigned)
                            
                            # Handle return value
                            return $SignatureString
                        }
                    }
                }
            }
        }
    }
    
    function Get-PublicKeyBytesEncodedString {
        <#
        .SYNOPSIS
            Returns the public key byte array encoded as a Base64 string, of the certificate where the thumbprint passed as parameter input is a match.
        
        .DESCRIPTION
            Returns the public key byte array encoded as a Base64 string, of the certificate where the thumbprint passed as parameter input is a match.
            The certificate used must be available in the LocalMachine\My certificate store.
    
        .PARAMETER Thumbprint
            Specify the thumbprint of the certificate.
        
        .NOTES
            Author:      Nickolaj Andersen / Thomas Kurth
            Contact:     @NickolajA
            Created:     2021-06-07
            Updated:     2021-06-07
        
            Version history:
            1.0.0 - (2021-06-07) Function created
    
            Credits to Thomas Kurth for sharing his original C# code.
        #>
        param(
            [parameter(Mandatory = $true, HelpMessage = "Specify the thumbprint of the certificate.")]
            [ValidateNotNullOrEmpty()]
            [string]$Thumbprint
        )
        Process {
            # Determine the certificate based on thumbprint input
            $Certificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Thumbprint -eq $Thumbprint }
            if ($Certificate -ne $null) {
                # Get the public key bytes
                [byte[]]$PublicKeyBytes = $Certificate.GetPublicKey()
    
                # Handle return value
                return [System.Convert]::ToBase64String($PublicKeyBytes)
            }
        }
    }

    function New-DeviceTrustBody {
        <#
        .SYNOPSIS
            Construct the body with the elements for a sucessful device trust validation required by a Function App that's leveraging the AADDeviceTrust.FunctionApp module.
    
        .DESCRIPTION
            Construct the body with the elements for a sucessful device trust validation required by a Function App that's leveraging the AADDeviceTrust.FunctionApp module.
    
        .EXAMPLE
            .\New-DeviceTrustBody.ps1
    
        .NOTES
            Author:      Nickolaj Andersen
            Contact:     @NickolajA
            Created:     2022-03-14
            Updated:     2022-03-14
    
            Version history:
            1.0.0 - (2022-03-14) Script created
        #>
        [CmdletBinding(SupportsShouldProcess = $true)]
        param()
        Process {
            # Retrieve required data for building the request body
            $EntraIDDeviceID = Get-EntraIDDeviceID
            $CertificateThumbprint = Get-EntraIDRegistrationCertificateThumbprint
            $Signature = New-RSACertificateSignature -Content $EntraIDDeviceID -Thumbprint $CertificateThumbprint
            $PublicKeyBytesEncoded = Get-PublicKeyBytesEncodedString -Thumbprint $CertificateThumbprint
            $EntraTenantID = Get-EntraTenantID
    
            # Construct client-side request header
            $BodyTable = [ordered]@{
                DeviceName = $env:COMPUTERNAME
                EntraDeviceID = $EntraIDDeviceID
                EntraTenantID = $EntraTenantID
                Signature = $Signature
                Thumbprint = $CertificateThumbprint
                PublicKey = $PublicKeyBytesEncoded
            }
    
            # Handle return value
            return $BodyTable
        }
    }

    function Test-EntraIDDeviceRegistration {
        <#
        .SYNOPSIS
            Determine if the device conforms to the requirement of being either Entra ID joined or Hybrid Entra ID joined.
        
        .DESCRIPTION
            Determine if the device conforms to the requirement of being either Entra ID joined or Hybrid Entra ID joined.
        
        .NOTES
            Author:      Nickolaj Andersen
            Contact:     @NickolajA
            Created:     2022-01-27
            Updated:     2022-01-27
        
            Version history:
            1.0.0 - (2022-01-27) Function created
        #>
        Process {
            $EntraIDJoinInfoRegistryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"
            if (Test-Path -Path $EntraIDJoinInfoRegistryKeyPath) {
                return $true
            }
            else {
                return $false
            }
        }
    }

    function Get-EntraIDJoinDate {
        <#
        .SYNOPSIS
            Get the Entra ID Join Date from the local device.
        
        .DESCRIPTION
            Get the Entra ID Join Date from the local device.
        
        .NOTES
            Author:      Jan Ketil Skanke (and Nickolaj Andersen)
            Contact:     @JankeSkanke
            Created:     2021-05-26
            Updated:     2024-01-08
        
            Version history:
            1.0.0 - (2021-05-26) Function created
            1.0.1 - (2022-15.09) Updated to support CloudPC (Different method to find EntraID DeviceID)
            1.0.2 - (2024-01-08) Improved function to find the correct certificate instance by including the issuer in the critiera filtering
        #>
        Process {
            # Define Cloud Domain Join information registry path
            $EntraIDJoinInfoRegistryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"
            
            # Retrieve the child key name that is the thumbprint of the machine certificate containing the device identifier guid
            $EntraIDJoinInfoKey = Get-ChildItem -Path $EntraIDJoinInfoRegistryKeyPath | Select-Object -ExpandProperty "PSChildName"
            if ($EntraIDJoinInfoKey -ne $null) {
                # Retrieve the machine certificate based on thumbprint from registry key
                
                if ($EntraIDJoinInfoKey -ne $null) {
                    # Match key data against GUID regex
                    if ([guid]::TryParse($EntraIDJoinInfoKey, $([ref][guid]::Empty))) {
                        $EntraIDJoinCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { ($PSItem.Issuer -like "*MS-Organization-Access*") -and ($PSItem.Subject -like "CN=$($EntraIDJoinInfoKey)") }
                    }
                    else {
                        $EntraIDJoinCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { ($PSItem.Issuer -like "*MS-Organization-Access*") -and ($PSItem.Thumbprint -eq $EntraIDJoinInfoKey) }
                    }
                }
            if ($EntraIDJoinCertificate -ne $null) {
                    # Determine the device identifier from the subject name
                    $EntraIDJoinDate = ($EntraIDJoinCertificate | Select-Object -ExpandProperty "NotBefore") 
                    # Handle return value
                    return $EntraIDJoinDate
                }
            }
        }
    }

    function New-RegistryKey {
        param(
            [parameter(Mandatory=$true)]
            [ValidateNotNullOrEmpty()]
            [string]$Path
        )
        try {
            Write-LogEntry -Value "Checking presence of registry key: $($Path)" -Severity 1
            if (-not(Test-Path -Path $Path)) {
                Write-LogEntry -Value "Attempting to create registry key: $($Path)" -Severity 1
                New-Item -Path $Path -ItemType "Directory" -Force -ErrorAction Stop | Out-Null
            }
        }
        catch [System.Exception] {
            Write-LogEntry -Value "Failed to create registry key '$($Path)'. Error message: $($_.Exception.Message)" -Severity 3
        }
    }

    function Set-RegistryValue {
        param(
            [parameter(Mandatory=$true)]
            [ValidateNotNullOrEmpty()]
            [string]$Path,
    
            [parameter(Mandatory=$true)]
            [ValidateNotNullOrEmpty()]
            [string]$Name,        
    
            [parameter(Mandatory=$true)]
            [ValidateNotNullOrEmpty()]
            [string]$Value,

            [parameter(Mandatory=$false)]
            [ValidateNotNullOrEmpty()]
            [ValidateSet("String", "ExpandString", "Binary", "DWord", "MultiString", "Qword")]
            [string]$Type = "String"
        )
        try {
            Write-LogEntry -Value "Checking presence of registry value '$($Name)' in registry key: $($Path)" -Severity 1
            $RegistryValue = Get-ItemPropertyValue -Path $Path -Name $Name -ErrorAction SilentlyContinue
            if ($RegistryValue -ne $null) {
                Write-LogEntry -Value "Setting registry value '$($Name)' to: $($Value)" -Severity 1
                Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force -ErrorAction Stop
            }
            else {
                New-RegistryKey -Path $Path -ErrorAction Stop
                Write-LogEntry -Value "Setting registry value '$($Name)' to: $($Value)" -Severity 1
                New-ItemProperty -Path $Path -Name $Name -PropertyType $Type -Value $Value -Force -ErrorAction Stop | Out-Null
            }
        }
        catch [System.Exception] {
            Write-LogEntry -Value "Failed to create or update registry value '$($Name)' in '$($Path)'. Error message: $($_.Exception.Message)" -Severity 3
        }
    }

    function Enable-LocationServices {
        $AppsAccessLocation = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
        Set-RegistryValue -Path $AppsAccessLocation -Name "LetAppsAccessLocation" -Value 0 -Type "DWord"

        $LocationConsentKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"
        Set-RegistryValue -Path $LocationConsentKey -Name "Value" -Value "Allow" -Type "String"

        $SensorPermissionStateKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}"
        Set-RegistryValue -Path $SensorPermissionStateKey -Name "SensorPermissionState" -Value 1 -Type "DWord"

        $LocationServiceConfigurationKey = "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration"
        Set-RegistryValue -Path $LocationServiceConfigurationKey -Name "Status" -Value 1 -Type "DWord"

        $LocationService = Get-Service -Name "lfsvc"
        Write-LogEntry -Value "Checking location service 'lfsvc' for status: Running" -Severity 1
        if ($LocationService.Status -notlike "Running") {
            Write-LogEntry -Value "Location service is not running, attempting to start service" -Severity 1
            Start-Service -Name "lfsvc"
        }
    }

    function Disable-LocationServices {
        $LocationConsentKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"
        Set-RegistryValue -Path $LocationConsentKey -Name "Value" -Value "Deny" -Type "String"
    
        $SensorPermissionStateKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}"
        Set-RegistryValue -Path $SensorPermissionStateKey -Name "SensorPermissionState" -Value 0 -Type "DWord"
    
        $LocationServiceConfigurationKey = "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration"
        Set-RegistryValue -Path $LocationServiceConfigurationKey -Name "Status" -Value 0 -Type "DWord"
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

    function Get-CustomEventData {
        <#
        .SYNOPSIS
            Get custom event data from a Windows Event Log event.
        
        .DESCRIPTION
            Get custom event data from a Windows Event Log event.
        
        .NOTES
            Author:      Nickolaj Andersen & Jan Ketil Skanke
            Contact:     @NickolajA & @JankeSkanke
            Created:     2024-10-17
            Created:     2024-10-17
        
            Version history:
            1.0.0 - (2024-10-17) Function created
        #>
        param(
            [parameter(Mandatory = $true, HelpMessage = "Specify the parameters to be used for the Get-WinEvent cmdlet.")]
            [ValidateNotNullOrEmpty()]
            [hashtable]$Params, 
    
            [parameter(Mandatory = $false, HelpMessage = "Specify the maximum number of events to retrieve.")]
            [int64]$MaxEvents
        )
        # Define the Get-WinEvent parameter input values dynamically depending on what's specified on the command line
        $SplatArgs = @{
            FilterHashtable = $Params
        }
        if ($PSBoundParameters["MaxEvents"]) {
            $SplatArgs.Add("MaxEvents", $MaxEvents)
        }
    
        # Construct a new list object to store the event data
        $EventList = New-Object -TypeName "System.Collections.Generic.List[System.Object]"
            
        # Retrieve all events from the event log using the specified parameters
        $WinEvents = Get-WinEvent @SplatArgs
    
        # Iterate through each event and extract desired data
        foreach ($WinEvent in $WinEvents) {
            # Convert the current event to XML
            $WinEventXml = ([xml]$WinEvent.ToXml()).Event
    
            # Construct a new ordered hashtable object to collect desired event data
            $EventTable = [ordered]@{
                EventDate = [DateTime]$WinEventXml.System.TimeCreated.SystemTime
                Computer = $WinEventXml.System.Computer
                Id = $WinEventXml.System.EventID
                Message = $WinEvent.Message
            }
    
            # Iterate through each child node in the EventData node and add to the ordered hashtable
            foreach ($ChildNode in $WinEventXml.EventData.ChildNodes) {
                $EventTable[$ChildNode.Name] = $ChildNode.'#text'
            }
    
            # Add the event data to the list object
            $EventList.Add([PSCustomObject]$EventTable)
        }
    
        # Handle return value
        return $EventList
    }

    # Initial logging details for detection script
    Write-LogEntry -Value "[$($ScriptName)] - Initializing" -Severity 1

    # Enable location services for retrieval of device coordinates
    Enable-LocationServices

    # Get coordinates for device
    $Coordinates = Get-GeoCoordinate

    # Get operating system details
    Write-LogEntry -Value "- Retrieving operating system details" -Severity 1
    $ComputerOSDetails = Get-CimInstance -ClassName "Win32_OperatingSystem"

    # Gathering data for upgrade failed payload with device details
    $FUStatusLogName = "FUStatus"
    $FUStatusPayloadTable = @( 
        @{
            TimeGenerated = (Get-Date).ToUniversalTime()
            IntuneDeviceID = Get-IntuneDeviceID
            EntraIDDeviceID = Get-EntraIDDeviceID
            CoordinatesLatitude = $Coordinates.Latitude
            CoordinatesLongitude = $Coordinates.Longitude
            OSVersion = $ComputerOSDetails.Version
            OSInstallDate = $ComputerOSDetails.InstallDate
            SerialNumber = Get-CimInstance -ClassName "Win32_BIOS" | Select-Object -ExpandProperty "SerialNumber"
            StatusMessage = "UpgradeFailed"
        }
    )

    # Convert payload to JSON
    $FUStatusPayloadJSON = ConvertTo-Json -InputObject $FUStatusPayloadTable -Depth 5

    # Construct custom object to hold multiple payloads for Function App request
    $LogPayLoad = New-Object -TypeName "PSObject"

    # Add the Windows feature update status payload to the Log Analytics workspace payload
    Write-LogEntry -Value "- Adding Windows feature update status object to Log Analytics workspace payload" -Severity 1
    $LogPayLoad | Add-Member -NotePropertyMembers @{ $FUStatusLogName = $FUStatusPayloadJSON }

    # Construct the parameters for the Get-CustomEventData function
    $Params = @{    
        LogName = "System"    
        ProviderName = "Microsoft-Windows-WindowsUpdateClient"    
        Id = 20
    }

    # Retrieve the last 200 events from the System event log using the specified parameters
    Write-LogEntry -Value "- Retrieving the last 200 Windows Client Update events" -Severity 1
    $UpgradeEvents = Get-CustomEventData -Params $Params -MaxEvents 200 -ErrorAction "SilentlyContinue"

    # Retrieve the last Windows feature update failure event, if present then send the payload to Log Analytics
    Write-LogEntry -Value "- Searching for Windows feature update failure event" -Severity 1
    $UpgradeFailureEvent = $UpgradeEvents | Where-Object { $_.Message -match "^Installation Failure:" -and $_.updateTitle -match "^Windows 11, version" -and $_.EventDate -ge (Get-Date).AddHours(-12) } | Sort-Object -Property "EventDate" -Descending | Select-Object -First 1
    if ($UpgradeFailureEvent -ne $null) {
        # Declare variable for Log Analytics workspace log name
        $FUFailureLogName = "FUFailures"

        # Construct payload for Log Analytics workspace
        $FUFailurePayloadTable = @(
            @{
                TimeGenerated = [DateTime]::UtcNow
                IntuneDeviceID = Get-IntuneDeviceID
                EntraIDDeviceID = Get-EntraIDDeviceID
                SerialNumber = Get-CimInstance -ClassName "Win32_BIOS" | Select-Object -ExpandProperty "SerialNumber"
                ErrorCode = $UpgradeFailureEvent.errorCode
                Message = $UpgradeFailureEvent.Message
                EventDate = $UpgradeFailureEvent.EventDate
            }
        )

        # Convert payload to JSON
        $FUFailurePayloadJSON = ConvertTo-Json -InputObject $FUFailurePayloadTable -Depth 5

        # Add the Windows feature update failure payload to the Log Analytics workspace payload
        Write-LogEntry -Value "- Adding Windows feature update failure object to Log Analytics workspace payload" -Severity 1
        $LogPayLoad | Add-Member -NotePropertyMembers @{ $FUFailureLogName = $FUFailurePayloadJSON }
    }
    else {
        Write-LogEntry -Value "- No Windows feature update failure event found" -Severity 1
    }

    # Validate that the script is running on an Entra ID joined or hybrid Entra ID joined device
    Write-LogEntry -Value "- Testing Entra ID device registration" -Severity 1
    if (Test-EntraIDDeviceRegistration -eq $true) {
        try {
            # Create body for Function App request
            Write-LogEntry -Value "- Creating body for Function App request" -Severity 1
            $BodyTable = New-DeviceTrustBody -ErrorAction "Stop"

            try {
                # Add payload to body
                Write-LogEntry -Value "- Adding log payload to request body" -Severity 1
                $BodyTable.Add("LogPayloads", $LogPayLoad)

                try {
                    # Construct URI for Function App request
                    Write-LogEntry -Value "- Sending log payload to Azure Function App" -Severity 1
                    $URI = "<function_app_uri>"
                    $Response = Invoke-RestMethod -Method "POST" -Uri $URI -Body ($BodyTable | ConvertTo-Json -Depth 9) -ContentType "application/json" -ErrorAction Stop
                }
                catch [System.Exception] {
                    Write-LogEntry -Value "- Failed to send log payload to Azure Function App. Error message: $($_.Exception.Message). Response: $($Response)" -Severity 3
                }
            }
            catch [System.Exception] {
                Write-LogEntry -Value "- Failed to add log payload to request body. Error message: $($_.Exception.Message)" -Severity 3
            }
        }
        catch [System.Exception] {
            Write-LogEntry -Value "- Failed to create body for Function App request. Error message: $($_.Exception.Message)" -Severity 3
        }
    }
    else {
        Write-LogEntry -Value "- Script is not running on an Entra ID joined or hybrid Entra ID joined device" -Severity 2
    }
}
End {
    # Disable location services after script execution
    Disable-LocationServices

    # Handle final logging details for script module
    Write-LogEntry -Value "[$($ScriptName)] - Completed" -Severity 1
}