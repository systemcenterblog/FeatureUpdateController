# Overview
Feature Update Controller is designed to streamline Windows upgrades for devices managed through Microsoft Intune. It provides centralized control over setup configurations, custom actions and script modules, ensuring a seamless and customizable upgrade experience.

![image](https://github.com/user-attachments/assets/aaefdd10-5c9d-4401-a664-f997de5d883f)

# What can it do
Due to the shortcomings of managing Windows upgrades with Microsoft Intune, the Feature Update Controller set out to overcome those and by giving administrators the following capabilities:

- Create and prepare SetupConfig.ini for the Windows setup engine
- Prestage what's called 'Script Modules', essentially individual scripts with a specific purpose (such as configuring a default wallpaper)
- Prestage and configure the device to make use of what's known as 'Custom Actions' (read more about them [here](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/windows-setup-enable-custom-actions))

In addition to the above, the Feature Update Controller solution not only creates the necessary configuration, it also capable of changing the configuration staged to devices or simply removing it.

# How does it work
Feature Update Controller is a Remediation script package designed to provide control over the Windows Feature Update deployment process for devices managed by Microsoft Intune. Upgrading between Windows releases with Microsoft Intune today provides some capabilities, but lacks a way to control the setup command-line options, prestage script files to control what happens during different stages of a Windows upgrade. For instance, the Windows setup utility uses default command-line options and values, unless the following file exist locally on the device being upgraded: 'C:\Users\Default\AppData\Local\Microsoft\Windows\WSUS\SetupConfig.ini'. With the Feature Update Controller solution, you are provided with capabilities to not only create this file if desired, but also provide its configuration values, such as the example below:

```ini
[SetupConfig]
Priority=Normal
Compat=IgnoreWarning
DynamicUpdate=Enable
ShowOOBE=None
Telemetry=Enable
Uninstall=Enable
POSTOOBE=C:\ProgramData\<company_name>\FeatureUpdateController\SetupComplete.cmd
PostRollback=C:\ProgramData\<company_name>\FeatureUpdateController\SetupRollback.cmd
```

As shown in the above example, several properties and their respective values are provided within the SetupConfig.ini file. Upon a Windows upgrade event, the setup engine adheres to what's configured here, providing you as the administrator control over the experience. With the Feature Update Controller, all you need to configure centrally, is the desired properties and their respective values, in what's called the 'manifest' file (read more about it's configuration options in the section named 'Manifest configuration (manifest.json)' below). As for the creation of the SetupConfig.ini file in the appropriate location, but also updating if configuration changes in the manifest file, it's all taken care of by the Feature Update Controller.

From an overview perspective, these are the capabilities that the Feature Update Controller solution provides:

- Download of latest manifest.json file with latest set of instructions to carry out
- Creation or updating of SetupConfig.ini file in its required location
  - If POSTOOBE property is specified:
    - Create the following file: C:\ProgramData\\<company_name>\FeatureUpdateController\SetupComplete.cmd
    - Download the SetupComplete.ps1 script from the specified Azure Storage Account
    - Modify SetupComplete.cmd to execute the SetupComplete.ps1 PowerShell script
  - If PostRollback property is specified:
    - Create the following file: C:\ProgramData\\<company_name>\FeatureUpdateController\SetupRollback.cmd
    - Download the SetupRollback.ps1 script from the specified Azure Storage Account
    - Modify SetupRollback.cmd to execute the SetupRollback.ps1 PowerShell script
- Staging or updating of Script Modules (separate scripts with a specific purpose)
- Staging or updating of Custom Actions


# Prerequisites
Feature Update Controller requires a bit of preconfiguration before it can be enabled in an environment.

- PowerShell 5.0 or higher (on your devices)
- Azure Storage Account with appropriate public permissions
- Access to modify and deploy Remediations


# Configuration

Below are the required bits of the solution that needs to be preconfigured before it can be used in a production environment.

## Storage Account and Container

Before administrators deploy the Remediation script package (Detection.ps1) to devices, a Storage Account resource in Azure must be created (or reuse an existing one) with a publicly accessible container. Structure wise, the content (blobs) that resides within the container is considered 'flat' from the Remediation script package perspective. This means that there should be no folder structure or similar. Here's an example:

- StorageAccountName/ContainerName/manifest.json
- StorageAccountName/ContainerName/Detection.ps1
- StorageAccountName/ContainerName/SetupComplete.ps1
- StorageAccountName/ContainerName/start2.bin
- StorageAccountName/ContainerName/...

Basically, everything that's referenced within the manifest file (manifest.json) in terms of script files or support files, should simply be added in the root of the container.

## Manifest configuration (manifest.json)

This is the central configuration file used to provide instructions to the Remediation script (Detection.ps1) executed on the devices. It must be available on a publicly available Azure Storage Account for the Remediation script to be able to download it when it executes. 

The manifest.json file consists of the following sections:

- Modules
  - Scripts that are automatically executed once the upgrade progress completes, initiated by the POSTOOBE referenced script file (POSTOOBE must be specified as a property in the SetupConfig part of the manifest, pointing to the path with SetupComplete.cmd)
  - This section is an array and can contain multiple modules (as shown in the sample within this repository)
  - Each module can have up to one support file, which is downloaded together with the main script of the module
  - Modules are version controlled, meaning if the manifest is updated with a newer version from what's staged on a device, the module will be re-downloaded and staged with the latest script and support file
  - When ForceUpdate is set to 'true', the script file and support file will always be re-downloaded 
- SetupConfig
  - See possible command-line options to be configured here to customize the Windows setup [here](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/windows-setup-command-line-options)
- SetupConfigScriptFiles
  - Determines what script files to download from the Azure Storage Account if any of the POSTOOBE or PostRollback command-line options are configured in the SetupConfig section
- CustomActionsConfig
  - Set to 'true' if all existing prestaged Custom Actions should be removed and replaced with what's configured in the manifest.json file (this is useful when a previous configuration is lingering on devices)
- CustomActions
  - Define the Custom Action type as either 'RunOnce' or 'Run', depending on if the script file should only be executed once or for every feature update in the future
- UpdateNotifications
  - Use this to configure additional registry values on the device, e.g. for Windows 10 devices where feature update notifications are delayed up towards 24 hours after the update requires a restart (registry value is provided in the sample manifest.json)

```json
{
    "Modules": [
        {
            "Name": "<module_name>", // name of the module, e.g. StartMenu
            "Version": "<semantic_version>", // versioning of the module, e.g. 1.0.0
            "ScriptFile": "<script_file.ps1>", // module specific script file, e.g. Set-StartMenu.ps1
            "SupportFile": "<support_file.txt>", // e.g. start2.bin
            "ForceUpdate": "false" // possible values: true / false
        }
    ],
    "SetupConfig": [
        {
            "Name": "<property_value>",
            "Value": "<property_value>"
        }
    ],
    "SetupConfigScriptFiles": [
        {
            "Type": "<property_value>", // possible values: POSTOOBE / PostRollback
            "Name": "<property_values", // possible values: SetupComplete / SetupRollback
            "ScriptFile": "<script_file.ps1>" // e.g. SetupComplete.ps1
        }
    ],
    "CustomActionsConfig": {
        "ForceUpdate": "false" // possible values: true / false
    },
    "CustomActions": [
        {
            "Type": "<property_value>", // possible values: RunOnce / Run
            "Name": "<custom_action_name>", // possible values: PreInstall, PreCommit, Success, Failure, PostUninstall
            "ScriptFile": "<script_file.ps1>" // e.g. Failure.ps1
        }
    ],
    "UpdateNotifications": [
        {
            "Name": "<registry_value_name>",
            "KeyPath": "HKLM:\\SOFTWARE\\Microsoft\\WindowsUpdate\\UX\\Settings",
            "DataValue": "<data_value>>",
            "Type": "<registry_value_type>" // possible values: Dword, String
        }
    ]
}
```

Embedded in this repository is a sample manifest.json file that should hopefully provide a good understanding of how to configure the Feature Update Controller, if the above description is somewhat confusing.

## Remediation script package file (Detection.ps1)

Within the Detection.ps1 script file, modify the following variables with values suitable for your organization:

```powershell
$CompanyName = "<company_name>"
$StorageAccountName = "<storage_account_name>"
$StorageAccountContainer = "<storage_account_container_name>"
```

**$CompanyName** 
  - Your organization's name
  - Example: "MSEndpointMgr"
  - Used for logging and directory path purposes
  - Don't use special characters that's not allowed for directory names

**$StorageAccountName**
  - The name of your Azure Storage account
  - Example: "az-mse-sa-fuc-store"
  - Must adhere to the rules of allowed characters for storage accounts in Azure

**$StorageAccountContainerName**
  - The name of the container within your Azure Storage account
  - Example: "data-prod"
  - Must be lowercase and can include hyphens

## Script Modules

Many of these script modules have been developed due to the shortcomings of Microsoft Intune, for instance where you can't set a default wallpaper and then let the end user change it. As for changing theme in Windows through Microsoft Intune, there's currently no functioning method available of accomplishing that. Same goes for removal of built-in apps and perhaps most importantly, managing the Start menu is either forced to a given configuration or non-managed, no inbetween where organizations may want to set a default Start menu layout but let their users then customize it.

Feature Update Controller comes pre-loaded with a set of ready made script modules to overcome these shortcomings. These script modules should be considered samples for your organization to analyze them and modify accordingly if needed:

- DarkTheme
  - Changes the default Light theme used in Windows 11 to the Dark theme for all local user profiles
  - Support file: Set-DarkThemeRunOnce.ps1
- DefaultWallpaper
  - Changes the default wallpaper to an image specified as the support file
  - Support file: img0.jpg
- RemoveApps
  - Removes all built-in apps except for those specified in the allow list
  - Support file: N/A
- StartMenu
  - Replaces the default Start menu layout using the community discovered method of replacing the start2.bin file
  - Support file: start2.bin
- TaskBar
  - Removes unwanted configuration from the task bar, such as the Copilot icon. Built to perform these actions for all local user profiles in their respective registry hive.

However, it doesn't stop there. You can create your own script modules and have them executed during a Feature Update event.


# Setup Instructions
1. Replace all placeholders (enclosed in `<>`) with your actual values in the following files:
   1. Detection.ps1
   2. SetupComplete.ps1
   3. SetupRollback.ps1
   4. Script Module files if used
2. Ensure that the required files are added to the Storage Account container specified within the Detection.ps1 script file
   1. Script Module files and support files
3. Configure manifest.json with desired settings 
4. Test the script in a controlled environment
5. Deploy to devices


## Notes
- Keep the manifest file name as "manifest.json" unless you have a specific reason to change it
- Test the script in a controlled environment before wide deployment

## Support
No support is provided for this solution. For issues and questions, open a new issue [here](https://github.com/MSEndpointMgr/FeatureUpdateController/issues).
