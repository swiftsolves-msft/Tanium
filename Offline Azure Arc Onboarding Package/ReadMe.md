# Offline Azure Arc Onboarding Package

The following assets and instructions can be used to onboard your Windows Servers with Azure Arc agent registered to a Azure Subscription using Tanium. The scripts are modified to work in a offline capacity and should not make any outbound Internet calls when running. This package and scripts does require a downloaded version of [AzureConnectedMachineAgent.msi](https://aka.ms/AzureConnectedMachineAgent) to be included into the Tanium package. 

## Instructions
1. You will need to generate a Azure AD SPN for Onboarding Arc to
    Windows Servers. [Follow the instructions
    here](https://learn.microsoft.com/en-us/azure/azure-arc/servers/onboard-service-principal%22%20%5Cl%20%22create-a-service-principal-for-onboarding-at-scale)
    in the Azure Portal. Be sure to copy the Key Secret as it will only
    be revealed once before finishing.
 2. Download the [OnboardingScript.ps1](https://raw.githubusercontent.com/swiftsolves-msft/Tanium/main/Offline%20Azure%20Arc%20Onboarding%20Package/OnboardingScript.ps1)
 3. Update OnboardingScript.ps1 and add the Secret Key into the script
 4. Download the [install_windows_azcmagent.ps1](https://raw.githubusercontent.com/swiftsolves-msft/Tanium/main/Offline%20Azure%20Arc%20Onboarding%20Package/install_windows_azcmagent.ps1)
 5. Download the Azure Arc Agent from: [https://aka.ms/AzureConnectedMachineAgent](https://aka.ms/AzureConnectedMachineAgent)
 6. In Tanium go to Administration -> Packages -> New Package
 7. Create the following Package and:
		 **Package Name:** OfflineArcforWindowsServer
		 **Display Name:** Offline Azure Arc for Windows
		 **Command:**  cmd.exe /d /c powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -NonInteractive -NoProfile -File OnboardingScript.ps1
		 **Files:**  ArcOnboardingScript.ps1, install_windows_azcmagent.ps1, AzureConnectedMachineAgent.msi
![enter image description here](https://github.com/swiftsolves-msft/Tanium/raw/main/Offline%20Azure%20Arc%20Onboarding%20Package/images/tapack.jpg)

## Changes in Script

install_windows_azcmagent.ps1
![install_windows_azcmagent.ps1](https://github.com/swiftsolves-msft/Tanium/raw/main/Offline%20Azure%20Arc%20Onboarding%20Package/images/modify1ps1.jpg)
![install_windows_azcmagent.ps1](https://github.com/swiftsolves-msft/Tanium/raw/main/Offline%20Azure%20Arc%20Onboarding%20Package/images/modify2ps1.jpg)

OnboardingScript.ps1
![OnboardingScript.ps1](https://github.com/swiftsolves-msft/Tanium/raw/main/Offline%20Azure%20Arc%20Onboarding%20Package/images/modify3ps1.jpg)
