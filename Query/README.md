# Tanium Queries

We can use queries in Tanium to get a full inventory of all servers with relevant information:

| Server Name | Operating System | Azure ARC Info ( Use custom sensor to return output of azcmagent show ) | Resource Group | Subscription ID | MSense version ( applicable to Windows Server 2012 R2 and Windows | Server 2016 ) | MDE Onboarding State | Installed AV software   Note:  The RegEx used in the question may | need to be modified if application names appear differently | Sophos, Cylance|  CarbonBlack | Domain Role | Member Server | Domain Controller | Windows Server with GUI vs. Core |
|--|--|--|--|--|--|--|--|--|--|--|--|--|--|--|--|
|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |


    Get Computer Name and Operating System and Azure ARC Info and Folder Contents["C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Platform"] contains 10. and Registry Value Data[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status,OnboardingState] and Installed Applications having Installed Applications:Name matches .*sophos.*|.*cylance.*|.*carbonblack.* and Domain Role and Windows Features contains Server-Gui-Mgmt from all machines with Windows OS Type contains server

If you prefer to limit the results to only Windows Server 2012 R2 and Windows Server 2016, we can use this:


    Get Computer Name and Operating System and Azure ARC Info and Folder Contents["C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Platform"] contains 10. and Registry Value Data[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status,OnboardingState] and Installed Applications having Installed Applications:Name matches .*sophos.*|.*cylance.*|.*carbonblack.* and Domain Role and Windows Features contains Server-Gui-Mgmt from all machines with Operating System matches .*Server 2012 R2.*|.*Server 2016.*