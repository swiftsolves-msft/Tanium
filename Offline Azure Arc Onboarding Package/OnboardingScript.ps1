try {
    # Add the service principal application ID and secret here
    $servicePrincipalClientId="<AAD SPN App Id>";
    $servicePrincipalSecret="<AAD SPN Key>";

    $env:SUBSCRIPTION_ID = "<Azure Subscription Id>";
    $env:RESOURCE_GROUP = "<RG Name>";
    $env:TENANT_ID = "<AAD Tenant Id>";
    $env:LOCATION = "<SPN Location>";
    $env:AUTH_TYPE = "principal";
    $env:CORRELATION_ID = "<CCORRELATION GUID>";
    $env:CLOUD = "AzureCloud";

    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072;

    # Download the installation package
    #Invoke-WebRequest -UseBasicParsing -Uri "https://aka.ms/azcmagent-windows" -TimeoutSec 30 -OutFile "$env:TEMP\install_windows_azcmagent.ps1";

    # Install the hybrid agent
    & ".\install_windows_azcmagent.ps1";
    if ($LASTEXITCODE -ne 0) { exit 1; }

    # Run connect command
    & "$env:ProgramW6432\AzureConnectedMachineAgent\azcmagent.exe" connect --service-principal-id "$servicePrincipalClientId" --service-principal-secret "$servicePrincipalSecret" --resource-group "$env:RESOURCE_GROUP" --tenant-id "$env:TENANT_ID" --location "$env:LOCATION" --subscription-id "$env:SUBSCRIPTION_ID" --cloud "$env:CLOUD" --tags "Datacenter='CLT Home Office',City=Charlotte,StateOrDistrict=NC,CountryOrRegion='United States'" --correlation-id "$env:CORRELATION_ID";
}
catch {
    $logBody = @{subscriptionId="$env:SUBSCRIPTION_ID";resourceGroup="$env:RESOURCE_GROUP";tenantId="$env:TENANT_ID";location="$env:LOCATION";correlationId="$env:CORRELATION_ID";authType="$env:AUTH_TYPE";operation="onboarding";messageType=$_.FullyQualifiedErrorId;message="$_";};
    #Invoke-WebRequest -UseBasicParsing -Uri "https://gbl.his.arc.azure.com/log" -Method "PUT" -Body ($logBody | ConvertTo-Json) | out-null;
    $logBody | ConvertTo-Json | Out-File arc.log
    Write-Host  -ForegroundColor red $_.Exception;
}