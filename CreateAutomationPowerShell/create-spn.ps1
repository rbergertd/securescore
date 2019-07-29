
#Initialize
$tenant = "cfb68b2e-eaf9-4bdb-a6b1-28499080e926"
$subscriptionId = "9b801453-ec47-4e1f-8c70-06ee950eb2ba"
$appDisplayName = "SecureScoreSPTest"
$appPassword = "SpN2019zf"
$ErrorActionPreference = "Stop"
$VerbosePreference = "SilentlyContinue"
$userName = $env:USERNAME
$homePage = "http://$tenant/$appDisplayName"
$identifierUri = $homePage
$spnRole = "contributor"

#Initialize subscription
$isAzureModulePresent = Get-Module -Name AzureRM* -ListAvailable
if ([String]::IsNullOrEmpty($isAzureModulePresent) -eq $true)
{
    Write-Output "Script requires AzureRM modules. Obtain from https://github.com/Azure/azure-powershell/releases." -Verbose
    return
}

Import-Module -Name AzureRM.Profile
Write-Output "Provide your credentials to access Azure subscription $subscriptionId" -Verbose
Login-AzureRmAccount -SubscriptionId $subscriptionId
$azureSubscription = Get-AzureRmSubscription -SubscriptionId $subscriptionId
$connectionName = $azureSubscription.SubscriptionName

#Check if AD Application Identifier URI is unique
Write-Output "Verifying App URI is unique ($identifierUri)" -Verbose
$existingApplication = Get-AzureRmADApplication -IdentifierUri $identifierUri
if ($existingApplication -ne $null) {
    $appId = $existingApplication.ApplicationId
    Write-Output "An AAD Application already exists with App URI $identifierUri (Application Id: $appId). Choose a different app display name"  -Verbose
    return
}

#Create a new AD Application
Write-Output "Creating a new Application in AAD (App URI - $identifierUri)" -Verbose
$secureAppPassword = $appPassword | ConvertTo-SecureString -AsPlainText -Force
$azureAdApplication = New-AzureRmADApplication -DisplayName $appDisplayName -HomePage $homePage -IdentifierUris $identifierUri -Password $secureAppPassword -Verbose
$appId = $azureAdApplication.ApplicationId
Write-Output "Azure AAD Application creation completed successfully (Application Id: $appId)" -Verbose

#Create new SPN
Write-Output "Creating a new SPN" -Verbose
$spn = New-AzureRmADServicePrincipal -ApplicationId $appId
$spnName = $spn.ServicePrincipalName
Write-Output "SPN creation completed successfully (SPN Name: $spnName)" -Verbose

#Assign role to SPN
Write-Output "Waiting for SPN creation to reflect in Directory before Role assignment"
Start-Sleep 40
Write-Output "Assigning role ($spnRole) to SPN App ($appId)" -Verbose
New-AzureRmRoleAssignment -RoleDefinitionName $spnRole -ServicePrincipalName $appId
Write-Output "SPN role assignment completed successfully" -Verbose

#Print the values
Write-Output "`nCopy and Paste below values for Service Connection" -Verbose
Write-Output "***************************************************************************"
Write-Output "Subscription Id: $subscriptionId"
Write-Output "Service Principal Id: $appId"
Write-Output "Service Principal Key: <appPassword that you typed in>"
Write-Output "***************************************************************************"