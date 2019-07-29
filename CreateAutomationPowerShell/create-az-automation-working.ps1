
 param(
$AutomationAccountName = "RBTestAutomationAcct",
$ResourceGroupOMS = "RB-PowerShellAutomation",
$SubscriptionId = "9b801453-ec47-4e1f-8c70-06ee950eb2ba",
$WorkspaceName = "RB-OMSTest",
$Location = "EastUS2",
$ObjectIDWorker = '5084279b-fb56-49f4-aecb-fd9ec84f0505'
 )

Get-AzureRmSubscription -SubscriptionId $SubscriptionId | Select-AzureRmSubscription

##############################################################################################################

$GetKeyVault = Get-AzureRmKeyVault -ResourceGroupName $ResourceGroupOMS | Select-Object -ExpandProperty VaultName
if (!$GetKeyVault) {
    $keyVaultName = ("RB-keyvaultPSAuto")
    Write-Warning -Message "Key Vault not found. Creating the Key Vault $keyVaultName"
    $keyValut = New-AzureRmKeyVault -VaultName $keyVaultName -ResourceGroupName $ResourceGroupOMS -Location $Location
    if (!$keyValut) {
        Write-Error -Message "Key Vault $keyVaultName creation failed. Please fix and continue"
        return
    }
    Start-Sleep -s 15     
}

#### granting SP access to KeyVault
Set-AzureRmKeyVaultAccessPolicy -ResourceGroupName $ResourceGroupOMS -VaultName $keyVaultName -ObjectId $ObjectIDWorker -PermissionsToCertificates create,import,delete,list -PermissionsToKeys create,import,delete,list -PermissionsToSecrets get,set,delete,list -PermissionsToStorage get,list,delete,set

##############################################################################################################

[String] $ApplicationDisplayName = "$AutomationAccountName"
[String] $SelfSignedCertPlainPassword = [Guid]::NewGuid().ToString().Substring(0, 8) + "!" 
$KeyVaultName = Get-AzureRmKeyVault -ResourceGroupName $ResourceGroupOMS | Select-Object -ExpandProperty VaultName
[int] $NoOfMonthsUntilExpired = 36
  

##############################################################################################################

$CertifcateAssetName = "AzureRunAsCertificate"
$CertificateName = $AutomationAccountName + $CertifcateAssetName
$PfxCertPathForRunAsAccount = Join-Path $env:TEMP ($CertificateName + ".pfx")
$PfxCertPlainPasswordForRunAsAccount = $SelfSignedCertPlainPassword
$CerCertPathForRunAsAccount = Join-Path $env:TEMP ($CertificateName + ".cer")

Write-Output "Generating the cert using Keyvault..."

$certSubjectName = "cn=" + $certificateName

$Policy = New-AzureKeyVaultCertificatePolicy -SecretContentType "application/x-pkcs12" -SubjectName $certSubjectName  -IssuerName "Self" -ValidityInMonths $noOfMonthsUntilExpired -ReuseKeyOnRenewal
$AddAzureKeyVaultCertificateStatus = Add-AzureKeyVaultCertificate -VaultName $keyVaultName -Name $certificateName -CertificatePolicy $Policy 
  
While ($AddAzureKeyVaultCertificateStatus.Status -eq "inProgress") {
    Start-Sleep -s 10
    $AddAzureKeyVaultCertificateStatus = Get-AzureKeyVaultCertificateOperation -VaultName $keyVaultName -Name $certificateName
}
 
if ($AddAzureKeyVaultCertificateStatus.Status -ne "completed") {
    Write-Error -Message "Key vault cert creation is not sucessfull and its status is: $status.Status" 
}

$secretRetrieved = Get-AzureKeyVaultSecret -VaultName $keyVaultName -Name $certificateName
$pfxBytes = [System.Convert]::FromBase64String($secretRetrieved.SecretValueText)
$certCollection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
$certCollection.Import($pfxBytes, $null, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
   
#Export  the .pfx file 
$protectedCertificateBytes = $certCollection.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $PfxCertPlainPasswordForRunAsAccount)
[System.IO.File]::WriteAllBytes($PfxCertPathForRunAsAccount, $protectedCertificateBytes)

#Export the .cer file 
$cert = Get-AzureKeyVaultCertificate -VaultName $keyVaultName -Name $certificateName
$certBytes = $cert.Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
[System.IO.File]::WriteAllBytes($CerCertPathForRunAsAccount, $certBytes)

##############################################################################################################

Write-Output "Creating service principal..."
# Create Service Principal
$PfxCert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @($PfxCertPathForRunAsAccount, $PfxCertPlainPasswordForRunAsAccount)
    
$keyValue = [System.Convert]::ToBase64String($PfxCert.GetRawCertData())
$KeyId = [Guid]::NewGuid() 

$startDate = Get-Date
$endDate = (Get-Date $PfxCert.GetExpirationDateString()).AddDays(-1)

# Use Key credentials and create AAD Application
$Application = New-AzureRmADApplication -DisplayName $ApplicationDisplayName -HomePage ("http://" + $applicationDisplayName) -IdentifierUris ("http://" + $KeyId)
New-AzureRmADAppCredential -ApplicationId $Application.ApplicationId -CertValue $keyValue -StartDate $startDate -EndDate $endDate 
New-AzureRMADServicePrincipal -ApplicationId $Application.ApplicationId 

# Sleep here for a few seconds to allow the service principal application to become active (should only take a couple of seconds normally)
Start-Sleep -s 15

$NewRole = $null
$Retries = 0;
While ($NewRole -eq $null -and $Retries -le 6) {
    New-AzureRMRoleAssignment -RoleDefinitionName Contributor -ServicePrincipalName $Application.ApplicationId -scope ("/subscriptions/" + $subscriptionId) -ErrorAction SilentlyContinue
    Start-Sleep -s 10
    $NewRole = Get-AzureRMRoleAssignment -ServicePrincipalName $Application.ApplicationId -ErrorAction SilentlyContinue
    $Retries++;
}

##############################################################################################################

Write-Output "Creating Automation account"
New-AzureRmAutomationAccount -ResourceGroupName $ResourceGroupOMS -Name $AutomationAccountName -Location "eastus2"

##############################################################################################################
    
Write-Output "Creating Certificate in the Asset..."
# Create the automation certificate asset
$CertPassword = ConvertTo-SecureString $PfxCertPlainPasswordForRunAsAccount -AsPlainText -Force   
Remove-AzureRmAutomationCertificate -ResourceGroupName $ResourceGroupOMS -automationAccountName $AutomationAccountName -Name $certifcateAssetName -ErrorAction SilentlyContinue
New-AzureRmAutomationCertificate -ResourceGroupName $ResourceGroupOMS -automationAccountName $AutomationAccountName -Path $PfxCertPathForRunAsAccount -Name $certifcateAssetName -Password $CertPassword -Exportable  | write-verbose

##############################################################################################################

# Populate the ConnectionFieldValues
$ConnectionTypeName = "AzureServicePrincipal"
$ConnectionAssetName = "AzureRunAsConnection"
$ApplicationId = $Application.ApplicationId 
$SubscriptionInfo = Get-AzureRmSubscription -SubscriptionId $SubscriptionId
$TenantID = $SubscriptionInfo | Select-Object TenantId -First 1
$Thumbprint = $PfxCert.Thumbprint
$ConnectionFieldValues = @{"ApplicationId" = $ApplicationID; "TenantId" = $TenantID.TenantId; "CertificateThumbprint" = $Thumbprint; "SubscriptionId" = $SubscriptionId} 
# Create a Automation connection asset named AzureRunAsConnection in the Automation account. This connection uses the service principal.
   
Write-Output "Creating Connection in the Asset..."
Remove-AzureRmAutomationConnection -ResourceGroupName $ResourceGroupOMS -automationAccountName $AutomationAccountName -Name $connectionAssetName -Force -ErrorAction SilentlyContinue
New-AzureRmAutomationConnection -ResourceGroupName $ResourceGroupOMS -automationAccountName $AutomationAccountName -Name $connectionAssetName -ConnectionTypeName $connectionTypeName -ConnectionFieldValues $connectionFieldValues 
    
##############################################################################################################

Write-Output "RunAsAccount Creation Completed..."