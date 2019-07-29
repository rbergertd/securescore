# Get the associated Service Principal for the Azure Run As Account
$runAsServicePrincipal = Get-AzureADServicePrincipal -ObjectId "9a738bfa-ab2b-4a8c-bb10-54815ef4792e"

# Add the Service Principal to the Directory Readers Role
Add-AzureADDirectoryRoleMember -ObjectId (Get-AzureADDirectoryRole | where-object {$_.DisplayName -eq "Directory Readers"}).Objectid -RefObjectId $runAsServicePrincipal.ObjectId

# Add the Service Principal to the User Administrator Role
Add-AzureADDirectoryRoleMember -ObjectId (Get-AzureADDirectoryRole | where-object {$_.DisplayName -eq "User Account Administrator"}).Objectid -RefObjectId $aaAadUser.ObjectId

# Add the Service Principal to the Global Administrator Role
Add-AzureADDirectoryRoleMember -ObjectId (Get-AzureADDirectoryRole | where-object {$_.DisplayName -eq "Company Administrator"}).Objectid -RefObjectId $runAsServicePrincipal.ObjectId