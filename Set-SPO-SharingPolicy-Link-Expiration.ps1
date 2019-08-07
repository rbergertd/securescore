$cred = Get-AutomationPSCredential -Name "MSOnline"
Connect-MsolService -Credential $cred

$expireindays = 14
$adminUPN="SecureScore@$orgname.onmicrosoft.com"
$orgName="How do we programatically get the tenant name?"
$userCredential = Get-Credential -UserName $adminUPN -Message "Type the password."
Connect-SPOService -Url https://$orgName-admin.sharepoint.com -Credential $cred
#Set Sharing
Set-SPOTenant -SharingCapability ExternalUserandGuestSharing
#Turn on ATP Malware Detection for SPO, OneDrive, and Teams
#https://docs.microsoft.com/en-us/office365/securitycompliance/turn-on-atp-for-spo-odb-and-teams 
Set-SPOTenant -DisallowInfectedFileDownload $false
#Set expiration date for Anonymous link expiration to 14 days.
Set-SPOTenant -RequireAnonymousLinksExpireInDays $ExpirationInDays
