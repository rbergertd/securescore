$cred = Get-AutomationPSCredential -Name "MSOnline"
Connect-AzureAD -Credential $cred
Connect-MsolService -Credential $cred

#Enable MFA for "Company Administrators" aka Global Admins

$multiFactor = New-Object -TypeName Microsoft.Online.Administration.StrongAuthenticationRequirement
$multiFactor.RelyingParty = "*"
$multiFactor.State = "Enforced"
$multiFactor.RememberDevicesNotIssuedBefore = (Get-Date) 
$multiFactorOff = @()
$domains = Get-MsolDomain
$secureScoreUser = Get-AutomationVariable -Name "User"


#For all users turn MFA on
Get-MsolUser | ForEach-Object {
     Set-MsolUser -UserPrincipalName $_.UserPrincipalName -StrongAuthenticationRequirements $multiFactor
}

#Turn off MFA for the SecureScore user. This is done explicitly in case SecureScore user is not in BreakGlass group yet
Set-MsolUser -UserPrincipalName $secureScoreUser -StrongAuthenticationRequirements $multiFactorOff 

#If there is a group called "SecureScoreBreakGlass" then exclude the additional users (i.e. Turn MFA Off for them)
#Else create the SecureScoreBreakGlass group
if ((Get-MsolGroup -SearchString "SecureScoreBreakGlass" | Measure-Object).Count -gt 0) {
  Get-MsolGroupMember -GroupObjectId (Get-MsolGroup -SearchString "SecureScoreBreakGlass").ObjectId | ForEach-Object {
    Set-MsolUser -UserPrincipalName $_.EmailAddress -StrongAuthenticationRequirements $multiFactorOff
  }
} else {
  New-AzureADGroup -DisplayName "SecureScoreBreakGlass" -MailEnabled $false -SecurityEnabled $true -MailNickName "NotSet"
}
