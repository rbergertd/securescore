$cred = Get-AutomationPSCredential -Name "MSOnline"
Connect-MsolService -Credential $cred

#Enable MFA for "Company Administrators" aka Global Admins

$multiFactor = New-Object -TypeName Microsoft.Online.Administration.StrongAuthenticationRequirement
$multiFactor.RelyingParty = "*"
$multiFactor.State = "Enforced"
$multiFactor.RememberDevicesNotIssuedBefore = (Get-Date) 
 
$role = Get-MsolRole -RoleName "Company Administrator"
Get-MsolRoleMember -RoleObjectId $role.ObjectId | ForEach-Object {
    Set-MsolUser -UserPrincipalName $_.EmailAddress -StrongAuthenticationRequirements $multiFactor
}

