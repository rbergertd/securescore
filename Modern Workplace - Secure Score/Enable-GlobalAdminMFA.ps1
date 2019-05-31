Import-Module MSOnline
Connect-MsolService

#Enable MFA for "Company Administrators"

$multiFactor = New-Object -TypeName Microsoft.Online.Administration.StrongAuthenticationRequirement
$multiFactor.RelyingParty = "*"
$multiFactor.State = "Enforced"
$multiFactor.RememberDevicesNotIssuedBefore = (Get-Date) 
 
$role = Get-MsolRole -RoleName "Company Administrator"
Get-MsolRoleMember -RoleObjectId $role.ObjectId | ForEach-Object {
    Set-MsolUser -UserPrincipalName $_.EmailAddress -StrongAuthenticationRequirements $multiFactor
}

