Import-Module MSOnline
Connect-MsolService

Write-Host 'Setting all 365 user passwords to Never Expire - 10 Points'
$Userexpire = Get-MSOLUser | Where-Object {$_.PasswordNeverExpires -eq $false}
if ($Userexpire.Count -eq "0") {
  Write-Host '***All user passwords are already set to never expire'
} else {
  $Userexpire | Set-MSOLUser -PasswordNeverExpires $true
  Write-Host '***All user passwords are now set to never expire'
  }