$cred = Get-AutomationPSCredential -Name "MSOnline"
Connect-MsolService -Credential $cred

#Automation Variables
$PasswordExpirationRules_Enabled = Get-AutomationVariable -Name "PasswordExpirationRules_Enabled"

#debug
#$PasswordExpirationRules_Enabled = "Yes"

if($PasswordExpirationRules_Enabled -Like "Yes") {

    Write-Host 'Setting all 365 user passwords to Never Expire'
    $Userexpire = Get-MSOLUser | Where-Object {$_.PasswordNeverExpires -eq $false}
    
    if ($Userexpire.Count -eq "0") {
        Write-Host '***All user passwords are already set to never expire'
    } else {
        $Userexpire | Set-MSOLUser -PasswordNeverExpires $true
        Write-Host '***All user passwords are now set to never expire'
    }
}
