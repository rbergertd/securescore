﻿$cred = Get-AutomationPSCredential -Name "MSOnline"
Connect-MsolService -Credential $cred

$recommendedValidityPeriod = 60
$notificationDays = 14

# Set the settings for the default domain.

$defaultDomain = Get-MsolDomain | where { $_.IsDefault } 
Set-MsolPasswordPolicy -DomainName $defaultDomain.Name -ValidityPeriod $recommendedValidityPeriod -NotificationDays $notificationDays 

# Set the settings for the residual domains (if any). You can also specify alternative settings per domain

Get-MsolDomain | where { $_.IsDefault -eq $false } | foreach-object {
    Set-MsolPasswordPolicy -DomainName $_.Name -ValidityPeriod $recommendedValidityPeriod -NotificationDays $notificationDays 
}