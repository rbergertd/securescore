$cred = Get-AutomationPSCredential -Name "MSOnline"
Connect-MsolService -Credential $cred
$Session = New-PSSession –ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid -Credential $cred -Authentication Basic -AllowRedirection
Import-PSSession -Session $Session -DisableNameChecking:$true -AllowClobber:$true | Out-Null
$GlobalAdminsRoleGroup = Get-MsolRole | ? { $_.Name -eq "Company Administrator" }
$NotifyOutboundSpamRecipients = (Get-MsolRoleMember -RoleObjectId $GlobalAdminsRoleGroup.ObjectId -MemberObjectTypes User -All).EmailAddress
$NotifyOutboundSpamRecipients = (Get-MsolCompanyInformation).TechnicalNotificationEmails
Get-HostedOutboundSpamFilterPolicy | Set-HostedOutboundSpamFilterPolicy -NotifyOutboundSpam $true -NotifyOutboundSpamRecipients $NotifyOutboundSpamRecipients
