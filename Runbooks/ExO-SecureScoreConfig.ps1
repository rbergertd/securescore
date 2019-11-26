$cred = Get-AutomationPSCredential -Name "MSOnline"
Connect-MsolService -Credential $cred
Start-Sleep 20
$Session = New-PSSession –ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid -Credential $cred -Authentication Basic -AllowRedirection
Import-PSSession -Session $Session -DisableNameChecking:$true -AllowClobber:$true | Out-Null
Start-Sleep 20
$GlobalAdminsRoleGroup = Get-MsolRole | ? { $_.Name -eq "Company Administrator" }
$NotifyOutboundSpamRecipients = (Get-MsolRoleMember -RoleObjectId $GlobalAdminsRoleGroup.ObjectId -MemberObjectTypes User -All).EmailAddress
$NotifyOutboundSpamRecipients = (Get-MsolCompanyInformation).TechnicalNotificationEmails
$Clientrules = Get-TransportRule | Select Name
$Clientdlp = Get-DlpPolicy
$AtpMailbox = Get-Mailbox
$Domains = Get-AcceptedDomain
$SafeAttachmentPolicies = Get-SafeAttachmentPolicy
$SafeLinksPolicies = Get-SafeLinksPolicy
# Set Outbound Spam Policy
Get-HostedOutboundSpamFilterPolicy | Set-HostedOutboundSpamFilterPolicy -NotifyOutboundSpam $true -NotifyOutboundSpamRecipients $NotifyOutboundSpamRecipients
# Enable Transport Rule: Client Forwarding Block
if ($Clientrules.Name -Like "Client Rules Forwarding Block") {
    Write-Host '***Client Rules Forwarding Block Already Exists'
}
else {
    New-TransportRule "Client Rules Forwarding Block" `
        -FromScope "InOrganization" `
        -MessageTypeMatches "AutoForward" `
        -SentToScope "NotInOrganization" `
        -RejectMessageReasonText "External Email Forwarding via Client Rules is not permitted"
    Write-Host '***Client Rules Forwarding Block has now been created'
}
# Enable DLP Policies
if ($Clientdlp.Name -Like "U.S. Personally Identifiable Information (PII) Data") {
    Write-Host '***DLP for U.S. Personally Identifiable Information (PII) Data Already Exists'
}
else {
    New-DlpPolicy -Name "U.S. Personally Identifiable Information (PII) Data" -Mode AuditAndNotify -Template 'U.S. Personally Identifiable Information (PII) Data';
    Remove-TransportRule -Identity "U.S. PII: Scan text limit exceeded" -Confirm:$false
    Remove-TransportRule -Identity "U.S. PII: Attachment not supported" -Confirm:$false
    Write-Host '***Added DLP for U.S. Personally Identifiable Information (PII) Data'
}
if ($Clientdlp.Name -Like "U.S. State Breach Notification Laws") {
    Write-Host '***DLP for U.S. State Breach Notification Laws Already Exists'
}
else {
    New-DlpPolicy -Name "U.S. State Breach Notification Laws" -Mode AuditAndNotify -Template 'U.S. State Breach Notification Laws'
    Remove-TransportRule -Identity "U.S. State Breach: Scan text limit exceeded" -Confirm:$false
    Remove-TransportRule -Identity "U.S. State Breach: Attachment not supported" -Confirm:$false
    Write-Host '***Added DLP for U.S. State Breach Notification Laws'
}
# Create a Redirected Mailbox for mail that gets flagged by the Safe Attachment policy to be delivered to.
if ($AtpMailbox.Name -Like "ATPRedirectedMessages") {
    Write-Host '***Configuration for ATP Mailbox and Default ATP Policies Already Exist'
}
else {
New-Mailbox -PrimarySmtpAddress "ATPRedirectedMessages@$($Domains[0].Name)" -Name ATPRedirectedMessages -DisplayName ATPRedirectedMessages -Password (ConvertTo-SecureString -AsPlainText -Force (([char[]]([char]33 .. [char]95) + ([char[]]([char]97 .. [char]126)) + 0 .. 9 | sort { Get-Random })[0 .. 8] -join '')) -MicrosoftOnlineServicesID "ATPRedirectedMessages@$($Domains[0].Name)"
Set-Mailbox -Identity "ATPRedirectedMessages@$($Domains[0].Name)" -HiddenFromAddressListsEnabled $True
Add-MailboxPermission -Identity "ATPRedirectedMessages@$($Domains[0].Name)" -AutoMapping $false -InheritanceType All -User $cred.UserName -AccessRights FullAccess
New-SafeAttachmentPolicy -Name 'Default Safe Attachment Policy' -AdminDisplayName 'Default Safe Attachment Policy' -Action Replace -Redirect $True -RedirectAddress "ATPRedirectedMessages@$($Domains[0].Name)" -Enable $True
New-SafeAttachmentRule -Name 'Default Safe Link Policy' -RecipientDomainIs $Domains.Name -SafeAttachmentPolicy Default -Enabled $True
# Create a new Safe Links policy.
New-SafeLinksPolicy -Name Default -AdminDisplayName Default -TrackClicks $true -IsEnabled $true -AllowClickThrough $false -ScanUrls $true
New-SafeLinksRule -Name Default -RecipientDomainIs $Domains.Name -SafeLinksPolicy Default -Enabled $true
}
# Disallow anonymous Calendar Sharing: Free/Busy
Get-SharingPolicy | Set-SharingPolicy -Domains @{ Remove = "Anonymous:CalendarSharingFreeBusyReviewer"; Add = "Anonymous:0" }
# Disallow anonymous Calendar Detail Sharing
Get-SharingPolicy | Set-SharingPolicy -Enabled $False
# Set mailbox auditing on all mailboxes
Get-Mailbox -ResultSize Unlimited -Filter {RecipientTypeDetails -eq "UserMailbox" -or RecipientTypeDetails -eq "SharedMailbox" -or RecipientTypeDetails -eq "RoomMailbox" -or RecipientTypeDetails -eq "DiscoveryMailbox"} | Set-Mailbox -AuditEnabled $true -AuditLogAgeLimit 730 -AuditAdmin Update, MoveToDeletedItems, SoftDelete, HardDelete, SendAs, SendOnBehalf, Create, UpdateFolderPermission -AuditDelegate Update, SoftDelete, HardDelete, SendAs, Create, UpdateFolderPermissions, MoveToDeletedItems, SendOnBehalf -AuditOwner UpdateFolderPermission, MailboxLogin, Create, SoftDelete, HardDelete, Update, MoveToDeletedItems 
Write-Host -ForegroundColor Green "Set mailbox auditing on all mailboxes."
# Enable audit data recording
Enable-OrganizationCustomization -ea silentlycontinue -wa silentlycontinue
Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true -ea silentlycontinue -wa silentlycontinue
Write-Host -ForegroundColor Green "Enabled Audit Data Recording."

# Close the PS Session
Remove-PSSession $Session

