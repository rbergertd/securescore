$cred = Get-AutomationPSCredential -Name "MSOnline"
$Session = New-PSSession –ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid -Credential $cred -Authentication Basic -AllowRedirection
 Import-PSSession -Session $Session -DisableNameChecking:$true -AllowClobber:$true | Out-Null
#Set mailbox auditing on all mailboxes
Get-Mailbox -ResultSize Unlimited -Filter {RecipientTypeDetails -eq "UserMailbox" -or RecipientTypeDetails -eq "SharedMailbox" -or RecipientTypeDetails -eq "RoomMailbox" -or RecipientTypeDetails -eq "DiscoveryMailbox"} | Set-Mailbox -AuditEnabled $true -AuditLogAgeLimit 365 -AuditAdmin Update, MoveToDeletedItems, SoftDelete, HardDelete, SendAs, SendOnBehalf, Create, UpdateFolderPermission -AuditDelegate Update, SoftDelete, HardDelete, SendAs, Create, UpdateFolderPermissions, MoveToDeletedItems, SendOnBehalf -AuditOwner UpdateFolderPermission, MailboxLogin, Create, SoftDelete, HardDelete, Update, MoveToDeletedItems 
Write-Host -ForegroundColor Green "Set mailbox auditing on all mailboxes."
#Enable audit data recording
Enable-OrganizationCustomization -ea silentlycontinue -wa silentlycontinue
Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true -ea silentlycontinue -wa silentlycontinue
Write-Host -ForegroundColor Green "Enabled Audit Data Recording."