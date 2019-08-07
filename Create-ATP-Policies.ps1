$cred = Get-AutomationPSCredential -Name "MSOnline"
$Session = New-PSSession –ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid -Credential $cred -Authentication Basic -AllowRedirection
$Domains = Get-AcceptedDomain
$SafeAttachmentPolicies = Get-SafeAttachmentPolicy
$SafeLinksPolicies = Get-SafeLinksPolicy
Import-PSSession -Session $Session -DisableNameChecking:$true -AllowClobber:$true | Out-Null
#Create a Redirected Mailbox for mail that gets flagged by the Safe Attachment policy to be delivered to.
New-Mailbox -PrimarySmtpAddress "ATPRedirectedMessages@$($Domains[0].Name)" -Name ATPRedirectedMessages -DisplayName ATPRedirectedMessages -Password (ConvertTo-SecureString -AsPlainText -Force (([char[]]([char]33 .. [char]95) + ([char[]]([char]97 .. [char]126)) + 0 .. 9 | sort { Get-Random })[0 .. 8] -join '')) -MicrosoftOnlineServicesID "ATPRedirectedMessages@$($Domains[0].Name)"
Set-Mailbox -Identity "ATPRedirectedMessages@$($Domains[0].Name)" -HiddenFromAddressListsEnabled $True
Add-MailboxPermission -Identity "ATPRedirectedMessages@$($Domains[0].Name)" -AutoMapping $false -InheritanceType All -User $cred.UserName -AccessRights FullAccess
New-SafeAttachmentPolicy -Name 'Default Safe Attachment Policy' -AdminDisplayName 'Default Safe Attachment Policy' -Action Replace -Redirect $True -RedirectAddress "ATPRedirectedMessages@$($Domains[0].Name)" -Enable $True
New-SafeAttachmentRule -Name 'Default Safe Link Policy' -RecipientDomainIs $Domains.Name -SafeAttachmentPolicy Default -Enabled $True
#Create a new Safe Links policy.
New-SafeLinksPolicy -Name Default -AdminDisplayName Default -TrackClicks $true -IsEnabled $true -AllowClickThrough $false -ScanUrls $true
New-SafeLinksRule -Name Default -RecipientDomainIs $Domains.Name -SafeLinksPolicy Default -Enabled $true