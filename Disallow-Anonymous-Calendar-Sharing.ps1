$cred = Get-AutomationPSCredential -Name "MSOnline"
$Session = New-PSSession –ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid -Credential $cred -Authentication Basic -AllowRedirection
Import-PSSession -Session $Session -DisableNameChecking:$true -AllowClobber:$true | Out-Null
#Disallow anonymous Calendar Sharing: Free/Busy
Get-SharingPolicy | Set-SharingPolicy -Domains @{ Remove = "Anonymous:CalendarSharingFreeBusyReviewer"; Add = "Anonymous:0" }
#Disallow anonymous Calendar Detail Sharing
Get-SharingPolicy | Set-SharingPolicy -Enabled $False
