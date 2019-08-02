$cred = Get-AutomationPSCredential -Name "MSOnline"
$Session = New-PSSession –ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid -Credential $cred -Authentication Basic -AllowRedirection
 Import-PSSession -Session $Session -DisableNameChecking:$true -AllowClobber:$true | Out-Null
$Clientrules = Get-TransportRule | Select Name
if ($Clientrules.Name -Like "Client Rules Forwarding Block") {
  Write-Host '***Client Rules Forwarding Block Already Exists'
} else {
    New-TransportRule "Client Rules Forwarding Block" `
      -FromScope "InOrganization" `
      -MessageTypeMatches "AutoForward" `
      -SentToScope "NotInOrganization" `
      -RejectMessageReasonText "External Email Forwarding via Client Rules is not permitted"
    Write-Host '***Client Rules Forwarding Block has now been created'
  }