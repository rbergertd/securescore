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