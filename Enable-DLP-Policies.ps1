$cred = Get-AutomationPSCredential -Name "MSOnline"
$Session = New-PSSession –ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid -Credential $cred -Authentication Basic -AllowRedirection
Write-Host 'Creating Data Loss Prevention Policies from Templates'
$Clientdlp = Get-DlpPolicy
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
