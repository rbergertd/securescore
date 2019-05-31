Import-Module MSOnline
Connect-MsolService

#Enable Audit Data Ingestion
$Auditdata = Get-AdminAuditLogConfig
if ($Auditdata.UnifiedAuditLogIngestionEnabled -eq $true) {
  Write-Host '***Audit Data Ingestion is Already Enabled'
} else {
    Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true;
    Write-Host '***Audit Data Ingestion is now Enabled'
  }