Import-Module MSOnline
Connect-MsolService

Write-Host 'Enabling Office365 Auditing Data Injestion - 15 Points'
$Auditdata = Get-AdminAuditLogConfig
if ($Auditdata.UnifiedAuditLogIngestionEnabled -eq $true) {
  Write-Host '***Audit Data Ingestion is Already Enabled'
} else {
    Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true;
    Write-Host '***Audit Data Ingestion is now Enabled'
  }