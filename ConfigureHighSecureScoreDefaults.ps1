<#	
.SYNOPSIS
Configure Secure Score components automatically

.NOTES
	2018-08-01	Fixed parameter binding problem
	2017-10-02	Added MobileDevicePolicy switch
	2017-09-28	Initial release
#>
[cmdletbinding(DefaultParameterSetName = 'Creds')]

Param (
	
	[Parameter(ParameterSetName="Creds",Mandatory = $True)][System.Management.Automation.PSCredential]$Credential,
	[Switch]$All,
	[switch]$EnableMFAForAllGlobalAdmins,
	[switch]$EnableMFAForAllUsers,
	[switch]$EnableAuditDataRecording,
	[switch]$EnableMailboxAuditing,
	[switch]$EnableClientRulesForwardingBlock,
	[switch]$ReviewSignInsAfterMultipleFailuresReport,
	[switch]$ReviewSignInsFromUnknownSourcesReportWeekly,
	[switch]$ReviewSignInsFromMultipleGeographiesReportWeekly,
	[switch]$ReviewRoleChangesWeekly,
	[switch]$UseAuditLogData,
	[switch]$DoNotUseTransportRuleToExternalDomains,
	[switch]$DoNotUseTransportWhiteLists,
	[switch]$ReviewMailboxForwardingRulesWeekly,
	[switch]$DoNotAllowAnonymousCalendarSharing,
	[switch]$DoNotAllowCalendarDetailsSharing,
	[switch]$ConfigureExpirationTimeForExternalSharingLinks,
	[int]$ExpirationTimeForExternalSharingLinksInDays,
	[switch]$AllowAnonymousGuestSharingLinksForSitesAndDocs,
	[switch]$EnableAdvancedThreatProtectionSafeAttachmentsPolicy,
	[switch]$EnableAdvancedThreatProtectionSafeLinksPolicy,
	
	# Begin SetOutboundSpamNotifications Parameter Set
	[Parameter(ParameterSetName = 'OutboundSpamNotificationsSet')]
	[switch]$SetOutboundSpamNotifications,
	[Parameter(ParameterSetName = 'OutboundSpamNotificationsSet',ValueFromPipeline = $True)]
	[ValidatePattern('(?:[a-zA-Z0-9!#$%&* + /= ?^_`{|}~ - ]+(?:\.[a-zA-Z0-9!#$%&*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])')]
	[array]$OutboundSpamNotificationUsers,
	# End SetOutboundSpamNotifications Parameter Set
	
	# Begin Enable IRM Parameter Set
	[Parameter(Mandatory = $false,
			   ValueFromPipeline = $True,
			   ParameterSetName = 'EnableIRMSet')]
	[ValidateSet('GCC', 'NA', 'EU', 'AP', 'SA')]
	[string]$IRMLocation,
	[Parameter(ParameterSetName = 'EnableIRMSet')]
	[switch]$EnableIRM,
	# End Enable IRM Parameter Set
	
	# ActiveSync Parameter Set
	[Parameter(Mandatory = $false,
			ValueFromPipeline = $True,
			ParameterSetName = 'ActiveSync')]
	[switch]$MobileDevicePolicy,
	[Parameter(ParameterSetName = 'ActiveSync')]
	[switch]$SetAsDefaultActiveSyncPolicy
	
	)

Function ActiveSync([switch]$Default)
{
	$MobileDevicePolicies = Get-MobileDeviceMailboxPolicy
	[int]$Acceptable = 0
	foreach ($policy in $MobileDevicePolicies)
	{
		Write-Host Processing $policy.Identity
		If ($policy.PasswordEnabled -eq $true `
			-and $policy.AlphanumericPasswordRequired -eq $True `
			-and $policy.AllowSimplePassword -eq $false `
			-and [int]$policy.PasswordHistory -ge 5 `
			-and $policy.RequireDeviceEncryption -eq $True `
			-and [int]$policy.MinPasswordComplexCharacters -ge 2 `
			-and [int]$policy.MaxPasswordFailedAttempts -ge 3 `
			-and [int]$policy.MinPasswordLength -ge 3)
		{
			$Acceptable++
			Write-Host "Is Acceptable?" $($Acceptable)
			Write-Host "Compliant policy found."
		}
		Else
		{
			Write-Host "Policy: $($policy.Identity)"
			Write-Host "Alpha: $($policy.AlphanumericPasswordRequired)"
			Write-Host "Simple: $($policy.AllowSimplePassword)"
			Write-Host "History: $($policy.PasswordHistory)"
			Write-Host "Encrpytion: $($policy.RequireDeviceEncryption)"
			Write-Host "ComplexChars: $($policy.MinPasswordComplexCharacters)"
			Write-Host "FailedAttempts: $($policy.MaxPasswordFailedAttempts)"
			Write-Host "Length: $($policy.MinPasswordLength)"
			Write-Host "-----"
		}
	}
	If ($Acceptable -eq 0)
		{
			Write-Host "Creating new policy."
			If ($Default) { $IsDefault = $True} Else { $IsDefault = $false }
			New-MobileDeviceMailboxPolicy -Name 'Office 365 Secure Score' `
			-AlphanumericPasswordRequired:$true `
			-AllowSimplePassword $false `
			-PasswordHistory '12' `
			-MinPasswordComplexCharacters '3' `
			-RequireDeviceEncryption:$true `
			-MaxPasswordFailedAttempts '10' `
			-PasswordEnabled:$true `
			-MinPasswordLength '4' `
			-IsDefault $IsDefault | Out-Null
		}
}

function Schedule($TaskName, $Frequency, $TaskDetail)
{
	schtasks.exe /create /RL HIGHEST /NP /sc MINUTE /MO 30 /st 06:00 /tn $taskname /tr ""`$PSHOME\powershell.exe -c '. ''`$(`$myinvocation.mycommand.definition)'''""`n
}

# You should enable MFA for all of your admin accounts because a breach of any of those accounts can lead to a breach of any of your data. 
function EnableMFAForAllGlobalAdmins()
{
	# MFA Configuration
	$auth = New-Object -TypeName Microsoft.Online.Administration.StrongAuthenticationRequirement
	$auth.RelyingParty = "*"
	$auth.State = "Enabled"
	$auth.RememberDevicesNotIssuedBefore = (Get-Date)
	
	# Get Global Admins	
	$GlobalAdminsRoleGroup = Get-MsolRole | ? { $_.Name -eq "Company Administrator" }
	$GlobalAdmins = Get-MsolRoleMember -RoleObjectId $GlobalAdminsRoleGroup.ObjectId -MemberObjectTypes User -All
	
	# Enable MFA for Global Admins
	$GlobalAdmins | % { Set-MsolUser -UserPrincipalName $_.EmailAddress -StrongAuthenticationRequirements $auth }
	
	Write-Host -ForegroundColor Green "Global Admins enabled for multifactor authentication. Direct users to http://aka.ms/MFASetup if they have not already completed enrollment."	
}

# You should enable MFA for all of your user accounts because a breach of any of those accounts can lead to a breach of any data that user has access to.
function EnableMFAForAllUsers()
{
	# MFA Configuration
	$auth = New-Object -TypeName Microsoft.Online.Administration.StrongAuthenticationRequirement
	$auth.RelyingParty = "*"
	$auth.State = "Enabled"
	$auth.RememberDevicesNotIssuedBefore = (Get-Date)
	
	# Get All Users
	$Users = Get-MsolUser -All
	
	# Enable MFA for all users
	$Users | % { Set-MsolUser -UserPrincipalName $_.UserPrincipalName -StrongAuthenticationRequirements $auth }
	
	Write-Host -ForegroundColor Green "All users enabled for multifactor authentication. Direct users to http://aka.ms/MFASetup if they have not already completed enrollment."
	Write-Host -ForegroundColor DarkGreen "For more information on Azure MFA, please see https://docs.microsoft.com/en-us/azure/multi-factor-authentication/multi-factor-authentication"
}

# This is the same as enabling Admin and User Activity Logging in the Security & Compliance Center
function EnableAuditDataRecording()
{
	Enable-OrganizationCustomization -ea silentlycontinue -wa silentlycontinue
	Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true -ea silentlycontinue -wa silentlycontinue
	Write-Host -ForegroundColor Green "Enabled Audit Data Recording."
}

Function EnableMailboxAuditing()
{
	Get-Mailbox -ResultSize Unlimited | Set-Mailbox -AuditEnabled $true -AuditLogAgeLimit 730 -wa silentlycontinue -ea silentlycontinue
	Write-Host -ForegroundColor Green Enabled mailbox auditing.
}

Function SetOutboundSpamNotifications($NotifyOutboundSpamRecipients)
{
	# Configure Outbound Spam Notifications.  If $NotifyOutboundSpamRecipients is present, use that value.
	# If $NotifyOutboundSpamRecipients is present AND the $UseGlobalAdminsForOutboundSpamNotifications is set, calculate the Global Admins users and use them for the Notification list.
	# If $NotifyOutboundSpamRecipients is not present, use the tenant Technical Contact.
	if (!(Test-Path "C:\Office365SecureScore")) { New-Item "C:\Office365SecureScore" -ItemType Directory }
	if (!(Test-Path "C:\Office365SecureScore\ConfigBackups")) { New-Item "C:\Office365SecureScore\ConfigBackups" -ItemType Directory }
	if (!(Test-Path "C:\Office365SecureScore\ConfigBackups\HostedOutboundSpamFilterPolicy")) { New-Item "C:\Office365SecureScore\ConfigBackups\HostedOutboundSpamFilterPolicy" -ItemType Directory }
	$FilePath = "C:\Office365SecureScore\ConfigBackups\HostedOutboundSpamFilterPolicy\$($Date)_HostedOutboundSpamFilterPolicy.xml"
	If (!($NotifyOutboundSpamRecipients) -and $UseGlobalAdminsForOutboundSpamNotifications)
	{
		$GlobalAdminsRoleGroup = Get-MsolRole | ? { $_.Name -eq "Company Administrator" }
		$NotifyOutboundSpamRecipients = (Get-MsolRoleMember -RoleObjectId $GlobalAdminsRoleGroup.ObjectId -MemberObjectTypes User -All).EmailAddress	
	}
	If (!($NotifyOutboundSpamRecipients))
	{
	$NotifyOutboundSpamRecipients = (Get-MsolCompanyInformation).TechnicalNotificationEmails
	}
	Get-HostedOutboundSpamFilterPolicy | Export-Clixml -Path $FilePath
	Get-HostedOutboundSpamFilterPolicy | Set-HostedOutboundSpamFilterPolicy -NotifyOutboundSpam $true -NotifyOutboundSpamRecipients $NotifyOutboundSpamRecipients
	Write-Host -ForegroundColor Green Configured Outbound Spam Notifications.	
}



function EnableClientRulesForwardingBlock($EnableClientRulesForwardingBlockExceptionList)
{
	# If Sender is Inside the organization
	# If receipient is Outside the organzation
	# If message type is auto-forward
	# Reject message with explanation 'external mail forwarding via client rules is not permitted'
	$TransportRules = Get-TransportRule
	foreach ($rule in $TransportRules)
	{
		If ($Rule.SentToScope -eq "NotInOrganization" -and $Rule.FromScope -eq "InOrganization" -and $Rule.RejectMessageEnhancedStatusCode -and $Rule.RejectMessageReasonText -and $Rule.MessageTypeMatches -eq "AutoForward")
		{
			Write-Host $Rule.Identity meets the requirement
		}
		Else
		{
			New-TransportRule -Comment "Rule Added by HighSecureScoreDefaults" -Enabled $True -Mode Enforce -RuleErrorAction Ignore -SenderAddressLocation Header -FromScope InOrganization -SentToScope NotInOrganization -HasNoClassification $False -HasSenderOverride $False -MessageTypeMatches AutoForward -AttachmentIsUnsupported $false -AttachmentProcessingLimitExceeded $False -AttachmentHasExecutableContent $False -AttachmentIsPasswordProtected $False -ExceptIfHasNoClassification $False -ExceptIfAttachmentIsUnsupported $False -ExceptIfAttachmentProcessingLimitExceeded $False -ExceptIfAttachmentIsPasswordProtected $False -ExceptIfHasSenderOverride $False -ModerateMessageByManager $False -RejectMessageEnhancedStatusCode "5.7.1" -RejectMessageReasonText "Client Forwarding Rules to External Domains Are Not Permitted." -DeleteMessage $False -Quarantine $False -StopRuleProcessing $False -RouteMessageOutboundRequireTls $False -ApplyOME $False -RemoveOME $False -Name "Client Rules to External Block" -ea SilentlyContinue
		}
	}
	Write-Host -ForegroundColor Green Enabled client forwarding rule block.
}

function EnableIRM($IRMLocation)
{
	# Check for AADRM cmdlets and install (EOP migration tool)
	# Enable for appropriate IRM location
	
	If ($EnableIRM)
	{
		Switch ($IRMLocation)
		{
			GCC	{ $RMSOnlineKeySharingLocation = "https://sp-rms.govus.aadrm.com/TenantManagement/ServicePartner.svc" }
			NA	{ $RMSOnlineKeySharingLocation = "https://sp-rms.na.aadrm.com/TenantManagement/ServicePartner.svc" }
			EU	{ $RMSOnlineKeySharingLocation = "https://sp-rms.eu.aadrm.com/TenantManagement/ServicePartner.svc" }
			AP	{ $RMSOnlineKeySharingLocation = "https://sp-rms.ap.aadrm.com/TenantManagement/ServicePartner.svc" }
			SA	{ $RMSOnlineKeySharingLocation = "https://sp-rms.sa.aadrm.com/TenantManagement/ServicePartner.svc" }
		} # End Switch
	}
	If (!(Get-Module -ListAvailable AADRM))
	{
		Write-Host -ForegroundColor Red "AADRM Module not present. Attempting to download and install."
		Invoke-WebRequest -uri https://download.microsoft.com/download/1/6/6/166A2668-2FA6-4C8C-BBC5-93409D47B339/WindowsAzureADRightsManagementAdministration_x64.exe -Outfile .\WindowsAzureADRightsManagementAdministration_x64.exe
		.\WindowsAzureADRightsManagementAdministration_x64.exe /quiet
	}
	
	If (!(Get-Module -ListAvailable AADRM))
	{
		Write-Host -ForegroundColor Red "Unable to configure IRM because the AADRM module is not installed."
	}
	Else
	{
		Import-Module AADRM
		Connect-AADRMService -Credential $Credential
		Enable-AADRM
		Set-IRMConfiguration -RMSOnlineKeySharingLocation $RMSOnlineKeySharingLocation
		Import-RMSTrustedPublishingDomain -RMSOnline -name "RMS Online"
		Set-IRMConfiguration -InternalLicensingEnabled $true
		Write-Host -ForegroundColor Green "Enabled AADRM and IRM Licensing."
	}
}

function ReviewSignInsAfterMultipleFailuresReport()
{
	# Review Sign In After Multiple Failures Report
	$url = "https://manage.windowsazure.com/$($TenantDomain)#Workspaces/ActiveDirectoryExtension/Directory/$($TenantID)/ReportSignInAfterMultipleFailuresSummaryEs/SignInAfterMultipleFailuresSummaryEs/ReportSignInAfterMultipleFailuresSummaryEs"
	
	$Frequency = "1"
	$TaskName = "Office 365 SecureScore Report - Sign-In Failures Review"
	$TaskDetail = "$($PSHOME)\powershell.exe -c `"[Diagnostics.Process]::Start(`'$url`')`""
	
	if (!(Test-Path "C:\Office365SecureScore\ScheduledSecurityTasks")) { New-Item "C:\Office365SecureScore\ScheduledSecurityTasks" -ItemType Directory }
	Set-Content -Path "C:\Office365SecureScore\ScheduledSecurityTasks\Office365SecureScore-SignInFailuresReport.ps1" -Value "#Scheduled Task to review Azure Sign-In Failures Report"
	Add-Content -Path "C:\Office365SecureScore\ScheduledSecurityTasks\Office365SecureScore-SignInFailuresReport.ps1" -Value $TaskDetail
	
	If (!(Get-ScheduledTask -TaskName $TaskName -ea silentlycontinue))
	{
		schtasks.exe /CREATE /RL HIGHEST /IT /SC Weekly /MO $Frequency /TR "$PSHOME\powershell.exe -c `"C:\Office365SecureScore\ScheduledSecurityTasks\Office365SecureScore-SignInFailuresReport.ps1`"" /TN $($TaskName)
	}
	Write-Host -ForegroundColor Green "Configured a scheduled task to check sign in failures reports."
}

function ReviewSignInsFromUnknownSourcesReportWeekly()
{
	$url = "https://manage.windowsazure.com/$($TenantDomain)#Workspaces/ActiveDirectoryExtension/Directory/$($TenantID)/ReportLoginsFromBlacklistedIpEs/LoginsFromBlacklistedIpEs/ReportLoginsFromBlacklistedIpEs"
	$Frequency = "1"
	$TaskName = "Office 365 SecureScore Report - Sign-In From Unknown Sources Review"
	$TaskDetail = "$($PSHOME)\powershell.exe -c `"[Diagnostics.Process]::Start(`'$url`')`""
	
	if (!(Test-Path "C:\Office365SecureScore\ScheduledSecurityTasks")) { New-Item "C:\Office365SecureScore\ScheduledSecurityTasks" -ItemType Directory }
	Set-Content -Path "C:\Office365SecureScore\ScheduledSecurityTasks\Office365SecureScore-SignInFailuresReport.ps1" -Value "#Scheduled Task to review Azure Sign-In Failures Report"
	Add-Content -Path "C:\Office365SecureScore\ScheduledSecurityTasks\Office365SecureScore-SignInFailuresReport.ps1" -Value $TaskDetail
	
	If (!(Get-ScheduledTask -TaskName $TaskName -ea silentlycontinue))
	{
		schtasks.exe /CREATE /RL HIGHEST /IT /SC Weekly /MO $Frequency /TR "$PSHOME\powershell.exe -c `"C:\Office365SecureScore\ScheduledSecurityTasks\Office365SecureScore-SignInFailuresReport.ps1`"" /TN $($TaskName)
	}
	Write-Host -ForegroundColor Green "Configured a scheduled task to check sign in from unknown sources reports."
}

function ReviewSignInsFromMultipleGeographiesReportWeekly()
{
	$url = "https://manage.windowsazure.com/$($TenantDomain)#Workspaces/ActiveDirectoryExtension/Directory/$($TenantID)/ReportSignInsFromMultipleGeographiesEs/SignInsFromMultipleGeographiesEs/ReportSignInsFromMultipleGeographiesEs"
	$Frequency = "1"
	$TaskName = "Office 365 SecureScore Report - Sign-In From Multiple Geographies Review"
	$TaskDetail = "$($PSHOME)\powershell.exe -c `"[Diagnostics.Process]::Start(`'$url`')`""
	
	if (!(Test-Path "C:\Office365SecureScore\ScheduledSecurityTasks")) { New-Item "C:\Office365SecureScore\ScheduledSecurityTasks" -ItemType Directory }
	Set-Content -Path "C:\Office365SecureScore\ScheduledSecurityTasks\Office365SecureScore-SignInMultipleGeographiesReport.ps1" -Value "#Scheduled Task to review Azure Sign-Ins From Multiple Geographies Report"
	Add-Content -Path "C:\Office365SecureScore\ScheduledSecurityTasks\Office365SecureScore-SignInMultipleGeographiesReport.ps1" -Value $TaskDetail
	
	If (!(Get-ScheduledTask -TaskName $TaskName -ea silentlycontinue))
	{
		schtasks.exe /CREATE /RL HIGHEST /IT /SC Weekly /MO $Frequency /TR "$PSHOME\powershell.exe -c `"C:\Office365SecureScore\ScheduledSecurityTasks\Office365SecureScore-SignInMultipleGeographiesReport.ps1`"" /TN $($TaskName)
	}
	Write-Host -ForegroundColor Green "Configured a scheduled task to check sign in from multiple geographies reports."
}

function ReviewRoleChangesWeekly()
{
	$url = "https://portal.office.com/Admin/Default.aspx#ActiveUsersPage"
	$Frequency = "1"
	$TaskName = "Office 365 SecureScore Report - Review Role Memberships"
	$TaskDetail = "$($PSHOME)\powershell.exe -c `"[Diagnostics.Process]::Start(`'$url`')`""
	
	if (!(Test-Path "C:\Office365SecureScore\ScheduledSecurityTasks")) { New-Item "C:\Office365SecureScore\ScheduledSecurityTasks" -ItemType Directory }
	Set-Content -Path "C:\Office365SecureScore\ScheduledSecurityTasks\Office365SecureScore-ReviewRoleMemberships.ps1" -Value "#Scheduled Task to review Azure Role Memberships"
	Add-Content -Path "C:\Office365SecureScore\ScheduledSecurityTasks\Office365SecureScore-ReviewRoleMemberships.ps1" -Value $TaskDetail
	
	If (!(Get-ScheduledTask -TaskName $TaskName -ea silentlycontinue))
	{
		schtasks.exe /CREATE /RL HIGHEST /IT /SC Weekly /MO $Frequency /TR "$PSHOME\powershell.exe -c `"C:\Office365SecureScore\ScheduledSecurityTasks\Office365SecureScore-ReviewRoleMemberships.ps1`"" /TN $($TaskName)
	}
	Write-Host -ForegroundColor Green "Configured a scheduled task to log into the portal to check role memberships."
}

function UseAuditLogData()
{
	$url = "https://protection.office.com/#/unifiedauditlog"
	$FilePath = "C:\Office365SecureScore\ScheduledSecurityTasks\Office365SecureScore-ReviewAuditData.ps1"
	$Frequency = "2"
	$TaskName = "Office 365 SecureScore Report - Review Audit Data"
	$TaskDetail = "$($PSHOME)\powershell.exe -c `"[Diagnostics.Process]::Start(`'$url`')`""
	
	if (!(Test-Path "C:\Office365SecureScore\ScheduledSecurityTasks")) { New-Item "C:\Office365SecureScore\ScheduledSecurityTasks" -ItemType Directory }
	if (!(Test-Path "C:\Office365SecureScore\ScheduledSecurityTasks\AuditLogs")) { New-Item "C:\Office365SecureScore\ScheduledSecurityTasks\AuditLogs" -ItemType Directory }
	Set-Content -Path $FilePath -Value "#Scheduled Task to review Unified Audit Logs"
	Add-Content -Path $FilePath -Value $TaskDetail
	
	
	If (!(Get-ScheduledTask -TaskName $TaskName -ea silentlycontinue))
	{
		schtasks.exe /CREATE /RL HIGHEST /IT /SC Weekly /MO $Frequency /TR "$PSHOME\powershell.exe -c `"C:\Office365SecureScore\ScheduledSecurityTasks\Office365SecureScore-ReviewAuditData.ps1`"" /TN $($TaskName)
	}
	Write-Host -ForegroundColor Green "Configured a scheduled task to login into the Security and Compliance Center to check Unified Audit Logs."
}

function DoNotUseTransportRuleToExternalDomains()
{
	if (!(Test-Path "C:\Office365SecureScore\ScheduledSecurityTasks")) { New-Item "C:\Office365SecureScore\ScheduledSecurityTasks" -ItemType Directory }
	if (!(Test-Path "C:\Office365SecureScore\AuditLogs")) { New-Item "C:\Office365SecureScore\AuditLogs" -ItemType Directory }
	if (!(Test-Path "C:\Office365SecureScore\AuditLogs\TransportRuleAudit")) { New-Item "C:\Office365SecureScore\AuditLogs\TransportRuleAudit" -ItemType Directory }
	$FilePath = "C:\Office365SecureScore\AuditLogs\TransportRuleAudit\$($Date)_TransportRuleExternalDomainAudit.csv"
	$Header = """" + "TransportRule" + """" + "," + """" + "Property" + """" + "," + """" + "Value" + """" + "," + """" + "Note" + """"
	$Header | Out-File $FilePath -Force 
	
	# Check transport rules for rules that are configured to forward messages outside of domain
	$Domains = Get-AcceptedDomain
	[regex]$RegDomains = '(?i)(' + "\@" + (($Domains.Name | foreach { [regex]::escape($_) }) -join "|") + ')'
	#$RegDomains.ToString()
	
	$TransportRules = Get-TransportRule
	foreach ($Rule in $TransportRules)
	{
		# Check rules that have "Add a To recipient" containing an address not in accepted domains
		If ($Rule.AddToRecipients -and $Rule.AddToRecipients -notmatch $RegDomains)
		{
		$RuleData = """" + $Rule.Name + """" + "," + """" + "AddToRecipients" + """" + "," + """" + $Rule.AddToRecipients -join ";"+ """" + "," + """" + "Possible external recipient / data exfiltration" + """"
		$RuleData | Out-File -FilePath $FilePath -Append
		}
		
		# Check rules that have "Add a Cc recipient" containing an address not in accepted domains
		If ($Rule.CopyTo -and $Rule.CopyTo -notmatch $RegDomains)
		{
			$RuleData = """" + $Rule.Name + """" + "," + """" + "CopyTo" + """" + "," + """" + $Rule.CopyTo -join ";" + """" + "," + """" + "Possible external recipient / data exfiltration" + """"
			$RuleData | Out-File -FilePath $FilePath -Append
		}
		
		# Check rules that have "Add a Cc recipient" containing an address not in accepted domains
		If ($Rule.BlindCopyTo -and $Rule.BlindCopyTo -notmatch $RegDomains)
		{
			$RuleData = """" + $Rule.Name + """" + "," + """" + "BlindCopyTo" + """" + "," + """" + $Rule.BlindCopyTo -join ";" + """" + "," + """" + "Possible external recipient / data exfiltration" + """"
			$RuleData | Out-File -FilePath $FilePath -Append
		}
		
		# Check rules that have "Add a Cc recipient" containing an address not in accepted domains
		If ($Rule.RedirectMessageTo -and $Rule.RedirectMessageTo -notmatch $RegDomains)
		{
			$RuleData = """" + $Rule.Name + """" + "," + """" + "RedirectMessageTo" + """" + "," + """" + $Rule.RedirectMessageTo -join ";" + """" + "," + """" + "Possible external recipient / data exfiltration" + """"
			$RuleData | Out-File -FilePath $FilePath -Append
		}
	}
	
	Write-Host -ForegroundColor Green "Reviewed Transport Rules for rules forwarding messages outside of org. Report is located at $($FilePath)."
}

function DoNotUseTransportWhiteLists()
{
	if (!(Test-Path "C:\Office365SecureScore\ScheduledSecurityTasks")) { New-Item "C:\Office365SecureScore\ScheduledSecurityTasks" -ItemType Directory }
	if (!(Test-Path "C:\Office365SecureScore\AuditLogs")) { New-Item "C:\Office365SecureScore\AuditLogs" -ItemType Directory }
	if (!(Test-Path "C:\Office365SecureScore\AuditLogs\TransportRuleAudit")) { New-Item "C:\Office365SecureScore\AuditLogs\TransportRuleAudit" -ItemType Directory }
	$FilePath = "C:\Office365SecureScore\AuditLogs\TransportRuleAudit\$($Date)_TransportRuleDomainWhitelistAudit.csv"
	$Header = """" + "TransportRule" + """" + "," + """" + "Property" + """" + "," + """" + "Value" + """" + "," + """" + "Note" + """"
	$Header | Out-File $FilePath -Force
	
	# Check transport rules for rules that are configured to whitelist domains
	$TransportRules = Get-TransportRule
	
	foreach ($Rule in $TransportRules)
	{
		If ($Rule.SetSCL -and $Rule.SetSCL -eq "-1")
		{
			$RuleData = """" + $Rule.Name + """" + "," + """" + "SetSCL" + """" + "," + """" + $Rule.SetSCL + """" + "," + """" + "Possible domain whitelisting. Please use spam filtering or Set-HostedContentFilterPolicy." + """"
			$RuleData | Out-File -FilePath $FilePath -Append
		}
	}
	Write-Host -ForegroundColor Green "Reviewed Transport Rules for whitelisting (SCL -1). Report is located at $($FilePath)."
}

function ReviewMailboxForwardingRulesWeekly()
{
	if (!(Test-Path "C:\Office365SecureScore\ScheduledSecurityTasks")) { New-Item "C:\Office365SecureScore\ScheduledSecurityTasks" -ItemType Directory }
	if (!(Test-Path "C:\Office365SecureScore\ScheduledSecurityTasks\AuditLogs")) { New-Item "C:\Office365SecureScore\ScheduledSecurityTasks\AuditLogs" -ItemType Directory }
	if (!(Test-Path "C:\Office365SecureScore\ScheduledSecurityTasks\AuditLogs\UserAudits")) { New-Item "C:\Office365SecureScore\ScheduledSecurityTasks\AuditLogs\UserAudits" -ItemType Directory }
	$FilePath = "C:\Office365SecureScore\ScheduledSecurityTasks\AuditLogs\UserAudits\$($Date)_UserInboxRuleDataExfiltrationAudit.csv"
	$Header = """" + "EmailAddress" + """" + "," + """" + "RuleName" + """" + "," + """" + "Value" + """" + "," + """" + "Note" + """"
	$Header | Out-File $FilePath -Force
	
	$Domains = Get-AcceptedDomain
	[regex]$RegDomains = '(?i)(' + "\@" + (($Domains.Name | foreach { [regex]::escape($_) }) -join "|") + ')'
	
	$Users = Get-Mailbox -Resultsize Unlimited
	foreach ($User in $Users)
	{
		$InboxRules = Get-InboxRule -Mailbox $User.PrimarySmtpAddress
		foreach ($Rule in $InboxRules)
		{
			If ($Rule.Enabled -eq $True -and $Rule.ForwardAsAttachmentTo -and $Rule.ForwardAsAttachmentTo -match "smtp" -and $Rule.ForwardAsAttachmentTo -notmatch $RegDomains)
			{
				$RuleData = """" + $User.PrimarySmtpAddress + """" + "," + """" + "ForwardAsAttachmentTo" + """" + "," + """" + $Rule.ForwardAsAttachmentTo -join ";" + """" + "," + """" + "Possible mail forwarding exfiltration.  Message forwarded to domain not in Exchange Online." + """"
				$RuleData | Out-File -FilePath $FilePath -Append
			}
			
			If ($Rule.Enabled -eq $True -and $Rule.ForwardTo -and $Rule.ForwardTo -match "smtp" -and $Rule.ForwardTo -notmatch $RegDomains)
			{
				$RuleData = """" + $User.PrimarySmtpAddress + """" + "," + """" + "ForwardTo" + """" + "," + """" + $Rule.ForwardTo -join ";" + """" + "," + """" + "Possible mail forwarding exfiltration.  Message forwarded to domain not in Exchange Online." + """"
				$RuleData | Out-File -FilePath $FilePath -Append
			}
			
			If ($Rule.Enabled -eq $True -and $Rule.RedirectTo -and $Rule.RedirectTo -match "smtp" -and $Rule.RedirectTo -notmatch $RegDomains)
			{
				$RuleData = """" + $User.PrimarySmtpAddress + """" + "," + """" + "RedirectTo" + """" + "," + """" + $Rule.RedirectTo -join ";" + """" + "," + """" + "Possible mail forwarding exfiltration.  Message forwarded to domain not in Exchange Online." + """"
				$RuleData | Out-File -FilePath $FilePath -Append
			}
		}
	}
	Write-Host -ForegroundColor Green "Reviewed Inbox Rules for users forwarding outside of organization. Report is located at $($FilePath)."
}

function DoNotAllowAnonymousCalendarSharing()
{
	if (!(Test-Path "C:\Office365SecureScore\ConfigBackups")) { New-Item "C:\Office365SecureScore\ConfigBackups" -ItemType Directory }
	if (!(Test-Path "C:\Office365SecureScore\ConfigBackups\CalendarSharing")) { New-Item "C:\Office365SecureScore\ConfigBackups\CalendarSharing" -ItemType Directory }
	$FilePath = "C:\Office365SecureScore\ConfigBackups\CalendarSharing\$($Date)_DoNotAllowAnonymousCalendarSharing.xml"
	Get-SharingPolicy | Export-Clixml -Path $FilePath
	Get-SharingPolicy | Set-SharingPolicy -Domains @{ Remove = "Anonymous:CalendarSharingFreeBusyReviewer"; Add = "Anonymous:0" }
	Write-Host -ForegroundColor Green "Disabled Anonymous Calendar Sharing. Configuration backup is located at $($FilePath)."
}

function DoNotAllowCalendarDetailsSharing()
{
	if (!(Test-Path "C:\Office365SecureScore\ConfigBackups")) { New-Item "C:\Office365SecureScore\ConfigBackups" -ItemType Directory }
	if (!(Test-Path "C:\Office365SecureScore\ConfigBackups\CalendarSharing")) { New-Item "C:\Office365SecureScore\ConfigBackups\CalendarSharing" -ItemType Directory }
	$FilePath = "C:\Office365SecureScore\ConfigBackups\CalendarSharing\$($Date)_DoNotAllowCalendarDetailsSharing.xml"
	Get-SharingPolicy | Export-Clixml -Path $FilePath
	Get-SharingPolicy | Set-SharingPolicy -Enabled $False
	Write-Host -ForegroundColor Green "Disabled external Calendar Sharing. Configuration backup is located at $($FilePath)."
}

function ConfigureExpirationTimeForExternalSharingLinks($ExpirationInDays)
{
	If (!($ExpirationInDays)) { $ExpirationInDays = 60 }
	if (!(Test-Path "C:\Office365SecureScore\ConfigBackups")) { New-Item "C:\Office365SecureScore\ConfigBackups" -ItemType Directory }
	if (!(Test-Path "C:\Office365SecureScore\ConfigBackups\SPOTenant")) { New-Item "C:\Office365SecureScore\ConfigBackups\SPOTenant" -ItemType Directory }
	$FilePath = "C:\Office365SecureScore\ConfigBackups\SPOTenant\$($Date)_ConfigureExpirationTimeForExternalSharingLinks.xml"
	Get-SPOTenant | Export-Clixml -Path $FilePath
	Set-SPOTenant -RequireAnonymousLinksExpireInDays $ExpirationInDays
	Write-Host -ForegroundColor Green "Enabled Expiration time for $($ExpirationInDays) days for external sharing invitations. Configuration backup is located at $($FilePath)."
}

function AllowAnonymousGuestSharingLinksForSitesAndDocs()
{
	if (!(Test-Path "C:\Office365SecureScore\ConfigBackups")) { New-Item "C:\Office365SecureScore\ConfigBackups" -ItemType Directory }
	if (!(Test-Path "C:\Office365SecureScore\ConfigBackups\SPOTenant")) { New-Item "C:\Office365SecureScore\ConfigBackups\SPOTenant" -ItemType Directory }
	$FilePath = "C:\Office365SecureScore\ConfigBackups\SPOTenant\$($Date)_AllowAnonymousGuestSharingLinksForSitesAndDocs.xml"
	Get-SPOTenant | Export-Clixml -Path $FilePath
	Set-SPOTenant -SharingCpability ExternaluserandGuesSharing
	Write-Host -ForegroundColor Green "Enabled anonymous guest sharing links for sites and docs. Configuration backup is located at $($FilePath)."
}

function EnableAdvancedThreatProtectionSafeAttachmentsPolicy()
{
	$Domains = Get-AcceptedDomain
	$SafeAttachmentPolicies = Get-SafeAttachmentPolicy
	If (!($SafeAttachmentPolicies))
	{
		New-Mailbox -PrimarySmtpAddress "ATPRedirectedMessages@$($Domains[0].Name)" -Name ATPRedirectedMessages -DisplayName ATPRedirectedMessages -Password (ConvertTo-SecureString -AsPlainText -Force (([char[]]([char]33 .. [char]95) + ([char[]]([char]97 .. [char]126)) + 0 .. 9 | sort { Get-Random })[0 .. 8] -join '')) -MicrosoftOnlineServicesID "ATPRedirectedMessages@$($Domains[0].Name)"
		Set-Mailbox -Identity "ATPRedirectedMessages@$($Domains[0].Name)" -HiddenFromAddressListsEnabled $True
		Add-MailboxPermission -Identity "ATPRedirectedMessages@$($Domains[0].Name)" -AutoMapping $false -InheritanceType All -User $Credential.UserName -AccessRights FullAccess
		New-SafeAttachmentPolicy -Name Default -AdminDisplayName Default -Action Replace -Redirect $True -RedirectAddress "ATPRedirectedMessages@$($Domains[0].Name)" -Enable $True
		New-SafeAttachmentRule -Name Default -RecipientDomainIs $Domains.Name -SafeAttachmentPolicy Default -Enabled $True
		Write-Host -ForegroundColor Green "Created new Safe Attachment policy."	
	}
}

function EnableAdvancedThreatProtectionSafeLinksPolicy()
{
	$Domains = Get-AcceptedDomain
	$SafeLinksPolicies = Get-SafeLinksPolicy
	If (!($SafeLinksPolicies))
	{
		New-SafeLinksPolicy -Name Default -AdminDisplayName Default -TrackClicks $True -Enabled $True -AllowClickThrough $false -ScanUrls $True -IsDefault $True
		New-SafeLinksRule -Name Default -RecipientDomainIs $Domains.Name -SafeLinksPolicy Default -Enabled $True
		Write-Host -ForegroundColor Green "Created new Safe Links policy."	
	}
}

function StoreCredential()
{
	$AppName = "Office365SecureScore"
	$AppName = $AppName.Replace(" ", "")
	
	If (!(Test-Path "HKCU:\Software\$AppName\Credentials"))
	{
		Try
		{
			Write-Host -ForegroundColor Red "Credentials Path Not Found."
			New-Item -Path "HKCU:\Software\$AppName" -Name "Credentials" -Force
		}
		Catch
		{
			[System.Exception]
			Write-Host -Foreground Red "Unable to create path."
		}
		Finally
		{
		}
	}
	
	If (!($Credential))
	{
		$secureCredential = Get-Credential -Message "Enter Office 365 Global Admin Credential in username@domain.com format."
	}
	Else
	{
		$secureCredential = $Credential
	}
	
	$CredentialName = "Office365SecureScoreLogin"
	$securePasswordString = $secureCredential.Password | ConvertFrom-SecureString
	$userNameString = $secureCredential.Username
	
	New-Item -Path HKCU:\Software\$AppName\Credentials\$credentialName
	New-ItemProperty -Path HKCU:\Software\$AppName\Credentials\$credentialName -PropertyType String -Name UserName -Value $userNameString
	New-ItemProperty -Path HKCU:\Software\$AppName\Credentials\$credentialName -PropertyType String -Name Password -Value $securePasswordString
}

function LoadCredential()
{
	$Username = (Get-ItemProperty -Path HKCU:\Software\Office365SecureScore\Credentials\Office365Admin).UserName
	$Password = (Get-ItemProperty -Path HKCU:\Software\Office365SecureScore\Credentials\Office365Admin).Password
	$SecurePassword = ConvertTo-SecureString $Password
	$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $Username, $SecurePassword
	
	# Add to functions to retrieve username/password 
	<#
	Add-Content -Path $FilePath -Value
	Add-Content -Path $FilePath -Value "`$Username = (Get-ItemProperty -Path HKCU:\Software\Office365SecureScore\Credentials\Office365Admin).UserName"
	Add-Content -Path $FilePath -Value "`$Password = (Get-ItemProperty -Path HKCU:\Software\Office365SecureScore\Credentials\Office365Admin).Password"
	Add-Content -Path $FilePath -Value "`$SecurePassword = ConvertTo-SecureString `$Password"
	Add-Content -Path $FilePath -Value "`$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList `$Username, `$SecurePassword"
	#>
}

Function o365Logon([switch]$Skype, [switch]$Compliance, $Credential)
{
	$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $Credential -Authentication Basic -AllowRedirection
	Import-PSSession $Session
	
	Connect-MsolService -Credential $Credential
	If ($Skype)
	{
		$SkypeSession = New-CSOnlineSession -Credential $Credential
		Import-PSSession $SkypeSession
	}
	If ($Compliance)
	{
		$ComplianceSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://ps.compliance.protection.outlook.com/powershell-liveid -Credential $Credential -Authentication Basic -AllowRedirection
		Import-PSSession $ComplianceSession -AllowClobber
	}
}

# Connect to Office 365
o365Logon -Credential $Credential

# Global Variables
$TenantDetail = Get-MsolAccountSku
$TenantDomain = $TenantDetail[0].AccountName+".onmicrosoft.com"
$TenantID = $TenantDetail.AccountObjectID
$Date = Get-Date -Format yyyyMMdd

# Execute Functions
If ($AllowAnonymousGuestSharingLinksForSitesAndDocs) { AllowAnonymousGuestSharingLinksForSitesAndDocs }
If ($ConfigureExpirationTimeForExternalSharingLinks)
{
	If ($ConfigureExpirationTimeForExternalSharingLinks -and $ExpirationTimeForExternalSharingLinksInDays)
	{
	ConfigureExpirationTimeForExternalSharingLinks -ExpirationInDays $ExpirationTimeForExternalSharingLinksInDays
	}
	Else { ConfigureExpirationTimeForExternalSharingLinks }
}
If ($DoNotAllowAnonymousCalendarSharing) { DoNotAllowAnonymousCalendarSharing }
If ($DoNotAllowCalendarDetailsSharing) { DoNotAllowCalendarDetailsSharing }
If ($DoNotUseTransportRuleToExternalDomains) { DoNotUseTransportRuleToExternalDomains }
If ($DoNotUseTransportWhiteLists) { DoNotUseTransportWhiteLists }
If ($EnableAdvancedThreatProtectionSafeAttachmentsPolicy) { EnableAdvancedThreatProtectionSafeAttachmentsPolicy }
If ($EnableAdvancedThreatProtectionSafeLinksPolicy) { EnableAdvancedThreatProtectionSafeLinksPolicy }
If ($EnableAuditDataRecording) { EnableAuditDataRecording }
If ($EnableClientRulesForwardingBlock) { EnableClientRulesForwardingBlock }
If ($EnableIRM -and $IRMLocation) { EnableIRM -IRMLocation $IRMLocation }
If ($EnableMailboxAuditing) { EnableMailboxAuditing }
If ($EnableMFAForAllGlobalAdmins) { EnableMFAForAllGlobalAdmins }
If ($EnableMFAForAllUsers) { EnableMFAForAllUsers }
If ($ReviewMailboxForwardingRulesWeekly) { ReviewMailboxForwardingRulesWeekly }
If ($ReviewRoleChangesWeekly) { ReviewRoleChangesWeekly }
If ($ReviewSignInsAfterMultipleFailuresReport) { ReviewSignInsAfterMultipleFailuresReport }
If ($ReviewSignInsFromMultipleGeographiesReportWeekly) { ReviewSignInsFromMultipleGeographiesReportWeekly }
If ($ReviewSignInsFromUnknownSourcesReportWeekly) { ReviewSignInsFromUnknownSourcesReportWeekly }
If ($SetOutboundSpamNotifications)
{
	If ($OutboundSpamNotificationUsers) { SetOutboundSpamNotifications -NotifyOutboundSpamRecipients $OutboundSpamNotificationUsers }
	Else { SetOutboundSpamNotifications }
}
If ($MobileDevicePolicy)
{
	If ($MobileDevicePolicy) { ActiveSync -Default }
	Else { ActiveSync }
}

If ($All)
{
	DoNotAllowAnonymousCalendarSharing
	DoNotAllowCalendarDetailsSharing
	DoNotUseTransportRuleToExternalDomains
	DoNotUseTransportWhiteLists
	EnableAdvancedThreatProtectionSafeAttachmentsPolicy
	EnableAdvancedThreatProtectionSafeLinksPolicy
	EnableAuditDataRecording
	EnableClientRulesForwardingBlock
	EnableIRM -IRMLocation $IRMLocation
	EnableMailboxAuditing
	EnableMFAForAllGlobalAdmins
	EnableMFAForAllUsers
	ReviewMailboxForwardingRulesWeekly
	ReviewRoleChangesWeekly
	ReviewSignInsAfterMultipleFailuresReport
	ReviewSignInsFromMultipleGeographiesReportWeekly
	ReviewSignInsFromUnknownSourcesReportWeekly
	If ($OutboundSpamNotificationUsers) { SetOutboundSpamNotifications -NotifyOutboundSpamRecipients $OutboundSpamNotificationUsers }
	Else { SetOutboundSpamNotifications }
	If ($SetAsDefaultActiveSyncPolicy) { ActiveSync -Default } Else { ActiveSync }
}
Get-PSSession | Remove-PSSession