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

#helpful debug commands:
#Write-Output $Clientdlp

#Enable Outbound Spam Filtering Rules
#Automation Variables
$OutboundSpamFilteringRules_Enabled = Get-AutomationVariable -Name "OutboundSpamFilteringRules_Enabled"

#debug
#$OutboundSpamFilteringRules_Enabled = "Yes"

if($OutboundSpamFilteringRules_Enabled -Like "Yes") {
    Get-HostedOutboundSpamFilterPolicy | Set-HostedOutboundSpamFilterPolicy -NotifyOutboundSpam $true -NotifyOutboundSpamRecipients $NotifyOutboundSpamRecipients
}

# Enable Client Forwarding Block Transport Mail Flow Rule:
#Automation Variables
$ClientForwardBlockRules_Enabled = Get-AutomationVariable -Name "ClientForwardBlockRules_Enabled" 

#debug
#$ClientForwardBlockRules_Enabled = "Yes"

if($ClientForwardBlockRules_Enabled -Like "Yes") {
    
    if ($Clientrules.Name -Like "Client Rules Forwarding Block") {
        Write-Output '***Client Rules Forwarding Block Already Exists'
    }
    else {
        New-TransportRule "Client Rules Forwarding Block" `
            -FromScope "InOrganization" `
            -MessageTypeMatches "AutoForward" `
            -SentToScope "NotInOrganization" `
            -RejectMessageReasonText "External Email Forwarding via Client Rules is not permitted"
        Write-Output '***Client Rules Forwarding Block has now been created'
    }
}

#Automation Variables
#DLPRules_Enabled = Get-AutomationVariable -Name "DLPRules_Enabled"
#DLPRules_Selection = Get-AutomationVariable -Name "DLPRules_Selection"
#DLPRules_DeploymentMode = Get-AutomationVariable -Name "DLPRules_DeploymentMode"

#debug
#$DLPRules_Enabled = "Yes"
#$DLPRules_Selection = "US" #Available options are US,Australia, Canada, France, Germany, Isreal
#$DLPRules_DeploymentMode= "AuditAndNotify"

if($DLPRules_Enabled -Like "Yes") {

    switch($DLPRules_Selection) {

        "US"{
            if ($Clientdlp.Name -Like "U.S. Personally Identifiable Information (PII) Data") {
                Write-Output '***DLP for U.S. State Breach Notification Laws Already Exists -- DLP Rule Not Installed'
            } else {
                New-DlpPolicy -Name "U.S. Personally Identifiable Information (PII) Data" -Mode $DLPRules_DeploymentMode -Template 'U.S. Personally Identifiable Information (PII) Data';
                Write-Output '***DLP for U.S. State Breach Notification Laws Installed'               
            }
           
            if ($Clientdlp.Name -Like "U.S. Personally Identifiable Information (PII) Data") {
                Write-Output '***DLP for U.S. State Breach Notification Laws Already Exists -- DLP Rule Not Installed'
            } else {
                New-DlpPolicy -Name "U.S. Personally Identifiable Information (PII) Data" -Mode $DLPRules_DeploymentMode -Template 'U.S. Personally Identifiable Information (PII) Data';
                Write-Output '***DLP for U.S. State Breach Notification Laws Installed'
            }
        }
        "Australia"{
            if ($Clientdlp.Name -Like "Australia Financial Data") {
                Write-Output '***DLP for Australia Financial Data Already Exists -- DLP Rule Not Installed'
            } else {
                New-DlpPolicy -Name "Australia Financial Data" -Mode $DLPRules_DeploymentMode -Template 'Australia Financial Data';
                Write-Output '***DLP for Australia Financial Data Installed'               
            }
           
            if ($Clientdlp.Name -Like "Australia Health Records Act (HRIP Act)") {
                Write-Output '***DLP for Australia Health Records Act (HRIP Act) Already Exists -- DLP Rule Not Installed'
            } else {
                New-DlpPolicy -Name "Australia Health Records Act (HRIP Act)" -Mode $DLPRules_DeploymentMode -Template 'Australia Health Records Act (HRIP Act)';
                Write-Output '***DLP for Australia Health Records Act (HRIP Act) Installed'
            }

            if ($Clientdlp.Name -Like "Australia Personally Identifiable Information (PII) Data") {
                Write-Output '***DLP for Australia Personally Identifiable Information (PII) Data Already Exists -- DLP Rule Not Installed'
            } else {
                New-DlpPolicy -Name "Australia Personally Identifiable Information (PII) Data" -Mode $DLPRules_DeploymentMode -Template 'Australia Personally Identifiable Information (PII) Data';
                Write-Output '***DLP for Australia Personally Identifiable Information (PII) Data Installed'
            }
        }
        "Canada"{
            if ($Clientdlp.Name -Like "Canada Financial Data") {
                Write-Output '***DLP for Canada Financial Data Already Exists -- DLP Rule Not Installed'
            } else {
                New-DlpPolicy -Name "Canada Financial Data" -Mode $DLPRules_DeploymentMode -Template 'Canada Financial Data';
                Write-Output '***DLP for Canada Financial Data Installed'               
            }
           
            if ($Clientdlp.Name -Like "Canada Health Information Act (HIA)") {
                Write-Output '***DLP for Canada Health Information Act (HIA) Already Exists -- DLP Rule Not Installed'
            } else {
                New-DlpPolicy -Name "Canada Health Information Act (HIA)" -Mode $DLPRules_DeploymentMode -Template 'Canada Health Information Act (HIA)';
                Write-Output '***DLP for Canada Health Information Act (HIA) Installed'
            }

            if ($Clientdlp.Name -Like "Canada Personal Health Act (PHIPA) – Ontario") {
                Write-Output '***DLP for Canada Personal Health Act (PHIPA) – Ontario Data Already Exists -- DLP Rule Not Installed'
            } else {
                New-DlpPolicy -Name "Canada Personal Health Act (PHIPA) – Ontario" -Mode $DLPRules_DeploymentMode -Template 'Canada Personal Health Act (PHIPA) – Ontario';
                Write-Output '***DLP for Canada Personal Health Act (PHIPA) – Ontario Installed'
            }
            
            if ($Clientdlp.Name -Like "Canada Personal Health Information Act (PHIA) - Manitoba") {
                Write-Output '***DLP for Canada Personal Health Information Act (PHIA) - Manitoba Already Exists -- DLP Rule Not Installed'
            } else {
                New-DlpPolicy -Name "Canada Personal Health Information Act (PHIA) - Manitoba" -Mode $DLPRules_DeploymentMode -Template 'Canada Personal Health Information Act (PHIA) - Manitoba';
                Write-Output '***DLP for Canada Personal Health Information Act (PHIA) - Manitoba Installed'               
            }
           
            if ($Clientdlp.Name -Like "Canada Personal Information Protection Act (PIPA)") {
                Write-Output '***DLP for Canada Personal Information Protection Act (PIPA) Already Exists -- DLP Rule Not Installed'
            } else {
                New-DlpPolicy -Name "Canada Personal Information Protection Act (PIPA)" -Mode $DLPRules_DeploymentMode -Template 'Canada Personal Information Protection Act (PIPA)';
                Write-Output '***DLP for Canada Personal Information Protection Act (PIPA) Installed'
            }

            if ($Clientdlp.Name -Like "Canada Personally Identifiable Protection Act (PIPEDA)") {
                Write-Output '***DLP for Canada Personally Identifiable Protection Act (PIPEDA) Already Exists -- DLP Rule Not Installed'
            } else {
                New-DlpPolicy -Name "Canada Personally Identifiable Protection Act (PIPEDA)" -Mode $DLPRules_DeploymentMode -Template 'Canada Personally Identifiable Protection Act (PIPEDA)';
                Write-Output '***DLP for Canada Personally Identifiable Protection Act (PIPEDA) Installed'
            }

            if ($Clientdlp.Name -Like "Canada Personally Identifiable Information (PII) Data") {
                Write-Output '***DLP for Canada Personally Identifiable Information (PII) Data Already Exists -- DLP Rule Not Installed'
            } else {
                New-DlpPolicy -Name "Canada Personally Identifiable Information (PII) Data" -Mode $DLPRules_DeploymentMode -Template 'Canada Personally Identifiable Information (PII) Data';
                Write-Output '***DLP for Canada Personally Identifiable Information (PII) Data Installed'
            }
        }
        "France"{
            if ($Clientdlp.Name -Like "France Data Protection Act") {
                Write-Output '***DLP for France Data Protection Act Already Exists -- DLP Rule Not Installed'
            } else {
                New-DlpPolicy -Name "France Data Protection Act" -Mode $DLPRules_DeploymentMode -Template 'France Data Protection Act';
                Write-Output '***DLP for France Data Protection Act Installed'               
            }
           
            if ($Clientdlp.Name -Like "France Financial Data") {
                Write-Output '***DLP for France Financial Data Already Exists -- DLP Rule Not Installed'
            } else {
                New-DlpPolicy -Name "France Financial Data" -Mode $DLPRules_DeploymentMode -Template 'France Financial Data';
                Write-Output '***DLP for France Financial Data Installed'
            }

            if ($Clientdlp.Name -Like "France Personally Identifiable Information (PII) Data") {
                Write-Output '***DLP for France Personally Identifiable Information (PII) Data Already Exists -- DLP Rule Not Installed'
            } else {
                New-DlpPolicy -Name "France Personally Identifiable Information (PII) Data" -Mode $DLPRules_DeploymentMode -Template 'France Personally Identifiable Information (PII) Data';
                Write-Output '***DLP for France Personally Identifiable Information (PII) Data Installed'
            }
        }
        "Germany"{
            if ($Clientdlp.Name -Like "Germany Financial Data") {
                Write-Output '***DLP for Germany Financial Data Already Exists -- DLP Rule Not Installed'
            } else {
                New-DlpPolicy -Name "Germany Financial Data" -Mode $DLPRules_DeploymentMode -Template 'Germany Financial Data';
                Write-Output '***DLP for Germany Financial Data Installed'               
            }

            if ($Clientdlp.Name -Like "Germany Personally Identifiable Information (PII) Data") {
                Write-Output '***DLP for Germany Personally Identifiable Information (PII) Data Already Exists -- DLP Rule Not Installed'
            } else {
                New-DlpPolicy -Name "Germany Personally Identifiable Information (PII) Data" -Mode $DLPRules_DeploymentMode -Template 'Germany Personally Identifiable Information (PII) Data';
                Write-Output '***DLP for Germany Personally Identifiable Information (PII) Data Installed'
            }
        }
        "Isreal"{
            if ($Clientdlp.Name -Like "Israel Financial Data") {
                Write-Output '***DLP for Israel Financial Data Already Exists -- DLP Rule Not Installed'
            } else {
                New-DlpPolicy -Name "Israel Financial Data" -Mode $DLPRules_DeploymentMode -Template 'Israel Financial Data';
                Write-Output '***DLP for Israel Financial Data Installed'               
            }
           
            if ($Clientdlp.Name -Like "Israel Personally Identifiable Information (PII) Data") {
                Write-Output '***DLP for Israel Personally Identifiable Information (PII) Data Already Exists -- DLP Rule Not Installed'
            } else {
                New-DlpPolicy -Name "Israel Personally Identifiable Information (PII) Data" -Mode $DLPRules_DeploymentMode -Template 'Israel Personally Identifiable Information (PII) Data';
                Write-Output '***DLP for Israel Personally Identifiable Information (PII) Data Installed'
            }

            if ($Clientdlp.Name -Like "Israel Protection of Privacy") {
                Write-Output '***DLP for Israel Protection of Privacy Already Exists -- DLP Rule Not Installed'
            } else {
                New-DlpPolicy -Name "Israel Protection of Privacy" -Mode $DLPRules_DeploymentMode -Template 'Israel Protection of Privacy';
                Write-Output '***DLP for Israel Protection of Privacy Installed'
            }
        }
        default{
            Write-Output '**No DLP Policies Deployed'
        }
    }
}

#Automation Variables
$SafeAttachmentRules_Enabled = Get-AutomationVariable -Name "SafeAttachmentRules_Enabled"
$SafeLinkRules_Enabled = Get-AutomationVariable -Name "SafeLinkRules_Enabled"

#debug
#$SafeAttachmentRules_Enabled = "Yes"
#$SafeLinkRules_Enabled = "Yes"

if($SafeAttachmentRules_Enabled -Like "Yes" -Or $SafeLinkRules_Enabled -Like "Yes") {

    # Create a Redirected Mailbox for mail that gets flagged by the Safe Attachment policy to be delivered to.
    if ($AtpMailbox.Name -Like "ATPRedirectedMessages") {
        Write-Output '***Configuration for ATP Mailbox and Default ATP Policies Already Exist'
    }
    else {
        New-Mailbox -PrimarySmtpAddress "ATPRedirectedMessages@$($Domains[0].Name)" -Name ATPRedirectedMessages -DisplayName ATPRedirectedMessages -Password (ConvertTo-SecureString -AsPlainText -Force (([char[]]([char]33 .. [char]95) + ([char[]]([char]97 .. [char]126)) + 0 .. 9 | sort { Get-Random })[0 .. 8] -join '')) -MicrosoftOnlineServicesID "ATPRedirectedMessages@$($Domains[0].Name)"
        Set-Mailbox -Identity "ATPRedirectedMessages@$($Domains[0].Name)" -HiddenFromAddressListsEnabled $True
        Add-MailboxPermission -Identity "ATPRedirectedMessages@$($Domains[0].Name)" -AutoMapping $false -InheritanceType All -User $cred.UserName -AccessRights FullAccess

        # Create a new Safe Attachment policy.
        if($SafeAttachmentRules_Enabled -Like "Yes") {
            New-SafeAttachmentPolicy -Name 'Default Safe Attachment Policy' -AdminDisplayName 'Default Safe Attachment Policy' -Action Replace -Redirect $True -RedirectAddress "ATPRedirectedMessages@$($Domains[0].Name)" -Enable $True
            New-SafeAttachmentRule -Name 'Default Safe Attachment Rule' -RecipientDomainIs $Domains.Name -SafeAttachmentPolicy 'Default Safe Attachment Policy' -Enabled $True
        }

        # Create a new Safe Links policy.
        if($SafeLinkRules_Enabled -Like "Yes") {
            New-SafeLinksPolicy -Name Default -AdminDisplayName Default -TrackClicks $true -IsEnabled $true -AllowClickThrough $false -ScanUrls $true
            New-SafeLinksRule -Name Default -RecipientDomainIs $Domains.Name -SafeLinksPolicy Default -Enabled $true
        }
    }
}

# Disallow anonymous Calendar Sharing: Free/Busy And Disallow anonymous Calendar Detail Sharing
#Automation Variables
$AnonymousCalendarSharingRules_Enabled = Get-AutomationVariable -Name "AnonymousCalendarSharingRules_Enabled"

#debug
#$AnonymousCalendarSharingRules_Enabled = "Yes"

if($AnonymousCalendarSharingRules_Enabled -Like "Yes") {
    Get-SharingPolicy | Set-SharingPolicy -Domains @{ Remove = "Anonymous:CalendarSharingFreeBusyReviewer"; Add = "Anonymous:0" }
    Get-SharingPolicy | Set-SharingPolicy -Enabled $False
}


# Set mailbox auditing on all mailboxes
#Automation Variables
$MailboxAuditingRules_Enabled = Get-AutomationVariable -Name "MailboxAuditingRules_Enabled"

#debug
#$MailboxAuditingRules_Enabled = "Yes"

if($MailboxAuditingRules_Enabled -Like "Yes") {
    Get-Mailbox -ResultSize Unlimited -Filter {RecipientTypeDetails -eq "UserMailbox" -or RecipientTypeDetails -eq "SharedMailbox" -or RecipientTypeDetails -eq "RoomMailbox" -or RecipientTypeDetails -eq "DiscoveryMailbox"} | Set-Mailbox -AuditEnabled $true -AuditLogAgeLimit 730 -AuditAdmin Update, MoveToDeletedItems, SoftDelete, HardDelete, SendAs, SendOnBehalf, Create, UpdateFolderPermission -AuditDelegate Update, SoftDelete, HardDelete, SendAs, Create, UpdateFolderPermissions, MoveToDeletedItems, SendOnBehalf -AuditOwner UpdateFolderPermission, MailboxLogin, Create, SoftDelete, HardDelete, Update, MoveToDeletedItems 
    Write-Output -ForegroundColor Green "Set mailbox auditing on all mailboxes."
    # Enable audit data recording
    Enable-OrganizationCustomization -ea silentlycontinue -wa silentlycontinue
    Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true -ea silentlycontinue -wa silentlycontinue
    Write-Output -ForegroundColor Green "Enabled Audit Data Recording."
}

# Close the PS Session
Remove-PSSession $Session
