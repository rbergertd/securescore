#Author: Ryan Berger
#Version: 1.6
#Comment: Updated to use AzureAD for User Creation rather than MSOL to get around MFA requirements.
#Vertex UI Parameters to collect through UI to pass into PowerShell script


# Import modules
#Import-Module MSOnline
Import-Module AzureAd
Import-Module AzureRm

#Resource Group name
$ResourceGroup = 'RB-SecureScoreTest'

#Automation Account name
$AutomationAccountName = 'SecureScore-Test'

#Location to deploy the Azure Automation Account 
$Location = 'EastUS2'

#Schedule Name - this should be HIDDEN
$ScheduleName = 'SecureScore Daily Run'

#Schedule Start time (in UTC) - this should be HIDDEN
$StartTime = Get-Date "23:59:00"

#End Time - this should be HIDDEN from the customer
$EndTime = $StartTime.AddYears(5)

#Tenant Name - they will need to input their tenant name (the one they created during checkout)
$Domain = 'tdsolutionfactory'

#User name - this should be HIDDEN from the customer. We always want this to be SecureScore@($Domain).onmicrosoft.com
$User = "SecureScorePatrick@$($Domain).onmicrosoft.com"

#Collect secure string password thru Vertex UI then pass it into the script and convert to SecurePassword. May need to chat with Pat on this. This does not work with the New-MsolUser command - I think it sets the password to System.Security.SecureString
$Password = 'P@$$word123!'
#$Password = ConvertTo-SecureString "P@$$word123!" -AsPlainText -Force
$SecurePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
#$ConvertPassword = [System.Net.NetworkCredential]::new("", $SecurePassword).Password

#We do not need to collect this via Vertex UI, just build it based off of $User and $Password.
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $User, $SecurePassword


# Password Profile for Azure AD User
$PasswordProfile = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile
$PasswordProfile.Password = $Password
$PasswordProfile.EnforceChangePasswordPolicy = $False
$PasswordProfile.ForceChangePasswordNextLogin = $False

# AzureAD Role Assignment
$userName = $User
$roleName="Company Administrator"
$role = Get-AzureADDirectoryRole | Where {$_.displayName -eq $roleName}
if ($role -eq $null) {
$roleTemplate = Get-AzureADDirectoryRoleTemplate | Where {$_.displayName -eq $roleName}
Enable-AzureADDirectoryRole -RoleTemplateId $roleTemplate.ObjectId
$role = Get-AzureADDirectoryRole | Where {$_.displayName -eq $roleName}
}

#Connect to Azure tenant and connect to O365 Tenant - this needs to be automated on the Vertex side - connect with our Admin account?
#For manual testing.
#$manualCredential = Get-Credential
# Manually connect to Azure - we need to automate both of these with a Vertex deployment
#Connect-AzureRmAccount -Credential $manualCredential
#Connect-MsolService

# Create the O365 admin user - Deprecated
#New-MsolUser -UserPrincipalName $User -DisplayName “Secure Score Automation” -FirstName “Secure” -LastName “Score” -Password $Password -PasswordNeverExpires $true -ForceChangePassword $false
#Start-Sleep 15
#Add-MsolRoleMember -RoleName “Company Administrator” –RoleMemberEmailAddress $User

# Create the O365 admin user (using AzureAd)
New-AzureADUser -AccountEnabled $True -DisplayName "Secure Score" -PasswordProfile $PasswordProfile -MailNickName "SecureScore" -UserPrincipalName $User -PasswordPolicies "DisablePasswordExpiration"
Add-AzureADDirectoryRoleMember -ObjectId $role.ObjectId -RefObjectId (Get-AzureADUser | Where {$_.UserPrincipalName -eq $userName}).ObjectID

# Create the Automation account, create the credential (using the O365 admin user), install the modules, and then import the runbooks.

New-AzureRmResourceGroup -Name $ResourceGroup -Location $Location
Start-Sleep 20
New-AzureRmAutomationAccount -Name $AutomationAccountName -Location $Location -ResourceGroupName $ResourceGroup -Plan Free
Start-Sleep 30
New-AzureRmAutomationSchedule -AutomationAccountName $AutomationAccountName -Name $ScheduleName -StartTime $StartTime -ExpiryTime $EndTime -DayInterval 1 -ResourceGroupName $ResourceGroup
New-AzureRmAutomationCredential -AutomationAccountName $AutomationAccountName -Name "MSOnline" -Value $Credential -ResourceGroupName $ResourceGroup
Start-Sleep 15
New-AzureRmAutomationModule -Name MSOnline -ContentLinkUri "https://github.com/rbergertd/securescore/raw/master/Modules/MSOnline.zip" -ResourceGroupName $ResourceGroup -AutomationAccountName $AutomationAccountName
Start-Sleep 15
New-AzureRmAutomationModule -Name AzureAD -ContentLinkUri "https://github.com/rbergertd/securescore/raw/master/Modules/AzureAD.zip" -ResourceGroupName $ResourceGroup -AutomationAccountName $AutomationAccountName
Start-Sleep 15
New-AzureRmAutomationModule -Name Microsoft.Online.SharePoint.PowerShell -ContentLinkUri "https://github.com/rbergertd/securescore/raw/master/Modules/Microsoft.Online.SharePoint.PowerShell.zip" -ResourceGroupName $ResourceGroup -AutomationAccountName $AutomationAccountName


# Importing RunBooks 
# We'll run an import, publish the imported runbook, and then register the runbook to the schedule we created so that it runs daily at 24:00.
Import-AzureRmAutomationRunbook -ResourceGroup $ResourceGroup –AutomationAccountName $AutomationAccountName –Name ExO-SecureScore-Config -Type PowerShell –Path "C:\Scripts\ExO-SecureScoreConfig.ps1"
Publish-AzureRmAutomationRunbook -AutomationAccountName $AutomationAccountName -Name ExO-SecureScore-Config -ResourceGroupName $ResourceGroup
Register-AzureRmAutomationScheduledRunbook -AutomationAccountName $AutomationAccountName -Name ExO-SecureScore-Config -ScheduleName $ScheduleName -ResourceGroupName $ResourceGroup

Import-AzureRmAutomationRunbook -ResourceGroup $ResourceGroup –AutomationAccountName $AutomationAccountName –Name Enable-Password-Expiration -Type PowerShell –Path "C:\Scripts\Enable-Password-Expiration.ps1"
Publish-AzureRmAutomationRunbook -AutomationAccountName $AutomationAccountName -Name Enable-Password-Expiration -ResourceGroupName $ResourceGroup
Register-AzureRmAutomationScheduledRunbook -AutomationAccountName $AutomationAccountName -Name Enable-Password-Expiration -ScheduleName $ScheduleName -ResourceGroupName $ResourceGroup

Import-AzureRmAutomationRunbook -ResourceGroup $ResourceGroup –AutomationAccountName $AutomationAccountName –Name Enable-GlobalAdmin-Mfa -Type PowerShell –Path "C:\Scripts\Enable-GlobalAdminMFA.ps1"
Publish-AzureRmAutomationRunbook -AutomationAccountName $AutomationAccountName -Name Enable-GlobalAdmin-Mfa -ResourceGroupName $ResourceGroup
Register-AzureRmAutomationScheduledRunbook -AutomationAccountName $AutomationAccountName -Name Enable-GlobalAdmin-Mfa -ScheduleName $ScheduleName -ResourceGroupName $ResourceGroup

