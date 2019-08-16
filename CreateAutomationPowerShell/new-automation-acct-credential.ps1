﻿$ResourceGroup = 'RB-SecureScoreAA'
$AutomationAccountName = 'SecureScore'
$Location = 'EastUS2'
$StartTime = Get-Date "23:59:00"
$EndTime = $StartTime.AddYears(5)
#How can we pass the tenant domain through into this (through Vertex)?
$User = 'SecureScore@domain.onmicrosoft.com'
$ScheduleName = 'SecureScore Daily Run'
#Collect secure string password thru Vertex UI then pass it into the script and convert to SecurePassword. May need to chat with Pat on this. This does not work with the New-MsolUser command - I think it sets the password to System.Security.SecureString
$Password = 'C@Pc0m10'
$SecurePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $User, $Password
#For manual testing.
$manualCredential = Get-Credential



# Manually connect to Azure - we need to automate both of these with a Vertex deployment
Connect-AzureRmAccount -Credential $manualCredential
Connect-MsolService

# Import modules
Import-Module MSOnline
Import-Module AzureRm

# Create the O365 admin user
New-MsolUser -UserPrincipalName $User -DisplayName “Secure Score Automation” -FirstName “Secure” -LastName “Score” -Password $Password -PasswordNeverExpires $true -ForceChangePassword $false
Start-Sleep 15
Add-MsolRoleMember -RoleName “Company Administrator” –RoleMemberEmailAddress $User

# Create the Automation account, create the credential (using the O365 admin user), install the modules, and then import the runbooks.

New-AzureRmResourceGroup -Name $ResourceGroup -Location $Location
Start-Sleep 10
New-AzureRmAutomationAccount -Name $AutomationAccountName -Location $Location -ResourceGroupName $ResourceGroup -Plan Free
Start-Sleep 30
New-AzureRmAutomationSchedule -AutomationAccountName $AutomationAccountName -Name $ScheduleName -StartTime $StartTime -ExpiryTime $EndTime -DayInterval 1 -ResourceGroupName $ResourceGroup
New-AzureRmAutomationCredential -AutomationAccountName $AutomationAccountName -Name "MSOnline" -Value $Credential -ResourceGroupName $ResourceGroup
Start-Sleep 10
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

