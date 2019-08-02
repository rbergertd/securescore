$ResourceGroup = 'RB-SecureScoreAA'
$AutomationAccountName = 'SecureScore'
$Location = 'EastUS2'
$User = 'SecureScore@tdsolutionfactory.onmicrosoft.com'
$StringPassWord ='C@Pc0m10'
$Password = ConvertTo-SecureString $StringPassWord -AsPlainText -Force
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $User, $Password

# Manually connect to Azure - we need to automate both of these with a Vertex deployment
Connect-AzureRmAccount
Connect-MsolService

# Import modules
Import-Module MSOnline
Import-Module AzureRm

# Create the O365 admin user
New-MsolUser -UserPrincipalName $User -DisplayName “Secure Score Admin” -FirstName “Secure” -LastName “Score” -Password $Password -PasswordNeverExpires $true -ForceChangePassword $false
Start-Sleep 15
Add-MsolRoleMember -RoleName “Company Administrator” –RoleMemberEmailAddress $User

# Create the Automation account, create the credential (using the O365 admin user), install the modules, and then import the runbooks.

New-AzureRmResourceGroup -Name $ResourceGroup -Location $Location
Start-Sleep 10
New-AzureRmAutomationAccount -Name $AutomationAccountName -Location $Location -ResourceGroupName $ResourceGroup -Plan Free
Start-Sleep 30
New-AzureRmAutomationCredential -AutomationAccountName $AutomationAccountName -Name "MSOnline" -Value $Credential -ResourceGroupName $ResourceGroup
Start-Sleep 10
New-AzureRmAutomationModule -Name MSOnline -ContentLinkUri "https://github.com/rbergertd/securescore/raw/master/Modules/MSOnline.zip" -ResourceGroupName $ResourceGroup -AutomationAccountName $AutomationAccountName
Start-Sleep 15
New-AzureRmAutomationModule -Name AzureAD -ContentLinkUri "https://github.com/rbergertd/securescore/raw/master/Modules/AzureAD.zip" -ResourceGroupName $ResourceGroup -AutomationAccountName $AutomationAccountName
Start-Sleep 15
Import-AzureRmAutomationRunbook -ResourceGroup $ResourceGroup –AutomationAccountName $automationAccountName –Name TestRunBookPSImport -Type PowerShell –Path "C:\Scripts\test-msol-creds.ps1"


