$Clientdomains = get-msoldomain | Select-Object Name
$Msdomain = $Clientdomains.name | Select-String -Pattern 'onmicrosoft.com' | Select-String -Pattern 'mail' -NotMatch
$Msdomain = $Msdomain -replace ".onmicrosoft.com",""