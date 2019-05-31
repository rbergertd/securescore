$Sites = Get-SPOSite | Select-Object Url
foreach ($Site in $Sites) {
    try{
        Write-Host "Sharepoint Site:" $Site.Url
        $Context = New-Object Microsoft.SharePoint.Client.ClientContext($Site.Url)
        $Creds = New-Object Microsoft.SharePoint.Client.SharePointOnlineCredentials($Usercredential)
        $Context.Credentials = $Creds
        $Web = $Context.Web
        $Context.Load($Web)
        $Context.load($Web.lists)
        $Context.executeQuery()
        foreach($List in $Web.lists) {
            if (($List.hidden -eq $false) -and ($List.Title -notmatch "Style Library")) {
                $List.EnableVersioning = $true
                $LiST.MajorVersionLimit = 50
                $List.Update()
                $Context.ExecuteQuery() 
                Write-host "Versioning has been turned ON for :" $List.title -foregroundcolor Green
            }
        }
    } catch {
        Write-Host "Error: $($_.Exception.Message)" -foregroundcolor Red
    }
}