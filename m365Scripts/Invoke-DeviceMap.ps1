$h = @{ Authorization = "Bearer $($tokens.access_token)" }
$all = @()
$uri = "https://graph.microsoft.com/v1.0/devices?`$expand=registeredOwners&`$top=999"
do {
    $r = Invoke-RestMethod -Headers $h -Uri $uri
    $all += $r.value
    $uri = $r.'@odata.nextLink'
} while ($uri)

$map = foreach ($d in $all) {
    $owners = if ($d.registeredOwners) {
        ($d.registeredOwners | ForEach-Object { "$($_.displayName) <$($_.userPrincipalName)>" }) -join "; "
    } else { "<none>" }
    [pscustomobject]@{
        DeviceName   = $d.displayName
        DeviceId     = $d.deviceId
        OS           = $d.operatingSystem
        OSVersion    = $d.operatingSystemVersion
        TrustType    = $d.trustType
        IsCompliant  = $d.isCompliant
        IsManaged    = $d.isManaged
        LastSignIn   = $d.approximateLastSignInDateTime
        Owners       = $owners
    }
}

$map | Export-Csv .\device_owner_map.csv -NoTypeInformation
"Total devices: $($all.Count)"
"Devices with at least one owner: $((@($map | Where-Object { $_.Owners -ne '<none>' })).Count)"