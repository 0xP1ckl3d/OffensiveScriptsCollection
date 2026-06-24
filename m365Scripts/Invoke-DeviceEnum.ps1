$h = @{ Authorization = "Bearer $($tokens.access_token)" }
$devices = @()
$uri = "https://graph.microsoft.com/v1.0/devices?`$top=999"
do {
    $r = Invoke-RestMethod -Headers $h -Uri $uri
    $devices += $r.value
    $uri = $r.'@odata.nextLink'
} while ($uri)
$devices | Select-Object displayName, deviceId, operatingSystem, operatingSystemVersion, trustType, isCompliant, isManaged, accountEnabled, approximateLastSignInDateTime | Format-Table -Auto
$devices | Export-Csv .\devices.csv -NoTypeInformation
"Total: $($devices.Count)"