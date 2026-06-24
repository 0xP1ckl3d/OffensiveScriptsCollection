$h = @{ Authorization = "Bearer $($tokens.access_token)" }

function Write-Header($t) { Write-Host "`n==== $t ====" -ForegroundColor Cyan }
function Write-KV($k,$v,$vc='White') {
    Write-Host ("{0,-12}: " -f $k) -ForegroundColor Yellow -NoNewline
    Write-Host $v -ForegroundColor $vc
}

$me    = Invoke-RestMethod -Headers $h -Uri "https://graph.microsoft.com/v1.0/me"
$mem   = (Invoke-RestMethod -Headers $h -Uri "https://graph.microsoft.com/v1.0/me/memberOf").value
$owned = (Invoke-RestMethod -Headers $h -Uri "https://graph.microsoft.com/v1.0/me/ownedObjects").value
$devs  = (Invoke-RestMethod -Headers $h -Uri "https://graph.microsoft.com/v1.0/me/ownedDevices").value
$org   = (Invoke-RestMethod -Headers $h -Uri "https://graph.microsoft.com/v1.0/organization").value | Select-Object -First 1

$seg = $tokens.access_token.Split('.')[1]
$pad = $seg + ('=' * ((4 - $seg.Length % 4) % 4))
$payload = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($pad.Replace('-','+').Replace('_','/'))) | ConvertFrom-Json

$expLocal = [DateTimeOffset]::FromUnixTimeSeconds($payload.exp).LocalDateTime
$iatLocal = [DateTimeOffset]::FromUnixTimeSeconds($payload.iat).LocalDateTime
$expColor = if ($expLocal -lt (Get-Date)) { 'Red' } else { 'Green' }

Write-Header 'Identity'
Write-KV 'DisplayName' $me.displayName
Write-KV 'UPN'         $me.userPrincipalName Green
Write-KV 'ObjectId'    $me.id
Write-KV 'Mail'        $me.mail
Write-KV 'JobTitle'    $me.jobTitle
Write-KV 'Department'  $me.department
Write-KV 'OfficeLoc'   $me.officeLocation

Write-Header 'Tenant'
Write-KV 'TenantName' $org.displayName Green
Write-KV 'TenantId'   $org.id
Write-KV 'DefaultDom' ($org.verifiedDomains | Where-Object isDefault).name

Write-Header 'Token'
Write-KV 'AppId'    $payload.appid
Write-KV 'AppName'  $payload.app_displayname Green
Write-KV 'Audience' $payload.aud
Write-KV 'Scopes'   $payload.scp Magenta
Write-KV 'Roles'    (($payload.roles -join ', ')) Magenta
Write-KV 'IssuedAt' $iatLocal
Write-KV 'Expires'  $expLocal $expColor

Write-Header 'Directory Roles'
$dr = $mem | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.directoryRole' }
if ($dr) { $dr | ForEach-Object { Write-Host " - $($_.displayName)" -ForegroundColor Red } }
else     { Write-Host ' <none>' -ForegroundColor DarkGray }

$groups = @($mem | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.group' })
Write-Header "Group Memberships ($($groups.Count))"
$groups | ForEach-Object {
    Write-Host " - " -NoNewline
    Write-Host $_.displayName -ForegroundColor Green -NoNewline
    Write-Host " [$($_.id)]" -ForegroundColor DarkGray
}

Write-Header "Owned Objects ($($owned.Count))"
$owned | ForEach-Object {
    $type = $_.'@odata.type'.Split('.')[-1]
    Write-Host " - " -NoNewline
    Write-Host $type -ForegroundColor Magenta -NoNewline
    Write-Host ": $($_.displayName) " -NoNewline
    Write-Host "[$($_.id)]" -ForegroundColor DarkGray
}

Write-Header "Owned Devices ($($devs.Count))"
$devs | ForEach-Object {
    Write-Host " - " -NoNewline
    Write-Host $_.displayName -ForegroundColor Green -NoNewline
    Write-Host " ($($_.operatingSystem) $($_.operatingSystemVersion))" -ForegroundColor White -NoNewline
    Write-Host " trust=$($_.trustType)" -ForegroundColor Yellow
}