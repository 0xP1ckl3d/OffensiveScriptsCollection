<#
.SYNOPSIS
    Test whether the legacy Azure AD Graph API (graph.windows.net) is still accessible from the
    current refresh token. Runs standalone or can be dot-sourced.

.DESCRIPTION
    Evidence collector for the "Legacy Azure AD Graph Access" finding.

    Microsoft has officially retired the Azure AD Graph API (https://graph.windows.net) in favour of
    Microsoft Graph. Tenants where legacy AAD Graph still issues tokens and returns data indicate the
    legacy API has not been fully blocked, exposing the tenant to deprecated, less-monitored, and
    weakly-scoped management surfaces.

    This script:
      1. Reads the existing $tokens.refresh_token without modifying $tokens.
      2. Exchanges the refresh token for an access token targeting https://graph.windows.net.
      3. Decodes and reports the issued token (audience, scopes, app id, expiry).
      4. Performs read-only queries against the legacy endpoint to confirm functional access:
           - GET /me
           - GET /tenantDetails
           - GET /users (top 5)
           - GET /groups (top 5)
           - GET /directoryRoles
           - GET /applications (top 5)
      5. Summarises which endpoints returned data versus which were blocked.

    The new access token is stored in $script:LegacyAADGraphToken for follow-up use and is NEVER
    written back to $tokens.

.PARAMETER ClientId
    The client_id to use for the refresh token exchange. Defaults to the well-known Microsoft Office
    client (d3590ed6-52b3-4102-aeff-aad2292ab01c), which is what GraphRunner and most refresh tokens
    are bound to.

.PARAMETER TenantId
    Tenant identifier or 'common'. Defaults to 'common', which uses the home tenant of the refresh
    token.

.EXAMPLE
    .\Invoke-TestLegacyAADGraph.ps1
    .\Invoke-TestLegacyAADGraph.ps1 -TenantId contoso.onmicrosoft.com
    . .\Invoke-TestLegacyAADGraph.ps1; Test-LegacyAADGraphAccess
#>
[CmdletBinding()]
param(
    [string]$ClientId = 'd3590ed6-52b3-4102-aeff-aad2292ab01c',
    [string]$TenantId = 'common',
    [switch]$h,
    [switch]$Help
)

function Test-LegacyAADGraphAccess {
    [CmdletBinding()]
    param(
        [string]$ClientId = 'd3590ed6-52b3-4102-aeff-aad2292ab01c',
        [string]$TenantId = 'common',
        [switch]$h,
        [switch]$Help
    )

    if ($h -or $Help) {
        Write-Host ""
        Write-Host "Invoke-TestLegacyAADGraph" -ForegroundColor Cyan
        Write-Host "-------------------------" -ForegroundColor Cyan
        Write-Host "  Evidence collector for 'Legacy Azure AD Graph Access'."
        Write-Host "  Exchanges the existing refresh token for an AAD Graph token and probes the API."
        Write-Host ""
        Write-Host "USAGE:" -ForegroundColor Yellow
        Write-Host "  .\Invoke-TestLegacyAADGraph.ps1 [-ClientId <guid>] [-TenantId <tenant|common>]"
        Write-Host ""
        Write-Host "  Defaults: ClientId d3590ed6-52b3-4102-aeff-aad2292ab01c (Office), TenantId common"
        Write-Host ""
        Write-Host "REQUIRES:" -ForegroundColor Yellow
        Write-Host "  `$tokens variable in the calling session with a valid refresh_token."
        Write-Host ""
        Write-Host "NOTE:" -ForegroundColor Yellow
        Write-Host "  The original `$tokens variable is not modified. The new AAD Graph token is stored"
        Write-Host "  in `$script:LegacyAADGraphToken for follow-up use."
        Write-Host ""
        return
    }

    if (-not $tokens.refresh_token) {
        Write-Host "[!] No `$tokens.refresh_token found in the current session. Authenticate first." -ForegroundColor Red
        return
    }

    function Write-Header($t) { Write-Host "`n==== $t ====" -ForegroundColor Cyan }
    function Write-KV($k,$val,$vc='White') {
        Write-Host ("{0,-22}: " -f $k) -ForegroundColor Yellow -NoNewline
        Write-Host $val -ForegroundColor $vc
    }

    function Decode-Jwt([string]$jwt) {
        try {
            $seg = $jwt.Split('.')[1]
            $pad = $seg + ('=' * ((4 - $seg.Length % 4) % 4))
            $bytes = [System.Convert]::FromBase64String($pad.Replace('-','+').Replace('_','/'))
            return [System.Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json
        } catch { return $null }
    }

    # ---- Exchange refresh token for AAD Graph access token ----
    Write-Header 'Token Exchange'
    Write-KV 'Resource'  'https://graph.windows.net' Green
    Write-KV 'ClientId'  $ClientId
    Write-KV 'TenantId'  $TenantId

    $body = @{
        grant_type    = 'refresh_token'
        refresh_token = $tokens.refresh_token
        client_id     = $ClientId
        resource      = 'https://graph.windows.net'
        scope         = 'openid'
    }

    $newTokens = $null
    try {
        $newTokens = Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$TenantId/oauth2/token" `
            -ContentType 'application/x-www-form-urlencoded' -Body $body
    } catch {
        Write-Host ""
        Write-Host "[-] Token exchange failed: $($_.Exception.Message)" -ForegroundColor Red
        try {
            $errBody = $_.ErrorDetails.Message
            if ($errBody) {
                $errJson = $errBody | ConvertFrom-Json
                Write-Host "    error             : $($errJson.error)" -ForegroundColor DarkGray
                Write-Host "    error_description : $($errJson.error_description -split [Environment]::NewLine | Select-Object -First 1)" -ForegroundColor DarkGray
            }
        } catch {}
        Write-Host ""
        Write-Host "[!] Tenant may be blocking AAD Graph token issuance. This is the expected secure state." -ForegroundColor Green
        return
    }

    Write-Host ""
    Write-Host "[+] Token exchange succeeded - AAD Graph is still issuing tokens to this user." -ForegroundColor Red

    $global:LegacyAADGraphToken = $newTokens
    $jwt = Decode-Jwt $newTokens.access_token

    Write-Header 'Issued Token'
    if ($jwt) {
        Write-KV 'Audience'    $jwt.aud $(if ($jwt.aud -match 'graph\.windows\.net') {'Red'} else {'Yellow'})
        Write-KV 'Issuer'      $jwt.iss
        Write-KV 'Tenant'      $jwt.tid
        Write-KV 'UPN'         $jwt.upn
        Write-KV 'AppId'       $jwt.appid
        Write-KV 'AppName'     $jwt.app_displayname
        Write-KV 'Scopes'      $jwt.scp
        Write-KV 'Roles'       (($jwt.roles -join ', '))
        try {
            $iat = [System.DateTimeOffset]::FromUnixTimeSeconds($jwt.iat).LocalDateTime
            $exp = [System.DateTimeOffset]::FromUnixTimeSeconds($jwt.exp).LocalDateTime
            Write-KV 'IssuedAt'    $iat
            Write-KV 'Expires'     $exp $(if ($exp -lt (Get-Date)) {'Red'} else {'Green'})
        } catch {}
    } else {
        Write-Host " <token did not decode as JWT>" -ForegroundColor Yellow
    }

    # ---- Probe AAD Graph endpoints ----
    $hdr = @{
        Authorization = "Bearer $($newTokens.access_token)"
        'Content-Type' = 'application/json'
    }
    $tid = if ($jwt -and $jwt.tid) { $jwt.tid } else { 'myorganization' }
    $base = "https://graph.windows.net/$tid"
    $apiVer = '?api-version=1.6'

    $probes = @(
        @{ Name = '/me'             ; Url = "$base/me$apiVer" }
        @{ Name = '/tenantDetails'  ; Url = "$base/tenantDetails$apiVer" }
        @{ Name = '/users (top 5)'  ; Url = "$base/users$apiVer&`$top=5" }
        @{ Name = '/groups (top 5)' ; Url = "$base/groups$apiVer&`$top=5" }
        @{ Name = '/directoryRoles' ; Url = "$base/directoryRoles$apiVer" }
        @{ Name = '/applications (top 5)' ; Url = "$base/applications$apiVer&`$top=5" }
    )

    Write-Header 'Endpoint Probes'
    $results = foreach ($p in $probes) {
        $status = 'UNKNOWN'
        $detail = ''
        try {
            $resp = Invoke-RestMethod -Headers $hdr -Method GET -Uri $p.Url -ErrorAction Stop
            $status = 'OK'
            if ($null -ne $resp.value) {
                $count = @($resp.value).Count
                $detail = "$count record(s) returned"
            } elseif ($resp.objectId) {
                $detail = "objectId $($resp.objectId) ($($resp.userPrincipalName))"
            } elseif ($resp.tenantId -or $resp.displayName) {
                $detail = "tenant $($resp.displayName) ($($resp.tenantId))"
            } else {
                $detail = 'response received'
            }
        } catch {
            $code = $_.Exception.Response.StatusCode.value__
            $status = if ($code) { "HTTP $code" } else { 'ERROR' }
            $detail = $_.Exception.Message -split [Environment]::NewLine | Select-Object -First 1
        }

        [pscustomobject]@{
            Endpoint = $p.Name
            Status   = $status
            Detail   = $detail
        }
    }

    foreach ($r in $results) {
        $colour = if ($r.Status -eq 'OK') { 'Red' }
                  elseif ($r.Status -like 'HTTP 4*') { 'Green' }
                  else { 'Yellow' }
        $label  = if ($r.Status -eq 'OK') { 'ACCESSIBLE' } else { $r.Status }
        Write-Host (" {0,-25}" -f $r.Endpoint) -ForegroundColor White -NoNewline
        Write-Host (" {0,-12}" -f $label) -ForegroundColor $colour -NoNewline
        Write-Host "  $($r.Detail)" -ForegroundColor DarkGray
    }

    $ok = @($results | Where-Object Status -eq 'OK').Count
    $blocked = @($results | Where-Object Status -like 'HTTP 4*').Count
    $other = $results.Count - $ok - $blocked

    Write-Host ""
    Write-Host "Summary: " -ForegroundColor Cyan -NoNewline
    Write-Host "$ok accessible " -ForegroundColor Red -NoNewline
    Write-Host "/ $blocked blocked " -ForegroundColor Green -NoNewline
    Write-Host "/ $other other" -ForegroundColor Yellow

    Write-Host ""
    if ($ok -gt 0) {
        Write-Host "[!] FINDING CONFIRMED: legacy Azure AD Graph (graph.windows.net) is accessible from this user context." -ForegroundColor Red
        Write-Host "[!] AAD Graph is officially retired. Continued availability indicates the tenant has not enforced the block." -ForegroundColor Red
    } else {
        Write-Host "[+] Legacy AAD Graph endpoints did not return data. Tenant appears to be blocking access." -ForegroundColor Green
    }

    Write-Host ""
    Write-Host "[i] New AAD Graph token stored in `$LegacyAADGraphToken (original `$tokens unchanged)." -ForegroundColor DarkGray

    return [pscustomobject]@{
        Token   = $newTokens
        Jwt     = $jwt
        Results = $results
    }
}

# ---- Auto-run when invoked as a script ----
if ($MyInvocation.InvocationName -ne '.') {
    Test-LegacyAADGraphAccess -ClientId $ClientId -TenantId $TenantId -h:$h -Help:$Help | Out-Null
}