<#
.SYNOPSIS
    Test whether the legacy MSOnline PowerShell module is still able to authenticate and query the
    tenant. Runs standalone or can be dot-sourced.

.DESCRIPTION
    Evidence collector for the "Legacy MSOnline PowerShell Module Not Restricted" finding.

    The MSOnline module (Connect-MsolService, Get-MsolUser, Set-MsolUserPassword, etc.) authenticates
    using the Azure Active Directory PowerShell client (1b730954-1685-4b74-9bfd-dac224a7b894) and
    targets the legacy Azure AD Graph API (graph.windows.net) plus the SOAP provisioning service at
    provisioningapi.microsoftonline.com. Microsoft has officially deprecated this module.

    This script:
      1. Reads the existing $tokens.refresh_token without modifying $tokens.
      2. Attempts to exchange it for an access token using the AzureAD PowerShell client ID.
      3. Falls back to interactive device code authentication when the existing RT is FOCI-bound and
         cannot be used by the non-FOCI AzureAD PowerShell client.
      4. Decodes and reports the issued token.
      5. Performs read-only queries against graph.windows.net that mirror Get-Msol* cmdlet behaviour.
      6. Drives Connect-MsolService and Get-MsolCompanyInformation (if the MSOnline module is
         installed) to validate end-to-end cmdlet functionality.
      7. Summarises which surfaces returned data versus which were blocked.

    The new access token is stored in $global:LegacyMSOnlineToken for follow-up use and is NEVER
    written back to $tokens.

.PARAMETER ClientId
    Defaults to 1b730954-1685-4b74-9bfd-dac224a7b894 (AzureAD PowerShell, used by MSOnline).

.PARAMETER TenantId
    Tenant identifier or 'common'. Defaults to 'common'.

.PARAMETER NoInvokeMsol
    Skip the Connect-MsolService cmdlet test. By default the script always drives the cmdlets when
    the MSOnline module is installed.

.PARAMETER DeviceCode
    Skip the refresh token attempt and go straight to interactive device code authentication.

.EXAMPLE
    .\Invoke-TestLegacyMSOnline.ps1
    .\Invoke-TestLegacyMSOnline.ps1 -DeviceCode
    .\Invoke-TestLegacyMSOnline.ps1 -NoInvokeMsol
    .\Invoke-TestLegacyMSOnline.ps1 -TenantId contoso.onmicrosoft.com
#>
[CmdletBinding()]
param(
    [string]$ClientId = '1b730954-1685-4b74-9bfd-dac224a7b894',
    [string]$TenantId = 'common',
    [switch]$NoInvokeMsol,
    [switch]$DeviceCode,
    [switch]$h,
    [switch]$Help
)

function Test-LegacyMSOnlineAccess {
    [CmdletBinding()]
    param(
        [string]$ClientId = '1b730954-1685-4b74-9bfd-dac224a7b894',
        [string]$TenantId = 'common',
        [switch]$NoInvokeMsol,
        [switch]$DeviceCode,
        [switch]$h,
        [switch]$Help
    )

    if ($h -or $Help) {
        Write-Host ""
        Write-Host "Invoke-TestLegacyMSOnline" -ForegroundColor Cyan
        Write-Host "-------------------------" -ForegroundColor Cyan
        Write-Host "  Evidence collector for 'Legacy MSOnline PowerShell Module Not Restricted'."
        Write-Host "  Tries refresh-token exchange first, falls back to device code, probes legacy"
        Write-Host "  AAD Graph endpoints, then drives Connect-MsolService to validate end-to-end."
        Write-Host ""
        Write-Host "USAGE:" -ForegroundColor Yellow
        Write-Host "  .\Invoke-TestLegacyMSOnline.ps1 [-ClientId <guid>] [-TenantId <tenant|common>] [-DeviceCode] [-NoInvokeMsol]"
        Write-Host ""
        Write-Host "  Defaults: ClientId 1b730954-1685-4b74-9bfd-dac224a7b894 (AzureAD PowerShell)"
        Write-Host "  Defaults: TenantId common"
        Write-Host "  Defaults: MSOnline cmdlet test runs automatically when the module is installed."
        Write-Host ""
        Write-Host "REQUIRES:" -ForegroundColor Yellow
        Write-Host "  `$tokens variable in the calling session with a valid refresh_token,"
        Write-Host "  unless -DeviceCode is supplied."
        Write-Host ""
        Write-Host "NOTE:" -ForegroundColor Yellow
        Write-Host "  The original `$tokens variable is not modified. The new token is stored"
        Write-Host "  in `$global:LegacyMSOnlineToken for follow-up use."
        Write-Host ""
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

    function Invoke-DeviceCodeAuth {
        param([string]$ClientId, [string]$TenantId)

        Write-Header 'Device Code Authentication'
        Write-KV 'Resource'   'https://graph.windows.net' Green
        Write-KV 'ClientId'   $ClientId
        Write-KV 'ClientName' 'AzureAD PowerShell (used by MSOnline module)'
        Write-KV 'TenantId'   $TenantId

        try {
            $dc = Invoke-RestMethod -Method POST `
                -Uri "https://login.microsoftonline.com/$TenantId/oauth2/devicecode?api-version=1.0" `
                -ContentType 'application/x-www-form-urlencoded' `
                -Body @{
                    client_id = $ClientId
                    resource  = 'https://graph.windows.net'
                }
        } catch {
            Write-Host ""
            Write-Host "[-] Device code request failed: $($_.Exception.Message)" -ForegroundColor Red
            try {
                $errBody = $_.ErrorDetails.Message
                if ($errBody) {
                    $errJson = $errBody | ConvertFrom-Json
                    Write-Host "    error             : $($errJson.error)" -ForegroundColor DarkGray
                    Write-Host "    error_description : $(($errJson.error_description -split "`n")[0])" -ForegroundColor DarkGray
                }
            } catch {}
            return $null
        }

        Write-Host ""
        Write-Host "[*] Open the URL below in a browser and enter the code." -ForegroundColor Yellow
        Write-Host "    URL : " -NoNewline; Write-Host $dc.verification_url -ForegroundColor Cyan
        Write-Host "    Code: " -NoNewline; Write-Host $dc.user_code -ForegroundColor Cyan
        Write-Host ""
        Write-Host "[*] Waiting for sign-in to complete..." -ForegroundColor DarkGray

        $interval = if ($dc.interval) { [int]$dc.interval } else { 5 }
        $expires  = if ($dc.expires_in) { [int]$dc.expires_in } else { 900 }
        $deadline = (Get-Date).AddSeconds($expires)
        $polled   = 0

        while ((Get-Date) -lt $deadline) {
            Start-Sleep -Seconds $interval
            $polled += $interval
            try {
                $resp = Invoke-RestMethod -Method POST `
                    -Uri "https://login.microsoftonline.com/$TenantId/oauth2/token" `
                    -ContentType 'application/x-www-form-urlencoded' `
                    -Body @{
                        grant_type = 'urn:ietf:params:oauth:grant-type:device_code'
                        client_id  = $ClientId
                        code       = $dc.device_code
                    } -ErrorAction Stop
                Write-Host "[+] Sign-in complete (polled for ${polled}s)." -ForegroundColor Green
                return $resp
            } catch {
                $errJson = $null
                try { $errJson = $_.ErrorDetails.Message | ConvertFrom-Json } catch {}
                switch ($errJson.error) {
                    'authorization_pending' {
                        Write-Host "." -ForegroundColor DarkGray -NoNewline
                        continue
                    }
                    'slow_down' {
                        $interval += 5
                        Write-Host "s" -ForegroundColor DarkGray -NoNewline
                        continue
                    }
                    'authorization_declined' {
                        Write-Host ""
                        Write-Host "[-] User declined sign-in." -ForegroundColor Red
                        return $null
                    }
                    'expired_token' {
                        Write-Host ""
                        Write-Host "[-] Device code expired before sign-in completed." -ForegroundColor Red
                        return $null
                    }
                    default {
                        Write-Host ""
                        Write-Host "[-] Device code poll failed: $($errJson.error) - $(($errJson.error_description -split "`n")[0])" -ForegroundColor Red
                        return $null
                    }
                }
            }
        }
        Write-Host ""
        Write-Host "[-] Device code timed out." -ForegroundColor Red
        return $null
    }

    # ---- Acquire token ----
    $newTokens = $null

    if ($DeviceCode) {
        $newTokens = Invoke-DeviceCodeAuth -ClientId $ClientId -TenantId $TenantId
    } else {
        if (-not $tokens.refresh_token) {
            Write-Host "[!] No `$tokens.refresh_token in current session. Falling back to device code." -ForegroundColor Yellow
            $newTokens = Invoke-DeviceCodeAuth -ClientId $ClientId -TenantId $TenantId
        } else {
            Write-Header 'Refresh Token Exchange'
            Write-KV 'Resource'   'https://graph.windows.net' Green
            Write-KV 'ClientId'   $ClientId
            Write-KV 'ClientName' 'AzureAD PowerShell (used by MSOnline module)'
            Write-KV 'TenantId'   $TenantId

            $body = @{
                grant_type    = 'refresh_token'
                refresh_token = $tokens.refresh_token
                client_id     = $ClientId
                resource      = 'https://graph.windows.net'
                scope         = 'openid'
            }
            $rtFailed = $false
            $errCode  = $null
            $errDesc  = $null
            try {
                $newTokens = Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$TenantId/oauth2/token" `
                    -ContentType 'application/x-www-form-urlencoded' -Body $body
                Write-Host ""
                Write-Host "[+] Refresh token exchange succeeded." -ForegroundColor Red
            } catch {
                $rtFailed = $true
                Write-Host ""
                Write-Host "[-] Refresh token exchange failed: $($_.Exception.Message)" -ForegroundColor Red
                try {
                    $errBody = $_.ErrorDetails.Message
                    if ($errBody) {
                        $errJson = $errBody | ConvertFrom-Json
                        $errCode = $errJson.error
                        $errDesc = ($errJson.error_description -split "`n")[0]
                        Write-Host "    error             : $errCode" -ForegroundColor DarkGray
                        Write-Host "    error_description : $errDesc" -ForegroundColor DarkGray
                    }
                } catch {}
            }

            if ($rtFailed) {
                Write-Host ""
                if ($errCode -eq 'invalid_grant') {
                    Write-Host "[!] The AzureAD PowerShell client (1b730954...) is NOT a FOCI family member." -ForegroundColor Yellow
                    Write-Host "    Existing `$tokens.refresh_token is FOCI-bound (from GraphRunner's Office client)" -ForegroundColor DarkGray
                    Write-Host "    and cannot be redeemed for a non-FOCI client - this is an IdP-level grant" -ForegroundColor DarkGray
                    Write-Host "    restriction, NOT a tenant block of MSOnline." -ForegroundColor DarkGray
                    Write-Host ""
                    Write-Host "[*] Falling back to interactive device code authentication..." -ForegroundColor Yellow
                } elseif ($errCode -in 'unauthorized_client','invalid_client') {
                    Write-Host "[+] Tenant rejected the AzureAD PowerShell client ($errCode)." -ForegroundColor Green
                    Write-Host "    MSOnline auth path appears to be blocked at the tenant level." -ForegroundColor Green
                    Write-Host "    No device code fallback - this is the secure state." -ForegroundColor DarkGray
                    return
                } else {
                    Write-Host "[!] Unrecognised error from token endpoint. Falling back to device code to confirm." -ForegroundColor Yellow
                }
                $newTokens = Invoke-DeviceCodeAuth -ClientId $ClientId -TenantId $TenantId
            }
        }
    }

    if (-not $newTokens) {
        Write-Host ""
        Write-Host "[-] No token obtained - cannot proceed with endpoint probes." -ForegroundColor Red
        return
    }

    Write-Host ""
    Write-Host "[+] AzureAD PowerShell client (MSOnline auth path) issued a token successfully." -ForegroundColor Red

    $global:LegacyMSOnlineToken = $newTokens
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

    # ---- Probe legacy directory endpoints that MSOnline cmdlets rely on ----
    $hdr = @{
        Authorization  = "Bearer $($newTokens.access_token)"
        'Content-Type' = 'application/json'
    }
    $tid = if ($jwt -and $jwt.tid) { $jwt.tid } else { 'myorganization' }
    $base = "https://graph.windows.net/$tid"
    $apiVer = '?api-version=1.6'
    $apiInt = '?api-version=1.61-internal'

    $probes = @(
        @{ Name = '/me'                ; Url = "$base/me$apiVer"                    ; Cmdlet = 'Get-MsolUser -SignedInUser' }
        @{ Name = '/tenantDetails'     ; Url = "$base/tenantDetails$apiVer"         ; Cmdlet = 'Get-MsolCompanyInformation' }
        @{ Name = '/users (top 5)'     ; Url = "$base/users$apiVer&`$top=5"         ; Cmdlet = 'Get-MsolUser' }
        @{ Name = '/groups (top 5)'    ; Url = "$base/groups$apiVer&`$top=5"        ; Cmdlet = 'Get-MsolGroup' }
        @{ Name = '/directoryRoles'    ; Url = "$base/directoryRoles$apiVer"        ; Cmdlet = 'Get-MsolRole' }
        @{ Name = '/policies'          ; Url = "$base/policies$apiInt"              ; Cmdlet = 'Get-MsolPasswordPolicy / tenant policies' }
        @{ Name = '/servicePrincipals (top 5)' ; Url = "$base/servicePrincipals$apiVer&`$top=5" ; Cmdlet = 'Get-MsolServicePrincipal' }
    )

    Write-Header 'Endpoint Probes'
    Write-Host "[*] These are the underlying calls Get-Msol* cmdlets make when the module is used." -ForegroundColor DarkGray
    Write-Host ""

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
                $detail = "objectId $($resp.objectId)"
            } elseif ($resp.tenantId -or $resp.displayName) {
                $detail = "tenant $($resp.displayName) ($($resp.tenantId))"
            } else {
                $detail = 'response received'
            }
        } catch {
            $code = $_.Exception.Response.StatusCode.value__
            $status = if ($code) { "HTTP $code" } else { 'ERROR' }
            $detail = ($_.Exception.Message -split "`n")[0]
        }

        [pscustomobject]@{
            Endpoint = $p.Name
            Cmdlet   = $p.Cmdlet
            Status   = $status
            Detail   = $detail
        }
    }

    foreach ($r in $results) {
        $colour = if ($r.Status -eq 'OK') { 'Red' }
                  elseif ($r.Status -like 'HTTP 4*') { 'Green' }
                  else { 'Yellow' }
        $label  = if ($r.Status -eq 'OK') { 'ACCESSIBLE' } else { $r.Status }
        Write-Host (" {0,-32}" -f $r.Endpoint) -ForegroundColor White -NoNewline
        Write-Host (" {0,-12}" -f $label) -ForegroundColor $colour -NoNewline
        Write-Host (" {0,-40}" -f $r.Cmdlet) -ForegroundColor Magenta -NoNewline
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

    # ---- Always invoke MSOnline cmdlets unless suppressed ----
    $msolEvidence = $null
    $msolConnected = $false
    if (-not $NoInvokeMsol) {
        Write-Header 'MSOnline Cmdlet Invocation'
        if (-not (Get-Module -ListAvailable -Name MSOnline)) {
            Write-Host "[-] MSOnline module not installed locally. Skipping cmdlet test." -ForegroundColor Yellow
            Write-Host "    Install with: Install-Module MSOnline -Scope CurrentUser" -ForegroundColor DarkGray
        } else {
            try {
                Import-Module MSOnline -ErrorAction Stop
                Connect-MsolService -AdGraphAccessToken $newTokens.access_token -ErrorAction Stop
                Write-Host "[+] Connect-MsolService succeeded using AzureAD PowerShell token." -ForegroundColor Red
                $msolConnected = $true

                try {
                    $ci = Get-MsolCompanyInformation -ErrorAction Stop
                    Write-Host "[+] Get-MsolCompanyInformation returned: $($ci.DisplayName)" -ForegroundColor Red
                    $msolEvidence = $ci
                } catch {
                    Write-Host "[-] Get-MsolCompanyInformation failed: $($_.Exception.Message)" -ForegroundColor Yellow
                }
            } catch {
                Write-Host "[-] Connect-MsolService failed: $(($_.Exception.Message -split "`n")[0])" -ForegroundColor Yellow
                if ($_.Exception.Message -match 'provisioningapi\.microsoftonline\.com') {
                    Write-Host "    The MSOnline SOAP provisioning endpoint is unreachable. This endpoint has been" -ForegroundColor DarkGray
                    Write-Host "    retired by Microsoft, meaning Get-Msol* cmdlets cannot function end-to-end." -ForegroundColor DarkGray
                }
            }
        }
    }

    # ---- Verdict ----
    Write-Host ""
    if ($ok -gt 0 -and $msolConnected) {
        Write-Host "[!] FINDING CONFIRMED: legacy MSOnline path is fully usable." -ForegroundColor Red
        Write-Host "[!] Token issuance + REST API + Connect-MsolService all succeeded." -ForegroundColor Red
    } elseif ($ok -gt 0) {
        Write-Host "[!] FINDING PARTIAL: legacy AAD Graph REST surface is accessible to this user." -ForegroundColor Red
        Write-Host "[!] Connect-MsolService did not complete; cmdlet-level path may be partly broken." -ForegroundColor Yellow
    } elseif ($msolConnected) {
        Write-Host "[!] FINDING CONFIRMED via cmdlet path despite REST 403s." -ForegroundColor Red
    } else {
        Write-Host "[+] Legacy MSOnline path is not usable end-to-end against this tenant." -ForegroundColor Green
        Write-Host "    Token issued but REST API returned 4xx and Connect-MsolService failed." -ForegroundColor DarkGray
        Write-Host "    Finding does not apply in current configuration." -ForegroundColor DarkGray
    }

    Write-Host ""
    Write-Host "[i] New token stored in `$LegacyMSOnlineToken (original `$tokens unchanged)." -ForegroundColor DarkGray

    return [pscustomobject]@{
        Token         = $newTokens
        Jwt           = $jwt
        Results       = $results
        MsolConnected = $msolConnected
        MsolEvidence  = $msolEvidence
    }
}

# ---- Auto-run when invoked as a script ----
if ($MyInvocation.InvocationName -ne '.') {
    Test-LegacyMSOnlineAccess -ClientId $ClientId -TenantId $TenantId -NoInvokeMsol:$NoInvokeMsol -DeviceCode:$DeviceCode -h:$h -Help:$Help | Out-Null
}