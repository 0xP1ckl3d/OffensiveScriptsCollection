<#
.SYNOPSIS
    Test whether the current authenticated user holds Azure Resource Manager access. Runs standalone
    or can be dot-sourced.

.DESCRIPTION
    Evidence collector for the "External Third-Party Account with Azure Resource Management Access"
    finding. Designed to be executed under a guest or third-party identity to demonstrate the access
    that account holds against Azure RBAC.

    This script:
      1. Reads the existing $tokens.refresh_token without modifying $tokens.
      2. Exchanges it for an ARM access token targeting https://management.azure.com.
         Falls back to interactive device code if the refresh token is unusable.
      3. Decodes and reports the issued token (audience, scopes, app id, user type, expiry).
      4. Confirms whether the acting user is a guest in the tenant (via Microsoft Graph).
      5. Enumerates accessible management groups, subscriptions, role assignments, and resource
         groups using ARM.
      6. Highlights privileged role assignments (Owner, Contributor, User Access Administrator,
         Role Based Access Control Administrator, custom roles with broad action sets) and the
         scope at which they apply.
      7. Summarises the blast radius for the finding writeup.

    The new ARM token is stored in $global:LegacyARMToken for follow-up use and is NEVER written
    back to $tokens.

.PARAMETER ClientId
    The client_id used for the token exchange. Defaults to the well-known Microsoft Azure CLI
    client (04b07795-8ddb-461a-bbee-02f9e1bf7b46) which is broadly available for ARM scopes.

.PARAMETER TenantId
    Tenant identifier or 'common'. Defaults to 'common'.

.PARAMETER DeviceCode
    Skip the refresh token attempt and go straight to interactive device code authentication.

.EXAMPLE
    .\Invoke-TestExternalARMAccess.ps1
    .\Invoke-TestExternalARMAccess.ps1 -DeviceCode
    .\Invoke-TestExternalARMAccess.ps1 -TenantId contoso.onmicrosoft.com
#>
[CmdletBinding()]
param(
    [string]$ClientId = '04b07795-8ddb-461a-bbee-02f9e1bf7b46',
    [string]$TenantId = 'common',
    [switch]$DeviceCode,
    [switch]$h,
    [switch]$Help
)

function Test-ExternalARMAccess {
    [CmdletBinding()]
    param(
        [string]$ClientId = '04b07795-8ddb-461a-bbee-02f9e1bf7b46',
        [string]$TenantId = 'common',
        [switch]$DeviceCode,
        [switch]$h,
        [switch]$Help
    )

    if ($h -or $Help) {
        Write-Host ""
        Write-Host "Invoke-TestExternalARMAccess" -ForegroundColor Cyan
        Write-Host "----------------------------" -ForegroundColor Cyan
        Write-Host "  Evidence collector for 'External Third-Party Account with Azure Resource"
        Write-Host "  Management Access'. Run under a guest or third-party identity."
        Write-Host ""
        Write-Host "USAGE:" -ForegroundColor Yellow
        Write-Host "  .\Invoke-TestExternalARMAccess.ps1 [-ClientId <guid>] [-TenantId <tenant|common>] [-DeviceCode]"
        Write-Host ""
        Write-Host "  Defaults: ClientId 04b07795-8ddb-461a-bbee-02f9e1bf7b46 (Azure CLI)"
        Write-Host "  Defaults: TenantId common"
        Write-Host ""
        Write-Host "REQUIRES:" -ForegroundColor Yellow
        Write-Host "  `$tokens variable in the calling session with a valid refresh_token,"
        Write-Host "  unless -DeviceCode is supplied."
        Write-Host ""
        Write-Host "NOTE:" -ForegroundColor Yellow
        Write-Host "  The original `$tokens variable is not modified. The new ARM token is stored"
        Write-Host "  in `$global:LegacyARMToken for follow-up use."
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
        param([string]$ClientId, [string]$TenantId, [string]$Resource)

        Write-Header 'Device Code Authentication'
        Write-KV 'Resource'  $Resource Green
        Write-KV 'ClientId'  $ClientId
        Write-KV 'TenantId'  $TenantId

        try {
            $dc = Invoke-RestMethod -Method POST `
                -Uri "https://login.microsoftonline.com/$TenantId/oauth2/devicecode?api-version=1.0" `
                -ContentType 'application/x-www-form-urlencoded' `
                -Body @{ client_id = $ClientId; resource = $Resource }
        } catch {
            Write-Host ""
            Write-Host "[-] Device code request failed: $($_.Exception.Message)" -ForegroundColor Red
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
                    'authorization_pending' { Write-Host "." -ForegroundColor DarkGray -NoNewline; continue }
                    'slow_down'             { $interval += 5; Write-Host "s" -ForegroundColor DarkGray -NoNewline; continue }
                    'authorization_declined'{ Write-Host ""; Write-Host "[-] User declined sign-in." -ForegroundColor Red; return $null }
                    'expired_token'         { Write-Host ""; Write-Host "[-] Device code expired." -ForegroundColor Red; return $null }
                    default                 { Write-Host ""; Write-Host "[-] Poll failed: $($errJson.error)" -ForegroundColor Red; return $null }
                }
            }
        }
        Write-Host ""
        Write-Host "[-] Device code timed out." -ForegroundColor Red
        return $null
    }

    $armResource = 'https://management.azure.com'
    $newTokens = $null

    # ---- Acquire ARM token ----
    if ($DeviceCode) {
        $newTokens = Invoke-DeviceCodeAuth -ClientId $ClientId -TenantId $TenantId -Resource $armResource
    } else {
        if (-not $tokens.refresh_token) {
            Write-Host "[!] No `$tokens.refresh_token in current session. Falling back to device code." -ForegroundColor Yellow
            $newTokens = Invoke-DeviceCodeAuth -ClientId $ClientId -TenantId $TenantId -Resource $armResource
        } else {
            Write-Header 'Refresh Token Exchange'
            Write-KV 'Resource'  $armResource Green
            Write-KV 'ClientId'  $ClientId
            Write-KV 'TenantId'  $TenantId

            $body = @{
                grant_type    = 'refresh_token'
                refresh_token = $tokens.refresh_token
                client_id     = $ClientId
                resource      = $armResource
                scope         = 'openid'
            }
            $rtFailed = $false
            $errCode  = $null
            try {
                $newTokens = Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$TenantId/oauth2/token" `
                    -ContentType 'application/x-www-form-urlencoded' -Body $body
                Write-Host ""
                Write-Host "[+] Refresh token exchange succeeded." -ForegroundColor Green
            } catch {
                $rtFailed = $true
                Write-Host ""
                Write-Host "[-] Refresh token exchange failed: $($_.Exception.Message)" -ForegroundColor Red
                try {
                    $errBody = $_.ErrorDetails.Message
                    if ($errBody) {
                        $errJson = $errBody | ConvertFrom-Json
                        $errCode = $errJson.error
                        Write-Host "    error             : $($errJson.error)" -ForegroundColor DarkGray
                        Write-Host "    error_description : $(($errJson.error_description -split "`n")[0])" -ForegroundColor DarkGray
                    }
                } catch {}
            }
            if ($rtFailed) {
                Write-Host ""
                Write-Host "[*] Falling back to interactive device code authentication..." -ForegroundColor Yellow
                $newTokens = Invoke-DeviceCodeAuth -ClientId $ClientId -TenantId $TenantId -Resource $armResource
            }
        }
    }

    if (-not $newTokens) {
        Write-Host ""
        Write-Host "[-] No ARM token obtained - cannot proceed." -ForegroundColor Red
        return
    }

    $global:LegacyARMToken = $newTokens
    $jwt = Decode-Jwt $newTokens.access_token

    Write-Header 'Issued Token'
    if ($jwt) {
        Write-KV 'Audience'    $jwt.aud $(if ($jwt.aud -match 'management\.azure\.com') {'Red'} else {'Yellow'})
        Write-KV 'Issuer'      $jwt.iss
        Write-KV 'Tenant'      $jwt.tid
        Write-KV 'UPN'         $jwt.upn
        Write-KV 'OID'         $jwt.oid
        Write-KV 'AppId'       $jwt.appid
        Write-KV 'Scopes'      $jwt.scp
        try {
            $exp = [System.DateTimeOffset]::FromUnixTimeSeconds($jwt.exp).LocalDateTime
            Write-KV 'Expires'     $exp $(if ($exp -lt (Get-Date)) {'Red'} else {'Green'})
        } catch {}
    }

    # ---- Guest status check via Microsoft Graph ----
    Write-Header 'Acting User - Guest Status'
    $isGuest = $null
    $userInfo = $null
    if ($tokens.access_token) {
        try {
            $ghdr = @{ Authorization = "Bearer $($tokens.access_token)" }
            $userInfo = Invoke-RestMethod -Headers $ghdr -Uri "https://graph.microsoft.com/v1.0/me?`$select=id,displayName,userPrincipalName,mail,userType,externalUserState,creationType,companyName,createdDateTime"
        } catch {
            Write-Host "[!] Could not query Microsoft Graph /me with existing `$tokens.access_token: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
    if ($userInfo) {
        Write-KV 'DisplayName' $userInfo.displayName Green
        Write-KV 'UPN'         $userInfo.userPrincipalName Green
        Write-KV 'Mail'        $userInfo.mail
        Write-KV 'UserType'    $userInfo.userType $(if ($userInfo.userType -eq 'Guest') {'Red'} else {'White'})
        Write-KV 'GuestState'  $userInfo.externalUserState
        Write-KV 'CreationType' $userInfo.creationType
        Write-KV 'CompanyName' $userInfo.companyName
        Write-KV 'Created'     $userInfo.createdDateTime
        $isGuest = ($userInfo.userType -eq 'Guest')
        if ($isGuest) {
            Write-Host ""
            Write-Host "[!] Confirmed external/guest identity in tenant $($jwt.tid)." -ForegroundColor Red
        } else {
            Write-Host ""
            Write-Host "[*] Acting user is a Member of the tenant, not a Guest. This finding targets external" -ForegroundColor Yellow
            Write-Host "    third-party identities. Continuing for completeness; treat the output accordingly." -ForegroundColor DarkGray
        }
    } else {
        Write-Host "[*] Guest status could not be verified via Graph. Inspect the token UPN/issuer above." -ForegroundColor DarkGray
    }

    # ---- Tenants visible to ARM ----
    $armHdr = @{ Authorization = "Bearer $($newTokens.access_token)" }
    Write-Header 'Tenants Visible to ARM'
    $tenants = @()
    try {
        $r = Invoke-RestMethod -Headers $armHdr -Uri 'https://management.azure.com/tenants?api-version=2022-12-01'
        $tenants = @($r.value)
        if ($tenants.Count -eq 0) {
            Write-Host " <none>" -ForegroundColor DarkGray
        } else {
            $tenants | ForEach-Object {
                Write-Host " - " -NoNewline
                Write-Host "$($_.displayName) " -ForegroundColor Green -NoNewline
                Write-Host "[$($_.tenantId)]" -ForegroundColor DarkGray
            }
        }
    } catch {
        Write-Host "[!] /tenants failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    # ---- Management groups ----
    Write-Header 'Accessible Management Groups'
    $mgs = @()
    try {
        $r = Invoke-RestMethod -Headers $armHdr -Uri 'https://management.azure.com/providers/Microsoft.Management/managementGroups?api-version=2023-04-01'
        $mgs = @($r.value)
    } catch {}
    if ($mgs.Count -eq 0) {
        Write-Host " <none>" -ForegroundColor DarkGray
    } else {
        $mgs | ForEach-Object {
            Write-Host " - " -NoNewline
            Write-Host "$($_.properties.displayName) " -ForegroundColor Green -NoNewline
            Write-Host "[$($_.name)]" -ForegroundColor DarkGray
        }
    }

    # ---- Subscriptions ----
    Write-Header 'Accessible Subscriptions'
    $subs = @()
    try {
        $r = Invoke-RestMethod -Headers $armHdr -Uri 'https://management.azure.com/subscriptions?api-version=2022-12-01'
        $subs = @($r.value)
    } catch {
        Write-Host "[!] /subscriptions failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    if ($subs.Count -eq 0) {
        Write-Host " <none>" -ForegroundColor DarkGray
    } else {
        foreach ($s in $subs) {
            Write-Host " - " -NoNewline
            Write-Host $s.displayName -ForegroundColor Green -NoNewline
            Write-Host " [$($s.subscriptionId)] " -ForegroundColor DarkGray -NoNewline
            Write-Host "state=$($s.state)" -ForegroundColor Yellow
        }
    }

    # ---- Role definition cache ----
    $roleDefs = @{}
    function Get-RoleDef([string]$scope, [string]$roleDefId) {
        if ($roleDefs.ContainsKey($roleDefId)) { return $roleDefs[$roleDefId] }
        try {
            $r = Invoke-RestMethod -Headers $armHdr -Uri "https://management.azure.com$roleDefId`?api-version=2022-04-01"
            $roleDefs[$roleDefId] = $r.properties
            return $r.properties
        } catch { return $null }
    }

    $privilegedRoles = @(
        'Owner','Contributor','User Access Administrator',
        'Role Based Access Control Administrator','Access Review Operator Service Role',
        'Reservations Administrator','Management Group Contributor','Management Group Reader'
    )

    function Test-PrivilegedRoleDef($def) {
        if (-not $def) { return $false }
        if ($privilegedRoles -contains $def.roleName) { return $true }
        if ($def.type -eq 'CustomRole') {
            foreach ($p in $def.permissions) {
                if ($p.actions -contains '*') { return $true }
                if ($p.actions | Where-Object { $_ -like '*/write' -and $_ -like 'Microsoft.Authorization/*' }) { return $true }
            }
        }
        return $false
    }

    # ---- Role assignments at each scope ----
    Write-Header 'Role Assignments (subscription scope and below)'
    $allAssignments = @()
    foreach ($s in $subs) {
        $subId = $s.subscriptionId
        Write-Host ""
        Write-Host "Subscription: $($s.displayName) [$subId]" -ForegroundColor Cyan
        $uri = "https://management.azure.com/subscriptions/$subId/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&`$filter=principalId eq '$($jwt.oid)'"
        try {
            $assignments = @()
            do {
                $r = Invoke-RestMethod -Headers $armHdr -Uri $uri
                $assignments += $r.value
                $uri = $r.nextLink
            } while ($uri)

            if ($assignments.Count -eq 0) {
                Write-Host "  <no direct assignments for principal $($jwt.oid)>" -ForegroundColor DarkGray
            } else {
                foreach ($a in $assignments) {
                    $def = Get-RoleDef -scope $a.properties.scope -roleDefId $a.properties.roleDefinitionId
                    $name = if ($def) { $def.roleName } else { '<unresolved>' }
                    $type = if ($def) { $def.type } else { '?' }
                    $priv = Test-PrivilegedRoleDef $def
                    $colour = if ($priv) { 'Red' } else { 'White' }
                    $label  = if ($priv) { 'PRIVILEGED' } else { 'standard' }
                    Write-Host "  - " -NoNewline
                    Write-Host $name -ForegroundColor $colour -NoNewline
                    Write-Host " ($type) " -ForegroundColor DarkGray -NoNewline
                    Write-Host "[$label]" -ForegroundColor $colour -NoNewline
                    Write-Host "  scope=$($a.properties.scope)" -ForegroundColor DarkGray
                    $allAssignments += [pscustomobject]@{
                        Subscription = $s.displayName
                        SubscriptionId = $subId
                        RoleName     = $name
                        RoleType     = $type
                        Privileged   = $priv
                        Scope        = $a.properties.scope
                        PrincipalId  = $a.properties.principalId
                    }
                }
            }
        } catch {
            Write-Host "  [!] roleAssignments query failed: $($_.Exception.Message)" -ForegroundColor Yellow
        }

        # Resource groups for context
        try {
            $rgr = Invoke-RestMethod -Headers $armHdr -Uri "https://management.azure.com/subscriptions/$subId/resourcegroups?api-version=2022-12-01"
            $rgCount = @($rgr.value).Count
            Write-Host "  visible resource groups: $rgCount" -ForegroundColor DarkGray
        } catch {}
    }

    # Management group scope assignments
    Write-Host ""
    Write-Header 'Role Assignments at Management Group Scope'
    if ($mgs.Count -eq 0) {
        Write-Host " <no management groups visible>" -ForegroundColor DarkGray
    } else {
        foreach ($mg in $mgs) {
            try {
                $uri = "https://management.azure.com/providers/Microsoft.Management/managementGroups/$($mg.name)/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&`$filter=principalId eq '$($jwt.oid)'"
                $r = Invoke-RestMethod -Headers $armHdr -Uri $uri
                if (@($r.value).Count -gt 0) {
                    Write-Host ""
                    Write-Host "MG: $($mg.properties.displayName) [$($mg.name)]" -ForegroundColor Cyan
                    foreach ($a in $r.value) {
                        $def = Get-RoleDef -scope $a.properties.scope -roleDefId $a.properties.roleDefinitionId
                        $name = if ($def) { $def.roleName } else { '<unresolved>' }
                        $priv = Test-PrivilegedRoleDef $def
                        $colour = if ($priv) { 'Red' } else { 'White' }
                        $label  = if ($priv) { 'PRIVILEGED' } else { 'standard' }
                        Write-Host "  - " -NoNewline
                        Write-Host $name -ForegroundColor $colour -NoNewline
                        Write-Host " [$label] " -ForegroundColor $colour -NoNewline
                        Write-Host "scope=$($a.properties.scope)" -ForegroundColor DarkGray
                        $allAssignments += [pscustomobject]@{
                            Subscription = 'MG: ' + $mg.properties.displayName
                            SubscriptionId = $mg.name
                            RoleName     = $name
                            RoleType     = if ($def) { $def.type } else { '?' }
                            Privileged   = $priv
                            Scope        = $a.properties.scope
                            PrincipalId  = $a.properties.principalId
                        }
                    }
                }
            } catch {}
        }
    }

    # ---- Group-inherited assignments ----
    Write-Header 'Group-Inherited Assignments'
    Write-Host "[*] Querying assignments without principalId filter to detect role grants via group membership..." -ForegroundColor DarkGray
    $userGroups = @()
    if ($tokens.access_token) {
        try {
            $ghdr = @{ Authorization = "Bearer $($tokens.access_token)" }
            $gr = Invoke-RestMethod -Headers $ghdr -Uri "https://graph.microsoft.com/v1.0/me/transitiveMemberOf/microsoft.graph.group?`$select=id,displayName"
            $userGroups = @($gr.value)
        } catch {}
    }
    $userGroupIds = @($userGroups | ForEach-Object { $_.id })

    $inheritedFound = 0
    foreach ($s in $subs) {
        $subId = $s.subscriptionId
        try {
            $uri = "https://management.azure.com/subscriptions/$subId/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
            $assignments = @()
            do {
                $r = Invoke-RestMethod -Headers $armHdr -Uri $uri
                $assignments += $r.value
                $uri = $r.nextLink
            } while ($uri)
            foreach ($a in $assignments) {
                if ($userGroupIds -contains $a.properties.principalId) {
                    $g = $userGroups | Where-Object { $_.id -eq $a.properties.principalId } | Select-Object -First 1
                    $def = Get-RoleDef -scope $a.properties.scope -roleDefId $a.properties.roleDefinitionId
                    $name = if ($def) { $def.roleName } else { '<unresolved>' }
                    $priv = Test-PrivilegedRoleDef $def
                    $colour = if ($priv) { 'Red' } else { 'Yellow' }
                    $inheritedFound++
                    Write-Host "  - " -NoNewline
                    Write-Host $name -ForegroundColor $colour -NoNewline
                    Write-Host " via group '$($g.displayName)' " -ForegroundColor Magenta -NoNewline
                    Write-Host "scope=$($a.properties.scope)" -ForegroundColor DarkGray
                    $allAssignments += [pscustomobject]@{
                        Subscription = $s.displayName
                        SubscriptionId = $subId
                        RoleName     = "$name (via group: $($g.displayName))"
                        RoleType     = if ($def) { $def.type } else { '?' }
                        Privileged   = $priv
                        Scope        = $a.properties.scope
                        PrincipalId  = $a.properties.principalId
                    }
                }
            }
        } catch {}
    }
    if ($inheritedFound -eq 0) {
        Write-Host " <none>" -ForegroundColor DarkGray
    }

    # ---- Verdict ----
    Write-Header 'Verdict'
    $directCount   = @($allAssignments | Where-Object { $_.RoleName -notmatch 'via group' }).Count
    $inheritCount  = @($allAssignments | Where-Object { $_.RoleName -match 'via group' }).Count
    $privCount     = @($allAssignments | Where-Object Privileged).Count
    $subCount      = $subs.Count
    $mgCount       = $mgs.Count

    Write-KV 'Acting user is Guest'       $(if ($isGuest -eq $true) {'YES'} elseif ($isGuest -eq $false) {'no'} else {'unknown'}) $(if ($isGuest) {'Red'} else {'Green'})
    Write-KV 'Tenants visible'            $tenants.Count
    Write-KV 'Subscriptions accessible'   $subCount $(if ($subCount -gt 0) {'Red'} else {'Green'})
    Write-KV 'Management groups visible'  $mgCount $(if ($mgCount -gt 0) {'Red'} else {'Green'})
    Write-KV 'Direct role assignments'    $directCount $(if ($directCount -gt 0) {'Red'} else {'Green'})
    Write-KV 'Group-inherited assignments' $inheritCount $(if ($inheritCount -gt 0) {'Red'} else {'Green'})
    Write-KV 'Privileged assignments'     $privCount $(if ($privCount -gt 0) {'Red'} else {'Green'})

    Write-Host ""
    if ($isGuest -and $allAssignments.Count -gt 0) {
        Write-Host "[!] FINDING CONFIRMED: external/guest identity holds Azure Resource Manager access." -ForegroundColor Red
        if ($privCount -gt 0) {
            Write-Host "[!] PRIVILEGED ROLES PRESENT - this is the high-impact case for the writeup." -ForegroundColor Red
        }
    } elseif ($isGuest -and $allAssignments.Count -eq 0 -and $subCount -gt 0) {
        Write-Host "[!] Guest can enumerate subscription metadata but has no role assignments. Worth noting" -ForegroundColor Yellow
        Write-Host "    in the writeup, but lower severity than holding RBAC roles." -ForegroundColor DarkGray
    } elseif ($isGuest -and $allAssignments.Count -eq 0 -and $subCount -eq 0) {
        Write-Host "[+] Guest identity has no visible Azure resource access. Finding does not apply." -ForegroundColor Green
    } elseif (-not $isGuest -and $allAssignments.Count -gt 0) {
        Write-Host "[*] Member account with RBAC access. Re-run under a confirmed guest identity for the finding." -ForegroundColor Yellow
    } else {
        Write-Host "[+] No Azure RBAC access detected for this identity." -ForegroundColor Green
    }

    Write-Host ""
    Write-Host "[i] New ARM token stored in `$LegacyARMToken (original `$tokens unchanged)." -ForegroundColor DarkGray

    return [pscustomobject]@{
        Token        = $newTokens
        Jwt          = $jwt
        UserInfo     = $userInfo
        IsGuest      = $isGuest
        Tenants      = $tenants
        Subscriptions = $subs
        ManagementGroups = $mgs
        Assignments  = $allAssignments
    }
}

# ---- Auto-run when invoked as a script ----
if ($MyInvocation.InvocationName -ne '.') {
    Test-ExternalARMAccess -ClientId $ClientId -TenantId $TenantId -DeviceCode:$DeviceCode -h:$h -Help:$Help | Out-Null
}