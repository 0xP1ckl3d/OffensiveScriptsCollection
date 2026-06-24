<#
.SYNOPSIS
    Audit a user's group management permissions in Entra ID. Runs standalone or can be dot-sourced.

.DESCRIPTION
    Evidence collector for the "Excessive Group Management Permissions" finding.

    Produces two distinct evaluations per group:
      - Write Access (Passive): metadata-only inference from ownership, directory roles, and group
        type signals. No probe traffic.
      - Write Access (Probe): authoritative check against the Graph estimateAccess endpoint, asking
        whether the caller holds 'microsoft.directory/groups/members/update' on each group. This is
        the same mechanism GraphRunner's Get-UpdatableGroups uses. Read-only, non-destructive.

    Also reports the tenant's group creation policy and whether the acting user can create both
    Security Groups and Microsoft 365 Groups.

    -Live additionally performs an empirical add+remove of -TargetUser against each writable group
    and a create+delete of a temporary security group. Use with caution.

    Uses the existing $tokens variable for authentication.

.PARAMETER Group
    Optional. ObjectId, DisplayName, comma/semicolon list, or array. If omitted, sweeps the tenant.

.PARAMETER User
    Acting user. ObjectId | UPN | Mail | SamAccountName | DisplayName. Defaults to /me.

.PARAMETER TargetUser
    User to add/remove during -Live membership tests. Defaults to -User.

.PARAMETER Live
    Empirically validate via add+remove and create+delete. USE WITH CAUTION.

.PARAMETER NoProbe
    Skip the estimateAccess probe. Passive section only.

.PARAMETER v
    Only meaningful in tenant-wide mode. Include non-writable rows in the output.

.PARAMETER PassThru
    Return result objects to the pipeline instead of pretty-printing.

.EXAMPLE
    .\Invoke-TestGroupWriteAccess.ps1
    .\Invoke-TestGroupWriteAccess.ps1 -v
    .\Invoke-TestGroupWriteAccess.ps1 -Live
    .\Invoke-TestGroupWriteAccess.ps1 "Tech Services - Admins" -Live
    .\Invoke-TestGroupWriteAccess.ps1 $groupIds -TargetUser "jane.doe@contoso.com" -Live
#>
[CmdletBinding()]
param(
    [Parameter(Position=0)]
    [object]$Group,
    [Parameter(Position=1)]
    [string]$User,
    [string]$TargetUser,
    [switch]$Live,
    [switch]$NoProbe,
    [switch]$v,
    [switch]$PassThru,
    [switch]$h,
    [switch]$Help
)

function Test-GraphGroupWriteAccess {
    [CmdletBinding()]
    param(
        [Parameter(Position=0)]
        [object]$Group,
        [Parameter(Position=1)]
        [string]$User,
        [string]$TargetUser,
        [switch]$Live,
        [switch]$NoProbe,
        [switch]$v,
        [switch]$PassThru,
        [switch]$h,
        [switch]$Help
    )

    if ($h -or $Help) {
        Write-Host ""
        Write-Host "Invoke-TestGroupWriteAccess" -ForegroundColor Cyan
        Write-Host "---------------------------" -ForegroundColor Cyan
        Write-Host "  Evidence collector for 'Excessive Group Management Permissions'."
        Write-Host ""
        Write-Host "USAGE:" -ForegroundColor Yellow
        Write-Host "  .\Invoke-TestGroupWriteAccess.ps1 [group(s)] [user] [-TargetUser <u>] [-Live] [-NoProbe] [-v] [-PassThru]"
        Write-Host ""
        Write-Host "  No group args : enumerate every group in the tenant."
        Write-Host "                  Default output is writable groups only. -v adds the rest."
        Write-Host "  With group(s) : audit only the supplied groups. All rows shown."
        Write-Host "  Default       : passive metadata inference, then estimateAccess probe."
        Write-Host "  -NoProbe      : passive only."
        Write-Host "  -Live         : also empirically test add/remove and create+delete."
        Write-Host ""
        Write-Host "REQUIRES:" -ForegroundColor Yellow
        Write-Host "  `$tokens variable in the calling session with a valid Graph access_token."
        Write-Host ""
        return
    }

    if (-not $tokens.access_token) {
        Write-Host "[!] No `$tokens.access_token found in the current session. Authenticate first." -ForegroundColor Red
        return
    }

    $hdr = @{
        Authorization  = "Bearer $($tokens.access_token)"
        'Content-Type' = 'application/json'
    }

    $UriT = [type]'System.Uri'
    function _Enc([string]$s) { $UriT::EscapeDataString($s) }

    function Write-Header($t) { Write-Host "`n==== $t ====" -ForegroundColor Cyan }
    function Write-KV($k,$val,$vc='White') {
        Write-Host ("{0,-46}: " -f $k) -ForegroundColor Yellow -NoNewline
        Write-Host $val -ForegroundColor $vc
    }

    $guidRx = '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'
    $samRx  = '^[A-Za-z0-9._-]+$'

    $writeRoles = @(
        'Global Administrator',
        'Privileged Role Administrator',
        'User Administrator',
        'Groups Administrator',
        'Directory Writers',
        'Identity Governance Administrator',
        'Exchange Administrator',
        'Teams Administrator',
        'SharePoint Administrator'
    )

    function Resolve-GraphUser([string]$ident, [switch]$AllowMe) {
        if (-not $ident) {
            if ($AllowMe) {
                try { return Invoke-RestMethod -Headers $hdr -Uri "https://graph.microsoft.com/v1.0/me`?`$select=id,displayName,userPrincipalName,mail,onPremisesSamAccountName,accountEnabled" } catch { return $null }
            }
            return $null
        }
        if ($ident -match $guidRx) {
            try { return Invoke-RestMethod -Headers $hdr -Uri "https://graph.microsoft.com/v1.0/users/$ident`?`$select=id,displayName,userPrincipalName,mail,onPremisesSamAccountName,accountEnabled" } catch { return $null }
        }
        if ($ident -match '@') {
            try { return Invoke-RestMethod -Headers $hdr -Uri "https://graph.microsoft.com/v1.0/users/$(_Enc $ident)`?`$select=id,displayName,userPrincipalName,mail,onPremisesSamAccountName,accountEnabled" } catch {}
            try {
                $enc = _Enc $ident
                $r = Invoke-RestMethod -Headers $hdr -Uri "https://graph.microsoft.com/v1.0/users?`$filter=mail eq '$enc' or userPrincipalName eq '$enc'&`$select=id,displayName,userPrincipalName,mail,onPremisesSamAccountName,accountEnabled"
                return $r.value | Select-Object -First 1
            } catch { return $null }
        }
        if ($ident -match $samRx) {
            try {
                $enc = _Enc $ident
                $r = Invoke-RestMethod -Headers $hdr -Uri "https://graph.microsoft.com/v1.0/users?`$filter=onPremisesSamAccountName eq '$enc' or mailNickname eq '$enc'&`$select=id,displayName,userPrincipalName,mail,onPremisesSamAccountName,accountEnabled"
                if ($r.value.Count -gt 0) { return $r.value[0] }
            } catch {}
        }
        try {
            $enc = _Enc $ident
            $r = Invoke-RestMethod -Headers $hdr -Uri "https://graph.microsoft.com/v1.0/users?`$filter=startswith(displayName,'$enc')&`$top=10&`$select=id,displayName,userPrincipalName,mail,onPremisesSamAccountName,accountEnabled"
            if ($r.value.Count -gt 1) {
                Write-Host "[!] Multiple users matched '$ident':" -ForegroundColor Yellow
                $r.value | ForEach-Object { Write-Host " - $($_.displayName)  <$($_.userPrincipalName)>  $($_.id)" -ForegroundColor DarkGray }
                Write-Host "[!] Re-run with UPN, mail, SamAccountName or ObjectId for a unique match." -ForegroundColor Yellow
                return $null
            }
            return $r.value | Select-Object -First 1
        } catch { return $null }
    }

    # ---- Resolve acting user ----
    Write-Header 'Resolving Acting User'
    if (-not $User) {
        Write-Host "[*] No user supplied, resolving current token holder via /me" -ForegroundColor DarkGray
    }
    $u = Resolve-GraphUser -ident $User -AllowMe
    if (-not $u) {
        Write-Host "[!] Could not resolve acting user." -ForegroundColor Red
        return
    }
    Write-KV 'DisplayName' $u.displayName Green
    Write-KV 'UPN'         $u.userPrincipalName Green
    Write-KV 'ObjectId'    $u.id
    Write-KV 'Enabled'     $u.accountEnabled $(if ($u.accountEnabled) {'Green'} else {'Red'})

    # ---- Acting user directory roles ----
    Write-Header 'Acting User Directory Roles'
    $userRoles = @()
    try {
        $rr = Invoke-RestMethod -Headers $hdr -Uri "https://graph.microsoft.com/v1.0/users/$($u.id)/memberOf/microsoft.graph.directoryRole?`$select=id,displayName,roleTemplateId"
        $userRoles = @($rr.value)
    } catch {
        Write-Host "[!] Could not read directory roles for user: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    if ($userRoles.Count -eq 0) {
        Write-Host ' <none>' -ForegroundColor DarkGray
    } else {
        $userRoles | ForEach-Object { Write-Host " - $($_.displayName)" -ForegroundColor Red }
    }
    $tenantWriteRole = @($userRoles | Where-Object { $writeRoles -contains $_.displayName })
    $hasTenantWrite  = $tenantWriteRole.Count -gt 0

    # ---- Group creation capability ----
    Write-Header 'Group Creation Capability'
    $secCreate = $null
    $m365Create = $null
    try {
        $authPolicy = Invoke-RestMethod -Headers $hdr -Uri "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"
        $secCreate = $authPolicy.defaultUserRolePermissions.allowedToCreateSecurityGroups
        Write-KV 'User can create Security Group (Default Permission)' $secCreate $(if ($secCreate) {'Red'} else {'Green'})
    } catch {
        Write-Host "[!] Could not read authorizationPolicy: $($_.Exception.Response.StatusCode.value__)" -ForegroundColor Yellow
    }
    try {
        $gs = Invoke-RestMethod -Headers $hdr -Uri "https://graph.microsoft.com/v1.0/groupSettings"
        $unified = $gs.value | Where-Object { $_.displayName -eq 'Group.Unified' } | Select-Object -First 1
        if ($unified) {
            $enable = ($unified.values | Where-Object name -eq 'EnableGroupCreation').value
            $allowedGid = ($unified.values | Where-Object name -eq 'GroupCreationAllowedGroupId').value
            if ($enable -eq 'true' -and -not $allowedGid) {
                $m365Create = $true
                Write-KV 'User can create Microsoft 365 Group (Default Permission)' 'True (unrestricted)' Red
            } elseif ($enable -eq 'true' -and $allowedGid) {
                $m365Create = 'restricted'
                Write-KV 'User can create Microsoft 365 Group (Default Permission)' "Restricted to group $allowedGid" Yellow
            } else {
                $m365Create = $false
                Write-KV 'User can create Microsoft 365 Group (Default Permission)' 'False' Green
            }
        } else {
            Write-KV 'User can create Microsoft 365 Group (Default Permission)' 'True (no Group.Unified setting, tenant default)' Red
            $m365Create = $true
        }
    } catch {
        Write-Host "[!] Could not read groupSettings: $($_.Exception.Response.StatusCode.value__)" -ForegroundColor Yellow
    }
    if ($hasTenantWrite) {
        Write-KV 'Effective creation capability for this user' 'YES via tenant role' Red
    } elseif ($secCreate -or $m365Create -eq $true) {
        Write-KV 'Effective creation capability for this user' 'YES via default user permissions' Red
    } else {
        Write-KV 'Effective creation capability for this user' 'No, blocked by policy' Green
    }

    if ($Live) {
        $stamp = (Get-Date).ToString('yyyyMMddHHmmss')
        $tmpName = "pt-write-access-test-$stamp"
        $body = @{
            displayName     = $tmpName
            mailEnabled     = $false
            mailNickname    = "pttest$stamp"
            securityEnabled = $true
            description     = 'Temporary group created by Invoke-TestGroupWriteAccess for permission validation. Safe to delete.'
        } | ConvertTo-Json
        try {
            $created = Invoke-RestMethod -Headers $hdr -Method POST -Uri "https://graph.microsoft.com/v1.0/groups" -Body $body
            Write-Host "[+] Live create succeeded: $tmpName ($($created.id))" -ForegroundColor Red
            try {
                Invoke-RestMethod -Headers $hdr -Method DELETE -Uri "https://graph.microsoft.com/v1.0/groups/$($created.id)" | Out-Null
                Write-Host "[+] Rollback succeeded, group deleted" -ForegroundColor DarkGray
            } catch {
                Write-Host "[!] ROLLBACK FAILED HTTP $($_.Exception.Response.StatusCode.value__). Test group $tmpName ($($created.id)) still exists." -ForegroundColor Red
            }
        } catch {
            Write-Host "[-] Live create denied HTTP $($_.Exception.Response.StatusCode.value__)" -ForegroundColor Green
        }
    }

    # ---- Resolve target user for live membership tests ----
    $tu = $null
    if ($Live) {
        Write-Header 'Resolving Target User (membership tests)'
        if (-not $TargetUser) {
            Write-Host "[*] No -TargetUser supplied, defaulting to acting user" -ForegroundColor DarkGray
            $tu = $u
        } else {
            $tu = Resolve-GraphUser -ident $TargetUser
            if (-not $tu) {
                Write-Host "[!] Could not resolve target user '$TargetUser'." -ForegroundColor Red
                return
            }
        }
        Write-KV 'DisplayName' $tu.displayName Green
        Write-KV 'UPN'         $tu.userPrincipalName Green
        Write-KV 'ObjectId'    $tu.id
    }

    # ---- Acting user owned groups ----
    $ownedIds = @()
    try {
        $oo = Invoke-RestMethod -Headers $hdr -Uri "https://graph.microsoft.com/v1.0/users/$($u.id)/ownedObjects/microsoft.graph.group?`$select=id"
        $ownedIds = @($oo.value | ForEach-Object { $_.id })
    } catch {}

    # ---- Build group set ----
    $groupTokens = @()
    if ($Group) {
        if ($Group -is [array]) {
            $groupTokens = $Group | ForEach-Object { "$_" }
        } else {
            $groupTokens = ("$Group") -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
        }
    }
    $explicitMode = $groupTokens.Count -gt 0

    $resolved = @()

    if ($explicitMode) {
        Write-Header "Resolving Groups ($($groupTokens.Count))"
        foreach ($t in $groupTokens) {
            try {
                if ($t -match $guidRx) {
                    $g = Invoke-RestMethod -Headers $hdr -Uri "https://graph.microsoft.com/v1.0/groups/$t`?`$select=id,displayName,securityEnabled,mailEnabled,groupTypes,isAssignableToRole,membershipRule,visibility"
                    $resolved += [pscustomobject]@{ Input = $t; Id = $g.id; Name = $g.displayName; Group = $g; Error = $null }
                } else {
                    $enc = _Enc $t
                    $r = Invoke-RestMethod -Headers $hdr -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$enc'&`$select=id,displayName,securityEnabled,mailEnabled,groupTypes,isAssignableToRole,membershipRule,visibility"
                    if ($r.value.Count -eq 0) {
                        $r = Invoke-RestMethod -Headers $hdr -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=startswith(displayName,'$enc')&`$top=10&`$select=id,displayName,securityEnabled,mailEnabled,groupTypes,isAssignableToRole,membershipRule,visibility"
                    }
                    if ($r.value.Count -eq 0) {
                        $resolved += [pscustomobject]@{ Input = $t; Id = $null; Name = $null; Group = $null; Error = 'NOT FOUND' }
                    } elseif ($r.value.Count -gt 1) {
                        Write-Host "[!] Multiple groups matched '$t':" -ForegroundColor Yellow
                        $r.value | ForEach-Object { Write-Host " - $($_.displayName)  [$($_.id)]" -ForegroundColor DarkGray }
                        $resolved += [pscustomobject]@{ Input = $t; Id = $null; Name = $null; Group = $null; Error = 'AMBIGUOUS' }
                    } else {
                        $g = $r.value[0]
                        $resolved += [pscustomobject]@{ Input = $t; Id = $g.id; Name = $g.displayName; Group = $g; Error = $null }
                    }
                }
            } catch {
                $code = $_.Exception.Response.StatusCode.value__
                $resolved += [pscustomobject]@{ Input = $t; Id = $null; Name = $null; Group = $null; Error = "HTTP $code" }
            }

            $last = $resolved[-1]
            if ($last.Error) {
                Write-Host (" {0,-40} " -f $last.Input) -ForegroundColor DarkGray -NoNewline
                Write-Host "-> $($last.Error)" -ForegroundColor Red
            } else {
                $tag = ''
                if ($last.Group.securityEnabled) { $tag += ' [sec]' }
                if ($last.Group.mailEnabled)     { $tag += ' [mail]' }
                if ($last.Group.groupTypes -contains 'Unified') { $tag += ' [m365]' }
                if ($last.Group.groupTypes -contains 'DynamicMembership') { $tag += ' [dynamic]' }
                if ($last.Group.isAssignableToRole) { $tag += ' [role-assignable]' }
                Write-Host (" {0,-40} " -f $last.Id) -ForegroundColor DarkGray -NoNewline
                Write-Host $last.Name -ForegroundColor Green -NoNewline
                Write-Host $tag -ForegroundColor Magenta
            }
        }
    }
    else {
        Write-Header 'Enumerating All Tenant Groups'
        Write-Host "[*] Paging /groups (this can take a while in large tenants)..." -ForegroundColor DarkGray
        $uri = "https://graph.microsoft.com/v1.0/groups?`$select=id,displayName,securityEnabled,mailEnabled,groupTypes,isAssignableToRole,membershipRule,visibility&`$top=999"
        try {
            do {
                $r = Invoke-RestMethod -Headers $hdr -Uri $uri
                foreach ($g in $r.value) {
                    $resolved += [pscustomobject]@{ Input = $g.id; Id = $g.id; Name = $g.displayName; Group = $g; Error = $null }
                }
                $uri = $r.'@odata.nextLink'
                Write-Host ("`r[*] Retrieved {0} groups..." -f $resolved.Count) -ForegroundColor DarkGray -NoNewline
            } while ($uri)
            Write-Host ""
            Write-Host "[*] Total groups: $($resolved.Count)" -ForegroundColor DarkGray
        } catch {
            Write-Host ""
            Write-Host "[!] Tenant group enumeration failed: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    if ($resolved.Count -eq 0) {
        $script:LastGroupWriteAccessResults = @()
        return
    }

    # ---- Pass 1: Passive metadata-only evaluation ----
    $passive = foreach ($g in $resolved) {
        if ($g.Error) {
            [pscustomobject]@{
                GroupId  = $g.Input
                Name     = "<$($g.Error)>"
                Verdict  = 'UNRESOLVED'
                Reason   = $g.Error
            }
            continue
        }
        $gobj    = $g.Group
        $reasons = @()
        $verdict = 'NO WRITE'

        if ($ownedIds -contains $g.Id) {
            $reasons += 'owner'
            $verdict = 'WRITE'
        }
        if ($hasTenantWrite) {
            $reasons += "role:$(($tenantWriteRole | ForEach-Object displayName) -join ',')"
            $verdict = 'WRITE'
        }
        if ($gobj.groupTypes -contains 'DynamicMembership') {
            $reasons += 'dynamic (members not directly writable)'
        }
        if ($gobj.isAssignableToRole -and -not $hasTenantWrite) {
            $reasons += 'role-assignable (requires Priv Role Admin)'
            if ($verdict -eq 'NO WRITE') { $verdict = 'RESTRICTED' }
        }
        if ($reasons.Count -eq 0) { $reasons += 'no ownership, no tenant role' }

        [pscustomobject]@{
            GroupId  = $g.Id
            Name     = $g.Name
            Verdict  = $verdict
            Reason   = ($reasons -join '; ')
        }
    }

    Write-Header 'Write Access (Passive)'
    Display-Results -Rows $passive -ExplicitMode:$explicitMode -Verbose:$v

    # ---- Pass 2: estimateAccess probe ----
    $probe = $null
    if (-not $NoProbe) {
        Write-Header 'Write Access (Probe)'
        Write-Host "[*] Probing each group via estimateAccess (microsoft.directory/groups/members/update)..." -ForegroundColor DarkGray

        $estimateUri = 'https://graph.microsoft.com/beta/roleManagement/directory/estimateAccess'
        $idx = 0
        $total = $resolved.Count
        $probe = foreach ($g in $resolved) {
            $idx++
            if (-not $explicitMode -and ($idx % 25 -eq 0 -or $idx -eq $total)) {
                Write-Host ("`r[*] Evaluating {0}/{1}..." -f $idx, $total) -ForegroundColor DarkGray -NoNewline
            }
            if ($g.Error) {
                [pscustomobject]@{
                    GroupId  = $g.Input
                    Name     = "<$($g.Error)>"
                    Verdict  = 'UNRESOLVED'
                    Reason   = $g.Error
                }
                continue
            }

            $req = @{
                resourceActionAuthorizationChecks = @(
                    @{
                        directoryScopeId = "/$($g.Id)"
                        resourceAction   = 'microsoft.directory/groups/members/update'
                    }
                )
            } | ConvertTo-Json -Depth 4

            $verdict = 'NO WRITE'
            $reason  = 'estimateAccess: denied'
            try {
                $resp = Invoke-RestMethod -Headers $hdr -Method POST -Uri $estimateUri -Body $req
                $check = $resp.value | Select-Object -First 1
                if ($check.accessDecision -eq 'allowed' -or $check.hasAccess -eq $true) {
                    $verdict = 'WRITE'
                    $reason  = 'estimateAccess: allowed'
                } else {
                    $verdict = 'NO WRITE'
                    $reason  = "estimateAccess: $($check.accessDecision)"
                }
            } catch {
                $code = $_.Exception.Response.StatusCode.value__
                $verdict = 'UNKNOWN'
                $reason  = "estimateAccess: HTTP $code"
            }

            [pscustomobject]@{
                GroupId  = $g.Id
                Name     = $g.Name
                Verdict  = $verdict
                Reason   = $reason
            }
        }
        if (-not $explicitMode) { Write-Host "" }
        Display-Results -Rows $probe -ExplicitMode:$explicitMode -Verbose:$v
    }

    # ---- Pass 3: Live add/remove ----
    $live = $null
    if ($Live) {
        Write-Header 'Write Access (Live add/remove)'
        $live = foreach ($g in $resolved) {
            if ($g.Error) { continue }
            if ($g.Group.groupTypes -contains 'DynamicMembership') {
                [pscustomobject]@{
                    GroupId  = $g.Id
                    Name     = $g.Name
                    Verdict  = 'SKIPPED'
                    Reason   = 'dynamic membership, not directly writable'
                }
                continue
            }

            $verdict = 'NO WRITE'
            $reason  = ''

            $alreadyMember = $false
            try {
                $chk = Invoke-RestMethod -Headers $hdr -Uri "https://graph.microsoft.com/v1.0/groups/$($g.Id)/members/microsoft.graph.user?`$filter=id eq '$($tu.id)'&`$select=id"
                if ($chk.value.Count -gt 0) { $alreadyMember = $true }
            } catch {}

            if ($alreadyMember) {
                $reason = 'live: target already a member, skipped'
                $verdict = 'SKIPPED'
            } else {
                $body = @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$($tu.id)" } | ConvertTo-Json
                $addOk = $false
                $addErr = $null
                try {
                    Invoke-RestMethod -Headers $hdr -Method POST -Uri "https://graph.microsoft.com/v1.0/groups/$($g.Id)/members/`$ref" -Body $body | Out-Null
                    $addOk = $true
                } catch {
                    $addErr = $_.Exception.Response.StatusCode.value__
                }
                if ($addOk) {
                    $verdict = 'WRITE'
                    $reason = 'live: add succeeded'
                    try {
                        Invoke-RestMethod -Headers $hdr -Method DELETE -Uri "https://graph.microsoft.com/v1.0/groups/$($g.Id)/members/$($tu.id)/`$ref" | Out-Null
                        $reason += '; rollback ok'
                    } catch {
                        $reason += "; ROLLBACK FAILED HTTP $($_.Exception.Response.StatusCode.value__)"
                    }
                } else {
                    $reason = "live: add denied HTTP $addErr"
                }
            }

            [pscustomobject]@{
                GroupId  = $g.Id
                Name     = $g.Name
                Verdict  = $verdict
                Reason   = $reason
            }
        }
        Display-Results -Rows $live -ExplicitMode:$explicitMode -Verbose:$v
    }

    if ($PassThru) {
        return [pscustomobject]@{
            Passive = $passive
            Probe   = $probe
            Live    = $live
        }
    }

    $script:LastGroupWriteAccessResults = [pscustomobject]@{
        Passive = $passive
        Probe   = $probe
        Live    = $live
    }

    if (-not $explicitMode -and -not $v) {
        Write-Host ""
        Write-Host "[i] Re-run with -v to include non-writable groups in the tables." -ForegroundColor DarkGray
    }
    if (-not $Live) {
        Write-Host "[i] Drop -Live to also empirically validate add/remove and create+delete." -ForegroundColor DarkGray
    }
}

function Display-Results {
    param(
        [object[]]$Rows,
        [switch]$ExplicitMode,
        [switch]$Verbose
    )

    if (-not $Rows -or $Rows.Count -eq 0) {
        Write-Host " <no results>" -ForegroundColor DarkGray
        return
    }

    if ($ExplicitMode -or $Verbose) {
        $display = $Rows
    } else {
        $display = @($Rows | Where-Object Verdict -eq 'WRITE')
    }

    if ($display.Count -eq 0) {
        Write-Host " <no writable groups>" -ForegroundColor Green
    } else {
        $maxName = ($display.Name | Measure-Object -Maximum -Property Length).Maximum
        if (-not $maxName) { $maxName = 4 }
        $nameWidth = if ($maxName -gt 50) { 50 } else { $maxName }
        if ($nameWidth -lt 4) { $nameWidth = 4 }

        foreach ($row in $display) {
            $label = switch ($row.Verdict) {
                'WRITE'      { 'WRITE ACCESS' }
                'NO WRITE'   { 'NO WRITE' }
                'RESTRICTED' { 'RESTRICTED' }
                'UNRESOLVED' { 'UNRESOLVED' }
                'UNKNOWN'    { 'UNKNOWN' }
                'SKIPPED'    { 'SKIPPED' }
                default      { $row.Verdict }
            }
            $colour = switch ($row.Verdict) {
                'WRITE'      { 'Red' }
                'NO WRITE'   { 'Green' }
                'RESTRICTED' { 'Yellow' }
                'UNRESOLVED' { 'Yellow' }
                'UNKNOWN'    { 'Yellow' }
                'SKIPPED'    { 'DarkGray' }
                default      { 'White' }
            }
            $nm = if ($row.Name) { $row.Name } else { '' }
            if ($nm.Length -gt $nameWidth) { $nm = $nm.Substring(0, $nameWidth - 1) + '...' }

            Write-Host (" {0,-38} " -f $row.GroupId) -ForegroundColor DarkGray -NoNewline
            Write-Host (("{0,-" + $nameWidth + "} ") -f $nm) -ForegroundColor White -NoNewline
            Write-Host ("{0,-13}" -f $label) -ForegroundColor $colour -NoNewline
            Write-Host "  $($row.Reason)" -ForegroundColor DarkGray
        }
    }

    $w  = @($Rows | Where-Object Verdict -eq 'WRITE').Count
    $nw = @($Rows | Where-Object Verdict -eq 'NO WRITE').Count
    $rs = @($Rows | Where-Object Verdict -eq 'RESTRICTED').Count
    $un = @($Rows | Where-Object Verdict -in 'UNRESOLVED','UNKNOWN').Count
    $sk = @($Rows | Where-Object Verdict -eq 'SKIPPED').Count
    Write-Host ""
    Write-Host "Summary: " -ForegroundColor Cyan -NoNewline
    Write-Host "$w write " -ForegroundColor Red -NoNewline
    Write-Host "/ $nw no-write " -ForegroundColor Green -NoNewline
    if ($rs -gt 0) { Write-Host "/ $rs restricted " -ForegroundColor Yellow -NoNewline }
    if ($sk -gt 0) { Write-Host "/ $sk skipped " -ForegroundColor DarkGray -NoNewline }
    Write-Host "/ $un unresolved" -ForegroundColor Yellow
}

# ---- Auto-run when invoked as a script ----
if ($MyInvocation.InvocationName -ne '.') {
    Test-GraphGroupWriteAccess -Group $Group -User $User -TargetUser $TargetUser -Live:$Live -NoProbe:$NoProbe -v:$v -PassThru:$PassThru -h:$h -Help:$Help
}