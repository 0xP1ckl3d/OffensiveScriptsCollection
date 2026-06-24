<#
.SYNOPSIS
    Test whether a user is a member of one or more Entra ID groups. Runs standalone or can be dot-sourced.

.DESCRIPTION
    Accepts a user (ObjectId, UPN, mail, SamAccountName or DisplayName) and one or more groups
    (ObjectId, DisplayName or a comma/semicolon-separated list, or an array). Resolves both, then
    reports membership against each group. Supports transitive (nested) membership checks.

    If no user is supplied, the current token holder (/me) is used.

    Uses the existing $tokens variable for authentication.

.PARAMETER Group
    One or more group identifiers. Accepts:
      - ObjectId (GUID)
      - DisplayName (exact or partial)
      - A comma or semicolon separated list of any of the above
      - A PowerShell array of any of the above

.PARAMETER User
    The user to test. Accepts:
      - ObjectId (GUID)
      - UPN (user@domain)
      - Mail
      - SamAccountName (onPremisesSamAccountName)
      - DisplayName (partial OK)
    If omitted, defaults to the current token holder via /me.

.PARAMETER Transitive
    Use transitiveMembers to include nested group membership.

.PARAMETER PassThru
    Return result objects to the pipeline instead of pretty-printing.

.EXAMPLE
    .\Invoke-TestGroupMembership.ps1 "All Company"
    .\Invoke-TestGroupMembership.ps1 "All Company" "jane.doe@contoso.com"
    .\Invoke-TestGroupMembership.ps1 "Group A,Group B,Group C" "Jane Doe"
    .\Invoke-TestGroupMembership.ps1 $groupIds 11111111-2222-3333-4444-555555555555 -Transitive

.EXAMPLE
    . .\Invoke-TestGroupMembership.ps1
    Test-GraphGroupMembership -Group $groupIds -User "jane.doe@contoso.com"
#>
[CmdletBinding()]
param(
    [Parameter(Position=0)]
    [object]$Group,
    [Parameter(Position=1)]
    [string]$User,
    [switch]$Transitive,
    [switch]$PassThru,
    [switch]$h,
    [switch]$Help
)

function Test-GraphGroupMembership {
    [CmdletBinding()]
    param(
        [Parameter(Position=0)]
        [object]$Group,
        [Parameter(Position=1)]
        [string]$User,
        [switch]$Transitive,
        [switch]$PassThru,
        [switch]$h,
        [switch]$Help
    )

    if (-not $Group -or $h -or $Help) {
        Write-Host ""
        Write-Host "Invoke-TestGroupMembership" -ForegroundColor Cyan
        Write-Host "--------------------------" -ForegroundColor Cyan
        Write-Host "  Test whether a user belongs to one or more Entra ID groups."
        Write-Host ""
        Write-Host "USAGE:" -ForegroundColor Yellow
        Write-Host "  .\Invoke-TestGroupMembership.ps1 <group(s)> [user] [-Transitive] [-PassThru]"
        Write-Host "  Test-GraphGroupMembership -Group <group(s)> [-User <user>] [-Transitive] [-PassThru]   (when dot-sourced)"
        Write-Host ""
        Write-Host "  If <user> is omitted, the current token holder (/me) is used."
        Write-Host ""
        Write-Host "ACCEPTS for <group(s)>:" -ForegroundColor Yellow
        Write-Host "  - ObjectId (GUID)"
        Write-Host "  - DisplayName (exact or partial)"
        Write-Host "  - Comma or semicolon separated list"
        Write-Host "  - PowerShell array of any of the above"
        Write-Host ""
        Write-Host "ACCEPTS for <user>:" -ForegroundColor Yellow
        Write-Host "  - ObjectId | UPN | Mail | SamAccountName | DisplayName"
        Write-Host ""
        Write-Host "EXAMPLES:" -ForegroundColor Yellow
        Write-Host '  .\Invoke-TestGroupMembership.ps1 "All Company"                       # defaults to current user'
        Write-Host '  .\Invoke-TestGroupMembership.ps1 "All Company" "jane.doe@contoso.com"'
        Write-Host '  .\Invoke-TestGroupMembership.ps1 "Group A,Group B,Group C" "Jane Doe"'
        Write-Host "  .\Invoke-TestGroupMembership.ps1 `$groupIds jdoe -Transitive"
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
    function Write-KV($k,$v,$vc='White') {
        Write-Host ("{0,-14}: " -f $k) -ForegroundColor Yellow -NoNewline
        Write-Host $v -ForegroundColor $vc
    }

    $guidRx = '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'
    $samRx  = '^[A-Za-z0-9._-]+$'

    # ---- Normalise group input into a flat string array ----
    $groupTokens = @()
    if ($Group -is [array]) {
        $groupTokens = $Group | ForEach-Object { "$_" }
    } else {
        $groupTokens = ("$Group") -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    }

    if ($groupTokens.Count -eq 0) {
        Write-Host "[!] No groups provided." -ForegroundColor Red
        return
    }

    # ---- Resolve user ----
    Write-Header 'Resolving User'
    $u = $null

    if (-not $User) {
        Write-Host "[*] No user supplied, resolving current token holder via /me" -ForegroundColor DarkGray
        try {
            $u = Invoke-RestMethod -Headers $hdr -Uri "https://graph.microsoft.com/v1.0/me`?`$select=id,displayName,userPrincipalName,mail,onPremisesSamAccountName,accountEnabled"
        } catch {
            Write-Host "[!] /me lookup failed: $($_.Exception.Message)" -ForegroundColor Red
            return
        }
    }
    elseif ($User -match $guidRx) {
        try {
            $u = Invoke-RestMethod -Headers $hdr -Uri "https://graph.microsoft.com/v1.0/users/$User`?`$select=id,displayName,userPrincipalName,mail,onPremisesSamAccountName,accountEnabled"
        } catch {
            Write-Host "[!] User lookup by ObjectId failed: $($_.Exception.Message)" -ForegroundColor Red
            return
        }
    }
    elseif ($User -match '@') {
        # Try direct UPN, then mail/UPN filter
        try {
            $u = Invoke-RestMethod -Headers $hdr -Uri "https://graph.microsoft.com/v1.0/users/$(_Enc $User)`?`$select=id,displayName,userPrincipalName,mail,onPremisesSamAccountName,accountEnabled"
        } catch {
            try {
                $enc = _Enc $User
                $r = Invoke-RestMethod -Headers $hdr -Uri "https://graph.microsoft.com/v1.0/users?`$filter=mail eq '$enc' or userPrincipalName eq '$enc'&`$select=id,displayName,userPrincipalName,mail,onPremisesSamAccountName,accountEnabled"
                $u = $r.value | Select-Object -First 1
            } catch {
                Write-Host "[!] User lookup by mail/UPN failed: $($_.Exception.Message)" -ForegroundColor Red
                return
            }
        }
    }
    else {
        # Try sam/mailNickname only if input could plausibly be one (no spaces, basic charset)
        if ($User -match $samRx) {
            try {
                $enc = _Enc $User
                $r = Invoke-RestMethod -Headers $hdr -Uri "https://graph.microsoft.com/v1.0/users?`$filter=onPremisesSamAccountName eq '$enc' or mailNickname eq '$enc'&`$select=id,displayName,userPrincipalName,mail,onPremisesSamAccountName,accountEnabled"
                $u = $r.value | Select-Object -First 1
            } catch {
                # ignore and fall through to displayName
            }
        }

        # Fall back to displayName startswith
        if (-not $u) {
            try {
                $enc = _Enc $User
                $r = Invoke-RestMethod -Headers $hdr -Uri "https://graph.microsoft.com/v1.0/users?`$filter=startswith(displayName,'$enc')&`$top=10&`$select=id,displayName,userPrincipalName,mail,onPremisesSamAccountName,accountEnabled"
                if ($r.value.Count -gt 1) {
                    Write-Host "[!] Multiple users matched '$User':" -ForegroundColor Yellow
                    $r.value | ForEach-Object { Write-Host " - $($_.displayName)  <$($_.userPrincipalName)>  $($_.id)" -ForegroundColor DarkGray }
                    Write-Host "[!] Re-run with UPN, mail, SamAccountName or ObjectId for a unique match." -ForegroundColor Yellow
                    return
                }
                $u = $r.value | Select-Object -First 1
            } catch {
                Write-Host "[!] User lookup by displayName failed: $($_.Exception.Message)" -ForegroundColor Red
                return
            }
        }
    }

    if (-not $u) {
        Write-Host "[!] No user found matching '$User'." -ForegroundColor Red
        return
    }

    Write-KV 'DisplayName' $u.displayName Green
    Write-KV 'UPN'         $u.userPrincipalName Green
    Write-KV 'ObjectId'    $u.id
    Write-KV 'Mail'        $u.mail
    Write-KV 'SamAccount'  $u.onPremisesSamAccountName
    Write-KV 'Enabled'     $u.accountEnabled $(if ($u.accountEnabled) {'Green'} else {'Red'})

    # ---- Resolve groups ----
    Write-Header "Resolving Groups ($($groupTokens.Count))"
    $resolved = @()
    foreach ($t in $groupTokens) {
        try {
            if ($t -match $guidRx) {
                $g = Invoke-RestMethod -Headers $hdr -Uri "https://graph.microsoft.com/v1.0/groups/$t`?`$select=id,displayName,securityEnabled,mailEnabled,groupTypes"
                $resolved += [pscustomobject]@{ Input = $t; Id = $g.id; Name = $g.displayName; Group = $g; Error = $null }
            } else {
                $enc = _Enc $t
                $r = Invoke-RestMethod -Headers $hdr -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$enc'&`$select=id,displayName,securityEnabled,mailEnabled,groupTypes"
                if ($r.value.Count -eq 0) {
                    $r = Invoke-RestMethod -Headers $hdr -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=startswith(displayName,'$enc')&`$top=10&`$select=id,displayName,securityEnabled,mailEnabled,groupTypes"
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
            Write-Host "-> " -ForegroundColor DarkGray -NoNewline
            Write-Host $last.Error -ForegroundColor Red
        } else {
            $tag = ''
            if ($last.Group.securityEnabled) { $tag += ' [sec]' }
            if ($last.Group.mailEnabled)     { $tag += ' [mail]' }
            if ($last.Group.groupTypes -contains 'Unified') { $tag += ' [m365]' }
            Write-Host (" {0,-40} " -f $last.Id) -ForegroundColor DarkGray -NoNewline
            Write-Host $last.Name -ForegroundColor Green -NoNewline
            Write-Host $tag -ForegroundColor Magenta
        }
    }

    # ---- Membership test ----
    $memberPath = if ($Transitive) { 'transitiveMembers' } else { 'members' }
    $mode = if ($Transitive) { 'transitive' } else { 'direct' }
    Write-Header "Membership ($mode)"

    $results = foreach ($g in $resolved) {
        if ($g.Error) {
            [pscustomobject]@{
                GroupId  = $g.Input
                Name     = "<$($g.Error)>"
                IsMember = 'N/A'
                Status   = $g.Error
            }
            continue
        }

        $isMember = $null
        $status   = 'OK'
        try {
            $found = $false
            $uri = "https://graph.microsoft.com/v1.0/groups/$($g.Id)/$memberPath/microsoft.graph.user?`$select=id&`$top=999"
            do {
                $r = Invoke-RestMethod -Headers $hdr -Uri $uri
                if ($r.value.id -contains $u.id) { $found = $true; break }
                $uri = $r.'@odata.nextLink'
            } while ($uri)
            $isMember = if ($found) { 'YES' } else { 'NO' }
        } catch {
            $code = $_.Exception.Response.StatusCode.value__
            $isMember = 'ERROR'
            $status   = "HTTP $code"
        }

        [pscustomobject]@{
            GroupId  = $g.Id
            Name     = $g.Name
            IsMember = $isMember
            Status   = $status
        }
    }

    if ($PassThru) {
            return $results
        }

    $maxName = ($results.Name | Measure-Object -Maximum -Property Length).Maximum
    if (-not $maxName) { $maxName = 4 }
    $nameWidth = if ($maxName -gt 60) { 60 } else { $maxName }
    if ($nameWidth -lt 4) { $nameWidth = 4 }

    foreach ($row in $results) {
        $label = switch ($row.IsMember) {
            'YES'   { 'MEMBER' }
            'NO'    { 'NOT A MEMBER' }
            'N/A'   { 'UNRESOLVED' }
            'ERROR' { 'ERROR' }
            default { $row.IsMember }
        }
        $colour = switch ($row.IsMember) {
            'YES'   { 'Green' }
            'NO'    { 'Red' }
            'N/A'   { 'Yellow' }
            'ERROR' { 'Red' }
            default { 'White' }
        }
        $nm = if ($row.Name) { $row.Name } else { '' }
        if ($nm.Length -gt $nameWidth) { $nm = $nm.Substring(0, $nameWidth - 1) + '...' }

        Write-Host (" {0,-38} " -f $row.GroupId) -ForegroundColor DarkGray -NoNewline
        Write-Host (("{0,-" + $nameWidth + "} ") -f $nm) -ForegroundColor White -NoNewline
        Write-Host ("{0,-13}" -f $label) -ForegroundColor $colour -NoNewline
        if ($row.Status -ne 'OK') {
            Write-Host "  $($row.Status)" -ForegroundColor Yellow
        } else {
            Write-Host ''
        }
    }

    $yes = @($results | Where-Object IsMember -eq 'YES').Count
    $no  = @($results | Where-Object IsMember -eq 'NO').Count
    $err = @($results | Where-Object { $_.IsMember -in 'ERROR','N/A' }).Count
    Write-Host ""
    Write-Host "Summary: " -ForegroundColor Cyan -NoNewline
    Write-Host "$yes member " -ForegroundColor Green -NoNewline
    Write-Host "/ $no non-member " -ForegroundColor Red -NoNewline
    Write-Host "/ $err error/unresolved" -ForegroundColor Yellow

    $script:LastGroupMembershipResults = $results
}

# ---- Auto-run when invoked as a script ----
if ($MyInvocation.InvocationName -ne '.') {
    Test-GraphGroupMembership -Group $Group -User $User -Transitive:$Transitive -PassThru:$PassThru -h:$h -Help:$Help
}