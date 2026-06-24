<#
.SYNOPSIS
    Entra ID user lookup via Microsoft Graph. Runs standalone or can be dot-sourced.

.DESCRIPTION
    Accepts a UPN, display name, object ID or mail address. Resolves the user, then enumerates
    identity, manager, direct reports, directory roles, groups, licenses, owned objects, owned
    devices and registered devices. Uses the existing $tokens variable for authentication.

.EXAMPLE
    .\GraphWhois.ps1 jane.doe@contoso.com
    .\GraphWhois.ps1 11111111-2222-3333-4444-555555555555
    .\GraphWhois.ps1 "Jane Doe"
    .\GraphWhois.ps1 -h

.EXAMPLE
    . .\GraphWhois.ps1
    Invoke-GraphWhois "Jane Doe"
#>
[CmdletBinding()]
param(
    [Parameter(Position=0)]
    [string]$User,
    [switch]$h,
    [switch]$Help
)

function Invoke-GraphWhois {
    [CmdletBinding()]
    param(
        [Parameter(Position=0)]
        [string]$User,
        [switch]$h,
        [switch]$Help
    )

    if (-not $User -or $h -or $Help) {
        Write-Host ""
        Write-Host "GraphWhois" -ForegroundColor Cyan
        Write-Host "----------" -ForegroundColor Cyan
        Write-Host "  Look up an Entra ID user and dump identity, roles, groups, owned objects and devices."
        Write-Host ""
        Write-Host "USAGE:" -ForegroundColor Yellow
        Write-Host "  .\GraphWhois.ps1 <UPN | DisplayName | ObjectId | Mail>"
        Write-Host "  Invoke-GraphWhois <UPN | DisplayName | ObjectId | Mail>   (when dot-sourced)"
        Write-Host ""
        Write-Host "EXAMPLES:" -ForegroundColor Yellow
        Write-Host "  .\GraphWhois.ps1 jane.doe@contoso.com"
        Write-Host "  .\GraphWhois.ps1 11111111-2222-3333-4444-555555555555"
        Write-Host '  .\GraphWhois.ps1 "Jane Doe"'
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

    $hdr = @{ Authorization = "Bearer $($tokens.access_token)" }

    # Resolve type via variable to avoid accelerator parsing quirks in some hosts
    $UriT = [type]'System.Uri'
    function _Enc([string]$s) { $UriT::EscapeDataString($s) }

    function Write-Header($t) { Write-Host "`n==== $t ====" -ForegroundColor Cyan }
    function Write-KV($k,$v,$vc='White') {
        Write-Host ("{0,-14}: " -f $k) -ForegroundColor Yellow -NoNewline
        Write-Host $v -ForegroundColor $vc
    }

    # ---- Resolve target ----
    $target = $null
    $guidRx = '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'

    try {
        if ($User -match $guidRx) {
            $target = Invoke-RestMethod -Headers $hdr -Uri "https://graph.microsoft.com/v1.0/users/$User"
        }
        elseif ($User -match '@') {
            try {
                $target = Invoke-RestMethod -Headers $hdr -Uri "https://graph.microsoft.com/v1.0/users/$(_Enc $User)"
            } catch {
                $enc = _Enc $User
                $r = Invoke-RestMethod -Headers $hdr -Uri "https://graph.microsoft.com/v1.0/users?`$filter=mail eq '$enc' or userPrincipalName eq '$enc'"
                $target = $r.value | Select-Object -First 1
            }
        }
        else {
            $enc = _Enc $User
            $r = Invoke-RestMethod -Headers $hdr -Uri "https://graph.microsoft.com/v1.0/users?`$filter=startswith(displayName,'$enc')&`$top=10"
            if ($r.value.Count -gt 1) {
                Write-Host "[!] Multiple matches for '$User':" -ForegroundColor Yellow
                $r.value | ForEach-Object { Write-Host " - $($_.displayName)  <$($_.userPrincipalName)>  $($_.id)" -ForegroundColor DarkGray }
                Write-Host "[!] Re-run with UPN or ObjectId for a unique match." -ForegroundColor Yellow
                return
            }
            $target = $r.value | Select-Object -First 1
        }
    } catch {
        Write-Host "[!] Lookup failed: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    if (-not $target) {
        Write-Host "[!] No user found matching '$User'." -ForegroundColor Red
        return
    }

    $uid = $target.id

    # ---- Enrich ----
    $full     = $null
    $mem      = @()
    $owned    = @()
    $ownedDev = @()
    $regDev   = @()
    $mgr      = $null
    $reports  = @()
    $licenses = @()

    try { $full     = Invoke-RestMethod -Headers $hdr -Uri "https://graph.microsoft.com/v1.0/users/$uid`?`$select=id,displayName,userPrincipalName,mail,jobTitle,department,officeLocation,city,country,companyName,mobilePhone,businessPhones,accountEnabled,createdDateTime,onPremisesSyncEnabled,onPremisesSamAccountName,proxyAddresses,userType" } catch {}
    try { $mem      = (Invoke-RestMethod -Headers $hdr -Uri "https://graph.microsoft.com/v1.0/users/$uid/memberOf").value } catch {}
    try { $owned    = (Invoke-RestMethod -Headers $hdr -Uri "https://graph.microsoft.com/v1.0/users/$uid/ownedObjects").value } catch {}
    try { $ownedDev = (Invoke-RestMethod -Headers $hdr -Uri "https://graph.microsoft.com/v1.0/users/$uid/ownedDevices").value } catch {}
    try { $regDev   = (Invoke-RestMethod -Headers $hdr -Uri "https://graph.microsoft.com/v1.0/users/$uid/registeredDevices").value } catch {}
    try { $mgr      = Invoke-RestMethod -Headers $hdr -Uri "https://graph.microsoft.com/v1.0/users/$uid/manager" } catch {}
    try { $reports  = (Invoke-RestMethod -Headers $hdr -Uri "https://graph.microsoft.com/v1.0/users/$uid/directReports").value } catch {}
    try { $licenses = (Invoke-RestMethod -Headers $hdr -Uri "https://graph.microsoft.com/v1.0/users/$uid/licenseDetails").value } catch {}

    $u = if ($full) { $full } else { $target }

    # ---- Identity ----
    Write-Header 'Identity'
    Write-KV 'DisplayName' $u.displayName Green
    Write-KV 'UPN'         $u.userPrincipalName Green
    Write-KV 'ObjectId'    $u.id
    Write-KV 'Mail'        $u.mail
    Write-KV 'UserType'    $u.userType $(if ($u.userType -eq 'Guest') {'Red'} else {'White'})
    Write-KV 'Enabled'     $u.accountEnabled $(if ($u.accountEnabled) {'Green'} else {'Red'})
    Write-KV 'JobTitle'    $u.jobTitle
    Write-KV 'Department'  $u.department
    Write-KV 'Company'     $u.companyName
    Write-KV 'OfficeLoc'   $u.officeLocation
    Write-KV 'City'        $u.city
    Write-KV 'Country'     $u.country
    Write-KV 'Mobile'      $u.mobilePhone
    Write-KV 'BusPhones'   ($u.businessPhones -join ', ')
    Write-KV 'Created'     $u.createdDateTime
    Write-KV 'OnPremSync'  $u.onPremisesSyncEnabled $(if ($u.onPremisesSyncEnabled) {'Yellow'} else {'White'})
    Write-KV 'SamAccount'  $u.onPremisesSamAccountName

    if ($u.proxyAddresses) {
        Write-Header 'Proxy Addresses'
        $u.proxyAddresses | ForEach-Object { Write-Host " - $_" -ForegroundColor DarkGray }
    }

    if ($mgr) {
        Write-Header 'Manager'
        Write-Host " - " -NoNewline
        Write-Host $mgr.displayName -ForegroundColor Green -NoNewline
        Write-Host " <$($mgr.userPrincipalName)> " -NoNewline
        Write-Host "[$($mgr.id)]" -ForegroundColor DarkGray
    }

    if ($reports.Count -gt 0) {
        Write-Header "Direct Reports ($($reports.Count))"
        $reports | ForEach-Object {
            Write-Host " - " -NoNewline
            Write-Host $_.displayName -ForegroundColor Green -NoNewline
            Write-Host " <$($_.userPrincipalName)>" -ForegroundColor White
        }
    }

    Write-Header 'Directory Roles'
    $dr = @($mem | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.directoryRole' })
    if ($dr.Count -gt 0) {
        $dr | ForEach-Object { Write-Host " - $($_.displayName)" -ForegroundColor Red }
    } else {
        Write-Host ' <none>' -ForegroundColor DarkGray
    }

    $groups = @($mem | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.group' })
    Write-Header "Group Memberships ($($groups.Count))"
    $groups | ForEach-Object {
        $tag = ''
        if ($_.securityEnabled) { $tag += ' [sec]' }
        if ($_.mailEnabled)     { $tag += ' [mail]' }
        if ($_.groupTypes -contains 'Unified') { $tag += ' [m365]' }
        Write-Host " - " -NoNewline
        Write-Host $_.displayName -ForegroundColor Green -NoNewline
        Write-Host $tag -ForegroundColor Magenta -NoNewline
        Write-Host " [$($_.id)]" -ForegroundColor DarkGray
    }

    if ($licenses.Count -gt 0) {
        Write-Header "Licenses ($($licenses.Count))"
        $licenses | ForEach-Object { Write-Host " - $($_.skuPartNumber)" -ForegroundColor Yellow }
    }

    Write-Header "Owned Objects ($($owned.Count))"
    if ($owned.Count -eq 0) {
        Write-Host ' <none>' -ForegroundColor DarkGray
    } else {
        $owned | ForEach-Object {
            $type = $_.'@odata.type'.Split('.')[-1]
            Write-Host " - " -NoNewline
            Write-Host $type -ForegroundColor Magenta -NoNewline
            Write-Host ": $($_.displayName) " -NoNewline
            Write-Host "[$($_.id)]" -ForegroundColor DarkGray
        }
    }

    Write-Header "Owned Devices ($($ownedDev.Count))"
    if ($ownedDev.Count -eq 0) {
        Write-Host ' <none>' -ForegroundColor DarkGray
    } else {
        $ownedDev | ForEach-Object {
            $compColor = if ($_.isCompliant) {'Green'} else {'Red'}
            Write-Host " - " -NoNewline
            Write-Host $_.displayName -ForegroundColor Green -NoNewline
            Write-Host " ($($_.operatingSystem) $($_.operatingSystemVersion))" -NoNewline
            Write-Host " trust=$($_.trustType)" -ForegroundColor Yellow -NoNewline
            Write-Host " compliant=$($_.isCompliant)" -ForegroundColor $compColor -NoNewline
            Write-Host " managed=$($_.isManaged)" -ForegroundColor White
        }
    }

    Write-Header "Registered Devices ($($regDev.Count))"
    if ($regDev.Count -eq 0) {
        Write-Host ' <none>' -ForegroundColor DarkGray
    } else {
        $regDev | ForEach-Object {
            Write-Host " - " -NoNewline
            Write-Host $_.displayName -ForegroundColor Green -NoNewline
            Write-Host " ($($_.operatingSystem) $($_.operatingSystemVersion)) trust=$($_.trustType)" -ForegroundColor White
        }
    }
}

# ---- Auto-run when invoked as a script ----
if ($MyInvocation.InvocationName -ne '.') {
    Invoke-GraphWhois -User $User -h:$h -Help:$Help
}