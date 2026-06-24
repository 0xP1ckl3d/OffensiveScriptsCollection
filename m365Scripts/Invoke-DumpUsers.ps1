<#
.SYNOPSIS
    Dump all users from Microsoft Entra ID via Microsoft Graph. Runs standalone or can be
    dot-sourced.

.DESCRIPTION
    Enumerates every user in the tenant and writes the result to a CSV (and optionally JSON) for
    evidence collection. Designed for the standard "Default User Permissions Allow Directory
    Enumeration" type findings where you need a complete user dump as supporting evidence.

    Pulls a wide set of properties: identity, contact, organisational, account state, sync state,
    sign-in activity, and on-prem attributes. Uses ConsistencyLevel=eventual + $count for any
    -Filter so advanced query syntax works.

    If the call 403s because the token lacks AuditLog.Read.All (signInActivity), the script
    automatically retries without signInActivity in the select set.

    Uses the existing $tokens variable for authentication.

.PARAMETER OutFile
    Path to the CSV output file. Defaults to .\users_<tenantid>_<timestamp>.csv

.PARAMETER Json
    Also write a .json file alongside the CSV containing the raw Graph objects.

.PARAMETER Filter
    Optional OData $filter. Example: "userType eq 'Guest'" or "startswith(displayName,'admin')".

.PARAMETER Top
    Page size for the Graph call. Defaults to 999 (max).

.PARAMETER Beta
    Use the /beta endpoint instead of /v1.0.

.PARAMETER NoSignInActivity
    Skip signInActivity from the start. Otherwise the script auto-falls-back on 403.

.PARAMETER PassThru
    Return the user objects to the pipeline in addition to writing files.

.EXAMPLE
    .\Invoke-DumpUsers.ps1
    .\Invoke-DumpUsers.ps1 -Json
    .\Invoke-DumpUsers.ps1 -Filter "userType eq 'Guest'"
    .\Invoke-DumpUsers.ps1 -Beta -OutFile .\everyone.csv
    .\Invoke-DumpUsers.ps1 -NoSignInActivity
#>
[CmdletBinding()]
param(
    [string]$OutFile,
    [switch]$Json,
    [string]$Filter,
    [int]$Top = 999,
    [switch]$Beta,
    [switch]$NoSignInActivity,
    [switch]$PassThru,
    [switch]$h,
    [switch]$Help
)

function Invoke-DumpAllUsers {
    [CmdletBinding()]
    param(
        [string]$OutFile,
        [switch]$Json,
        [string]$Filter,
        [int]$Top = 999,
        [switch]$Beta,
        [switch]$NoSignInActivity,
        [switch]$PassThru,
        [switch]$h,
        [switch]$Help
    )

    if ($h -or $Help) {
        Write-Host ""
        Write-Host "Invoke-DumpUsers" -ForegroundColor Cyan
        Write-Host "----------------" -ForegroundColor Cyan
        Write-Host "  Dump every user object the current token can read."
        Write-Host ""
        Write-Host "USAGE:" -ForegroundColor Yellow
        Write-Host "  .\Invoke-DumpUsers.ps1 [-OutFile <path>] [-Filter <odata>] [-Json] [-Beta]"
        Write-Host "                         [-NoSignInActivity] [-Top <n>] [-PassThru]"
        Write-Host ""
        Write-Host "  Defaults: writes CSV to .\users_<tid>_<timestamp>.csv"
        Write-Host "  Auto-retries without signInActivity on 403 (standard user tokens)."
        Write-Host ""
        Write-Host "REQUIRES:" -ForegroundColor Yellow
        Write-Host "  `$tokens variable in the calling session with a valid Graph access_token."
        Write-Host ""
        return
    }

    if (-not $tokens.access_token) {
        Write-Host "[!] No `$tokens.access_token found. Authenticate first." -ForegroundColor Red
        return
    }

    function Write-Header($t) { Write-Host "`n==== $t ====" -ForegroundColor Cyan }
    function Write-KV($k,$v,$vc='White') {
        Write-Host ("{0,-18}: " -f $k) -ForegroundColor Yellow -NoNewline
        Write-Host $v -ForegroundColor $vc
    }

    # Decode token for tenant context
    $tid = 'unknown'
    $upn = 'unknown'
    try {
        $seg = $tokens.access_token.Split('.')[1]
        $pad = $seg + ('=' * ((4 - $seg.Length % 4) % 4))
        $jwt = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($pad.Replace('-','+').Replace('_','/'))) | ConvertFrom-Json
        $tid = $jwt.tid
        $upn = $jwt.upn
    } catch {}

    if (-not $OutFile) {
        $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
        $OutFile = ".\users_${tid}_${stamp}.csv"
    }

    $apiBase = if ($Beta) { 'https://graph.microsoft.com/beta' } else { 'https://graph.microsoft.com/v1.0' }

    # Base property set (without signInActivity)
    $baseProps = @(
        'id','displayName','givenName','surname','userPrincipalName','mail','mailNickname',
        'otherMails','proxyAddresses','imAddresses',
        'jobTitle','department','companyName','employeeId','employeeType','employeeHireDate',
        'officeLocation','streetAddress','city','state','postalCode','country',
        'businessPhones','mobilePhone','faxNumber',
        'userType','externalUserState','externalUserStateChangeDateTime','creationType','createdDateTime',
        'accountEnabled','usageLocation','preferredLanguage',
        'onPremisesSyncEnabled','onPremisesSamAccountName','onPremisesUserPrincipalName',
        'onPremisesDomainName','onPremisesDistinguishedName','onPremisesSecurityIdentifier',
        'onPremisesImmutableId','onPremisesLastSyncDateTime',
        'passwordPolicies','lastPasswordChangeDateTime','ageGroup','consentProvidedForMinor'
    )

    $useSignIn = -not $NoSignInActivity
    $props = if ($useSignIn) { $baseProps + 'signInActivity' } else { $baseProps }

    Write-Header 'Dump Configuration'
    Write-KV 'Tenant'        $tid Green
    Write-KV 'ActingUser'    $upn Green
    Write-KV 'API'           $apiBase
    Write-KV 'Filter'        $(if ($Filter) { $Filter } else { '<none>' })
    Write-KV 'PageSize'      $Top
    Write-KV 'SignInActivity' $(if ($useSignIn) { 'included (will fall back on 403)' } else { 'excluded' })
    Write-KV 'OutFile'       $OutFile Green
    if ($Json) {
        $jsonFile = [System.IO.Path]::ChangeExtension($OutFile, '.json')
        Write-KV 'JsonFile' $jsonFile Green
    }

    $hdr = @{
        Authorization    = "Bearer $($tokens.access_token)"
        ConsistencyLevel = 'eventual'
        'Content-Type'   = 'application/json'
    }

    function Build-Uri([string[]]$selectProps) {
        $sel = ($selectProps -join ',')
        $u = "$apiBase/users?`$select=$sel&`$top=$Top"
        if ($Filter) {
            $encFilter = [System.Uri]::EscapeDataString($Filter)
            $u += "&`$filter=$encFilter&`$count=true"
        }
        return $u
    }

    function Extract-ErrorBody($errRecord) {
        $body = $null
        try { $body = $errRecord.ErrorDetails.Message } catch {}
        if (-not $body) {
            try {
                $stream = $errRecord.Exception.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($stream)
                $body = $reader.ReadToEnd()
            } catch {}
        }
        return $body
    }

    function Print-ErrorBody($body) {
        if (-not $body) { return }
        Write-Host "    raw     : $(($body -split "`n")[0])" -ForegroundColor DarkGray
        try {
            $j = $body | ConvertFrom-Json
            if ($j.error.code)    { Write-Host "    error   : $($j.error.code)" -ForegroundColor DarkGray }
            if ($j.error.message) { Write-Host "    message : $(($j.error.message -split "`n")[0])" -ForegroundColor DarkGray }
        } catch {}
    }

    function Run-Enumeration([string[]]$selectProps) {
        $list = New-Object System.Collections.Generic.List[object]
        $uri = Build-Uri $selectProps
        $page = 0
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        do {
            $page++
            $r = Invoke-RestMethod -Headers $hdr -Method GET -Uri $uri -ErrorAction Stop
            foreach ($u in $r.value) { [void]$list.Add($u) }
            $uri = $r.'@odata.nextLink'
            Write-Host ("`r[*] Retrieved {0} users ({1} pages, {2:N1}s)..." -f $list.Count, $page, $sw.Elapsed.TotalSeconds) -ForegroundColor DarkGray -NoNewline
        } while ($uri)
        $sw.Stop()
        Write-Host ""
        return ,$list
    }

    Write-Header 'Enumeration'
    Write-Host "[*] Paging /users..." -ForegroundColor DarkGray

    $all = $null
    try {
        $all = Run-Enumeration -selectProps $props
    } catch {
        Write-Host ""
        $code = $_.Exception.Response.StatusCode.value__
        Write-Host "[-] Enumeration failed (HTTP $code): $($_.Exception.Message)" -ForegroundColor Red
        $body = Extract-ErrorBody $_
        Print-ErrorBody $body

        if ($code -eq 403 -and $useSignIn) {
            Write-Host ""
            Write-Host "[*] Retrying without signInActivity (current token lacks AuditLog.Read.All)..." -ForegroundColor Yellow
            $useSignIn = $false
            try {
                $all = Run-Enumeration -selectProps $baseProps
                Write-Host "[+] Retry succeeded." -ForegroundColor Green
            } catch {
                Write-Host ""
                $code2 = $_.Exception.Response.StatusCode.value__
                Write-Host "[-] Retry also failed (HTTP $code2): $($_.Exception.Message)" -ForegroundColor Red
                $body2 = Extract-ErrorBody $_
                Print-ErrorBody $body2
                return
            }
        } else {
            return
        }
    }

    if (-not $all -or $all.Count -eq 0) {
        Write-Host "[!] No users returned." -ForegroundColor Yellow
        return
    }

    Write-Host "[+] Collected $($all.Count) users." -ForegroundColor Green

    # ---- Flatten for CSV ----
    Write-Header 'Writing Output'

    $flat = foreach ($u in $all) {
        $sia = $u.signInActivity
        [pscustomobject]@{
            id                          = $u.id
            displayName                 = $u.displayName
            givenName                   = $u.givenName
            surname                     = $u.surname
            userPrincipalName           = $u.userPrincipalName
            mail                        = $u.mail
            mailNickname                = $u.mailNickname
            otherMails                  = ($u.otherMails -join ';')
            proxyAddresses              = ($u.proxyAddresses -join ';')
            imAddresses                 = ($u.imAddresses -join ';')
            jobTitle                    = $u.jobTitle
            department                  = $u.department
            companyName                 = $u.companyName
            employeeId                  = $u.employeeId
            employeeType                = $u.employeeType
            employeeHireDate            = $u.employeeHireDate
            officeLocation              = $u.officeLocation
            streetAddress               = $u.streetAddress
            city                        = $u.city
            state                       = $u.state
            postalCode                  = $u.postalCode
            country                     = $u.country
            businessPhones              = ($u.businessPhones -join ';')
            mobilePhone                 = $u.mobilePhone
            faxNumber                   = $u.faxNumber
            userType                    = $u.userType
            externalUserState           = $u.externalUserState
            externalUserStateChange     = $u.externalUserStateChangeDateTime
            creationType                = $u.creationType
            createdDateTime             = $u.createdDateTime
            accountEnabled              = $u.accountEnabled
            usageLocation               = $u.usageLocation
            preferredLanguage           = $u.preferredLanguage
            onPremisesSyncEnabled       = $u.onPremisesSyncEnabled
            onPremisesSamAccountName    = $u.onPremisesSamAccountName
            onPremisesUserPrincipalName = $u.onPremisesUserPrincipalName
            onPremisesDomainName        = $u.onPremisesDomainName
            onPremisesDistinguishedName = $u.onPremisesDistinguishedName
            onPremisesSID               = $u.onPremisesSecurityIdentifier
            onPremisesImmutableId       = $u.onPremisesImmutableId
            onPremisesLastSync          = $u.onPremisesLastSyncDateTime
            passwordPolicies            = $u.passwordPolicies
            lastPasswordChange          = $u.lastPasswordChangeDateTime
            ageGroup                    = $u.ageGroup
            consentForMinor             = $u.consentProvidedForMinor
            lastInteractiveSignIn       = if ($sia) { $sia.lastSignInDateTime } else { '' }
            lastNonInteractiveSignIn    = if ($sia) { $sia.lastNonInteractiveSignInDateTime } else { '' }
            lastSuccessfulSignIn        = if ($sia) { $sia.lastSuccessfulSignInDateTime } else { '' }
        }
    }

    try {
        $flat | Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8
        Write-Host "[+] CSV: $OutFile" -ForegroundColor Green
    } catch {
        Write-Host "[-] Failed writing CSV: $($_.Exception.Message)" -ForegroundColor Red
    }

    if ($Json) {
        try {
            $all | ConvertTo-Json -Depth 8 | Set-Content -Path $jsonFile -Encoding UTF8
            Write-Host "[+] JSON: $jsonFile" -ForegroundColor Green
        } catch {
            Write-Host "[-] Failed writing JSON: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    # ---- Quick stats ----
    Write-Header 'Stats'
    $members  = @($all | Where-Object userType -eq 'Member').Count
    $guests   = @($all | Where-Object userType -eq 'Guest').Count
    $enabled  = @($all | Where-Object accountEnabled -eq $true).Count
    $disabled = @($all | Where-Object accountEnabled -eq $false).Count
    $synced   = @($all | Where-Object onPremisesSyncEnabled -eq $true).Count
    $cloud    = $all.Count - $synced
    Write-KV 'Total'     $all.Count Green
    Write-KV 'Members'   $members
    Write-KV 'Guests'    $guests   $(if ($guests -gt 0) {'Yellow'} else {'White'})
    Write-KV 'Enabled'   $enabled  Green
    Write-KV 'Disabled'  $disabled Yellow
    Write-KV 'Synced'    $synced
    Write-KV 'CloudOnly' $cloud

    $global:LastUserDump = $all
    Write-Host ""
    Write-Host "[i] Raw objects also available in `$LastUserDump for follow-up filtering." -ForegroundColor DarkGray

    if ($PassThru) { return $all }
}

# ---- Auto-run when invoked as a script ----
if ($MyInvocation.InvocationName -ne '.') {
    Invoke-DumpAllUsers -OutFile $OutFile -Json:$Json -Filter $Filter -Top $Top -Beta:$Beta `
        -NoSignInActivity:$NoSignInActivity -PassThru:$PassThru -h:$h -Help:$Help | Out-Null
}