<#
.SYNOPSIS
    Obtain Microsoft Entra ID tokens via device code or interactive browser authentication.

.DESCRIPTION
    Supports explicit tenant, client, resource, scope, CAE claims, User-Agent control and output
    variable handling.

    The script is both runnable and importable:

      .\Invoke-GetGraphTokens.ps1 -TenantId <tenant-guid>
      .\Invoke-GetGraphTokens.ps1 -TenantId <tenant-guid> -Resource arm -OutVar armTokens
      .\Invoke-GetGraphTokens.ps1 -TenantId <tenant-guid> -Method Interactive

      . .\Invoke-GetGraphTokens.ps1
      Invoke-GetGraphTokens -TenantId <tenant-guid> -Resource msgraph
      Invoke-GetGraphTokens -TenantId <tenant-guid> -Resource powerbi -OutVar powerbiTokens

.PARAMETER Tenant
    Target tenant domain or well-known authority.

.PARAMETER TenantId
    Target tenant GUID.

.PARAMETER ClientId
    OAuth client GUID or alias. Default is Microsoft Office.

.PARAMETER Resource
    Target resource URL, GUID or alias. Default is Microsoft Graph.

.PARAMETER Scope
    v2 scope string. Default is '.default offline_access openid profile'.

.PARAMETER Method
    DeviceCode or Interactive. Default is DeviceCode.

.PARAMETER RedirectPort
    Local TCP port for interactive loopback flow. Default 0 selects a random free port.

.PARAMETER RedirectPath
    Local HTTP path for interactive loopback flow. Default '/'.

.PARAMETER RedirectUri
    Explicit redirect URI override for interactive flow.

.PARAMETER UseV1Endpoint
    Force v1 OAuth endpoints.

.PARAMETER UseCAE
    Request CAE-capable token using xms_cc=cp1 on v2 flows.

.PARAMETER Device
    User-Agent device profile.

.PARAMETER Browser
    User-Agent browser profile.

.PARAMETER CustomUserAgent
    Full User-Agent override.

.PARAMETER NoStore
    Do not assign the result to $global:tokens.

.PARAMETER OutVar
    Additional global variable name to populate.

.PARAMETER Quiet
    Suppress token claim output.

.PARAMETER ShowMap
    Print client and resource alias maps.

.PARAMETER Help
    Print help.

.EXAMPLE
    .\Invoke-GetGraphTokens.ps1 -TenantId c418882f-4027-479e-b3b9-ffa0a7081c93

.EXAMPLE
    .\Invoke-GetGraphTokens.ps1 -TenantId c418882f-4027-479e-b3b9-ffa0a7081c93 -Resource arm -OutVar armTokens

.EXAMPLE
    .\Invoke-GetGraphTokens.ps1 -Tenant contoso.onmicrosoft.com -Method Interactive -Resource powerbi -OutVar powerbiTokens
#>

[CmdletBinding()]
param(
    [string]$Tenant,
    [string]$TenantId,
    [string]$ClientId = 'office',
    [string]$Resource = 'msgraph',
    [string]$Scope = '.default offline_access openid profile',
    [ValidateSet('DeviceCode','Interactive')]
    [string]$Method = 'DeviceCode',
    [int]$RedirectPort = 0,
    [string]$RedirectPath = '/',
    [string]$RedirectUri,
    [switch]$UseV1Endpoint,
    [switch]$UseCAE,
    [ValidateSet('Mac','Windows','Linux','AndroidMobile','iPhone','OS/2')]
    [string]$Device = 'Windows',
    [ValidateSet('Android','IE','Chrome','Firefox','Edge','Safari')]
    [string]$Browser = 'Edge',
    [string]$CustomUserAgent,
    [switch]$NoStore,
    [string]$OutVar,
    [switch]$Quiet,
    [switch]$ShowMap,
    [Alias('h')]
    [switch]$Help
)

function Invoke-GetGraphTokens {
    [CmdletBinding()]
    param(
        [string]$Tenant,
        [string]$TenantId,
        [string]$ClientId = 'office',
        [string]$Resource = 'msgraph',
        [string]$Scope = '.default offline_access openid profile',
        [ValidateSet('DeviceCode','Interactive')]
        [string]$Method = 'DeviceCode',
        [int]$RedirectPort = 0,
        [string]$RedirectPath = '/',
        [string]$RedirectUri,
        [switch]$UseV1Endpoint,
        [switch]$UseCAE,
        [ValidateSet('Mac','Windows','Linux','AndroidMobile','iPhone','OS/2')]
        [string]$Device = 'Windows',
        [ValidateSet('Android','IE','Chrome','Firefox','Edge','Safari')]
        [string]$Browser = 'Edge',
        [string]$CustomUserAgent,
        [switch]$NoStore,
        [string]$OutVar,
        [switch]$Quiet,
        [switch]$ShowMap,
        [Alias('h')]
        [switch]$Help
    )

    $clientAliasMap = @{
        'office'        = 'd3590ed6-52b3-4102-aeff-aad2292ab01c'
        'teams'         = '1fec8e78-bce4-4aaf-ab1b-5451cc387264'
        'msgraphps'     = '14d82eec-204b-4c2f-b7e8-296a70dab67e'
        'graphps'       = '14d82eec-204b-4c2f-b7e8-296a70dab67e'
        'authbroker'    = '29d9ed98-a469-4536-ade2-f981bc1d605e'
        'authenticator' = '4813382a-8fa7-425e-ab75-3b753aab3abb'
        'outlook'       = '27922004-5251-4030-b22d-91ecd9a37ea4'
        'onedrive'      = 'ab9b8c07-8f02-4f72-87fa-80105867a763'
        'intune'        = '9ba1a5c7-f17a-4de9-a1f1-6178c8d51223'
        'vs'            = '872cd9fa-d31f-45e0-9eab-6e460a02d1f1'
        'visualstudio'  = '872cd9fa-d31f-45e0-9eab-6e460a02d1f1'
        'officepwa'     = '0ec893e0-5785-4de6-99da-4ed124e5296c'
        'accountsui'    = 'a40d7d7d-59aa-447e-a655-679a4107e548'
        'az'            = '04b07795-8ddb-461a-bbee-02f9e1bf7b46'
        'azcli'         = '04b07795-8ddb-461a-bbee-02f9e1bf7b46'
        'azureps'       = '1950a258-227b-4e31-a9cf-717495945fc2'
        'msol'          = '1b730954-1685-4b74-9bfd-dac224a7b894'
        'aadps'         = '1b730954-1685-4b74-9bfd-dac224a7b894'
    }

    $clientDescriptions = @{
        'd3590ed6-52b3-4102-aeff-aad2292ab01c' = 'Microsoft Office'
        '1fec8e78-bce4-4aaf-ab1b-5451cc387264' = 'Microsoft Teams'
        '14d82eec-204b-4c2f-b7e8-296a70dab67e' = 'Microsoft Graph PowerShell SDK'
        '29d9ed98-a469-4536-ade2-f981bc1d605e' = 'Microsoft Authentication Broker'
        '4813382a-8fa7-425e-ab75-3b753aab3abb' = 'Microsoft Authenticator App'
        '27922004-5251-4030-b22d-91ecd9a37ea4' = 'Outlook Mobile iOS'
        'ab9b8c07-8f02-4f72-87fa-80105867a763' = 'OneDrive iOS'
        '9ba1a5c7-f17a-4de9-a1f1-6178c8d51223' = 'Intune Company Portal'
        '872cd9fa-d31f-45e0-9eab-6e460a02d1f1' = 'Visual Studio'
        '0ec893e0-5785-4de6-99da-4ed124e5296c' = 'Office UWP PWA'
        'a40d7d7d-59aa-447e-a655-679a4107e548' = 'Accounts Control UI'
        '04b07795-8ddb-461a-bbee-02f9e1bf7b46' = 'Azure CLI'
        '1950a258-227b-4e31-a9cf-717495945fc2' = 'Azure PowerShell'
        '1b730954-1685-4b74-9bfd-dac224a7b894' = 'AzureAD PowerShell / MSOnline'
    }

    $resourceAliasMap = @{
        'msgraph'       = 'https://graph.microsoft.com'
        'graph'         = 'https://graph.microsoft.com'
        'aadgraph'      = 'https://graph.windows.net'
        'arm'           = 'https://management.azure.com'
        'asm'           = 'https://management.core.windows.net'
        'vault'         = 'https://vault.azure.net'
        'keyvault'      = 'https://vault.azure.net'
        'storage'       = 'https://storage.azure.com'
        'sql'           = 'https://database.windows.net'
        'outlook'       = 'https://outlook.office.com'
        'exo'           = 'https://outlook.office365.com'
        'substrate'     = 'https://substrate.office.com'
        'powerbi'       = 'https://analysis.windows.net/powerbi/api'
        'powerbidax'    = 'https://analysis.windows.net/powerbi/api'
        'flow'          = 'https://service.flow.microsoft.com'
        'fabric'        = 'https://api.fabric.microsoft.com'
        'partner'       = 'https://api.partnercenter.microsoft.com'
        'spaces'        = 'https://api.spaces.skype.com'
        'appinsights'   = 'https://api.applicationinsights.io'
        'loganalytics'  = 'https://api.loganalytics.io'
        'defender'      = 'https://api.security.microsoft.com'
        'devops'        = '499b84ac-1321-427f-aa17-267ca6975798'
        'intune'        = '0000000a-0000-0000-c000-000000000000'
        'aadgraphguid'  = '00000002-0000-0000-c000-000000000000'
        'msgraphguid'   = '00000003-0000-0000-c000-000000000000'
        'armguid'       = '797f4846-ba00-4fd7-ba43-dac1f8f63013'
        'exoguid'       = '00000002-0000-0ff1-ce00-000000000000'
        'spoguid'       = '00000003-0000-0ff1-ce00-000000000000'
        'officeapps'    = 'https://officeapps.live.com'
        'officemgmt'    = 'https://manage.office.com'
        'yammer'        = 'https://www.yammer.com'
        'mam'           = 'https://wip.mam.manage.microsoft.com'
    }

    $resourceDescriptions = @{
        'https://graph.microsoft.com'                = 'Microsoft Graph'
        'https://graph.windows.net'                  = 'Azure AD Graph'
        'https://management.azure.com'               = 'Azure Resource Manager'
        'https://management.core.windows.net'        = 'Azure Service Management'
        'https://vault.azure.net'                    = 'Azure Key Vault'
        'https://storage.azure.com'                  = 'Azure Storage'
        'https://database.windows.net'               = 'Azure SQL'
        'https://outlook.office.com'                 = 'Outlook / Exchange Online'
        'https://outlook.office365.com'              = 'Outlook / Exchange Online alternate audience'
        'https://substrate.office.com'               = 'M365 Substrate'
        'https://analysis.windows.net/powerbi/api'   = 'Power BI Service'
        'https://service.flow.microsoft.com'         = 'Power Automate'
        'https://api.fabric.microsoft.com'           = 'Microsoft Fabric'
        'https://api.partnercenter.microsoft.com'    = 'Partner Center'
        'https://api.spaces.skype.com'               = 'Skype / Teams Spaces'
        'https://api.applicationinsights.io'         = 'Application Insights'
        'https://api.loganalytics.io'                = 'Log Analytics'
        'https://api.security.microsoft.com'         = 'Microsoft Defender XDR'
        '499b84ac-1321-427f-aa17-267ca6975798'       = 'Azure DevOps'
        '0000000a-0000-0000-c000-000000000000'       = 'Intune Graph'
        '00000002-0000-0000-c000-000000000000'       = 'Azure AD Graph GUID'
        '00000003-0000-0000-c000-000000000000'       = 'Microsoft Graph GUID'
        '797f4846-ba00-4fd7-ba43-dac1f8f63013'       = 'Azure Resource Manager GUID'
        '00000002-0000-0ff1-ce00-000000000000'       = 'Exchange Online GUID'
        '00000003-0000-0ff1-ce00-000000000000'       = 'SharePoint Online GUID'
        'https://officeapps.live.com'                = 'Office Apps Live'
        'https://manage.office.com'                  = 'Office Management API'
        'https://www.yammer.com'                     = 'Yammer / Viva Engage'
        'https://wip.mam.manage.microsoft.com'       = 'Intune MAM'
    }

    $caeSupportedResources = @(
        'https://graph.microsoft.com',
        'https://management.azure.com',
        'https://outlook.office.com',
        'https://outlook.office365.com',
        'https://substrate.office.com',
        '00000003-0000-0000-c000-000000000000',
        '00000003-0000-0ff1-ce00-000000000000',
        '797f4846-ba00-4fd7-ba43-dac1f8f63013'
    )

    function Write-Header {
        param([string]$Text)
        Write-Host ""
        Write-Host "==== $Text ====" -ForegroundColor Cyan
    }

    function Write-KV {
        param(
            [string]$Key,
            $Value,
            [string]$Colour = 'White'
        )

        Write-Host ("{0,-22}: " -f $Key) -ForegroundColor Yellow -NoNewline
        Write-Host $Value -ForegroundColor $Colour
    }

    function Test-IsValidPSVariableName {
        param([string]$Name)

        if (-not $Name) {
            return $false
        }

        return ($Name -match '^[A-Za-z_][A-Za-z0-9_]{0,127}$')
    }

    function Test-IsValidTenant {
        param([string]$Value)

        if (-not $Value) {
            return $false
        }

        if ($Value -in @('common','organizations','consumers')) {
            return $true
        }

        if ($Value -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') {
            return $true
        }

        if ($Value -match '^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$') {
            return $true
        }

        return $false
    }

    function Resolve-Alias {
        param(
            [string]$Value,
            [hashtable]$Map
        )

        if ($Value -and $Map.ContainsKey($Value.ToLower())) {
            return $Map[$Value.ToLower()]
        }

        return $Value
    }

    function Decode-Jwt {
        param([string]$Jwt)

        try {
            if (-not $Jwt) {
                return $null
            }

            $parts = $Jwt.Split('.')

            if ($parts.Count -lt 2) {
                return $null
            }

            $segment = $parts[1]
            $padding = '=' * ((4 - $segment.Length % 4) % 4)
            $segment = $segment + $padding
            $segment = $segment.Replace('-','+').Replace('_','/')

            $json = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($segment))
            return $json | ConvertFrom-Json
        } catch {
            return $null
        }
    }

    function Get-ForgedUA {
        param(
            [string]$Device,
            [string]$Browser,
            [string]$CustomUA
        )

        if ($CustomUA) {
            return $CustomUA
        }

        $map = @{
            'Windows-Edge'          = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0'
            'Windows-Chrome'        = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36'
            'Windows-Firefox'       = 'Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0'
            'Windows-IE'            = 'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko'
            'Mac-Safari'            = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15'
            'Mac-Chrome'            = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36'
            'Mac-Edge'              = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0'
            'Mac-Firefox'           = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:128.0) Gecko/20100101 Firefox/128.0'
            'Linux-Chrome'          = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36'
            'Linux-Firefox'         = 'Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0'
            'iPhone-Safari'         = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1'
            'iPhone-Chrome'         = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/128.0.6613.69 Mobile/15E148 Safari/604.1'
            'iPhone-Edge'           = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 EdgiOS/128.0.0.0 Mobile/15E148 Safari/605.1.15'
            'AndroidMobile-Android' = 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36'
            'AndroidMobile-Chrome'  = 'Mozilla/5.0 (Linux; Android 14; SM-G998U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36'
            'AndroidMobile-Firefox' = 'Mozilla/5.0 (Android 14; Mobile; rv:128.0) Gecko/128.0 Firefox/128.0'
            'OS/2-Firefox'          = 'Mozilla/5.0 (OS/2; Warp 4.5; rv:45.0) Gecko/20100101 Firefox/45.0'
        }

        $key = "$Device-$Browser"

        if ($map.ContainsKey($key)) {
            return $map[$key]
        }

        return $map['Windows-Edge']
    }

    function Get-ErrorBody {
        param($ErrorRecord)

        $body = $null

        try {
            $body = $ErrorRecord.ErrorDetails.Message
        } catch {}

        if (-not $body) {
            try {
                $stream = $ErrorRecord.Exception.Response.GetResponseStream()
                if ($stream.CanSeek) {
                    $stream.Position = 0
                }
                $reader = New-Object System.IO.StreamReader($stream)
                $body = $reader.ReadToEnd()
            } catch {}
        }

        return $body
    }

    function Print-ErrorBody {
        param(
            [string]$RawBody,
            [string]$Prefix = 'error'
        )

        if (-not $RawBody) {
            return
        }

        try {
            $errJson = $RawBody | ConvertFrom-Json
            if ($errJson.error) {
                Write-Host "    $Prefix             : $($errJson.error)" -ForegroundColor DarkGray
            }
            if ($errJson.error_description) {
                $desc = ($errJson.error_description -split "`n")[0]
                Write-Host "    error_description : $desc" -ForegroundColor DarkGray
            }
            if ($errJson.error_codes) {
                Write-Host "    error_codes       : $(($errJson.error_codes) -join ',')" -ForegroundColor DarkGray
            }
            if ($errJson.trace_id) {
                Write-Host "    trace_id          : $($errJson.trace_id)" -ForegroundColor DarkGray
            }
            if ($errJson.correlation_id) {
                Write-Host "    correlation_id    : $($errJson.correlation_id)" -ForegroundColor DarkGray
            }
        } catch {
            $firstLine = ($RawBody -split "`n")[0]
            Write-Host "    raw               : $firstLine" -ForegroundColor DarkGray
        }
    }

    function New-RandomBase64Url {
        param([int]$ByteCount = 32)

        $bytes = New-Object byte[] $ByteCount
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $rng.GetBytes($bytes)
        $rng.Dispose()

        return [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+','-').Replace('/','_')
    }

    function Get-CodeChallenge {
        param([string]$Verifier)

        $bytes = [System.Text.Encoding]::ASCII.GetBytes($Verifier)
        $hash = [System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes)
        return [Convert]::ToBase64String($hash).TrimEnd('=').Replace('+','-').Replace('/','_')
    }

    function Get-FreePort {
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
        $listener.Start()
        $port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
        $listener.Stop()
        return $port
    }

    function Build-EffectiveScope {
        param(
            [string]$Resource,
            [string]$Scope
        )

        $items = @()

        if ($Scope) {
            $items = $Scope -split '\s+' | Where-Object { $_ }
        }

        if ($items.Count -eq 0) {
            $items = @('.default','offline_access','openid','profile')
        }

        $effective = @()

        foreach ($item in $items) {
            if ($item -eq '.default') {
                $effective += "$Resource/.default"
            } else {
                $effective += $item
            }
        }

        if (-not ($effective -contains 'offline_access')) {
            $effective += 'offline_access'
        }

        if (-not ($effective -contains 'openid')) {
            $effective += 'openid'
        }

        if (-not ($effective -contains 'profile')) {
            $effective += 'profile'
        }

        return (($effective | Select-Object -Unique) -join ' ')
    }

    function Show-GetTokenHelp {
        Write-Host ""
        Write-Host "Invoke-GetGraphTokens" -ForegroundColor Cyan
        Write-Host "---------------------" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "USAGE:" -ForegroundColor Yellow
        Write-Host "  .\Invoke-GetGraphTokens.ps1 -TenantId <guid>"
        Write-Host "  .\Invoke-GetGraphTokens.ps1 -Tenant <domain>"
        Write-Host "  .\Invoke-GetGraphTokens.ps1 -TenantId <guid> -Resource arm -OutVar armTokens"
        Write-Host "  .\Invoke-GetGraphTokens.ps1 -TenantId <guid> -Method Interactive"
        Write-Host "  . .\Invoke-GetGraphTokens.ps1"
        Write-Host "  Invoke-GetGraphTokens -TenantId <guid> -Resource powerbi -OutVar powerbiTokens"
        Write-Host ""
        Write-Host "SWITCHES:" -ForegroundColor Yellow
        Write-Host "  -Tenant           <domain>       Target tenant domain or authority"
        Write-Host "  -TenantId         <guid>         Target tenant GUID"
        Write-Host "  -ClientId         <id|alias>     OAuth client GUID or alias              (default: office)"
        Write-Host "  -Resource         <url|alias>    Target audience                         (default: msgraph)"
        Write-Host "  -Scope            <scope>        v2 scope string                         (default: .default offline_access openid profile)"
        Write-Host "  -Method           <method>       DeviceCode or Interactive               (default: DeviceCode)"
        Write-Host "  -RedirectPort     <port>         Interactive loopback port               (default: random)"
        Write-Host "  -RedirectPath     <path>         Interactive loopback path               (default: /)"
        Write-Host "  -RedirectUri      <uri>          Explicit interactive redirect URI"
        Write-Host "  -UseV1Endpoint                  Force /oauth2 endpoint"
        Write-Host "  -UseCAE                         Request CAE-capable token"
        Write-Host "  -Device           <platform>     UA device                               (default: Windows)"
        Write-Host "  -Browser          <browser>      UA browser                              (default: Edge)"
        Write-Host "  -CustomUserAgent  <ua>           Full UA override"
        Write-Host "  -NoStore                         Do not write to `$global:tokens"
        Write-Host "  -OutVar           <name>         Additional global output variable"
        Write-Host "  -Quiet                           Suppress decoded token output"
        Write-Host "  -ShowMap                         Print client/resource aliases"
        Write-Host "  -Help, -h                        Print this help menu"
        Write-Host ""
    }

    function Show-Map {
        Write-Host ""
        Write-Host "CLIENT ALIASES:" -ForegroundColor Green

        foreach ($key in ($clientAliasMap.Keys | Sort-Object)) {
            $id = $clientAliasMap[$key]
            $desc = ''
            if ($clientDescriptions.ContainsKey($id)) {
                $desc = $clientDescriptions[$id]
            }
            Write-Host ("  {0,-14} -> {1,-40} {2}" -f $key, $id, $desc)
        }

        Write-Host ""
        Write-Host "RESOURCE ALIASES:" -ForegroundColor Green

        foreach ($key in ($resourceAliasMap.Keys | Sort-Object)) {
            $value = $resourceAliasMap[$key]
            $desc = ''
            if ($resourceDescriptions.ContainsKey($value)) {
                $desc = $resourceDescriptions[$value]
            }
            Write-Host ("  {0,-14} -> {1,-48} {2}" -f $key, $value, $desc)
        }

        Write-Host ""
    }

    if ($Help) {
        Show-GetTokenHelp
        return
    }

    if ($ShowMap) {
        Show-Map
        return
    }

    if ($TenantId -and -not (Test-IsValidTenant -Value $TenantId)) {
        Write-Host "[!] -TenantId is not a valid tenant identifier." -ForegroundColor Red
        return
    }

    if ($Tenant -and -not (Test-IsValidTenant -Value $Tenant)) {
        Write-Host "[!] -Tenant is not a valid tenant identifier." -ForegroundColor Red
        return
    }

    if ($OutVar -and -not (Test-IsValidPSVariableName -Name $OutVar)) {
        Write-Host "[!] -OutVar value is not a valid PowerShell variable name." -ForegroundColor Red
        return
    }

    if ($RedirectPort -lt 0 -or $RedirectPort -gt 65535) {
        Write-Host "[!] -RedirectPort must be between 0 and 65535." -ForegroundColor Red
        return
    }

    if (-not $RedirectPath) {
        Write-Host "[!] -RedirectPath cannot be empty." -ForegroundColor Red
        return
    }

    $authority = 'common'

    if ($Tenant) {
        $authority = $Tenant
    }

    if ($TenantId) {
        $authority = $TenantId
    }

    $clientWasExplicit = $PSBoundParameters.ContainsKey('ClientId')
    $resourceWasExplicit = $PSBoundParameters.ContainsKey('Resource')

    $originalClientId = $ClientId
    $originalResource = $Resource

    $ClientId = Resolve-Alias -Value $ClientId -Map $clientAliasMap
    $Resource = Resolve-Alias -Value $Resource -Map $resourceAliasMap

    if ($Method -eq 'Interactive' -and -not $clientWasExplicit -and $ClientId -eq 'd3590ed6-52b3-4102-aeff-aad2292ab01c') {
        Write-Host "[*] Interactive flow selected with default Office client." -ForegroundColor Yellow
        Write-Host "    Switching to Azure CLI client for loopback interactive flow. Pass -ClientId to override." -ForegroundColor DarkGray
        $ClientId = '04b07795-8ddb-461a-bbee-02f9e1bf7b46'
    }

    if (-not $UseV1Endpoint) {
        if ($Resource -match 'graph\.windows\.net' -or $Resource -match 'management\.core\.windows\.net') {
            $UseV1Endpoint = $true
        }
    }

    $baseUri = "https://login.microsoftonline.com/$authority"

    if ($UseV1Endpoint) {
        $tokenUri = "$baseUri/oauth2/token"
        $authUri = "$baseUri/oauth2/authorize"
        $deviceCodeUri = "$baseUri/oauth2/devicecode?api-version=1.0"
        $endpointVersion = 'v1.0'
        $effectiveScope = $null
    } else {
        $tokenUri = "$baseUri/oauth2/v2.0/token"
        $authUri = "$baseUri/oauth2/v2.0/authorize"
        $deviceCodeUri = "$baseUri/oauth2/v2.0/devicecode"
        $endpointVersion = 'v2.0'
        $effectiveScope = Build-EffectiveScope -Resource $Resource -Scope $Scope
    }

    $userAgent = Get-ForgedUA -Device $Device -Browser $Browser -CustomUA $CustomUserAgent

    Write-Header 'Authentication Setup'
    Write-KV 'Method' $Method Green
    Write-KV 'Authority' $baseUri
    Write-KV 'Tenant' $authority Green

    $clientDisplay = $ClientId
    if ($originalClientId -ne $ClientId) {
        $clientDisplay = "$ClientId  (alias: $originalClientId)"
    }
    Write-KV 'ClientId' $clientDisplay

    if ($clientDescriptions.ContainsKey($ClientId)) {
        Write-KV 'ClientName' $clientDescriptions[$ClientId]
    }

    $resourceDisplay = $Resource
    if ($originalResource -ne $Resource) {
        $resourceDisplay = "$Resource  (alias: $originalResource)"
    }
    Write-KV 'Resource' $resourceDisplay Green

    if ($resourceDescriptions.ContainsKey($Resource)) {
        Write-KV 'ResourceName' $resourceDescriptions[$Resource]
    }

    Write-KV 'EndpointVer' $endpointVersion
    Write-KV 'Device/Browser' "$Device / $Browser"

    if (-not $UseV1Endpoint) {
        Write-KV 'Scope' $effectiveScope
    }

    if ($UseCAE) {
        if ($UseV1Endpoint) {
            Write-KV 'CAE' 'not applied on v1 endpoint' Yellow
        } else {
            Write-KV 'CAE' 'requested using xms_cc=cp1' Magenta
        }
    }

    function Invoke-DeviceCodeFlow {
        Write-Header 'Device Code Request'

        if ($UseV1Endpoint) {
            $deviceBody = @{
                client_id = $ClientId
                resource  = $Resource
            }
        } else {
            $deviceBody = @{
                client_id = $ClientId
                scope     = $effectiveScope
            }

            if ($UseCAE) {
                $deviceBody.claims = '{"access_token":{"xms_cc":{"values":["cp1"]}}}'
            }
        }

        try {
            $deviceCode = Invoke-RestMethod `
                -Method POST `
                -Uri $deviceCodeUri `
                -ContentType 'application/x-www-form-urlencoded' `
                -Headers @{ 'User-Agent' = $userAgent } `
                -Body $deviceBody `
                -ErrorAction Stop
        } catch {
            Write-Host ""
            Write-Host "[-] Device code request failed." -ForegroundColor Red
            $raw = Get-ErrorBody -ErrorRecord $_
            Print-ErrorBody -RawBody $raw
            return $null
        }

        $verifyUri = $deviceCode.verification_uri
        if (-not $verifyUri) {
            $verifyUri = $deviceCode.verification_url
        }

        Write-Host ""
        Write-Host "[*] Open the URL below and enter the code." -ForegroundColor Yellow
        Write-Host "    URL : " -NoNewline
        Write-Host $verifyUri -ForegroundColor Cyan
        Write-Host "    Code: " -NoNewline
        Write-Host $deviceCode.user_code -ForegroundColor Cyan
        Write-Host ""
        Write-Host "[*] Waiting for sign-in to complete..." -ForegroundColor DarkGray

        $interval = 5
        if ($deviceCode.interval) {
            $interval = [int]$deviceCode.interval
        }

        $expiresIn = 900
        if ($deviceCode.expires_in) {
            $expiresIn = [int]$deviceCode.expires_in
        }

        $deadline = (Get-Date).AddSeconds($expiresIn)
        $polled = 0

        while ((Get-Date) -lt $deadline) {
            Start-Sleep -Seconds $interval
            $polled += $interval

            if ($UseV1Endpoint) {
                $tokenBody = @{
                    grant_type = 'urn:ietf:params:oauth:grant-type:device_code'
                    client_id  = $ClientId
                    code       = $deviceCode.device_code
                }
            } else {
                $tokenBody = @{
                    grant_type  = 'urn:ietf:params:oauth:grant-type:device_code'
                    client_id   = $ClientId
                    device_code = $deviceCode.device_code
                }
            }

            try {
                $response = Invoke-RestMethod `
                    -Method POST `
                    -Uri $tokenUri `
                    -ContentType 'application/x-www-form-urlencoded' `
                    -Headers @{ 'User-Agent' = $userAgent } `
                    -Body $tokenBody `
                    -ErrorAction Stop

                Write-Host ""
                Write-Host "[+] Sign-in complete. Polled for ${polled}s." -ForegroundColor Green
                return $response
            } catch {
                $raw = Get-ErrorBody -ErrorRecord $_
                $errJson = $null

                if ($raw) {
                    try {
                        $errJson = $raw | ConvertFrom-Json
                    } catch {}
                }

                if ($errJson -and $errJson.error -eq 'authorization_pending') {
                    Write-Host "." -ForegroundColor DarkGray -NoNewline
                    continue
                }

                if ($errJson -and $errJson.error -eq 'slow_down') {
                    $interval += 5
                    Write-Host "s" -ForegroundColor DarkGray -NoNewline
                    continue
                }

                if ($errJson -and $errJson.error -eq 'authorization_declined') {
                    Write-Host ""
                    Write-Host "[-] User declined sign-in." -ForegroundColor Red
                    return $null
                }

                if ($errJson -and $errJson.error -eq 'expired_token') {
                    Write-Host ""
                    Write-Host "[-] Device code expired." -ForegroundColor Red
                    return $null
                }

                Write-Host ""
                Write-Host "[-] Device code polling failed." -ForegroundColor Red
                Print-ErrorBody -RawBody $raw
                return $null
            }
        }

        Write-Host ""
        Write-Host "[-] Device code timed out." -ForegroundColor Red
        return $null
    }

    function Invoke-InteractiveFlow {
        if ($RedirectUri) {
            $effectiveRedirectUri = $RedirectUri
            $listenerPrefix = $RedirectUri
        } else {
            if ($RedirectPort -le 0) {
                $RedirectPort = Get-FreePort
            }

            $cleanPath = $RedirectPath
            if (-not $cleanPath.StartsWith('/')) {
                $cleanPath = "/$cleanPath"
            }
            if (-not $cleanPath.EndsWith('/')) {
                $cleanPath = "$cleanPath/"
            }

            $effectiveRedirectUri = "http://localhost:$RedirectPort$cleanPath"
            $listenerPrefix = $effectiveRedirectUri
        }

        if (-not $listenerPrefix.EndsWith('/')) {
            $listenerPrefix = "$listenerPrefix/"
        }

        $state = New-RandomBase64Url -ByteCount 16
        $nonce = New-RandomBase64Url -ByteCount 16
        $codeVerifier = New-RandomBase64Url -ByteCount 64
        $codeChallenge = Get-CodeChallenge -Verifier $codeVerifier

        Write-Header 'Interactive Browser Flow'
        Write-KV 'RedirectUri' $effectiveRedirectUri Green

        $query = [ordered]@{
            client_id             = $ClientId
            response_type         = 'code'
            redirect_uri          = $effectiveRedirectUri
            response_mode         = 'query'
            state                 = $state
            code_challenge        = $codeChallenge
            code_challenge_method = 'S256'
        }

        if ($UseV1Endpoint) {
            $query.resource = $Resource
        } else {
            $query.scope = $effectiveScope
            $query.nonce = $nonce

            if ($UseCAE) {
                $query.claims = '{"access_token":{"xms_cc":{"values":["cp1"]}}}'
            }
        }

        $queryString = ($query.GetEnumerator() | ForEach-Object {
            $key = $_.Key
            $value = [System.Uri]::EscapeDataString([string]$_.Value)
            "$key=$value"
        }) -join '&'

        $authoriseUrl = "$authUri`?$queryString"

        $listener = [System.Net.HttpListener]::new()

        try {
            $listener.Prefixes.Add($listenerPrefix)
            $listener.Start()
        } catch {
            Write-Host ""
            Write-Host "[-] Could not start HTTP listener." -ForegroundColor Red
            Write-Host "    Prefix: $listenerPrefix" -ForegroundColor DarkGray
            Write-Host "    $($_.Exception.Message)" -ForegroundColor DarkGray
            return $null
        }

        Write-Host ""
        Write-Host "[*] Listening on $listenerPrefix" -ForegroundColor DarkGray
        Write-Host "[*] Opening system default browser..." -ForegroundColor Yellow

        try {
            Start-Process $authoriseUrl | Out-Null
        } catch {
            Write-Host "[!] Could not auto-open browser. Open this URL manually:" -ForegroundColor Yellow
            Write-Host "    $authoriseUrl" -ForegroundColor Cyan
        }

        Write-Host ""
        Write-Host "[*] Waiting for authorisation code on loopback..." -ForegroundColor DarkGray

        $task = $listener.GetContextAsync()
        $timeout = (Get-Date).AddMinutes(5)

        while (-not $task.IsCompleted -and (Get-Date) -lt $timeout) {
            Start-Sleep -Milliseconds 250
        }

        if (-not $task.IsCompleted) {
            $listener.Stop()
            Write-Host ""
            Write-Host "[-] Interactive flow timed out." -ForegroundColor Red
            return $null
        }

        $context = $task.GetAwaiter().GetResult()
        $request = $context.Request
        $response = $context.Response

        Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue | Out-Null
        $parsedQuery = [System.Web.HttpUtility]::ParseQueryString($request.Url.Query)

        $code = $parsedQuery['code']
        $errorValue = $parsedQuery['error']
        $errorDescription = $parsedQuery['error_description']
        $receivedState = $parsedQuery['state']

        if ($errorValue) {
            $pageBody = "<html><body><h1>Authentication failed</h1><p>$errorValue</p><p>$errorDescription</p></body></html>"
        } else {
            $pageBody = "<html><body><h1>Authentication successful</h1><p>You can close this window and return to PowerShell.</p></body></html>"
        }

        $bytes = [System.Text.Encoding]::UTF8.GetBytes($pageBody)
        $response.ContentType = 'text/html'
        $response.ContentLength64 = $bytes.Length
        $response.OutputStream.Write($bytes, 0, $bytes.Length)
        $response.OutputStream.Close()
        $listener.Stop()

        if ($errorValue) {
            Write-Host ""
            Write-Host "[-] Identity provider returned an error: $errorValue" -ForegroundColor Red
            if ($errorDescription) {
                Write-Host "    $errorDescription" -ForegroundColor DarkGray
            }
            return $null
        }

        if (-not $code) {
            Write-Host ""
            Write-Host "[-] No authorisation code received." -ForegroundColor Red
            return $null
        }

        if ($receivedState -ne $state) {
            Write-Host ""
            Write-Host "[-] State mismatch. Aborting." -ForegroundColor Red
            return $null
        }

        Write-Host "[+] Authorisation code received. Exchanging for token..." -ForegroundColor Green

        $tokenBody = @{
            grant_type    = 'authorization_code'
            client_id     = $ClientId
            code          = $code
            redirect_uri  = $effectiveRedirectUri
            code_verifier = $codeVerifier
        }

        if ($UseV1Endpoint) {
            $tokenBody.resource = $Resource
        } else {
            $tokenBody.scope = $effectiveScope
        }

        try {
            return Invoke-RestMethod `
                -Method POST `
                -Uri $tokenUri `
                -ContentType 'application/x-www-form-urlencoded' `
                -Headers @{ 'User-Agent' = $userAgent } `
                -Body $tokenBody `
                -ErrorAction Stop
        } catch {
            Write-Host ""
            Write-Host "[-] Token exchange failed." -ForegroundColor Red
            $raw = Get-ErrorBody -ErrorRecord $_
            Print-ErrorBody -RawBody $raw
            return $null
        }
    }

    if ($Method -eq 'Interactive') {
        $tokenResponse = Invoke-InteractiveFlow
    } else {
        $tokenResponse = Invoke-DeviceCodeFlow
    }

    if (-not $tokenResponse) {
        return
    }

    $jwt = Decode-Jwt -Jwt $tokenResponse.access_token

    if (-not $Quiet) {
        Write-Header 'Issued Token'

        if ($jwt) {
            Write-KV 'Audience' $jwt.aud Green
            Write-KV 'Issuer' $jwt.iss
            Write-KV 'TenantId' $jwt.tid
            Write-KV 'UPN' $jwt.upn
            Write-KV 'UniqueName' $jwt.unique_name
            Write-KV 'Idp' $jwt.idp
            Write-KV 'ObjectId' $jwt.oid
            Write-KV 'AppId' $jwt.appid
            Write-KV 'Scopes' $jwt.scp

            if ($jwt.roles) {
                Write-KV 'Roles' ($jwt.roles -join ', ')
            }

            if ($jwt.amr) {
                Write-KV 'AuthMethods' ($jwt.amr -join ', ')
            }

            if ($jwt.xms_cc) {
                Write-KV 'CAE Capability' ($jwt.xms_cc -join ', ') Magenta
            }

            try {
                $issuedAt = [System.DateTimeOffset]::FromUnixTimeSeconds($jwt.iat).LocalDateTime
                $expires = [System.DateTimeOffset]::FromUnixTimeSeconds($jwt.exp).LocalDateTime
                $validHours = [math]::Round(($expires - $issuedAt).TotalHours, 2)

                Write-KV 'IssuedAt' $issuedAt

                $expiryColour = 'Green'
                if ($expires -lt (Get-Date)) {
                    $expiryColour = 'Red'
                }

                Write-KV 'Expires' $expires $expiryColour
                Write-KV 'ValidForHours' $validHours
            } catch {}

            if ($TenantId -and $jwt.tid -and $jwt.tid -ne $TenantId) {
                Write-Host ""
                Write-Host "[!] WARNING: token tenant does not match requested TenantId." -ForegroundColor Red
                Write-Host "    Requested: $TenantId" -ForegroundColor DarkGray
                Write-Host "    Received : $($jwt.tid)" -ForegroundColor DarkGray
            } else {
                Write-Host ""
                Write-Host "[+] Token issued under requested authority." -ForegroundColor Green
            }
        } else {
            Write-Host " <access_token did not decode as JWT>" -ForegroundColor Yellow
        }
    }

    if (-not $NoStore) {
        $global:tokens = $tokenResponse
        Write-Host ""
        Write-Host "[i] Token stored in `$global:tokens." -ForegroundColor DarkGray
    }

    if ($OutVar) {
        Set-Variable -Name $OutVar -Value $tokenResponse -Scope Global
        Write-Host "[i] Token also stored in `$global:$OutVar." -ForegroundColor DarkGray
    }

    return $tokenResponse
}

Set-Alias -Name Get-GraphTokensManual -Value Invoke-GetGraphTokens -Scope Global

if ($MyInvocation.InvocationName -ne '.') {
    Invoke-GetGraphTokens @PSBoundParameters | Out-Null
}