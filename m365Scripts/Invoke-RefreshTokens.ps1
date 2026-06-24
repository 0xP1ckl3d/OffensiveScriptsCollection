<#
.SYNOPSIS
    Refresh Microsoft Entra ID tokens with explicit control over client, resource, tenant, scope,
    CAE, User-Agent, and sweep mode.

.DESCRIPTION
    Supports two modes:

    Single mode:
      Refresh one source token to one target audience.

    Sweep mode:
      Refresh one source token to multiple Microsoft service audiences and store each result in a
      distinct global variable.

    The script is both runnable and importable:

      .\Invoke-RefreshTokens.ps1 -Sweep -UseCAE

      . .\Invoke-RefreshTokens.ps1
      Invoke-RefreshTokens -Sweep -UseCAE
      Invoke-RefreshTokens -Resource arm -OutVar armTokens

    Guarantees:
      - Output variables are not overwritten unless the refresh succeeds and an access_token is returned.
      - v2 refreshes include offline_access, openid and profile unless explicitly overridden.
      - InputVar and OutVar are validated before use.
      - TenantId is validated before any HTTP request.
      - -Help and -h print the full switch breakdown.
#>

[CmdletBinding()]
param(
    [string]$ClientId = 'office',
    [string]$Resource = 'msgraph',
    [string]$TenantId,
    [string]$InputVar = 'tokens',
    [string]$OutVar,
    [string]$Scope,
    [switch]$UseV1Endpoint,
    [switch]$UseCAE,
    [ValidateSet('Mac','Windows','Linux','AndroidMobile','iPhone','OS/2')]
    [string]$Device = 'Windows',
    [ValidateSet('Android','IE','Chrome','Firefox','Edge','Safari')]
    [string]$Browser = 'Edge',
    [string]$CustomUserAgent,
    [switch]$Sweep,
    [string[]]$OnlyAudiences,
    [string[]]$SkipAudiences,
    [switch]$Force,
    [switch]$Quiet,
    [switch]$ShowMap,
    [switch]$ClearAll,
    [Alias('h')]
    [switch]$Help
)

function Invoke-RefreshTokens {
    [CmdletBinding()]
    param(
        [string]$ClientId = 'office',
        [string]$Resource = 'msgraph',
        [string]$TenantId,
        [string]$InputVar = 'tokens',
        [string]$OutVar,
        [string]$Scope,
        [switch]$UseV1Endpoint,
        [switch]$UseCAE,
        [ValidateSet('Mac','Windows','Linux','AndroidMobile','iPhone','OS/2')]
        [string]$Device = 'Windows',
        [ValidateSet('Android','IE','Chrome','Firefox','Edge','Safari')]
        [string]$Browser = 'Edge',
        [string]$CustomUserAgent,
        [switch]$Sweep,
        [string[]]$OnlyAudiences,
        [string[]]$SkipAudiences,
        [switch]$Force,
        [switch]$Quiet,
        [switch]$ShowMap,
        [switch]$ClearAll,
        [Alias('h')]
        [switch]$Help
    )

    $refreshCapableOrder = @(
        'd3590ed6-52b3-4102-aeff-aad2292ab01c',
        '1fec8e78-bce4-4aaf-ab1b-5451cc387264',
        '14d82eec-204b-4c2f-b7e8-296a70dab67e',
        '29d9ed98-a469-4536-ade2-f981bc1d605e',
        '4813382a-8fa7-425e-ab75-3b753aab3abb',
        '27922004-5251-4030-b22d-91ecd9a37ea4',
        'ab9b8c07-8f02-4f72-87fa-80105867a763',
        '9ba1a5c7-f17a-4de9-a1f1-6178c8d51223',
        '872cd9fa-d31f-45e0-9eab-6e460a02d1f1',
        '0ec893e0-5785-4de6-99da-4ed124e5296c',
        'a40d7d7d-59aa-447e-a655-679a4107e548'
    )

    $refreshCapable = @{
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
    }

    $refreshIncapableOrder = @(
        '04b07795-8ddb-461a-bbee-02f9e1bf7b46',
        '1950a258-227b-4e31-a9cf-717495945fc2',
        '1b730954-1685-4b74-9bfd-dac224a7b894',
        '00b41c95-dab0-4487-9791-b9d2c32c80f2',
        '00000003-0000-0ff1-ce00-000000000000',
        'de8bc8b5-d9f9-48b1-a8ad-b748da725064',
        'fb78d390-0c51-40cd-8e17-fdbfab77341b'
    )

    $refreshIncapable = @{
        '04b07795-8ddb-461a-bbee-02f9e1bf7b46' = 'Azure CLI'
        '1950a258-227b-4e31-a9cf-717495945fc2' = 'Azure PowerShell'
        '1b730954-1685-4b74-9bfd-dac224a7b894' = 'AzureAD PowerShell / MSOnline'
        '00b41c95-dab0-4487-9791-b9d2c32c80f2' = 'Office 365 Management'
        '00000003-0000-0ff1-ce00-000000000000' = 'SharePoint Online'
        'de8bc8b5-d9f9-48b1-a8ad-b748da725064' = 'Graph Explorer'
        'fb78d390-0c51-40cd-8e17-fdbfab77341b' = 'Microsoft Exchange REST API'
    }

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
        'https://analysis.windows.net/powerbi/api'   = 'Power BI Service / REST API / DAX executeQueries'
        'https://service.flow.microsoft.com'         = 'Power Automate'
        'https://api.fabric.microsoft.com'           = 'Microsoft Fabric'
        'https://api.partnercenter.microsoft.com'    = 'Partner Center'
        'https://api.spaces.skype.com'               = 'Skype / Teams Spaces'
        'https://api.applicationinsights.io'         = 'Application Insights'
        'https://api.loganalytics.io'                = 'Log Analytics'
        'https://api.security.microsoft.com'         = 'Microsoft Defender XDR'
        'https://officeapps.live.com'                = 'Office Apps Live'
        'https://manage.office.com'                  = 'Office Management API'
        'https://www.yammer.com'                     = 'Yammer / Viva Engage'
        'https://wip.mam.manage.microsoft.com'       = 'Intune MAM'
        '499b84ac-1321-427f-aa17-267ca6975798'       = 'Azure DevOps'
        '0000000a-0000-0000-c000-000000000000'       = 'Intune Graph'
        '00000002-0000-0000-c000-000000000000'       = 'Azure AD Graph GUID'
        '00000003-0000-0000-c000-000000000000'       = 'Microsoft Graph GUID'
        '797f4846-ba00-4fd7-ba43-dac1f8f63013'       = 'Azure Resource Manager GUID'
        '00000002-0000-0ff1-ce00-000000000000'       = 'Exchange Online GUID'
        '00000003-0000-0ff1-ce00-000000000000'       = 'SharePoint Online GUID'
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

    $sweepAudiences = @(
        @{ Key='msgraph'    ; Name='Microsoft Graph'           ; Resource='https://graph.microsoft.com'              ; ClientId='d3590ed6-52b3-4102-aeff-aad2292ab01c' ; OutVar='graphTokens'      ; CAE=$true  },
        @{ Key='aadgraph'   ; Name='Azure AD Graph legacy'     ; Resource='https://graph.windows.net'                ; ClientId='d3590ed6-52b3-4102-aeff-aad2292ab01c' ; OutVar='aadGraphTokens'   ; CAE=$false },
        @{ Key='arm'        ; Name='Azure Resource Manager'    ; Resource='https://management.azure.com'             ; ClientId='d3590ed6-52b3-4102-aeff-aad2292ab01c' ; OutVar='armTokens'        ; CAE=$true  },
        @{ Key='asm'        ; Name='Azure Service Management'  ; Resource='https://management.core.windows.net'      ; ClientId='d3590ed6-52b3-4102-aeff-aad2292ab01c' ; OutVar='asmTokens'        ; CAE=$false },
        @{ Key='outlook'    ; Name='Outlook / Exchange Online' ; Resource='https://outlook.office.com'               ; ClientId='d3590ed6-52b3-4102-aeff-aad2292ab01c' ; OutVar='outlookTokens'    ; CAE=$true  },
        @{ Key='substrate'  ; Name='M365 Substrate'            ; Resource='https://substrate.office.com'             ; ClientId='d3590ed6-52b3-4102-aeff-aad2292ab01c' ; OutVar='substrateTokens'  ; CAE=$true  },
        @{ Key='teams'      ; Name='Microsoft Teams'           ; Resource='https://api.spaces.skype.com'             ; ClientId='1fec8e78-bce4-4aaf-ab1b-5451cc387264' ; OutVar='teamsTokens'      ; CAE=$true  },
        @{ Key='officeapps' ; Name='Office Apps'               ; Resource='https://officeapps.live.com'              ; ClientId='d3590ed6-52b3-4102-aeff-aad2292ab01c' ; OutVar='officeAppsTokens' ; CAE=$false },
        @{ Key='officemgmt' ; Name='Office Management API'     ; Resource='https://manage.office.com'                ; ClientId='d3590ed6-52b3-4102-aeff-aad2292ab01c' ; OutVar='officeMgmtTokens' ; CAE=$false },
        @{ Key='vault'      ; Name='Azure Key Vault'           ; Resource='https://vault.azure.net'                  ; ClientId='d3590ed6-52b3-4102-aeff-aad2292ab01c' ; OutVar='vaultTokens'      ; CAE=$false },
        @{ Key='storage'    ; Name='Azure Storage'             ; Resource='https://storage.azure.com'                ; ClientId='d3590ed6-52b3-4102-aeff-aad2292ab01c' ; OutVar='storageTokens'    ; CAE=$false },
        @{ Key='powerbi'    ; Name='Power BI Service'          ; Resource='https://analysis.windows.net/powerbi/api' ; ClientId='d3590ed6-52b3-4102-aeff-aad2292ab01c' ; OutVar='powerbiTokens'    ; CAE=$false },
        @{ Key='flow'       ; Name='Power Automate'            ; Resource='https://service.flow.microsoft.com'       ; ClientId='d3590ed6-52b3-4102-aeff-aad2292ab01c' ; OutVar='flowTokens'       ; CAE=$false },
        @{ Key='fabric'     ; Name='Microsoft Fabric'          ; Resource='https://api.fabric.microsoft.com'         ; ClientId='d3590ed6-52b3-4102-aeff-aad2292ab01c' ; OutVar='fabricTokens'     ; CAE=$false },
        @{ Key='defender'   ; Name='Microsoft Defender XDR'    ; Resource='https://api.security.microsoft.com'       ; ClientId='d3590ed6-52b3-4102-aeff-aad2292ab01c' ; OutVar='defenderTokens'   ; CAE=$false },
        @{ Key='intune'     ; Name='Intune Service'            ; Resource='0000000a-0000-0000-c000-000000000000'     ; ClientId='9ba1a5c7-f17a-4de9-a1f1-6178c8d51223' ; OutVar='intuneTokens'     ; CAE=$false },
        @{ Key='mam'        ; Name='Intune MAM'                ; Resource='https://wip.mam.manage.microsoft.com'     ; ClientId='9ba1a5c7-f17a-4de9-a1f1-6178c8d51223' ; OutVar='mamTokens'        ; CAE=$false },
        @{ Key='yammer'     ; Name='Yammer / Viva Engage'      ; Resource='https://www.yammer.com'                   ; ClientId='d3590ed6-52b3-4102-aeff-aad2292ab01c' ; OutVar='yammerTokens'     ; CAE=$false },
        @{ Key='sql'        ; Name='Azure SQL'                 ; Resource='https://database.windows.net'             ; ClientId='d3590ed6-52b3-4102-aeff-aad2292ab01c' ; OutVar='sqlTokens'        ; CAE=$false },
        @{ Key='devops'     ; Name='Azure DevOps'              ; Resource='499b84ac-1321-427f-aa17-267ca6975798'     ; ClientId='d3590ed6-52b3-4102-aeff-aad2292ab01c' ; OutVar='devopsTokens'     ; CAE=$false }
    )

    $aadStsMap = @{
        '500011' = 'invalid_resource. The target resource/audience is not registered or is not valid for this tenant.'
        '50034'  = 'Account does not exist in the directory specified. Wrong tenant.'
        '50053'  = 'Account locked out due to too many failed sign-ins.'
        '50076'  = 'MFA required for this resource or client.'
        '50079'  = 'Strong authentication enrolment required.'
        '50105'  = 'User is not assigned to this app.'
        '50158'  = 'External security challenge or Conditional Access step-up required.'
        '50173'  = 'FreshTokenNeeded. Refresh token no longer satisfies Conditional Access freshness.'
        '53000'  = 'Device not compliant or not joined.'
        '53003'  = 'Conditional Access blocked the request.'
        '65001'  = 'Consent not granted for this scope or client.'
        '65002'  = 'invalid_request. The resource or client combination is invalid.'
        '70000'  = 'invalid_grant. Common causes include stale refresh token, non-FOCI target client, or Conditional Access freshness.'
        '70008'  = 'Refresh token expired.'
        '70011'  = 'Invalid scope.'
        '70043'  = 'Refresh token expired due to inactivity.'
        '700016' = 'unauthorised_client. The client_id is not authorised in this tenant.'
        '900023' = 'Invalid tenant identifier.'
        '9002313'= 'Invalid request. Verify client_id, scope and grant_type.'
    }

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
        Write-Host ("{0,-18}: " -f $Key) -ForegroundColor Yellow -NoNewline
        Write-Host $Value -ForegroundColor $Colour
    }

    function Get-OrDefault {
        param($Value, $Default)
        if ($null -ne $Value -and "$Value" -ne '') {
            return $Value
        }
        return $Default
    }

    function Test-IsValidPSVariableName {
        param([string]$Name)
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
        if ($Value -match '^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$') {
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
            if (-not $Jwt -or $Jwt.Split('.').Count -lt 2) {
                return $null
            }

            $segment = $Jwt.Split('.')[1]
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

    function Test-IsCaeResource {
        param(
            [string]$Resource,
            [string[]]$CaeList
        )

        if (-not $Resource) {
            return $false
        }

        $resourceNorm = $Resource.TrimEnd('/').ToLower()

        foreach ($item in $CaeList) {
            $itemNorm = $item.TrimEnd('/').ToLower()
            if ($itemNorm -eq $resourceNorm) {
                return $true
            }
        }

        return $false
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

    function Print-Diagnostic {
        param(
            $ErrJson,
            [string]$RawBody,
            [bool]$CrossClient,
            [string]$SrcAppId,
            [string]$ClientId,
            [string]$TenantId,
            [string]$InputVar,
            [hashtable]$IncapableMap,
            [hashtable]$AadMap
        )

        if (-not $ErrJson) {
            if ($RawBody) {
                $firstLine = ($RawBody -split "`n")[0]
                Write-Host "    raw : $firstLine" -ForegroundColor DarkGray
            }
            return
        }

        Write-Host ""
        Write-Host "    error             : $($ErrJson.error)" -ForegroundColor Red

        if ($ErrJson.error_description) {
            $desc = ($ErrJson.error_description -split "`n")[0]
            Write-Host "    error_description : $desc" -ForegroundColor DarkGray
        }

        if ($ErrJson.error_codes) {
            Write-Host "    error_codes       : $(($ErrJson.error_codes) -join ',')" -ForegroundColor DarkGray
        }

        if ($ErrJson.suberror) {
            Write-Host "    suberror          : $($ErrJson.suberror)" -ForegroundColor DarkGray
        }

        if ($ErrJson.trace_id) {
            Write-Host "    trace_id          : $($ErrJson.trace_id)" -ForegroundColor DarkGray
        }

        if ($ErrJson.correlation_id) {
            Write-Host "    correlation_id    : $($ErrJson.correlation_id)" -ForegroundColor DarkGray
        }

        $codes = @()

        if ($ErrJson.error_codes) {
            $codes += $ErrJson.error_codes
        }

        if ($ErrJson.error_description -and $ErrJson.error_description -match 'AADSTS(\d+)') {
            $codes += [int]$Matches[1]
        }

        $codes = $codes | Sort-Object -Unique

        if ($codes.Count -gt 0) {
            Write-Host ""
            Write-Host "[!] Diagnostic:" -ForegroundColor Yellow

            foreach ($code in $codes) {
                $key = "$code"
                if ($AadMap.ContainsKey($key)) {
                    Write-Host "    AADSTS$key - $($AadMap[$key])" -ForegroundColor Yellow
                }
            }
        }

        if ($ErrJson.error -eq 'invalid_grant') {
            Write-Host ""

            if ($CrossClient -and $IncapableMap.ContainsKey($ClientId)) {
                Write-Host "[i] Cross-client refresh into a refresh-incapable client." -ForegroundColor Cyan
                Write-Host "    Use device code for that client instead:" -ForegroundColor DarkGray
                Write-Host "    .\Invoke-GetGraphTokens.ps1 -Method DeviceCode -ClientId $ClientId -TenantId $TenantId" -ForegroundColor Cyan
            } elseif ($CrossClient) {
                Write-Host "[i] Cross-client refresh from $SrcAppId to $ClientId failed." -ForegroundColor Cyan
                Write-Host "    Possible causes:" -ForegroundColor DarkGray
                Write-Host "    - Target client is not FOCI-capable in this tenant." -ForegroundColor DarkGray
                Write-Host "    - Conditional Access blocked the cross-client refresh token exchange." -ForegroundColor DarkGray
                Write-Host "    - Source refresh token does not have a usable FOCI chain." -ForegroundColor DarkGray
            } else {
                Write-Host "[i] Possible causes:" -ForegroundColor Cyan
                Write-Host "    - Refresh token in `$$InputVar was rotated elsewhere." -ForegroundColor DarkGray
                Write-Host "    - Conditional Access freshness expired." -ForegroundColor DarkGray
                Write-Host "    - Wrong identity or tenant." -ForegroundColor DarkGray
            }
        }
    }

    function Invoke-SingleRefresh {
        param(
            [string]$ClientId,
            [string]$Resource,
            [string]$TenantId,
            [string]$RefreshToken,
            [string]$Scope,
            [switch]$UseV1Endpoint,
            [switch]$UseCAE,
            [string]$UserAgent
        )

        $useV2 = -not $UseV1Endpoint
        $baseUri = "https://login.microsoftonline.com/$TenantId"

        if ($useV2) {
            $tokenUri = "$baseUri/oauth2/v2.0/token"
        } else {
            $tokenUri = "$baseUri/oauth2/token"
        }

        $body = [ordered]@{
            grant_type    = 'refresh_token'
            refresh_token = $RefreshToken
            client_id     = $ClientId
        }

        if ($useV2) {
            if ($Scope) {
                $effectiveScope = $Scope

                if ($effectiveScope -notmatch '\boffline_access\b') {
                    $effectiveScope = "$effectiveScope offline_access"
                }

                if ($effectiveScope -notmatch '\bopenid\b') {
                    $effectiveScope = "$effectiveScope openid"
                }

                if ($effectiveScope -notmatch '\bprofile\b') {
                    $effectiveScope = "$effectiveScope profile"
                }

                $body.scope = $effectiveScope
            } else {
                $body.scope = "$Resource/.default offline_access openid profile"
            }
        } else {
            $body.resource = $Resource

            if ($Scope) {
                $body.scope = $Scope
            } else {
                $body.scope = 'openid'
            }
        }

        if ($UseCAE) {
            $body.claims = '{"access_token":{"xms_cc":{"values":["cp1"]}}}'
        }

        $headers = @{
            'Content-Type' = 'application/x-www-form-urlencoded'
        }

        if ($UserAgent) {
            $headers['User-Agent'] = $UserAgent
        }

        try {
            $response = Invoke-RestMethod -Method POST -Uri $tokenUri -Headers $headers -Body $body -ErrorAction Stop
            return [pscustomobject]@{
                Success = $true
                Token   = $response
                ErrJson = $null
                RawBody = $null
                Status  = 200
            }
        } catch {
            $status = $null

            try {
                $status = $_.Exception.Response.StatusCode.value__
            } catch {}

            $raw = Get-ErrorBody -ErrorRecord $_
            $errJson = $null

            if ($raw) {
                try {
                    $errJson = $raw | ConvertFrom-Json
                } catch {}
            }

            return [pscustomobject]@{
                Success = $false
                Token   = $null
                ErrJson = $errJson
                RawBody = $raw
                Status  = $status
            }
        }
    }

    function Print-IssuedToken {
        param(
            $NewTokens,
            [string]$ReqResource,
            [bool]$UseCAE,
            [bool]$CaeSupported,
            [string]$ClientId
        )

        $jwt = Decode-Jwt -Jwt $NewTokens.access_token

        Write-Header 'Issued Token'

        if (-not $jwt) {
            Write-Host " <token did not decode as JWT>" -ForegroundColor Yellow
            return
        }

        Write-KV 'Audience' $jwt.aud Green
        Write-KV 'Issuer' $jwt.iss
        Write-KV 'TenantId' $jwt.tid
        Write-KV 'UPN' $jwt.upn
        Write-KV 'UniqueName' $jwt.unique_name
        Write-KV 'AppId' $jwt.appid
        Write-KV 'AppName' $jwt.app_displayname
        Write-KV 'ObjectId' $jwt.oid
        Write-KV 'Scopes' $jwt.scp

        if ($jwt.roles) {
            Write-KV 'Roles' ($jwt.roles -join ', ')
        }

        if ($jwt.amr) {
            Write-KV 'AuthMethods' ($jwt.amr -join ', ')
        }

        if ($jwt.idp) {
            Write-KV 'Identity Provider' $jwt.idp Magenta
        }

        if ($jwt.xms_cc) {
            Write-KV 'CAE Capability' ($jwt.xms_cc -join ', ') Magenta
        }

        $validHours = $null

        try {
            $issuedAt = [System.DateTimeOffset]::FromUnixTimeSeconds($jwt.iat).LocalDateTime
            $notBefore = [System.DateTimeOffset]::FromUnixTimeSeconds($jwt.nbf).LocalDateTime
            $expires = [System.DateTimeOffset]::FromUnixTimeSeconds($jwt.exp).LocalDateTime
            $valid = $expires - $issuedAt
            $validHours = [math]::Round($valid.TotalHours, 2)

            Write-KV 'IssuedAt' $issuedAt
            Write-KV 'NotBefore' $notBefore

            $expiryColour = 'Green'
            if ($expires -lt (Get-Date)) {
                $expiryColour = 'Red'
            }

            Write-KV 'ExpirationDate' $expires $expiryColour

            $hoursColour = 'White'
            if ($valid.TotalHours -gt 2) {
                $hoursColour = 'Magenta'
            }

            Write-KV 'ValidForHours' $validHours $hoursColour
        } catch {}

        if ($UseCAE -and $validHours -ne $null -and $validHours -lt 2) {
            Write-Host ""

            if ($CaeSupported) {
                Write-Host "[!] Requested CAE but token lifetime is still about one hour." -ForegroundColor Yellow
                Write-Host "    Tenant policy or client registration may not honour CAE for this exchange." -ForegroundColor DarkGray
            } else {
                Write-Host "[i] CAE was requested but this resource is not in the CAE extended-lifetime list." -ForegroundColor DarkGray
                Write-Host "    Token lifetime remaining at about one hour is expected." -ForegroundColor DarkGray
            }
        }

        try {
            $requestedNorm = $ReqResource.TrimEnd('/').ToLower()
            $audNorm = "$($jwt.aud)".TrimEnd('/').ToLower()
            $requestedIsGuid = $requestedNorm -match '^[0-9a-f]{8}-'

            if (-not $requestedIsGuid -and $requestedNorm -and $audNorm -and $audNorm -ne $requestedNorm) {
                Write-Host ""
                Write-Host "[!] Audience mismatch." -ForegroundColor Yellow
                Write-Host "    Requested : $ReqResource" -ForegroundColor DarkGray
                Write-Host "    Received  : $($jwt.aud)" -ForegroundColor DarkGray
            }
        } catch {}

        if ($jwt.appid -and $jwt.appid -ne $ClientId) {
            Write-Host ""
            Write-Host "[!] AppId mismatch. Requested $ClientId but token contains $($jwt.appid)." -ForegroundColor Yellow
        }
    }

    function Show-RefreshHelp {
        Write-Host ""
        Write-Host "Invoke-RefreshTokens - Quick Reference" -ForegroundColor Cyan
        Write-Host "--------------------------------------" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "USAGE:" -ForegroundColor Yellow
        Write-Host "  .\Invoke-RefreshTokens.ps1"
        Write-Host "  .\Invoke-RefreshTokens.ps1 -Sweep -UseCAE"
        Write-Host "  .\Invoke-RefreshTokens.ps1 -Resource arm -OutVar armTokens -UseCAE"
        Write-Host "  . .\Invoke-RefreshTokens.ps1"
        Write-Host "  Invoke-RefreshTokens -Sweep -UseCAE"
        Write-Host "  Invoke-RefreshTokens -Resource powerbi -OutVar powerbiTokens"
        Write-Host ""
        Write-Host "SWITCHES:" -ForegroundColor Yellow
        Write-Host "  -ClientId          <id|alias>   Target client GUID or alias              (default: office)"
        Write-Host "  -Resource          <url|alias>  Target audience                          (default: msgraph)"
        Write-Host "  -TenantId          <id>         Tenant GUID, domain, common, organisations or consumers"
        Write-Host "  -InputVar          <name>       Source variable name                     (default: tokens)"
        Write-Host "  -OutVar            <name>       Destination variable name                (default: InputVar)"
        Write-Host "  -Scope             <scope>      Explicit scope override                  (default: resource/.default openid profile offline_access)"
        Write-Host "  -UseV1Endpoint                  Force /oauth2/token v1 endpoint"
        Write-Host "  -UseCAE                         Request CAE-capable token using xms_cc=cp1"
        Write-Host "  -Device            <platform>   UA device                                (default: Windows)"
        Write-Host "  -Browser           <browser>    UA browser                               (default: Edge)"
        Write-Host "  -CustomUserAgent   <ua>         Full UA override"
        Write-Host "  -Sweep                          Sweep mode: refresh all configured audiences"
        Write-Host "  -OnlyAudiences     <list>       Sweep: only attempt these audience keys"
        Write-Host "  -SkipAudiences     <list>       Sweep: skip these audience keys"
        Write-Host "  -Force                          Bypass pre-flight refresh-incapable block"
        Write-Host "  -Quiet                          Suppress per-token decode output"
        Write-Host "  -ShowMap                        Print reference tables and exit"
        Write-Host "  -ClearAll                       Remove token variables from global session"
        Write-Host "  -Help, -h                       Print this help menu"
        Write-Host ""

        Write-Host ""
        Write-Host "SWEEP AUDIENCES:" -ForegroundColor Magenta

        foreach ($audience in $sweepAudiences) {
            $caeLabel = '   '
            if ($audience.CAE) {
                $caeLabel = 'CAE'
            }

            $outVarDisplay = '$' + $audience.OutVar
            Write-Host ("  {0,-12} [{1}] -> {2,-22} {3}" -f $audience.Key, $caeLabel, $outVarDisplay, $audience.Name)
        }

        Write-Host ""
        Write-Host "CLIENT ALIASES:" -ForegroundColor Green

        foreach ($key in ($clientAliasMap.Keys | Sort-Object)) {
            Write-Host ("  {0,-14} -> {1}" -f $key, $clientAliasMap[$key])
        }

        Write-Host ""
        Write-Host "RESOURCE ALIASES:" -ForegroundColor Green

        foreach ($key in ($resourceAliasMap.Keys | Sort-Object)) {
            $value = $resourceAliasMap[$key]
            $description = ''

            if ($resourceDescriptions.ContainsKey($value)) {
                $description = $resourceDescriptions[$value]
            }

            Write-Host ("  {0,-14} -> {1,-48} {2}" -f $key, $value, $description)
        }

        Write-Host ""
        Write-Host "REFRESH-CAPABLE CLIENTS:" -ForegroundColor Green

        foreach ($id in $refreshCapableOrder) {
            Write-Host ("  {0,-40} {1}" -f $id, $refreshCapable[$id])
        }

        Write-Host ""
        Write-Host "REFRESH-INCAPABLE CLIENTS:" -ForegroundColor Red

        foreach ($id in $refreshIncapableOrder) {
            Write-Host ("  {0,-40} {1}" -f $id, $refreshIncapable[$id])
        }

        Write-Host ""
        Write-Host "CAE-SUPPORTED RESOURCES:" -ForegroundColor Magenta

        foreach ($resourceItem in $caeSupportedResources) {
            Write-Host "  $resourceItem"
        }

        Write-Host ""
    }

    if ($Help -or $ShowMap) {
        Show-RefreshHelp
        return
    }

    if ($ClearAll) {
        $extra = $sweepAudiences | ForEach-Object { $_.OutVar }

        $candidates = @(
            'tokens',
            'armTokens',
            'aadGraphTokens',
            'teamsTokens',
            'exTokens',
            'outlookTokens',
            'guestTokens',
            'guestArm',
            'guestGraph',
            'LegacyAADGraphToken',
            'LegacyMSOnlineToken',
            'LegacyARMToken',
            'cliTokens',
            'authTokens',
            'officeTokens',
            'LastSweepResults'
        )

        $candidates = @($candidates + $extra) | Select-Object -Unique
        $cleared = 0

        foreach ($candidate in $candidates) {
            if (Get-Variable -Name $candidate -Scope Global -ErrorAction SilentlyContinue) {
                Remove-Variable -Name $candidate -Scope Global -Force -ErrorAction SilentlyContinue
                Write-Host "[-] Cleared `$global:$candidate" -ForegroundColor DarkGray
                $cleared++
            }
        }

        Write-Host ""
        Write-Host "[+] Cleared $cleared token variable(s)." -ForegroundColor Green
        return
    }

    if (-not (Test-IsValidPSVariableName -Name $InputVar)) {
        Write-Host "[!] -InputVar value is not a valid PowerShell variable name." -ForegroundColor Red
        Write-Host "    Pass the variable name only, for example: tokens" -ForegroundColor DarkGray
        return
    }

    if ($OutVar -and -not (Test-IsValidPSVariableName -Name $OutVar)) {
        Write-Host "[!] -OutVar value is not a valid PowerShell variable name." -ForegroundColor Red
        Write-Host "    Pass the variable name only, for example: armTokens" -ForegroundColor DarkGray
        return
    }

    if ($TenantId -and -not (Test-IsValidTenant -Value $TenantId)) {
        Write-Host "[!] -TenantId '$TenantId' is not a valid tenant identifier." -ForegroundColor Red
        Write-Host "    Accepted forms: GUID, DNS domain, common, organizations or consumers." -ForegroundColor DarkGray
        return
    }

    $src = Get-Variable -Name $InputVar -ValueOnly -ErrorAction SilentlyContinue

    if (-not $src) {
        Write-Host "[!] Source variable `$$InputVar not found." -ForegroundColor Red
        return
    }

    if (-not $src.refresh_token) {
        Write-Host "[!] `$$InputVar has no refresh_token property." -ForegroundColor Red
        return
    }

    $srcJwt = Decode-Jwt -Jwt $src.access_token
    $srcAppId = $null
    $srcTid = $null
    $srcUpn = $null
    $srcExp = $null

    if ($srcJwt) {
        $srcAppId = $srcJwt.appid
        $srcTid = $srcJwt.tid
        $srcUpn = $srcJwt.upn

        if (-not $srcUpn) {
            $srcUpn = $srcJwt.unique_name
        }

        try {
            $srcExp = [System.DateTimeOffset]::FromUnixTimeSeconds($srcJwt.exp).LocalDateTime
        } catch {}
    }

    if (-not $TenantId) {
        if ($srcTid) {
            $TenantId = $srcTid
        } else {
            $TenantId = 'common'
        }
    }

    $ua = Get-ForgedUA -Device $Device -Browser $Browser -CustomUA $CustomUserAgent
    $displayUpn = Get-OrDefault -Value $srcUpn -Default '<unknown>'
    $displayApp = Get-OrDefault -Value $srcAppId -Default '<unknown>'

    if ($Sweep) {
        Write-Header 'Sweep Mode'
        Write-KV 'InputVar' ("`$" + $InputVar)
        Write-KV 'Source UPN' $displayUpn
        Write-KV 'Source AppId' $displayApp
        Write-KV 'TenantId' $TenantId
        Write-KV 'Device/Browser' "$Device / $Browser"

        $caeText = 'no'
        if ($UseCAE) {
            $caeText = 'yes (xms_cc=cp1 where enabled per audience)'
        }

        Write-KV 'UseCAE' $caeText

        if ($srcExp) {
            $remaining = $srcExp - (Get-Date)
            $expiryText = "in $([int]$remaining.TotalMinutes)m"

            if ($remaining.TotalSeconds -lt 0) {
                $expiryText = "EXPIRED $([math]::Abs([int]$remaining.TotalMinutes))m ago"
            }

            Write-KV 'Src AT Expiry' "$srcExp ($expiryText)"
        }

        $targets = $sweepAudiences

        if ($OnlyAudiences) {
            $onlyNormalised = $OnlyAudiences | ForEach-Object { $_.ToLower() }
            $targets = $targets | Where-Object { $onlyNormalised -contains $_.Key.ToLower() }
        }

        if ($SkipAudiences) {
            $skipNormalised = $SkipAudiences | ForEach-Object { $_.ToLower() }
            $targets = $targets | Where-Object { $skipNormalised -notcontains $_.Key.ToLower() }
        }

        if (-not $targets -or @($targets).Count -eq 0) {
            Write-Host "[!] No audiences match the requested filter." -ForegroundColor Red
            return
        }

        Write-Host ""
        Write-Host ("Attempting {0} audience(s)..." -f @($targets).Count) -ForegroundColor DarkGray
        Write-Host ""

        $summary = @()

        foreach ($target in $targets) {
            $useCaeForTarget = $false

            if ($UseCAE -and $target.CAE) {
                $useCaeForTarget = $true
            }

            $result = Invoke-SingleRefresh `
                -ClientId $target.ClientId `
                -Resource $target.Resource `
                -TenantId $TenantId `
                -RefreshToken $src.refresh_token `
                -UseCAE:$useCaeForTarget `
                -UserAgent $ua

            if ($result.Success -and $result.Token.access_token) {
                Set-Variable -Name $target.OutVar -Value $result.Token -Scope Global

                $jwt = Decode-Jwt -Jwt $result.Token.access_token
                $expiry = $null
                $hours = '?'
                $aud = $target.Resource

                if ($jwt -and $jwt.aud) {
                    $aud = $jwt.aud
                }

                try {
                    $expiry = [System.DateTimeOffset]::FromUnixTimeSeconds($jwt.exp).LocalDateTime
                    $hours = [math]::Round(($expiry - (Get-Date)).TotalHours, 2)
                } catch {}

                $varDisplay = '$' + $target.OutVar

                Write-Host (" {0,-12} " -f $target.Key) -ForegroundColor Yellow -NoNewline
                Write-Host "OK   " -ForegroundColor Green -NoNewline
                Write-Host ($varDisplay.PadRight(22)) -ForegroundColor Cyan -NoNewline
                Write-Host (" aud={0}  expires in {1}h" -f $aud, $hours) -ForegroundColor DarkGray

                $summary += [pscustomobject]@{
                    Audience = $target.Key
                    Service  = $target.Name
                    OutVar   = $varDisplay
                    Aud      = $aud
                    Hours    = $hours
                    Status   = 'OK'
                    Error    = $null
                }
            } else {
                $errCode = "HTTP $($result.Status)"

                if ($result.ErrJson -and $result.ErrJson.error) {
                    $errCode = $result.ErrJson.error
                }

                $aadsts = $null

                if ($result.ErrJson) {
                    if ($result.ErrJson.error_codes) {
                        $aadsts = $result.ErrJson.error_codes[0]
                    } elseif ($result.ErrJson.error_description -and $result.ErrJson.error_description -match 'AADSTS(\d+)') {
                        $aadsts = $Matches[1]
                    }
                }

                $message = $errCode

                if ($aadsts) {
                    $message = "$errCode (AADSTS$aadsts)"
                }

                $varDisplay = '$' + $target.OutVar

                Write-Host (" {0,-12} " -f $target.Key) -ForegroundColor Yellow -NoNewline
                Write-Host "FAIL " -ForegroundColor Red -NoNewline
                Write-Host ($varDisplay.PadRight(22)) -ForegroundColor DarkGray -NoNewline
                Write-Host " $message" -ForegroundColor Red

                $summary += [pscustomobject]@{
                    Audience = $target.Key
                    Service  = $target.Name
                    OutVar   = $varDisplay
                    Aud      = $null
                    Hours    = $null
                    Status   = 'FAIL'
                    Error    = $message
                }
            }

            Start-Sleep -Milliseconds 200
        }

        $okCount = @($summary | Where-Object { $_.Status -eq 'OK' }).Count
        $failCount = @($summary | Where-Object { $_.Status -eq 'FAIL' }).Count

        Write-Host ""
        Write-Host ("Sweep complete: {0} succeeded, {1} failed." -f $okCount, $failCount) -ForegroundColor Cyan
        Write-Host "Summary stashed in `$LastSweepResults." -ForegroundColor DarkGray

        $global:LastSweepResults = $summary
        return
    }

    $originalClientId = $ClientId
    $ClientId = Resolve-Alias -Value $ClientId -Map $clientAliasMap

    $originalResource = $Resource
    $Resource = Resolve-Alias -Value $Resource -Map $resourceAliasMap

    if (-not $OutVar) {
        $OutVar = $InputVar
    }

    $crossClient = $false

    if ($srcAppId -and $srcAppId -ne $ClientId) {
        $crossClient = $true
    }

    $caeSupported = Test-IsCaeResource -Resource $Resource -CaeList $caeSupportedResources

    Write-Header 'Refresh Token Exchange'
    Write-KV 'InputVar' ("`$" + $InputVar)
    Write-KV 'OutVar' ("`$" + $OutVar) Green
    Write-KV 'Source UPN' $displayUpn
    Write-KV 'Source AppId' $displayApp
    Write-KV 'TenantId' $TenantId

    $clientIdDisplay = $ClientId

    if ($originalClientId -ne $ClientId) {
        $clientIdDisplay = "$ClientId  (alias: $originalClientId)"
    }

    Write-KV 'ClientId' $clientIdDisplay

    $clientName = $null

    if ($refreshCapable.ContainsKey($ClientId)) {
        $clientName = $refreshCapable[$ClientId]
    }

    if ($refreshIncapable.ContainsKey($ClientId)) {
        $clientName = $refreshIncapable[$ClientId]
    }

    if ($clientName) {
        Write-KV 'ClientName' $clientName
    }

    $resourceDisplay = $Resource

    if ($originalResource -ne $Resource) {
        $resourceDisplay = "$Resource  (alias: $originalResource)"
    }

    Write-KV 'Resource' $resourceDisplay Green

    if ($resourceDescriptions.ContainsKey($Resource)) {
        Write-KV 'ResourceName' $resourceDescriptions[$Resource]
    }

    $endpointLabel = 'v2.0'

    if ($UseV1Endpoint) {
        $endpointLabel = 'v1.0'
    }

    Write-KV 'Endpoint' $endpointLabel

    if ($UseCAE) {
        $caeLabel = 'enabled (xms_cc=cp1, resource not in extended-lifetime list)'
        $caeColour = 'Yellow'

        if ($caeSupported) {
            $caeLabel = 'enabled (xms_cc=cp1, resource is in extended-lifetime list)'
            $caeColour = 'Magenta'
        }

        Write-KV 'CAE' $caeLabel $caeColour
    }

    Write-KV 'Device/Browser' "$Device / $Browser"

    if ($ua) {
        $uaShort = $ua

        if ($ua.Length -gt 70) {
            $uaShort = $ua.Substring(0, 70) + '...'
        }

        Write-KV 'User-Agent' $uaShort
    }

    if ($crossClient) {
        Write-KV 'Cross-client' "$srcAppId -> $ClientId" Magenta
    }

    if ($srcExp) {
        $remaining = $srcExp - (Get-Date)
        $expiryText = "in $([int]$remaining.TotalMinutes)m"

        if ($remaining.TotalSeconds -lt 0) {
            $expiryText = "EXPIRED $([math]::Abs([int]$remaining.TotalMinutes))m ago"
        }

        Write-KV 'Src AT Expiry' "$srcExp ($expiryText)"
    }

    if ($refreshIncapable.ContainsKey($ClientId)) {
        Write-Host ""
        Write-Host "[!] Target client '$($refreshIncapable[$ClientId])' is not treated as refresh-capable by this script." -ForegroundColor Red
        Write-Host "    Cross-client refresh into this client is expected to fail." -ForegroundColor Red
        Write-Host "    Obtain a fresh token via device code instead:" -ForegroundColor Yellow
        Write-Host "      .\Invoke-GetGraphTokens.ps1 -Method DeviceCode -ClientId $ClientId -TenantId $TenantId" -ForegroundColor Cyan

        if (-not $Force) {
            Write-Host ""
            Write-Host "[*] Aborting. Pass -Force to attempt anyway." -ForegroundColor Yellow
            return
        }

        Write-Host "[*] -Force supplied. Attempting anyway..." -ForegroundColor Yellow
    }

    $refreshResult = Invoke-SingleRefresh `
        -ClientId $ClientId `
        -Resource $Resource `
        -TenantId $TenantId `
        -RefreshToken $src.refresh_token `
        -Scope $Scope `
        -UseV1Endpoint:$UseV1Endpoint `
        -UseCAE:$UseCAE `
        -UserAgent $ua

    if (-not $refreshResult.Success -or -not $refreshResult.Token.access_token) {
        Write-Host ""
        Write-Host "[-] Refresh failed (HTTP $($refreshResult.Status))" -ForegroundColor Red

        Print-Diagnostic `
            -ErrJson $refreshResult.ErrJson `
            -RawBody $refreshResult.RawBody `
            -CrossClient $crossClient `
            -SrcAppId $srcAppId `
            -ClientId $ClientId `
            -TenantId $TenantId `
            -InputVar $InputVar `
            -IncapableMap $refreshIncapable `
            -AadMap $aadStsMap

        Write-Host ""
        Write-Host "[*] `$$OutVar was NOT modified." -ForegroundColor DarkGray
        return
    }

    Set-Variable -Name $OutVar -Value $refreshResult.Token -Scope Global

    Write-Host ""
    Write-Host "[+] Refresh succeeded. Token written to `$$OutVar." -ForegroundColor Green

    if (-not $refreshResult.Token.refresh_token) {
        Write-Host "[!] WARNING: response did not include a refresh_token. The chain may not continue." -ForegroundColor Red
        Write-Host "    If you supplied -Scope manually, confirm offline_access was included." -ForegroundColor DarkGray
    }

    if (-not $Quiet) {
        Print-IssuedToken `
            -NewTokens $refreshResult.Token `
            -ReqResource $Resource `
            -UseCAE:$UseCAE `
            -CaeSupported:$caeSupported `
            -ClientId $ClientId
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    Invoke-RefreshTokens @PSBoundParameters
}