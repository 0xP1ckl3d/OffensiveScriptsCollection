# m365Scripts

PowerShell scripts for Microsoft 365, Microsoft Entra ID, Microsoft Graph, Azure Resource Manager, and legacy Azure AD assessment workflows.

The collection is intended for authorised offensive security testing, tenant exposure validation, and evidence collection. Most scripts operate directly against Microsoft REST endpoints using bearer tokens and do not require the Microsoft Graph PowerShell SDK.

## Contents

| File | Purpose | Auth / input required | Output |
|---|---|---|---|
| `Invoke-GetGraphTokens.ps1` | Obtain Microsoft Entra ID tokens via device-code or interactive browser authentication. Supports client/resource aliases, v1/v2 endpoints, Continuous Access Evaluation claims, custom user agents, and named output variables. | Tenant domain or tenant ID. | Stores token object in `$global:tokens` by default, or a named variable via `-OutVar`. |
| `Invoke-RefreshTokens.ps1` | Refresh an existing token into another Microsoft audience, or sweep multiple Microsoft service audiences. | Existing token object, default `$global:tokens`, containing a `refresh_token`. | Writes refreshed token objects to named global variables. |
| `Invoke-GraphWhoami.ps1` | Summarise the current authenticated identity, tenant, token claims, directory roles, group memberships, owned objects, and owned devices. | `$tokens.access_token`. | Console summary. |
| `Invoke-GraphWhois.ps1` | Look up a target Entra ID user by UPN, mail, display name, or object ID, then enumerate identity details, manager/direct reports, roles, groups, licences, owned objects, owned devices, and registered devices. | `$tokens.access_token` and a user identifier. | Console summary. |
| `Invoke-DumpUsers.ps1` | Dump all readable Entra ID users through Microsoft Graph for directory enumeration evidence. Supports OData filters, `/beta`, optional JSON, and fallback when `signInActivity` is denied. | `$tokens.access_token`. | CSV by default; optional JSON. |
| `Invoke-DeviceEnum.ps1` | Enumerate Entra ID devices and selected device state fields. | `$tokens.access_token`. | Table output and `devices.csv`. |
| `Invoke-DeviceMap.ps1` | Enumerate devices with registered owner mapping. | `$tokens.access_token`. | `device_owner_map.csv`. |
| `Invoke-TestGroupMembership.ps1` | Test whether a user is a direct or transitive member of one or more Entra ID groups. Defaults to the current token holder when no user is supplied. | `$tokens.access_token`, group identifier(s), optional user identifier. | Console summary or pipeline objects with `-PassThru`. |
| `Invoke-TestGroupWriteAccess.ps1` | Assess group management exposure. Performs passive inference and, by default, a read-only Graph `estimateAccess` probe. Optional `-Live` mode empirically validates add/remove and create/delete behaviour. | `$tokens.access_token`, optional group/user/target user. | Console summary or pipeline objects with `-PassThru`. |
| `Invoke-TestExternalARMAccess.ps1` | Test whether the current or guest/third-party identity has Azure Resource Manager access. Exchanges the current refresh token for an ARM token or falls back to device-code authentication. | `$tokens.refresh_token`, unless `-DeviceCode` is used. | Console evidence summary and `$global:LegacyARMToken`. |
| `Invoke-TestLegacyAADGraph.ps1` | Test whether legacy Azure AD Graph (`graph.windows.net`) still issues tokens and returns directory data. | `$tokens.refresh_token`. | Console evidence summary and `$global:LegacyAADGraphToken`. |
| `Invoke-TestLegacyMSOnline.ps1` | Test whether the deprecated MSOnline/AzureAD PowerShell client path can still authenticate and query tenant data. Can optionally drive `Connect-MsolService` when the MSOnline module is installed. | `$tokens.refresh_token`, unless `-DeviceCode` is used. | Console evidence summary and `$global:LegacyMSOnlineToken`. |
| `Invoke-EnumerateAzureSubDomains.ps1` | Enumerate public Azure/Microsoft-hosted service names by resolving generated DNS permutations. | Base organisation/project word and a permutations file. | Console table of discovered subdomains and service type. |
| `fuzz.txt` | General-purpose wordlist/permutation list. | N/A | Used as input to DNS or content fuzzing workflows. |
| `containers.txt` | Large wordlist of common files, directories, hidden paths, repository artefacts, configuration files, and web content paths. | N/A | Used as input to web/content discovery tooling. |

## Requirements

- PowerShell 5.1 or later. PowerShell 7+ should work for most Graph/REST scripts.
- Network access to the relevant Microsoft endpoints, such as:
  - `login.microsoftonline.com`
  - `graph.microsoft.com`
  - `management.azure.com`
  - `graph.windows.net` for legacy Azure AD Graph tests
- A valid Microsoft Entra ID authentication context.
- The optional `MSOnline` module only if you want `Invoke-TestLegacyMSOnline.ps1` to validate the legacy cmdlets end-to-end. Use `-NoInvokeMsol` to skip that cmdlet test.
- `Resolve-DnsName` for `Invoke-EnumerateAzureSubDomains.ps1`. Windows PowerShell is the lowest-friction environment for that script.

## Token model

Most scripts expect a PowerShell variable named `$tokens` in the current session.

At minimum:

```powershell
$tokens.access_token   # required by Graph read/enumeration scripts
$tokens.refresh_token  # required by refresh, ARM, and legacy-token tests
```

The normal starting point is:

```powershell
cd .\m365Scripts
.\Invoke-GetGraphTokens.ps1 -TenantId <tenant-id-or-domain>
```

By default, `Invoke-GetGraphTokens.ps1` stores the resulting token object in `$global:tokens`. Use `-OutVar` when you want to keep multiple token objects in memory:

```powershell
.\Invoke-GetGraphTokens.ps1 -TenantId <tenant-id-or-domain> -Resource msgraph -OutVar graphTokens
.\Invoke-GetGraphTokens.ps1 -TenantId <tenant-id-or-domain> -Resource arm -OutVar armTokens
```

Refresh an existing token into another audience:

```powershell
.\Invoke-RefreshTokens.ps1 -Resource arm -OutVar armTokens
.\Invoke-RefreshTokens.ps1 -Resource powerbi -OutVar powerbiTokens
.\Invoke-RefreshTokens.ps1 -Sweep -UseCAE
```

## Quick start workflow

```powershell
cd .\m365Scripts

# 1. Authenticate and store tokens in $global:tokens
.\Invoke-GetGraphTokens.ps1 -TenantId <tenant-id-or-domain>

# 2. Confirm who the token represents and what it can see
.\Invoke-GraphWhoami.ps1

# 3. Dump tenant users for evidence collection
.\Invoke-DumpUsers.ps1 -Json

# 4. Enumerate devices and owner mappings
.\Invoke-DeviceEnum.ps1
.\Invoke-DeviceMap.ps1

# 5. Inspect a specific user
.\Invoke-GraphWhois.ps1 user@domain.com

# 6. Check group membership and writable group exposure
.\Invoke-TestGroupMembership.ps1 "All Company" user@domain.com -Transitive
.\Invoke-TestGroupWriteAccess.ps1 -v
```

## Common examples

### Authenticate with device code

```powershell
.\Invoke-GetGraphTokens.ps1 -TenantId contoso.onmicrosoft.com
```

### Authenticate with interactive browser flow

```powershell
.\Invoke-GetGraphTokens.ps1 -TenantId contoso.onmicrosoft.com -Method Interactive
```

### Request a token for a specific Microsoft resource

```powershell
.\Invoke-GetGraphTokens.ps1 -TenantId contoso.onmicrosoft.com -Resource arm -OutVar armTokens
.\Invoke-GetGraphTokens.ps1 -TenantId contoso.onmicrosoft.com -Resource powerbi -OutVar powerbiTokens
```

### Dump all users

```powershell
.\Invoke-DumpUsers.ps1
.\Invoke-DumpUsers.ps1 -Json
.\Invoke-DumpUsers.ps1 -Filter "userType eq 'Guest'"
.\Invoke-DumpUsers.ps1 -NoSignInActivity
```

### Look up a user

```powershell
.\Invoke-GraphWhois.ps1 jane.doe@contoso.com
.\Invoke-GraphWhois.ps1 "Jane Doe"
.\Invoke-GraphWhois.ps1 11111111-2222-3333-4444-555555555555
```

### Test group membership

```powershell
.\Invoke-TestGroupMembership.ps1 "All Company"
.\Invoke-TestGroupMembership.ps1 "All Company" "jane.doe@contoso.com"
.\Invoke-TestGroupMembership.ps1 "Group A,Group B,Group C" "Jane Doe" -Transitive
```

### Test group write access

Default mode is intended to be non-destructive: passive inference plus the Graph `estimateAccess` probe.

```powershell
.\Invoke-TestGroupWriteAccess.ps1
.\Invoke-TestGroupWriteAccess.ps1 -v
.\Invoke-TestGroupWriteAccess.ps1 "Tech Services - Admins"
.\Invoke-TestGroupWriteAccess.ps1 "Tech Services - Admins" -NoProbe
```

Use `-Live` only when authorised to perform temporary membership and group-create/delete validation:

```powershell
.\Invoke-TestGroupWriteAccess.ps1 "Tech Services - Admins" -TargetUser "test.user@contoso.com" -Live
```

### Test external or guest ARM access

```powershell
.\Invoke-TestExternalARMAccess.ps1
.\Invoke-TestExternalARMAccess.ps1 -DeviceCode
.\Invoke-TestExternalARMAccess.ps1 -TenantId contoso.onmicrosoft.com
```

### Test legacy Azure AD Graph access

```powershell
.\Invoke-TestLegacyAADGraph.ps1
.\Invoke-TestLegacyAADGraph.ps1 -TenantId contoso.onmicrosoft.com
```

### Test legacy MSOnline access

```powershell
.\Invoke-TestLegacyMSOnline.ps1
.\Invoke-TestLegacyMSOnline.ps1 -NoInvokeMsol
.\Invoke-TestLegacyMSOnline.ps1 -DeviceCode
```

### Enumerate Azure-hosted public subdomains

The current folder contains `fuzz.txt`; the script default references `permutations.txt`. Either pass the file explicitly or copy/rename the wordlist.

```powershell
.\Invoke-EnumerateAzureSubDomains.ps1 -Base contoso -Permutations .\fuzz.txt -Verbose
```

## Dot-sourcing

Several scripts expose functions and can be dot-sourced instead of run as one-off scripts:

```powershell
. .\Invoke-GetGraphTokens.ps1
Invoke-GetGraphTokens -TenantId contoso.onmicrosoft.com -Resource msgraph

. .\Invoke-GraphWhois.ps1
Invoke-GraphWhois "Jane Doe"

. .\Invoke-TestGroupMembership.ps1
Test-GraphGroupMembership -Group "All Company" -User "jane.doe@contoso.com" -Transitive
```

## Output handling

Generated outputs can contain sensitive tenant data, including user details, group memberships, device identifiers, ownership mappings, role assignments, token claims, and directory metadata.

Recommended handling:

- Store outputs in an engagement-specific evidence directory.
- Do not commit generated CSV, JSON, token objects, screenshots, or raw console logs to this repository.
- Redact user principal names, object IDs, tenant IDs, and sensitive group names before including evidence in client-facing reporting.
- Treat token-bearing PowerShell sessions as sensitive until closed.

## Operational notes

- `Invoke-TestGroupWriteAccess.ps1` is read-only by default, but `-Live` intentionally performs add/remove and create/delete validation. Use it only where that behaviour is explicitly authorised.
- `Invoke-TestLegacyAADGraph.ps1` and `Invoke-TestLegacyMSOnline.ps1` are useful for proving whether deprecated identity surfaces remain reachable. A blocked token exchange or blocked query is generally the desired secure outcome.
- `Invoke-TestExternalARMAccess.ps1` stores any ARM token it obtains in `$global:LegacyARMToken` and does not overwrite the original `$tokens` object.
- `Invoke-RefreshTokens.ps1` avoids overwriting output variables unless refresh succeeds and an `access_token` is returned.
- `Invoke-DumpUsers.ps1` automatically retries without `signInActivity` when the current token lacks the permissions required for that property.

## Suggested evidence workflow

```powershell
$stamp = Get-Date -Format yyyyMMdd-HHmmss
New-Item -ItemType Directory -Path ".\evidence-$stamp" | Out-Null

.\Invoke-DumpUsers.ps1 -OutFile ".\evidence-$stamp\users.csv" -Json
.\Invoke-DeviceEnum.ps1
Move-Item .\devices.csv ".\evidence-$stamp\devices.csv" -Force
.\Invoke-DeviceMap.ps1
Move-Item .\device_owner_map.csv ".\evidence-$stamp\device_owner_map.csv" -Force
```

## Disclaimer

These scripts are for authorised security testing, internal security validation, and controlled lab use only. They may expose sensitive tenant data or perform live authentication attempts against Microsoft services. Run them only in environments where you have permission to test and collect evidence.
