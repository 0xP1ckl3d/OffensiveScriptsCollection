param(
    [Parameter(Position = 0)]
    [ValidateRange(1, 65535)]
    [int]$Port = 8000,

    [Parameter(Position = 1)]
    [string]$Root = (Get-Location).Path,

    [string]$LogFile
)

$ErrorActionPreference = 'Stop'

$ResolvedRoot = Resolve-Path -LiteralPath $Root -ErrorAction Stop
$Root = [IO.Path]::GetFullPath($ResolvedRoot.Path)

if ($LogFile) {
    $LogFile = [IO.Path]::GetFullPath($LogFile)

    $LogDirectory = [IO.Path]::GetDirectoryName($LogFile)

    if (
        $LogDirectory -and
        -not [IO.Directory]::Exists($LogDirectory)
    ) {
        [IO.Directory]::CreateDirectory($LogDirectory) | Out-Null
    }
}

$MimeTypes = @{
    '.html' = 'text/html; charset=utf-8'
    '.htm'  = 'text/html; charset=utf-8'
    '.css'   = 'text/css; charset=utf-8'
    '.js'    = 'application/javascript; charset=utf-8'
    '.mjs'   = 'application/javascript; charset=utf-8'
    '.json'  = 'application/json; charset=utf-8'
    '.txt'   = 'text/plain; charset=utf-8'
    '.xml'   = 'application/xml; charset=utf-8'
    '.csv'   = 'text/csv; charset=utf-8'
    '.md'    = 'text/markdown; charset=utf-8'
    '.png'   = 'image/png'
    '.jpg'   = 'image/jpeg'
    '.jpeg'  = 'image/jpeg'
    '.gif'   = 'image/gif'
    '.webp'  = 'image/webp'
    '.svg'   = 'image/svg+xml'
    '.ico'   = 'image/x-icon'
    '.pdf'   = 'application/pdf'
    '.zip'   = 'application/zip'
    '.gz'    = 'application/gzip'
    '.tar'   = 'application/x-tar'
    '.7z'    = 'application/x-7z-compressed'
    '.mp4'   = 'video/mp4'
    '.mp3'   = 'audio/mpeg'
    '.wav'   = 'audio/wav'
    '.wasm'  = 'application/wasm'
}

function Write-AccessLog {
    param(
        [string]$Remote,
        [string]$Request,
        [int]$Status,
        [long]$Length,
        [long]$ElapsedMilliseconds
    )

    $Timestamp = Get-Date -Format 'dd/MMM/yyyy HH:mm:ss zzz'

    $Line = '{0} - - [{1}] "{2}" {3} {4} {5}ms' -f `
        $Remote,
        $Timestamp,
        $Request,
        $Status,
        $Length,
        $ElapsedMilliseconds

    Write-Host $Line

    if ($LogFile) {
        try {
            Add-Content `
                -LiteralPath $LogFile `
                -Value $Line `
                -Encoding UTF8
        }
        catch {
            Write-Warning "Unable to write access log: $($_.Exception.Message)"
        }
    }
}

function Send-Headers {
    param(
        [Parameter(Mandatory)]
        [IO.Stream]$Stream,

        [Parameter(Mandatory)]
        [int]$Status,

        [Parameter(Mandatory)]
        [string]$Reason,

        [Parameter(Mandatory)]
        [string]$ContentType,

        [Parameter(Mandatory)]
        [long]$ContentLength,

        [hashtable]$ExtraHeaders
    )

    $Headers = @(
        "HTTP/1.1 $Status $Reason"
        "Date: $([DateTime]::UtcNow.ToString('R'))"
        'Server: PowerShell-TcpServer'
        "Content-Type: $ContentType"
        "Content-Length: $ContentLength"
        'Connection: close'
        'X-Content-Type-Options: nosniff'
    )

    if ($ExtraHeaders) {
        foreach ($Header in $ExtraHeaders.GetEnumerator()) {
            $Headers += "$($Header.Key): $($Header.Value)"
        }
    }

    $HeaderText = ($Headers -join "`r`n") + "`r`n`r`n"
    $HeaderBytes = [Text.Encoding]::ASCII.GetBytes($HeaderText)

    $Stream.Write($HeaderBytes, 0, $HeaderBytes.Length)
}

function Send-ByteResponse {
    param(
        [Parameter(Mandatory)]
        [IO.Stream]$Stream,

        [Parameter(Mandatory)]
        [int]$Status,

        [Parameter(Mandatory)]
        [string]$Reason,

        [Parameter(Mandatory)]
        [string]$ContentType,

        [Parameter(Mandatory)]
        [byte[]]$Body,

        [bool]$HeadOnly = $false,

        [hashtable]$ExtraHeaders
    )

    Send-Headers `
        -Stream $Stream `
        -Status $Status `
        -Reason $Reason `
        -ContentType $ContentType `
        -ContentLength $Body.Length `
        -ExtraHeaders $ExtraHeaders

    if (-not $HeadOnly -and $Body.Length -gt 0) {
        $Stream.Write($Body, 0, $Body.Length)
    }

    return [long]$Body.Length
}

$Listener = [Net.Sockets.TcpListener]::new(
    [Net.IPAddress]::Any,
    $Port
)

try {
    $Listener.Start()
}
catch {
    throw "Unable to listen on 0.0.0.0:$Port. $($_.Exception.Message)"
}

Write-Host "Serving:      $Root"
Write-Host "Listening on: 0.0.0.0:$Port"
Write-Host "Local URL:    http://localhost:$Port/"

if ($LogFile) {
    Write-Host "Log file:     $LogFile"
}

Write-Host 'Press Ctrl+C to stop.'

try {
    while ($true) {
        # AcceptTcpClient() blocks indefinitely. Polling Pending() allows
        # PowerShell to process Ctrl+C while the server is idle.
        while (-not $Listener.Pending()) {
            [Threading.Thread]::Sleep(100)
        }

        $Client = $null
        $Stream = $null
        $Reader = $null
        $Stopwatch = [Diagnostics.Stopwatch]::StartNew()

        $Remote = '-'
        $RequestLine = ''
        $Status = 0
        $ResponseLength = 0
        $ShouldLog = $false

        try {
            $Client = $Listener.AcceptTcpClient()

            # Prevent incomplete or deliberately stalled requests from
            # holding the single-threaded server open indefinitely.
            $Client.ReceiveTimeout = 10000
            $Client.SendTimeout = 30000
            $Client.NoDelay = $true

            $Stream = $Client.GetStream()
            $Stream.ReadTimeout = 10000
            $Stream.WriteTimeout = 30000

            $RemoteEndpoint = $Client.Client.RemoteEndPoint

            if ($RemoteEndpoint) {
                $Remote = $RemoteEndpoint.Address.ToString()
            }

            $Reader = [IO.StreamReader]::new(
                $Stream,
                [Text.Encoding]::ASCII,
                $false,
                8192,
                $true
            )

            $RequestLine = $Reader.ReadLine()

            if ([string]::IsNullOrWhiteSpace($RequestLine)) {
                continue
            }

            $ShouldLog = $true

            # Consume and limit request headers.
            $HeaderCount = 0
            $HeaderBytes = 0

            while ($true) {
                $HeaderLine = $Reader.ReadLine()

                if ([string]::IsNullOrEmpty($HeaderLine)) {
                    break
                }

                $HeaderCount++
                $HeaderBytes += $HeaderLine.Length

                if ($HeaderCount -gt 100 -or $HeaderBytes -gt 65536) {
                    $Body = [Text.Encoding]::UTF8.GetBytes(
                        '431 Request Header Fields Too Large'
                    )

                    $ResponseLength = Send-ByteResponse `
                        -Stream $Stream `
                        -Status 431 `
                        -Reason 'Request Header Fields Too Large' `
                        -ContentType 'text/plain; charset=utf-8' `
                        -Body $Body

                    $Status = 431
                    continue 2
                }
            }

            $Parts = $RequestLine -split ' ', 3

            if ($Parts.Count -ne 3) {
                $Body = [Text.Encoding]::UTF8.GetBytes(
                    '400 Bad Request'
                )

                $ResponseLength = Send-ByteResponse `
                    -Stream $Stream `
                    -Status 400 `
                    -Reason 'Bad Request' `
                    -ContentType 'text/plain; charset=utf-8' `
                    -Body $Body

                $Status = 400
                continue
            }

            $Method = $Parts[0].ToUpperInvariant()
            $RawTarget = $Parts[1]
            $HeadOnly = $Method -eq 'HEAD'

            if ($Method -notin @('GET', 'HEAD')) {
                $Body = [Text.Encoding]::UTF8.GetBytes(
                    '405 Method Not Allowed'
                )

                $ResponseLength = Send-ByteResponse `
                    -Stream $Stream `
                    -Status 405 `
                    -Reason 'Method Not Allowed' `
                    -ContentType 'text/plain; charset=utf-8' `
                    -Body $Body `
                    -HeadOnly $HeadOnly `
                    -ExtraHeaders @{
                        Allow = 'GET, HEAD'
                    }

                $Status = 405
                continue
            }

            try {
                $RequestUri = [Uri]::new(
                    [Uri]'http://localhost/',
                    $RawTarget
                )
            }
            catch {
                $Body = [Text.Encoding]::UTF8.GetBytes(
                    '400 Bad Request'
                )

                $ResponseLength = Send-ByteResponse `
                    -Stream $Stream `
                    -Status 400 `
                    -Reason 'Bad Request' `
                    -ContentType 'text/plain; charset=utf-8' `
                    -Body $Body `
                    -HeadOnly $HeadOnly

                $Status = 400
                continue
            }

            try {
                $DecodedPath = [Uri]::UnescapeDataString(
                    $RequestUri.AbsolutePath
                )
            }
            catch {
                $Body = [Text.Encoding]::UTF8.GetBytes(
                    '400 Bad Request'
                )

                $ResponseLength = Send-ByteResponse `
                    -Stream $Stream `
                    -Status 400 `
                    -Reason 'Bad Request' `
                    -ContentType 'text/plain; charset=utf-8' `
                    -Body $Body `
                    -HeadOnly $HeadOnly

                $Status = 400
                continue
            }

            $RelativePath = $DecodedPath.TrimStart(
                [char[]]"/\"
            ).Replace(
                '/',
                [IO.Path]::DirectorySeparatorChar
            )

            try {
                $Target = [IO.Path]::GetFullPath(
                    [IO.Path]::Combine($Root, $RelativePath)
                )
            }
            catch {
                $Body = [Text.Encoding]::UTF8.GetBytes(
                    '400 Bad Request'
                )

                $ResponseLength = Send-ByteResponse `
                    -Stream $Stream `
                    -Status 400 `
                    -Reason 'Bad Request' `
                    -ContentType 'text/plain; charset=utf-8' `
                    -Body $Body `
                    -HeadOnly $HeadOnly

                $Status = 400
                continue
            }

            $RootPrefix = $Root.TrimEnd(
                [char[]]"/\"
            ) + [IO.Path]::DirectorySeparatorChar

            $InsideRoot = (
                $Target -eq $Root -or
                $Target.StartsWith(
                    $RootPrefix,
                    [StringComparison]::OrdinalIgnoreCase
                )
            )

            if (-not $InsideRoot) {
                $Body = [Text.Encoding]::UTF8.GetBytes(
                    '403 Forbidden'
                )

                $ResponseLength = Send-ByteResponse `
                    -Stream $Stream `
                    -Status 403 `
                    -Reason 'Forbidden' `
                    -ContentType 'text/plain; charset=utf-8' `
                    -Body $Body `
                    -HeadOnly $HeadOnly

                $Status = 403
                continue
            }

            if ([IO.Directory]::Exists($Target)) {
                $IndexPath = $null

                foreach ($IndexName in @('index.html', 'index.htm')) {
                    $Candidate = Join-Path $Target $IndexName

                    if ([IO.File]::Exists($Candidate)) {
                        $IndexPath = $Candidate
                        break
                    }
                }

                if ($IndexPath) {
                    $Target = $IndexPath
                }
                else {
                    $BasePath = $RequestUri.AbsolutePath.TrimEnd('/')

                    $Items = Get-ChildItem -LiteralPath $Target |
                        Sort-Object `
                            @{
                                Expression = 'PSIsContainer'
                                Descending = $true
                            },
                            @{
                                Expression = 'Name'
                                Descending = $false
                            }

                    $Links = foreach ($Item in $Items) {
                        $DisplayName = [Net.WebUtility]::HtmlEncode(
                            $Item.Name
                        )

                        $EncodedName = [Uri]::EscapeDataString(
                            $Item.Name
                        )

                        if ($BasePath) {
                            $Href = "$BasePath/$EncodedName"
                        }
                        else {
                            $Href = "/$EncodedName"
                        }

                        if ($Item.PSIsContainer) {
                            $DisplayName += '/'
                            $Href += '/'
                        }

                        '<li><a href="{0}">{1}</a></li>' -f `
                            $Href,
                            $DisplayName
                    }

                    if ($Target -ne $Root) {
                        $ParentLink = '<li><a href="../">../</a></li>'
                    }
                    else {
                        $ParentLink = ''
                    }

                    $EncodedPath = [Net.WebUtility]::HtmlEncode(
                        $DecodedPath
                    )

                    $Html = @"
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Directory listing for $EncodedPath</title>
    <style>
        body {
            max-width: 960px;
            margin: 2rem auto;
            padding: 0 1rem;
            font-family: system-ui, sans-serif;
        }

        li {
            margin: 0.35rem 0;
        }
    </style>
</head>
<body>
    <h1>Directory listing for $EncodedPath</h1>
    <ul>
        $ParentLink
        $($Links -join "`n")
    </ul>
</body>
</html>
"@

                    $Body = [Text.Encoding]::UTF8.GetBytes($Html)

                    $ResponseLength = Send-ByteResponse `
                        -Stream $Stream `
                        -Status 200 `
                        -Reason 'OK' `
                        -ContentType 'text/html; charset=utf-8' `
                        -Body $Body `
                        -HeadOnly $HeadOnly

                    $Status = 200
                    continue
                }
            }

            if ([IO.File]::Exists($Target)) {
                $File = [IO.FileInfo]$Target
                $Extension = $File.Extension.ToLowerInvariant()
                $ContentType = $MimeTypes[$Extension]

                if (-not $ContentType) {
                    $ContentType = 'application/octet-stream'
                }

                Send-Headers `
                    -Stream $Stream `
                    -Status 200 `
                    -Reason 'OK' `
                    -ContentType $ContentType `
                    -ContentLength $File.Length `
                    -ExtraHeaders @{
                        'Last-Modified' = $File.LastWriteTimeUtc.ToString('R')
                    }

                if (-not $HeadOnly) {
                    $FileStream = $null

                    try {
                        $FileStream = $File.OpenRead()
                        $FileStream.CopyTo($Stream)
                    }
                    finally {
                        if ($FileStream) {
                            $FileStream.Dispose()
                        }
                    }
                }

                $Status = 200
                $ResponseLength = $File.Length
                continue
            }

            $Body = [Text.Encoding]::UTF8.GetBytes(
                '404 Not Found'
            )

            $ResponseLength = Send-ByteResponse `
                -Stream $Stream `
                -Status 404 `
                -Reason 'Not Found' `
                -ContentType 'text/plain; charset=utf-8' `
                -Body $Body `
                -HeadOnly $HeadOnly

            $Status = 404
        }
        catch [IO.IOException] {
            # Covers client read timeout, write timeout and disconnects.
            if ($Status -eq 0) {
                $Status = 408
            }
        }
        catch {
            $Status = 500

            $Body = [Text.Encoding]::UTF8.GetBytes(
                "500 Internal Server Error`r`n$($_.Exception.Message)"
            )

            try {
                if ($Stream -and $Stream.CanWrite) {
                    $ResponseLength = Send-ByteResponse `
                        -Stream $Stream `
                        -Status 500 `
                        -Reason 'Internal Server Error' `
                        -ContentType 'text/plain; charset=utf-8' `
                        -Body $Body
                }
            }
            catch {
                # The client may already have disconnected.
            }
        }
        finally {
            $Stopwatch.Stop()

            if ($Reader) {
                try {
                    $Reader.Dispose()
                }
                catch {
                }
            }

            if ($Stream) {
                try {
                    $Stream.Dispose()
                }
                catch {
                }
            }

            if ($Client) {
                try {
                    $Client.Dispose()
                }
                catch {
                }
            }

            if ($ShouldLog) {
                Write-AccessLog `
                    -Remote $Remote `
                    -Request $RequestLine `
                    -Status $Status `
                    -Length $ResponseLength `
                    -ElapsedMilliseconds $Stopwatch.ElapsedMilliseconds
            }
        }
    }
}
finally {
    try {
        $Listener.Stop()
    }
    catch {
    }

    Write-Host "`nServer stopped."
}
