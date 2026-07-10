param(
    [Parameter(Position = 0)]
    [ValidateRange(1, 65535)]
    [int]$Port = 8000,

    [Parameter(Position = 1)]
    [string]$Root = (Get-Location).Path,

    [string]$LogFile
)

$ErrorActionPreference = 'Stop'

$Root = [IO.Path]::GetFullPath(
    (Resolve-Path -LiteralPath $Root).Path
)

$MimeTypes = @{
    '.html' = 'text/html; charset=utf-8'
    '.htm'  = 'text/html; charset=utf-8'
    '.css'   = 'text/css; charset=utf-8'
    '.js'    = 'application/javascript; charset=utf-8'
    '.json'  = 'application/json; charset=utf-8'
    '.txt'   = 'text/plain; charset=utf-8'
    '.xml'   = 'application/xml; charset=utf-8'
    '.csv'   = 'text/csv; charset=utf-8'
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
    '.mp4'   = 'video/mp4'
    '.mp3'   = 'audio/mpeg'
}

function Write-AccessLog {
    param(
        [string]$Remote,
        [string]$Request,
        [int]$Status,
        [long]$Length
    )

    $Timestamp = Get-Date -Format 'dd/MMM/yyyy HH:mm:ss'
    $Line = "$Remote - - [$Timestamp] `"$Request`" $Status $Length"

    Write-Host $Line

    if ($LogFile) {
        Add-Content -LiteralPath $LogFile -Value $Line
    }
}

function Send-Headers {
    param(
        [IO.Stream]$Stream,
        [int]$Status,
        [string]$Reason,
        [string]$ContentType,
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
    )

    if ($ExtraHeaders) {
        foreach ($Header in $ExtraHeaders.GetEnumerator()) {
            $Headers += "$($Header.Key): $($Header.Value)"
        }
    }

    $HeaderBytes = [Text.Encoding]::ASCII.GetBytes(
        ($Headers -join "`r`n") + "`r`n`r`n"
    )

    $Stream.Write($HeaderBytes, 0, $HeaderBytes.Length)
}

$Listener = [Net.Sockets.TcpListener]::new(
    [Net.IPAddress]::Any,
    $Port
)

$Listener.Start()

Write-Host "Serving: $Root"
Write-Host "Listening on: 0.0.0.0:$Port"
Write-Host "Local URL:    http://localhost:$Port/"
Write-Host 'Press Ctrl+C to stop.'

try {
    while ($true) {
        $Client = $Listener.AcceptTcpClient()
        $Stream = $Client.GetStream()
        $Remote = $Client.Client.RemoteEndPoint.Address.ToString()

        $RequestLine = ''
        $Status = 500
        $ResponseLength = 0

        try {
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

            # Consume request headers.
            while ($true) {
                $HeaderLine = $Reader.ReadLine()

                if ([string]::IsNullOrEmpty($HeaderLine)) {
                    break
                }
            }

            $Parts = $RequestLine -split ' ', 3

            if ($Parts.Count -ne 3) {
                throw 'Malformed HTTP request.'
            }

            $Method = $Parts[0].ToUpperInvariant()
            $RawTarget = $Parts[1]
            $HeadOnly = $Method -eq 'HEAD'

            if ($Method -notin @('GET', 'HEAD')) {
                $Body = [Text.Encoding]::UTF8.GetBytes(
                    '405 Method Not Allowed'
                )

                Send-Headers `
                    -Stream $Stream `
                    -Status 405 `
                    -Reason 'Method Not Allowed' `
                    -ContentType 'text/plain; charset=utf-8' `
                    -ContentLength $Body.Length `
                    -ExtraHeaders @{ Allow = 'GET, HEAD' }

                if (-not $HeadOnly) {
                    $Stream.Write($Body, 0, $Body.Length)
                }

                $Status = 405
                $ResponseLength = $Body.Length
                continue
            }

            $RequestUri = [Uri]::new(
                [Uri]'http://localhost/',
                $RawTarget
            )

            $DecodedPath = [Uri]::UnescapeDataString(
                $RequestUri.AbsolutePath
            )

            $RelativePath = $DecodedPath.TrimStart(
                [char[]]@('/', '\')
            ).Replace(
                '/',
                [IO.Path]::DirectorySeparatorChar
            )

            $Target = [IO.Path]::GetFullPath(
                [IO.Path]::Combine($Root, $RelativePath)
            )

            $RootPrefix = $Root.TrimEnd(
                [char[]]@('/', '\')
            ) + [IO.Path]::DirectorySeparatorChar

            $InsideRoot = (
                $Target -eq $Root -or
                $Target.StartsWith(
                    $RootPrefix,
                    [StringComparison]::OrdinalIgnoreCase
                )
            )

            if (-not $InsideRoot) {
                $Body = [Text.Encoding]::UTF8.GetBytes('403 Forbidden')

                Send-Headers `
                    -Stream $Stream `
                    -Status 403 `
                    -Reason 'Forbidden' `
                    -ContentType 'text/plain; charset=utf-8' `
                    -ContentLength $Body.Length

                if (-not $HeadOnly) {
                    $Stream.Write($Body, 0, $Body.Length)
                }

                $Status = 403
                $ResponseLength = $Body.Length
                continue
            }

            if ([IO.Directory]::Exists($Target)) {
                $Index = @(
                    (Join-Path $Target 'index.html')
                    (Join-Path $Target 'index.htm')
                ) | Where-Object {
                    [IO.File]::Exists($_)
                } | Select-Object -First 1

                if ($Index) {
                    $Target = $Index
                }
                else {
                    $BasePath = $RequestUri.AbsolutePath.TrimEnd('/')

                    $Links = foreach (
                        $Item in Get-ChildItem -LiteralPath $Target |
                            Sort-Object `
                                @{ Expression = 'PSIsContainer'; Descending = $true },
                                Name
                    ) {
                        $Name = [Net.WebUtility]::HtmlEncode($Item.Name)
                        $EncodedName = [Uri]::EscapeDataString($Item.Name)

                        $Href = if ($BasePath) {
                            "$BasePath/$EncodedName"
                        }
                        else {
                            "/$EncodedName"
                        }

                        if ($Item.PSIsContainer) {
                            $Name += '/'
                            $Href += '/'
                        }

                        "<li><a href=`"$Href`">$Name</a></li>"
                    }

                    $Parent = if ($Target -ne $Root) {
                        '<li><a href="../">../</a></li>'
                    }
                    else {
                        ''
                    }

                    $Html = @"
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Directory listing</title>
</head>
<body>
<h1>Directory listing for $([Net.WebUtility]::HtmlEncode($DecodedPath))</h1>
<ul>
$Parent
$($Links -join "`n")
</ul>
</body>
</html>
"@

                    $Body = [Text.Encoding]::UTF8.GetBytes($Html)

                    Send-Headers `
                        -Stream $Stream `
                        -Status 200 `
                        -Reason 'OK' `
                        -ContentType 'text/html; charset=utf-8' `
                        -ContentLength $Body.Length

                    if (-not $HeadOnly) {
                        $Stream.Write($Body, 0, $Body.Length)
                    }

                    $Status = 200
                    $ResponseLength = $Body.Length
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
                    -ContentLength $File.Length

                if (-not $HeadOnly) {
                    $FileStream = $File.OpenRead()

                    try {
                        $FileStream.CopyTo($Stream)
                    }
                    finally {
                        $FileStream.Dispose()
                    }
                }

                $Status = 200
                $ResponseLength = $File.Length
                continue
            }

            $Body = [Text.Encoding]::UTF8.GetBytes('404 Not Found')

            Send-Headers `
                -Stream $Stream `
                -Status 404 `
                -Reason 'Not Found' `
                -ContentType 'text/plain; charset=utf-8' `
                -ContentLength $Body.Length

            if (-not $HeadOnly) {
                $Stream.Write($Body, 0, $Body.Length)
            }

            $Status = 404
            $ResponseLength = $Body.Length
        }
        catch {
            $Status = 500
            $Body = [Text.Encoding]::UTF8.GetBytes(
                "500 Internal Server Error`r`n$($_.Exception.Message)"
            )

            try {
                Send-Headers `
                    -Stream $Stream `
                    -Status 500 `
                    -Reason 'Internal Server Error' `
                    -ContentType 'text/plain; charset=utf-8' `
                    -ContentLength $Body.Length

                $Stream.Write($Body, 0, $Body.Length)
                $ResponseLength = $Body.Length
            }
            catch {
                # Client disconnected.
            }
        }
        finally {
            Write-AccessLog `
                -Remote $Remote `
                -Request $RequestLine `
                -Status $Status `
                -Length $ResponseLength

            $Stream.Dispose()
            $Client.Dispose()
        }
    }
}
finally {
    $Listener.Stop()
    Write-Host 'Server stopped.'
}
