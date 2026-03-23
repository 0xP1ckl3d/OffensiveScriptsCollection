# ScreenRemember.psm1
# PowerShell module for capturing and managing screenshots in memory using Win32 APIs

# In-memory screenshot storage
$script:Screenshots = @()
$script:NextId = 1

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# P/Invoke signatures for Win32 APIs
Add-Type @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public class Win32 {
    [DllImport("user32.dll")]
    public static extern IntPtr GetDesktopWindow();
    
    [DllImport("user32.dll")]
    public static extern IntPtr GetWindowDC(IntPtr hWnd);
    
    [DllImport("user32.dll")]
    public static extern IntPtr ReleaseDC(IntPtr hWnd, IntPtr hDC);
    
    [DllImport("gdi32.dll")]
    public static extern bool BitBlt(IntPtr hdcDest, int xDest, int yDest, 
        int wDest, int hDest, IntPtr hdcSource, int xSrc, int ySrc, int RasterOp);
    
    [DllImport("gdi32.dll")]
    public static extern IntPtr CreateCompatibleDC(IntPtr hdc);
    
    [DllImport("gdi32.dll")]
    public static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int nWidth, int nHeight);
    
    [DllImport("gdi32.dll")]
    public static extern IntPtr SelectObject(IntPtr hdc, IntPtr hObject);
    
    [DllImport("gdi32.dll")]
    public static extern bool DeleteDC(IntPtr hdc);
    
    [DllImport("gdi32.dll")]
    public static extern bool DeleteObject(IntPtr hObject);
    
    [DllImport("user32.dll")]
    public static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);
    
    [DllImport("user32.dll")]
    public static extern bool IsWindowVisible(IntPtr hWnd);
    
    [DllImport("user32.dll")]
    public static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);
    
    [DllImport("user32.dll")]
    public static extern int GetWindowTextLength(IntPtr hWnd);
    
    [DllImport("user32.dll")]
    public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);
    
    [DllImport("user32.dll")]
    public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);
    
    [DllImport("user32.dll")]
    public static extern bool PrintWindow(IntPtr hWnd, IntPtr hdcBlt, uint nFlags);
    
    [DllImport("user32.dll")]
    public static extern bool IsIconic(IntPtr hWnd);
    
    [DllImport("user32.dll")]
    public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    
    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
    
    public const int SRCCOPY = 0x00CC0020;
    public const uint PW_RENDERFULLCONTENT = 0x00000002;
    public const int SW_RESTORE = 9;
    
    [StructLayout(LayoutKind.Sequential)]
    public struct RECT {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;
    }
}
"@

function Get-ScreenshotAll {
    <#
    .SYNOPSIS
    Captures all screens and stores the screenshot in memory.
    
    .DESCRIPTION
    Uses Win32 APIs to capture all screens combined into a single bitmap.
    
    .PARAMETER Quiet
    Suppresses console output.
    
    .PARAMETER PassThru
    Returns the screenshot object for pipeline use.
    
    .EXAMPLE
    Get-ScreenshotAll
    
    .EXAMPLE
    Get-ScreenshotAll -PassThru | Export-Screenshot
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$Quiet,
        
        [Parameter()]
        [switch]$PassThru
    )
    
    try {
        Write-Verbose "Capturing all screens"
        
        # Get virtual screen bounds (all monitors)
        $left = [System.Windows.Forms.SystemInformation]::VirtualScreen.Left
        $top = [System.Windows.Forms.SystemInformation]::VirtualScreen.Top
        $width = [System.Windows.Forms.SystemInformation]::VirtualScreen.Width
        $height = [System.Windows.Forms.SystemInformation]::VirtualScreen.Height
        
        Write-Verbose "Screen bounds: X:$left Y:$top ${width}x${height}"
        
        # Capture screenshot using Win32 APIs
        $bitmap = Capture-ScreenRegion -X $left -Y $top -Width $width -Height $height
        
        Write-Verbose "Bitmap captured successfully"
        
        # Store in memory
        $screenshot = [PSCustomObject]@{
            PSTypeName = 'ScreenCapture.Screenshot'
            Id = $script:NextId++
            Timestamp = Get-Date
            Type = "All Screens"
            Bitmap = $bitmap
            Width = $width
            Height = $height
        }
        
        $script:Screenshots += $screenshot
        
        if (-not $Quiet) {
            Write-Host "Screenshot captured (ID: $($screenshot.Id)) - All Screens: ${width}x${height}" -ForegroundColor Green
        }
        
        if ($PassThru) {
            return $screenshot
        }
    }
    catch {
        Write-Error "Failed to capture all screens: $_"
    }
}

function Get-ScreenshotCurrent {
    <#
    .SYNOPSIS
    Captures the current primary screen and stores the screenshot in memory.
    
    .DESCRIPTION
    Uses Win32 APIs to capture the primary display screen.
    
    .PARAMETER Quiet
    Suppresses console output.
    
    .PARAMETER PassThru
    Returns the screenshot object for pipeline use.
    
    .EXAMPLE
    Get-ScreenshotCurrent
    
    .EXAMPLE
    Get-ScreenshotCurrent -PassThru | Export-Screenshot
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$Quiet,
        
        [Parameter()]
        [switch]$PassThru
    )
    
    try {
        Write-Verbose "Capturing primary screen"
        
        # Get primary screen bounds
        $screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
        $width = $screen.Width
        $height = $screen.Height
        
        Write-Verbose "Screen dimensions: ${width}x${height}"
        
        # Capture screenshot using Win32 APIs
        $bitmap = Capture-ScreenRegion -X 0 -Y 0 -Width $width -Height $height
        
        Write-Verbose "Bitmap captured successfully"
        
        # Store in memory
        $screenshot = [PSCustomObject]@{
            PSTypeName = 'ScreenCapture.Screenshot'
            Id = $script:NextId++
            Timestamp = Get-Date
            Type = "Primary Screen"
            Bitmap = $bitmap
            Width = $width
            Height = $height
        }
        
        $script:Screenshots += $screenshot
        
        if (-not $Quiet) {
            Write-Host "Screenshot captured (ID: $($screenshot.Id)) - Primary Screen: ${width}x${height}" -ForegroundColor Green
        }
        
        if ($PassThru) {
            return $screenshot
        }
    }
    catch {
        Write-Error "Failed to capture current screen: $_"
    }
}

function Get-ScreenshotRegion {
    <#
    .SYNOPSIS
    Captures a specific region of the screen.
    
    .DESCRIPTION
    Uses Win32 APIs to capture a rectangular region of the screen.
    
    .PARAMETER X
    X coordinate of the top-left corner.
    
    .PARAMETER Y
    Y coordinate of the top-left corner.
    
    .PARAMETER Width
    Width of the region to capture.
    
    .PARAMETER Height
    Height of the region to capture.
    
    .PARAMETER Quiet
    Suppresses console output.
    
    .PARAMETER PassThru
    Returns the screenshot object for pipeline use.
    
    .EXAMPLE
    Get-ScreenshotRegion -X 0 -Y 0 -Width 800 -Height 600
    
    .EXAMPLE
    Get-ScreenshotRegion 0 0 1920 1080 -PassThru | Show-Screenshot
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [int]$X,
        
        [Parameter(Mandatory=$true, Position=1)]
        [int]$Y,
        
        [Parameter(Mandatory=$true, Position=2)]
        [int]$Width,
        
        [Parameter(Mandatory=$true, Position=3)]
        [int]$Height,
        
        [Parameter()]
        [switch]$Quiet,
        
        [Parameter()]
        [switch]$PassThru
    )
    
    try {
        if ($Width -le 0 -or $Height -le 0) {
            Write-Error "Width and Height must be positive values."
            return
        }
        
        Write-Verbose "Capturing region: X:$X Y:$Y ${Width}x${Height}"
        
        # Capture screenshot using Win32 APIs
        $bitmap = Capture-ScreenRegion -X $X -Y $Y -Width $Width -Height $Height
        
        Write-Verbose "Region captured successfully"
        
        # Store in memory
        $screenshot = [PSCustomObject]@{
            PSTypeName = 'ScreenCapture.Screenshot'
            Id = $script:NextId++
            Timestamp = Get-Date
            Type = "Region"
            Region = "X:$X Y:$Y"
            Bitmap = $bitmap
            Width = $Width
            Height = $Height
        }
        
        $script:Screenshots += $screenshot
        
        if (-not $Quiet) {
            Write-Host "Screenshot captured (ID: $($screenshot.Id)) - Region: X:$X Y:$Y ${Width}x${Height}" -ForegroundColor Green
        }
        
        if ($PassThru) {
            return $screenshot
        }
    }
    catch {
        Write-Error "Failed to capture region: $_"
    }
}

function Get-Windows {
    <#
    .SYNOPSIS
    Lists all visible windows with their handles and titles.
    
    .DESCRIPTION
    Enumerates all visible windows using Win32 APIs and displays them with handle and title information.
    
    .PARAMETER Title
    Filter windows by title (partial match, case-insensitive).
    
    .PARAMETER Process
    Filter windows by process name (partial match, case-insensitive).
    
    .EXAMPLE
    Get-Windows
    
    .EXAMPLE
    Get-Windows -Title "Chrome"
    
    .EXAMPLE
    Get-Windows -Process "explorer"
    
    .EXAMPLE
    Get-Windows -Title "Chrome" | Select-Object -First 1 | Get-ScreenshotWindow
    #>
    [CmdletBinding()]
    [OutputType('ScreenCapture.WindowInfo')]
    param(
        [Parameter()]
        [string]$Title,
        
        [Parameter()]
        [string]$Process
    )
    
    $windows = @()
    
    Write-Verbose "Enumerating windows"
    
    # Callback function for EnumWindows
    $callback = {
        param($hWnd, $lParam)
        
        if ([Win32]::IsWindowVisible($hWnd)) {
            $length = [Win32]::GetWindowTextLength($hWnd)
            if ($length -gt 0) {
                $sb = New-Object System.Text.StringBuilder($length + 1)
                [Win32]::GetWindowText($hWnd, $sb, $sb.Capacity) | Out-Null
                $windowTitle = $sb.ToString()
                
                if (-not [string]::IsNullOrWhiteSpace($windowTitle)) {
                    $rect = New-Object Win32+RECT
                    [Win32]::GetWindowRect($hWnd, [ref]$rect) | Out-Null
                    
                    $processId = 0
                    [Win32]::GetWindowThreadProcessId($hWnd, [ref]$processId) | Out-Null
                    
                    try {
                        $proc = Get-Process -Id $processId -ErrorAction SilentlyContinue
                        $processName = if ($proc) { $proc.ProcessName } else { "Unknown" }
                    }
                    catch {
                        $processName = "Unknown"
                    }
                    
                    $width = $rect.Right - $rect.Left
                    $height = $rect.Bottom - $rect.Top
                    $isMinimized = [Win32]::IsIconic($hWnd)
                    
                    $script:windowList += [PSCustomObject]@{
                        PSTypeName = 'ScreenCapture.WindowInfo'
                        Handle = $hWnd.ToInt64()
                        Title = $windowTitle
                        Process = $processName
                        ProcessId = $processId
                        Width = $width
                        Height = $height
                        IsMinimized = $isMinimized
                    }
                }
            }
        }
        return $true
    }
    
    # Create delegate for callback
    $script:windowList = @()
    $enumDelegate = [Win32+EnumWindowsProc]$callback
    [Win32]::EnumWindows($enumDelegate, [IntPtr]::Zero) | Out-Null
    
    Write-Verbose "Found $($script:windowList.Count) windows"
    
    # Apply filters
    if ($Title) {
        $script:windowList = $script:windowList | Where-Object { $_.Title -like "*$Title*" }
        Write-Verbose "Filtered to $($script:windowList.Count) windows matching title '$Title'"
    }
    
    if ($Process) {
        $script:windowList = $script:windowList | Where-Object { $_.Process -like "*$Process*" }
        Write-Verbose "Filtered to $($script:windowList.Count) windows matching process '$Process'"
    }
    
    if ($script:windowList.Count -eq 0) {
        Write-Host "No visible windows found matching criteria." -ForegroundColor Yellow
        return
    }
    
    Write-Host "`nVisible Windows:" -ForegroundColor Cyan
    Write-Host ("=" * 110) -ForegroundColor Cyan
    
    $script:windowList | Format-Table -Property @(
        @{Label="Handle"; Expression={$_.Handle}; Width=15},
        @{Label="Process"; Expression={$_.Process}; Width=20},
        @{Label="Dimensions"; Expression={"$($_.Width)x$($_.Height)"}; Width=12},
        @{Label="Min"; Expression={if($_.IsMinimized){"Yes"}else{"No"}}; Width=4},
        @{Label="Title"; Expression={$_.Title}; Width=50}
    ) -AutoSize
    
    Write-Host "Total: $($script:windowList.Count) window(s)`n" -ForegroundColor Cyan
    
    # Return objects for pipeline
    return $script:windowList
}

function Get-ScreenshotWindow {
    <#
    .SYNOPSIS
    Captures a screenshot of a specific window and stores it in memory.
    
    .DESCRIPTION
    Uses Win32 APIs to capture a screenshot of a specific window by its handle, title, or process name.
    Supports pipeline input from Get-Windows.
    
    .PARAMETER Handle
    The window handle (from Get-Windows output).
    
    .PARAMETER Title
    Window title to search for (partial match, captures first match).
    
    .PARAMETER Process
    Process name to search for (partial match, captures first match).
    
    .PARAMETER Interactive
    Show an interactive menu to select a window.
    
    .PARAMETER InputObject
    Window object from pipeline (from Get-Windows).
    
    .PARAMETER RestoreIfMinimized
    Temporarily restore minimized windows before capture.
    
    .PARAMETER Quiet
    Suppresses console output.
    
    .PARAMETER PassThru
    Returns the screenshot object for pipeline use.
    
    .EXAMPLE
    Get-ScreenshotWindow -Handle 12345678
    
    .EXAMPLE
    Get-ScreenshotWindow -Title "Chrome" -PassThru | Export-Screenshot
    
    .EXAMPLE
    Get-Windows -Title "Chrome" | Select-Object -First 1 | Get-ScreenshotWindow
    
    .EXAMPLE
    Get-ScreenshotWindow -Interactive
    #>
    [CmdletBinding(DefaultParameterSetName='Handle')]
    param(
        [Parameter(Mandatory=$true, Position=0, ParameterSetName='Handle')]
        [long]$Handle,
        
        [Parameter(Mandatory=$true, ParameterSetName='Title')]
        [string]$Title,
        
        [Parameter(Mandatory=$true, ParameterSetName='Process')]
        [string]$Process,
        
        [Parameter(Mandatory=$true, ParameterSetName='Interactive')]
        [switch]$Interactive,
        
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='Pipeline')]
        [PSTypeName('ScreenCapture.WindowInfo')]
        $InputObject,
        
        [Parameter()]
        [switch]$RestoreIfMinimized,
        
        [Parameter()]
        [switch]$Quiet,
        
        [Parameter()]
        [switch]$PassThru
    )
    
    process {
        try {
            $hWnd = [IntPtr]::Zero
            
            # Handle different parameter sets
            if ($PSCmdlet.ParameterSetName -eq 'Pipeline') {
                $hWnd = [IntPtr]$InputObject.Handle
                Write-Verbose "Using window from pipeline: $($InputObject.Title)"
            }
            elseif ($PSCmdlet.ParameterSetName -eq 'Interactive') {
                # Build window list with better formatting
                $script:windowList = @()
                $callback = {
                    param($hwnd, $lParam)
                    if ([Win32]::IsWindowVisible($hwnd)) {
                        $length = [Win32]::GetWindowTextLength($hwnd)
                        if ($length -gt 0) {
                            $sb = New-Object System.Text.StringBuilder($length + 1)
                            [Win32]::GetWindowText($hwnd, $sb, $sb.Capacity) | Out-Null
                            $windowTitle = $sb.ToString()
                            if (-not [string]::IsNullOrWhiteSpace($windowTitle)) {
                                $processId = 0
                                [Win32]::GetWindowThreadProcessId($hwnd, [ref]$processId) | Out-Null
                                try {
                                    $proc = Get-Process -Id $processId -ErrorAction SilentlyContinue
                                    $processName = if ($proc) { $proc.ProcessName } else { "Unknown" }
                                } catch {
                                    $processName = "Unknown"
                                }
                                
                                $script:windowList += [PSCustomObject]@{
                                    Handle = $hwnd.ToInt64()
                                    Title = $windowTitle
                                    Process = $processName
                                }
                            }
                        }
                    }
                    return $true
                }
                
                $enumDelegate = [Win32+EnumWindowsProc]$callback
                [Win32]::EnumWindows($enumDelegate, [IntPtr]::Zero) | Out-Null
                
                Write-Host "`nSelect a window to capture:" -ForegroundColor Cyan
                Write-Host ("=" * 80) -ForegroundColor Cyan
                for ($i = 0; $i -lt $script:windowList.Count; $i++) {
                    $proc = $script:windowList[$i].Process.PadRight(20)
                    Write-Host "  [$i] " -NoNewline -ForegroundColor Yellow
                    Write-Host "$proc" -NoNewline -ForegroundColor Gray
                    Write-Host " - $($script:windowList[$i].Title)" -ForegroundColor White
                }
                Write-Host "  [q] Quit" -ForegroundColor Yellow
                Write-Host ""
                
                $selection = Read-Host "Enter selection"
                if ($selection -eq 'q') {
                    Write-Host "Cancelled." -ForegroundColor Yellow
                    return
                }
                if ($selection -match '^\d+$' -and [int]$selection -lt $script:windowList.Count) {
                    $hWnd = [IntPtr]$script:windowList[[int]$selection].Handle
                } else {
                    Write-Error "Invalid selection."
                    return
                }
            }
            elseif ($PSCmdlet.ParameterSetName -eq 'Title') {
                Write-Verbose "Searching for window with title: $Title"
                $windows = Get-Windows -Title $Title
                if (-not $windows -or $windows.Count -eq 0) {
                    Write-Error "No window found with title matching '$Title'."
                    return
                }
                $hWnd = [IntPtr]$windows[0].Handle
                if (-not $Quiet) {
                    Write-Host "Found window: $($windows[0].Title)" -ForegroundColor Gray
                }
            }
            elseif ($PSCmdlet.ParameterSetName -eq 'Process') {
                Write-Verbose "Searching for window with process: $Process"
                $windows = Get-Windows -Process $Process
                if (-not $windows -or $windows.Count -eq 0) {
                    Write-Error "No window found with process matching '$Process'."
                    return
                }
                $hWnd = [IntPtr]$windows[0].Handle
                if (-not $Quiet) {
                    Write-Host "Found window: $($windows[0].Title)" -ForegroundColor Gray
                }
            }
            else {
                $hWnd = [IntPtr]$Handle
                Write-Verbose "Using window handle: $Handle"
            }
            
            # Verify window is valid
            if (-not [Win32]::IsWindowVisible($hWnd)) {
                Write-Error "Window handle $($hWnd.ToInt64()) is not valid or not visible."
                return
            }
            
            # Check if minimized and restore if requested
            $wasMinimized = [Win32]::IsIconic($hWnd)
            if ($wasMinimized) {
                if ($RestoreIfMinimized) {
                    Write-Verbose "Window is minimized, restoring temporarily"
                    if (-not $Quiet) {
                        Write-Host "Window is minimized, restoring temporarily..." -ForegroundColor Yellow
                    }
                    [Win32]::ShowWindow($hWnd, [Win32]::SW_RESTORE) | Out-Null
                    Start-Sleep -Milliseconds 500
                } else {
                    Write-Warning "Window is minimized. Use -RestoreIfMinimized to temporarily restore it."
                }
            }
            
            # Get window title
            $length = [Win32]::GetWindowTextLength($hWnd)
            $sb = New-Object System.Text.StringBuilder($length + 1)
            [Win32]::GetWindowText($hWnd, $sb, $sb.Capacity) | Out-Null
            $windowTitle = $sb.ToString()
            
            Write-Verbose "Capturing window: $windowTitle"
            
            # Get window dimensions
            $rect = New-Object Win32+RECT
            [Win32]::GetWindowRect($hWnd, [ref]$rect) | Out-Null
            
            $width = $rect.Right - $rect.Left
            $height = $rect.Bottom - $rect.Top
            
            if ($width -le 0 -or $height -le 0) {
                Write-Error "Invalid window dimensions: ${width}x${height}"
                return
            }
            
            Write-Verbose "Window dimensions: ${width}x${height}"
            
            # Get process ID
            $processId = 0
            [Win32]::GetWindowThreadProcessId($hWnd, [ref]$processId) | Out-Null
            
            # Capture window
            $captureMethod = "PrintWindow"
            $bitmap = Capture-Window -hWnd $hWnd -Width $width -Height $height -CaptureMethodVar ([ref]$captureMethod)
            
            Write-Verbose "Capture method used: $captureMethod"
            
            # Store in memory
            $screenshot = [PSCustomObject]@{
                PSTypeName = 'ScreenCapture.Screenshot'
                Id = $script:NextId++
                Timestamp = Get-Date
                Type = "Window"
                WindowTitle = $windowTitle
                WindowHandle = $hWnd.ToInt64()
                ProcessId = $processId
                CaptureMethod = $captureMethod
                Bitmap = $bitmap
                Width = $width
                Height = $height
            }
            
            $script:Screenshots += $screenshot
            
            if (-not $Quiet) {
                Write-Host "Screenshot captured (ID: $($screenshot.Id)) - Window: $windowTitle" -ForegroundColor Green
                Write-Host "  Dimensions: ${width}x${height}" -ForegroundColor Gray
            }
            
            if ($PassThru) {
                return $screenshot
            }
        }
        catch {
            Write-Error "Failed to capture window: $_"
        }
    }
}

function Get-Screenshots {
    <#
    .SYNOPSIS
    Lists all screenshots currently stored in memory.
    
    .DESCRIPTION
    Displays a table of all captured screenshots with their reference numbers and timestamps.
    Supports filtering by type, title, and time range.
    
    .PARAMETER Type
    Filter by screenshot type (Window, Region, Primary Screen, All Screens).
    
    .PARAMETER Title
    Filter window screenshots by title (partial match).
    
    .PARAMETER After
    Only show screenshots taken after this date/time.
    
    .PARAMETER Before
    Only show screenshots taken before this date/time.
    
    .EXAMPLE
    Get-Screenshots
    
    .EXAMPLE
    Get-Screenshots -Type Window
    
    .EXAMPLE
    Get-Screenshots -Title "Chrome"
    
    .EXAMPLE
    Get-Screenshots -After (Get-Date).AddHours(-1)
    
    .EXAMPLE
    Get-Screenshots -Type Window | Export-Screenshot
    #>
    [CmdletBinding()]
    [OutputType('ScreenCapture.Screenshot')]
    param(
        [Parameter()]
        [ValidateSet('Window', 'Region', 'Primary Screen', 'All Screens')]
        [string]$Type,
        
        [Parameter()]
        [string]$Title,
        
        [Parameter()]
        [datetime]$After,
        
        [Parameter()]
        [datetime]$Before
    )
    
    if ($script:Screenshots.Count -eq 0) {
        Write-Host "No screenshots in memory." -ForegroundColor Yellow
        return
    }
    
    $filtered = $script:Screenshots
    
    # Apply filters
    if ($Type) {
        $filtered = $filtered | Where-Object { $_.Type -eq $Type }
        Write-Verbose "Filtered by type: $Type"
    }
    
    if ($Title) {
        $filtered = $filtered | Where-Object { $_.WindowTitle -like "*$Title*" }
        Write-Verbose "Filtered by title: $Title"
    }
    
    if ($After) {
        $filtered = $filtered | Where-Object { $_.Timestamp -gt $After }
        Write-Verbose "Filtered by after: $After"
    }
    
    if ($Before) {
        $filtered = $filtered | Where-Object { $_.Timestamp -lt $Before }
        Write-Verbose "Filtered by before: $Before"
    }
    
    if ($filtered.Count -eq 0) {
        Write-Host "No screenshots match the filter criteria." -ForegroundColor Yellow
        return
    }
    
    Write-Host "`nScreenshots in Memory:" -ForegroundColor Cyan
    Write-Host ("=" * 110) -ForegroundColor Cyan
    
    $filtered | Format-Table -Property @(
        @{Label="ID"; Expression={$_.Id}; Width=5},
        @{Label="Timestamp"; Expression={$_.Timestamp.ToString("yyyy-MM-dd HH:mm:ss")}; Width=20},
        @{Label="Type"; Expression={$_.Type}; Width=15},
        @{Label="Window/Info"; Expression={
            if ($_.Type -eq "Window") { $_.WindowTitle }
            elseif ($_.Type -eq "Region") { $_.Region }
            else { "" }
        }; Width=35},
        @{Label="Dimensions"; Expression={"$($_.Width)x$($_.Height)"}; Width=15}
    ) -AutoSize
    
    Write-Host "Total: $($filtered.Count) screenshot(s)" -ForegroundColor Cyan
    if ($filtered.Count -ne $script:Screenshots.Count) {
        Write-Host "       ($($script:Screenshots.Count) total in memory)`n" -ForegroundColor Gray
    } else {
        Write-Host ""
    }
    
    # Return objects for pipeline
    return $filtered
}

function Export-Screenshot {
    <#
    .SYNOPSIS
    Exports screenshots from memory to the clipboard.
    
    .DESCRIPTION
    Takes one or more screenshot reference numbers or objects and places them on the clipboard.
    Supports pipeline input.
    
    .PARAMETER Id
    The reference number(s) of the screenshot(s) to export.
    
    .PARAMETER InputObject
    Screenshot object(s) from pipeline.
    
    .EXAMPLE
    Export-Screenshot -Id 1
    
    .EXAMPLE
    Export-Screenshot -Id 1,2,3
    
    .EXAMPLE
    Get-Screenshots -Type Window | Export-Screenshot
    
    .EXAMPLE
    Get-ScreenshotWindow -Title "Chrome" -PassThru | Export-Screenshot
    #>
    [CmdletBinding(DefaultParameterSetName='ById')]
    param(
        [Parameter(Mandatory=$true, Position=0, ParameterSetName='ById')]
        [int[]]$Id,
        
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='Pipeline')]
        [PSTypeName('ScreenCapture.Screenshot')]
        $InputObject
    )
    
    begin {
        $count = 0
    }
    
    process {
        try {
            if ($PSCmdlet.ParameterSetName -eq 'Pipeline') {
                $screenshot = $InputObject
                
                if (-not $screenshot -or -not $screenshot.Bitmap) {
                    Write-Warning "Invalid screenshot object received."
                    return
                }
                
                Write-Verbose "Exporting screenshot ID $($screenshot.Id) to clipboard"
                
                # Copy to clipboard
                [System.Windows.Forms.Clipboard]::SetImage($screenshot.Bitmap)
                
                Write-Host "Screenshot ID $($screenshot.Id) copied to clipboard." -ForegroundColor Green
                Write-Host "  Type: $($screenshot.Type)" -ForegroundColor Gray
                Write-Host "  Dimensions: $($screenshot.Width)x$($screenshot.Height)" -ForegroundColor Gray
                Write-Host "  Timestamp: $($screenshot.Timestamp.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Gray
                Write-Host ""
                
                $count++
            }
            else {
                foreach ($screenshotId in $Id) {
                    $screenshot = $script:Screenshots | Where-Object { $_.Id -eq $screenshotId }
                    
                    if (-not $screenshot) {
                        Write-Warning "Screenshot with ID $screenshotId not found."
                        continue
                    }
                    
                    Write-Verbose "Exporting screenshot ID $screenshotId to clipboard"
                    
                    # Copy to clipboard
                    [System.Windows.Forms.Clipboard]::SetImage($screenshot.Bitmap)
                    
                    Write-Host "Screenshot ID $screenshotId copied to clipboard." -ForegroundColor Green
                    Write-Host "  Type: $($screenshot.Type)" -ForegroundColor Gray
                    Write-Host "  Dimensions: $($screenshot.Width)x$($screenshot.Height)" -ForegroundColor Gray
                    Write-Host "  Timestamp: $($screenshot.Timestamp.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Gray
                    
                    if ($Id.Count -gt 1) {
                        Write-Host ""
                    }
                    
                    $count++
                }
            }
        }
        catch {
            Write-Error "Failed to export screenshot: $_"
        }
    }
    
    end {
        if ($count -gt 1) {
            Write-Host "Exported $count screenshots (last one is on clipboard)" -ForegroundColor Cyan
        }
    }
}

function Save-Screenshot {
    <#
    .SYNOPSIS
    Saves screenshots from memory to files.
    
    .DESCRIPTION
    Saves one or more screenshots to disk in PNG, JPG, or BMP format.
    Supports pipeline input and batch operations.
    
    .PARAMETER Id
    The reference number(s) of the screenshot(s) to save.
    
    .PARAMETER Path
    The file path where the screenshot will be saved. Extension determines format (png, jpg, bmp).
    For single screenshots, full file path. For multiple/All, directory path.
    
    .PARAMETER InputObject
    Screenshot object(s) from pipeline.
    
    .PARAMETER All
    Save all screenshots to a directory.
    
    .PARAMETER Format
    Image format when saving multiple screenshots (PNG, JPEG, BMP). Default is PNG.
    
    .EXAMPLE
    Save-Screenshot -Id 1 -Path "C:\screenshots\capture.png"
    
    .EXAMPLE
    Save-Screenshot -Id 1,2,3 -Path "C:\screenshots\"
    
    .EXAMPLE
    Save-Screenshot -All -Path "C:\screenshots\" -Format PNG
    
    .EXAMPLE
    Get-Screenshots -Type Window | Save-Screenshot -Path "C:\screenshots\"
    
    .EXAMPLE
    Save-Screenshot -All -Path "C:\screenshots\" -WhatIf
    #>
    [CmdletBinding(DefaultParameterSetName='Single', SupportsShouldProcess=$true, ConfirmImpact='Low')]
    param(
        [Parameter(Mandatory=$true, Position=0, ParameterSetName='Single')]
        [Parameter(Mandatory=$true, Position=0, ParameterSetName='Multiple')]
        [int[]]$Id,
        
        [Parameter(Mandatory=$true, Position=1, ParameterSetName='Single')]
        [Parameter(Mandatory=$true, Position=1, ParameterSetName='Multiple')]
        [Parameter(Mandatory=$true, Position=0, ParameterSetName='All')]
        [Parameter(Mandatory=$true, ParameterSetName='Pipeline')]
        [string]$Path,
        
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='Pipeline')]
        [PSTypeName('ScreenCapture.Screenshot')]
        $InputObject,
        
        [Parameter(Mandatory=$true, ParameterSetName='All')]
        [switch]$All,
        
        [Parameter(ParameterSetName='All')]
        [Parameter(ParameterSetName='Multiple')]
        [Parameter(ParameterSetName='Pipeline')]
        [ValidateSet('PNG', 'JPEG', 'BMP')]
        [string]$Format = 'PNG'
    )
    
    begin {
        $savedCount = 0
        $pipelineScreenshots = @()
        
        # Normalize path
        $Path = [System.IO.Path]::GetFullPath($Path)
    }
    
    process {
        if ($PSCmdlet.ParameterSetName -eq 'Pipeline') {
            $pipelineScreenshots += $InputObject
        }
    }
    
    end {
        try {
            if ($PSCmdlet.ParameterSetName -eq 'All') {
                # Ensure directory exists
                if (-not (Test-Path -Path $Path -PathType Container)) {
                    if ($PSCmdlet.ShouldProcess($Path, "Create directory")) {
                        New-Item -Path $Path -ItemType Directory -Force | Out-Null
                    }
                }
                
                $imageFormat = switch ($Format) {
                    'PNG' { [System.Drawing.Imaging.ImageFormat]::Png; '.png' }
                    'JPEG' { [System.Drawing.Imaging.ImageFormat]::Jpeg; '.jpg' }
                    'BMP' { [System.Drawing.Imaging.ImageFormat]::Bmp; '.bmp' }
                }
                
                $ext = $imageFormat[1]
                $fmt = $imageFormat[0]
                
                $total = $script:Screenshots.Count
                $current = 0
                
                foreach ($screenshot in $script:Screenshots) {
                    $current++
                    Write-Progress -Activity "Saving Screenshots" -Status "Processing ID $($screenshot.Id)" -PercentComplete ($current/$total*100)
                    
                    $timestamp = $screenshot.Timestamp.ToString("yyyyMMdd_HHmmss")
                    $sanitizedTitle = if ($screenshot.Type -eq "Window") {
                        ($screenshot.WindowTitle -replace '[\\/:*?"<>|]', '_').Substring(0, [Math]::Min(50, $screenshot.WindowTitle.Length))
                    } else {
                        $screenshot.Type -replace ' ', '_'
                    }
                    
                    $filename = "Screenshot_$($screenshot.Id)_${timestamp}_${sanitizedTitle}${ext}"
                    $fullPath = Join-Path -Path $Path -ChildPath $filename
                    
                    if ($PSCmdlet.ShouldProcess($fullPath, "Save screenshot")) {
                        Write-Verbose "Saving screenshot ID $($screenshot.Id) to $fullPath"
                        $screenshot.Bitmap.Save($fullPath, $fmt)
                        Write-Host "Saved: $fullPath" -ForegroundColor Green
                        $savedCount++
                    }
                }
                
                Write-Progress -Activity "Saving Screenshots" -Completed
                
                if ($savedCount -gt 0) {
                    Write-Host "`nSaved $savedCount screenshot(s) to $Path" -ForegroundColor Cyan
                }
            }
            elseif ($PSCmdlet.ParameterSetName -eq 'Pipeline') {
                # Handle pipeline input
                if ($pipelineScreenshots.Count -eq 0) {
                    Write-Warning "No screenshots received from pipeline."
                    return
                }
                
                # Ensure directory exists
                if (-not (Test-Path -Path $Path -PathType Container)) {
                    if ($PSCmdlet.ShouldProcess($Path, "Create directory")) {
                        New-Item -Path $Path -ItemType Directory -Force | Out-Null
                    }
                }
                
                $imageFormat = switch ($Format) {
                    'PNG' { [System.Drawing.Imaging.ImageFormat]::Png; '.png' }
                    'JPEG' { [System.Drawing.Imaging.ImageFormat]::Jpeg; '.jpg' }
                    'BMP' { [System.Drawing.Imaging.ImageFormat]::Bmp; '.bmp' }
                }
                
                $ext = $imageFormat[1]
                $fmt = $imageFormat[0]
                
                $total = $pipelineScreenshots.Count
                $current = 0
                
                foreach ($screenshot in $pipelineScreenshots) {
                    $current++
                    Write-Progress -Activity "Saving Screenshots" -Status "Processing ID $($screenshot.Id)" -PercentComplete ($current/$total*100)
                    
                    $timestamp = $screenshot.Timestamp.ToString("yyyyMMdd_HHmmss")
                    $sanitizedTitle = if ($screenshot.Type -eq "Window") {
                        ($screenshot.WindowTitle -replace '[\\/:*?"<>|]', '_').Substring(0, [Math]::Min(50, $screenshot.WindowTitle.Length))
                    } else {
                        $screenshot.Type -replace ' ', '_'
                    }
                    
                    $filename = "Screenshot_$($screenshot.Id)_${timestamp}_${sanitizedTitle}${ext}"
                    $fullPath = Join-Path -Path $Path -ChildPath $filename
                    
                    if ($PSCmdlet.ShouldProcess($fullPath, "Save screenshot")) {
                        Write-Verbose "Saving screenshot ID $($screenshot.Id) to $fullPath"
                        $screenshot.Bitmap.Save($fullPath, $fmt)
                        Write-Host "Saved: $fullPath" -ForegroundColor Green
                        $savedCount++
                    }
                }
                
                Write-Progress -Activity "Saving Screenshots" -Completed
                
                if ($savedCount -gt 0) {
                    Write-Host "`nSaved $savedCount screenshot(s) to $Path" -ForegroundColor Cyan
                }
            }
            elseif ($Id.Count -eq 1) {
                # Single screenshot
                $screenshot = $script:Screenshots | Where-Object { $_.Id -eq $Id[0] }
                
                if (-not $screenshot) {
                    Write-Error "Screenshot with ID $($Id[0]) not found."
                    return
                }
                
                # Determine format from extension
                $ext = [System.IO.Path]::GetExtension($Path).ToLower()
                $imageFormat = switch ($ext) {
                    '.png' { [System.Drawing.Imaging.ImageFormat]::Png }
                    '.jpg' { [System.Drawing.Imaging.ImageFormat]::Jpeg }
                    '.jpeg' { [System.Drawing.Imaging.ImageFormat]::Jpeg }
                    '.bmp' { [System.Drawing.Imaging.ImageFormat]::Bmp }
                    default { 
                        Write-Warning "Unknown format '$ext', defaulting to PNG"
                        $Path = [System.IO.Path]::ChangeExtension($Path, '.png')
                        [System.Drawing.Imaging.ImageFormat]::Png 
                    }
                }
                
                # Ensure directory exists
                $directory = [System.IO.Path]::GetDirectoryName($Path)
                if ($directory -and -not (Test-Path -Path $directory)) {
                    if ($PSCmdlet.ShouldProcess($directory, "Create directory")) {
                        New-Item -Path $directory -ItemType Directory -Force | Out-Null
                    }
                }
                
                if ($PSCmdlet.ShouldProcess($Path, "Save screenshot")) {
                    Write-Verbose "Saving screenshot ID $($Id[0]) to $Path"
                    $screenshot.Bitmap.Save($Path, $imageFormat)
                    Write-Host "Screenshot ID $($Id[0]) saved to: $Path" -ForegroundColor Green
                    Write-Host "  Type: $($screenshot.Type)" -ForegroundColor Gray
                    Write-Host "  Dimensions: $($screenshot.Width)x$($screenshot.Height)" -ForegroundColor Gray
                    Write-Host "  Format: $($imageFormat.ToString())" -ForegroundColor Gray
                    $savedCount++
                }
            }
            else {
                # Multiple screenshots by ID
                if (-not (Test-Path -Path $Path -PathType Container)) {
                    if ($PSCmdlet.ShouldProcess($Path, "Create directory")) {
                        New-Item -Path $Path -ItemType Directory -Force | Out-Null
                    }
                }
                
                $imageFormat = switch ($Format) {
                    'PNG' { [System.Drawing.Imaging.ImageFormat]::Png; '.png' }
                    'JPEG' { [System.Drawing.Imaging.ImageFormat]::Jpeg; '.jpg' }
                    'BMP' { [System.Drawing.Imaging.ImageFormat]::Bmp; '.bmp' }
                }
                
                $ext = $imageFormat[1]
                $fmt = $imageFormat[0]
                
                $total = $Id.Count
                $current = 0
                
                foreach ($screenshotId in $Id) {
                    $current++
                    Write-Progress -Activity "Saving Screenshots" -Status "Processing ID $screenshotId" -PercentComplete ($current/$total*100)
                    
                    $screenshot = $script:Screenshots | Where-Object { $_.Id -eq $screenshotId }
                    
                    if (-not $screenshot) {
                        Write-Warning "Screenshot with ID $screenshotId not found."
                        continue
                    }
                    
                    $timestamp = $screenshot.Timestamp.ToString("yyyyMMdd_HHmmss")
                    $sanitizedTitle = if ($screenshot.Type -eq "Window") {
                        ($screenshot.WindowTitle -replace '[\\/:*?"<>|]', '_').Substring(0, [Math]::Min(50, $screenshot.WindowTitle.Length))
                    } else {
                        $screenshot.Type -replace ' ', '_'
                    }
                    
                    $filename = "Screenshot_$($screenshot.Id)_${timestamp}_${sanitizedTitle}${ext}"
                    $fullPath = Join-Path -Path $Path -ChildPath $filename
                    
                    if ($PSCmdlet.ShouldProcess($fullPath, "Save screenshot")) {
                        Write-Verbose "Saving screenshot ID $screenshotId to $fullPath"
                        $screenshot.Bitmap.Save($fullPath, $fmt)
                        Write-Host "Saved: $fullPath" -ForegroundColor Green
                        $savedCount++
                    }
                }
                
                Write-Progress -Activity "Saving Screenshots" -Completed
                
                if ($savedCount -gt 0) {
                    Write-Host "`nSaved $savedCount screenshot(s) to $Path" -ForegroundColor Cyan
                }
            }
        }
        catch {
            Write-Error "Failed to save screenshot: $_"
        }
    }
}

function Show-Screenshot {
    <#
    .SYNOPSIS
    Displays a screenshot in a window directly from memory.
    
    .DESCRIPTION
    Opens a WPF window to display the screenshot without writing to disk.
    
    .PARAMETER Id
    The reference number of the screenshot to show.
    
    .PARAMETER InputObject
    Screenshot object from pipeline.
    
    .EXAMPLE
    Show-Screenshot -Id 1
    
    .EXAMPLE
    Get-Screenshots -Type Window | Select-Object -First 1 | Show-Screenshot
    
    .EXAMPLE
    Get-ScreenshotWindow -Title "Chrome" -PassThru | Show-Screenshot
    #>
    [CmdletBinding(DefaultParameterSetName='ById')]
    param(
        [Parameter(Mandatory=$true, Position=0, ParameterSetName='ById')]
        [int]$Id,
        
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='Pipeline')]
        [PSTypeName('ScreenCapture.Screenshot')]
        $InputObject
    )
    
    process {
        try {
            if ($PSCmdlet.ParameterSetName -eq 'Pipeline') {
                $screenshot = $InputObject
            }
            else {
                $screenshot = $script:Screenshots | Where-Object { $_.Id -eq $Id }
            }
            
            if (-not $screenshot) {
                Write-Error "Screenshot with ID $Id not found."
                return
            }
            
            Write-Verbose "Displaying screenshot ID $($screenshot.Id) from memory"
            
            # Load WPF assemblies
            Add-Type -AssemblyName PresentationFramework
            Add-Type -AssemblyName PresentationCore
            Add-Type -AssemblyName WindowsBase
            
            # Convert Bitmap to BitmapSource for WPF
            $memoryStream = New-Object System.IO.MemoryStream
            $screenshot.Bitmap.Save($memoryStream, [System.Drawing.Imaging.ImageFormat]::Png)
            $memoryStream.Position = 0
            
            $bitmapImage = New-Object System.Windows.Media.Imaging.BitmapImage
            $bitmapImage.BeginInit()
            $bitmapImage.StreamSource = $memoryStream
            $bitmapImage.CacheOption = [System.Windows.Media.Imaging.BitmapCacheOption]::OnLoad
            $bitmapImage.EndInit()
            $bitmapImage.Freeze()
            $memoryStream.Close()
            
            # Create WPF Window
            $window = New-Object System.Windows.Window
            $window.Title = "Screenshot ID: $($screenshot.Id) - $($screenshot.Type)"
            if ($screenshot.WindowTitle) {
                $window.Title += " - $($screenshot.WindowTitle)"
            }
            $window.SizeToContent = [System.Windows.SizeToContent]::WidthAndHeight
            $window.ResizeMode = [System.Windows.ResizeMode]::CanResize
            $window.WindowStartupLocation = [System.Windows.WindowStartupLocation]::CenterScreen
            
            # Create Image control
            $image = New-Object System.Windows.Controls.Image
            $image.Source = $bitmapImage
            $image.Stretch = [System.Windows.Media.Stretch]::Uniform
            
            # Set max size to 90% of screen
            $screen = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
            $image.MaxWidth = $screen.Width * 0.9
            $image.MaxHeight = $screen.Height * 0.9
            
            # Create ScrollViewer for large images
            $scrollViewer = New-Object System.Windows.Controls.ScrollViewer
            $scrollViewer.HorizontalScrollBarVisibility = [System.Windows.Controls.ScrollBarVisibility]::Auto
            $scrollViewer.VerticalScrollBarVisibility = [System.Windows.Controls.ScrollBarVisibility]::Auto
            $scrollViewer.Content = $image
            
            $window.Content = $scrollViewer
            
            Write-Host "Displaying screenshot ID $($screenshot.Id) (from memory)..." -ForegroundColor Green
            Write-Host "  Dimensions: $($screenshot.Width)x$($screenshot.Height)" -ForegroundColor Gray
            Write-Host "  Close window when done viewing" -ForegroundColor Gray
            
            # Show window
            [void]$window.ShowDialog()
        }
        catch {
            Write-Error "Failed to show screenshot: $_"
        }
    }
}

function Clear-Screenshots {
    <#
    .SYNOPSIS
    Clears all screenshots from memory.
    
    .DESCRIPTION
    Removes all stored screenshots and resets the ID counter.
    
    .PARAMETER Force
    Skip confirmation prompt.
    
    .EXAMPLE
    Clear-Screenshots
    
    .EXAMPLE
    Clear-Screenshots -Force
    
    .EXAMPLE
    Clear-Screenshots -WhatIf
    #>
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [Parameter()]
        [switch]$Force
    )
    
    $count = $script:Screenshots.Count
    
    if ($count -eq 0) {
        Write-Host "No screenshots in memory to clear." -ForegroundColor Yellow
        return
    }
    
    if ($Force -or $PSCmdlet.ShouldProcess("$count screenshot(s)", "Clear from memory")) {
        Write-Verbose "Clearing $count screenshots from memory"
        
        # Dispose bitmaps to free memory
        foreach ($screenshot in $script:Screenshots) {
            if ($screenshot.Bitmap) {
                $screenshot.Bitmap.Dispose()
            }
        }
        
        $script:Screenshots = @()
        $script:NextId = 1
        
        Write-Host "Cleared $count screenshot(s) from memory." -ForegroundColor Green
    }
}

# Helper function to capture screen region using Win32 APIs
function Capture-ScreenRegion {
    param(
        [int]$X,
        [int]$Y,
        [int]$Width,
        [int]$Height
    )
    
    $hdcSrc = [IntPtr]::Zero
    $hdcDest = [IntPtr]::Zero
    $hBitmap = [IntPtr]::Zero
    $hOldBitmap = [IntPtr]::Zero
    
    try {
        # Get device context for entire screen
        $hdcSrc = [Win32]::GetWindowDC([Win32]::GetDesktopWindow())
        
        # Create compatible DC and bitmap
        $hdcDest = [Win32]::CreateCompatibleDC($hdcSrc)
        $hBitmap = [Win32]::CreateCompatibleBitmap($hdcSrc, $Width, $Height)
        $hOldBitmap = [Win32]::SelectObject($hdcDest, $hBitmap)
        
        # Bit block transfer
        [Win32]::BitBlt($hdcDest, 0, 0, $Width, $Height, $hdcSrc, $X, $Y, [Win32]::SRCCOPY) | Out-Null
        
        # Create bitmap from handle
        $bitmap = [System.Drawing.Image]::FromHbitmap($hBitmap)
        
        return $bitmap
    }
    finally {
        # Cleanup
        if ($hOldBitmap -ne [IntPtr]::Zero) {
            [Win32]::SelectObject($hdcDest, $hOldBitmap) | Out-Null
        }
        if ($hBitmap -ne [IntPtr]::Zero) {
            [Win32]::DeleteObject($hBitmap) | Out-Null
        }
        if ($hdcDest -ne [IntPtr]::Zero) {
            [Win32]::DeleteDC($hdcDest) | Out-Null
        }
        if ($hdcSrc -ne [IntPtr]::Zero) {
            [Win32]::ReleaseDC([Win32]::GetDesktopWindow(), $hdcSrc) | Out-Null
        }
    }
}

# Helper function to capture a specific window using Win32 APIs
function Capture-Window {
    param(
        [IntPtr]$hWnd,
        [int]$Width,
        [int]$Height,
        [ref]$CaptureMethodVar
    )
    
    $hdcSrc = [IntPtr]::Zero
    $hdcDest = [IntPtr]::Zero
    $hBitmap = [IntPtr]::Zero
    $hOldBitmap = [IntPtr]::Zero
    
    try {
        # Get window DC
        $hdcSrc = [Win32]::GetWindowDC($hWnd)
        
        # Create compatible DC and bitmap
        $hdcDest = [Win32]::CreateCompatibleDC($hdcSrc)
        $hBitmap = [Win32]::CreateCompatibleBitmap($hdcSrc, $Width, $Height)
        $hOldBitmap = [Win32]::SelectObject($hdcDest, $hBitmap)
        
        # Use PrintWindow for better window capture
        $result = [Win32]::PrintWindow($hWnd, $hdcDest, [Win32]::PW_RENDERFULLCONTENT)
        
        if (-not $result) {
            # Fallback to BitBlt if PrintWindow fails
            [Win32]::BitBlt($hdcDest, 0, 0, $Width, $Height, $hdcSrc, 0, 0, [Win32]::SRCCOPY) | Out-Null
            $CaptureMethodVar.Value = "BitBlt (fallback)"
        }
        else {
            $CaptureMethodVar.Value = "PrintWindow"
        }
        
        # Create bitmap from handle
        $bitmap = [System.Drawing.Image]::FromHbitmap($hBitmap)
        
        return $bitmap
    }
    finally {
        # Cleanup
        if ($hOldBitmap -ne [IntPtr]::Zero) {
            [Win32]::SelectObject($hdcDest, $hOldBitmap) | Out-Null
        }
        if ($hBitmap -ne [IntPtr]::Zero) {
            [Win32]::DeleteObject($hBitmap) | Out-Null
        }
        if ($hdcDest -ne [IntPtr]::Zero) {
            [Win32]::DeleteDC($hdcDest) | Out-Null
        }
        if ($hdcSrc -ne [IntPtr]::Zero) {
            [Win32]::ReleaseDC($hWnd, $hdcSrc) | Out-Null
        }
    }
}

# Set up aliases for common commands
Set-Alias -Name gsca -Value Get-ScreenshotAll
Set-Alias -Name gscc -Value Get-ScreenshotCurrent
Set-Alias -Name gscw -Value Get-ScreenshotWindow
Set-Alias -Name gscr -Value Get-ScreenshotRegion
Set-Alias -Name gsc -Value Get-Screenshots
Set-Alias -Name gw -Value Get-Windows

# Display help on module import
Write-Host ""
Write-Host "====================================================================" -ForegroundColor Cyan
Write-Host "         ScreenRemember - In Memory Screenshot Tool" -ForegroundColor Cyan
Write-Host "====================================================================" -ForegroundColor Cyan
Write-Host "`nCapture Commands:" -ForegroundColor Yellow
Write-Host "  Get-ScreenshotAll (gsca)    " -NoNewline -ForegroundColor Green
Write-Host "- Capture all screens" -ForegroundColor Gray
Write-Host "  Get-ScreenshotCurrent (gscc)" -NoNewline -ForegroundColor Green
Write-Host "- Capture primary screen" -ForegroundColor Gray
Write-Host "  Get-ScreenshotRegion (gscr) " -NoNewline -ForegroundColor Green
Write-Host "- Capture specific region" -ForegroundColor Gray
Write-Host "  Get-ScreenshotWindow (gscw) " -NoNewline -ForegroundColor Green
Write-Host "- Capture window (supports pipeline)" -ForegroundColor Gray
Write-Host "`nManagement Commands:" -ForegroundColor Yellow
Write-Host "  Get-Windows (gw)            " -NoNewline -ForegroundColor Green
Write-Host "- List windows (supports filtering)" -ForegroundColor Gray
Write-Host "  Get-Screenshots (gsc)       " -NoNewline -ForegroundColor Green
Write-Host "- List screenshots (supports filtering)" -ForegroundColor Gray
Write-Host "  Clear-Screenshots           " -NoNewline -ForegroundColor Green
Write-Host "- Clear all from memory" -ForegroundColor Gray
Write-Host "`nExport Commands:" -ForegroundColor Yellow
Write-Host "  Export-Screenshot           " -NoNewline -ForegroundColor Green
Write-Host "- Copy to clipboard (supports pipeline)" -ForegroundColor Gray
Write-Host "  Save-Screenshot             " -NoNewline -ForegroundColor Green
Write-Host "- Save to file (supports pipeline)" -ForegroundColor Gray
Write-Host "  Show-Screenshot             " -NoNewline -ForegroundColor Green
Write-Host "- Display in window (memory only)" -ForegroundColor Gray
Write-Host "`nKey Features:" -ForegroundColor Yellow
Write-Host "  - Full pipeline support for chaining operations" -ForegroundColor Gray
Write-Host "  - Memory-only operation (unless explicitly saved)" -ForegroundColor Gray
Write-Host "  - WhatIf/Confirm support for safety" -ForegroundColor Gray
Write-Host "  - Verbose logging with -Verbose" -ForegroundColor Gray
Write-Host "  - Batch operations with progress bars" -ForegroundColor Gray
Write-Host "`nPipeline Examples:" -ForegroundColor Cyan
Write-Host "  # Capture and immediately export" -ForegroundColor Gray
Write-Host "  Get-ScreenshotWindow -Title 'Chrome' -PassThru | Export-Screenshot" -ForegroundColor White
Write-Host ""
Write-Host "  # Filter and save window screenshots" -ForegroundColor Gray
Write-Host "  Get-Screenshots -Type Window | Save-Screenshot -Path C:\screens\" -ForegroundColor White
Write-Host ""
Write-Host "  # Find window and capture" -ForegroundColor Gray
Write-Host "  Get-Windows -Title 'Chrome' | Select -First 1 | Get-ScreenshotWindow" -ForegroundColor White
Write-Host ""
Write-Host "  # Batch save with custom format" -ForegroundColor Gray
Write-Host "  Save-Screenshot -Id 1,2,3 -Path C:\screens\ -Format JPEG" -ForegroundColor White
Write-Host ""
Write-Host "  # Interactive selection" -ForegroundColor Gray
Write-Host "  Get-ScreenshotWindow -Interactive" -ForegroundColor White
Write-Host ""
Write-Host "  # Safety checks" -ForegroundColor Gray
Write-Host "  Clear-Screenshots -WhatIf" -ForegroundColor White
Write-Host "  Save-Screenshot -All -Path C:\screens\ -WhatIf" -ForegroundColor White
Write-Host ""

# Export module functions
Export-ModuleMember -Function Get-ScreenshotAll, Get-ScreenshotCurrent, Get-ScreenshotRegion, Get-Windows, Get-ScreenshotWindow, Get-Screenshots, Export-Screenshot, Save-Screenshot, Show-Screenshot, Clear-Screenshots -Alias gsca, gscc, gscw, gscr, gsc, gw
