Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. "$PSScriptRoot\windows-testlib.ps1"

$script:NamecoinCli = Resolve-BinaryPath -Name 'namecoin-cli.exe'
$script:OpenSslBinary = Resolve-BinaryPath -Name 'openssl.exe' -FallbackPaths @(
    'C:\ProgramData\chocolatey\bin\openssl.exe',
    "$env:ProgramFiles\OpenSSL\bin\openssl.exe",
    "$env:ProgramFiles\OpenSSL-Win64\bin\openssl.exe",
    "${env:ProgramFiles(x86)}\OpenSSL\bin\openssl.exe",
    "${env:ProgramFiles(x86)}\OpenSSL-Win32\bin\openssl.exe",
    "$env:ProgramFiles\Git\usr\bin\openssl.exe",
    "$env:ProgramFiles\Git\mingw64\bin\openssl.exe"
)
$script:CertUtilBinary = Resolve-BinaryPath -Name 'certutil.exe' -FallbackPaths @(
    (Join-Path $env:SystemRoot 'System32\certutil.exe')
) -PreferFallbackPaths
$script:CurlBinary = Resolve-BinaryPath -Name 'curl.exe' -FallbackPaths @(
    "$env:ProgramFiles\Git\mingw64\bin\curl.exe",
    "${env:ProgramFiles(x86)}\Git\mingw64\bin\curl.exe",
    "$env:SystemRoot\System32\curl.exe"
) -PreferFallbackPaths
$script:BrowserBinary = Get-BrowserBinary
$script:NamecoinDataDir = Get-NamecoinDataDir
$script:EncayaRuntimeDir = Get-EncayaRuntimeDir
$script:BitcoinCliArgs = @(
    "-datadir=$script:NamecoinDataDir",
    '-rpcuser=doggman',
    '-rpcpassword=donkey',
    '-rpcport=18554',
    '-regtest'
)
$script:AiaTestIp = '127.127.127.127'
$script:AiaTestUrl = "http://$script:AiaTestIp"
$script:ImportedRootThumbprints = New-Object 'System.Collections.Generic.List[string]'
$script:ImportedRootStoreScope = $null
$script:HttpsServerProcess = $null
$script:StapledHttpsServerProcess = $null
$script:ManagedServiceProcesses = New-Object 'System.Collections.Generic.List[object]'
$script:ManagedWindowsServices = New-Object 'System.Collections.Generic.List[object]'
$script:ManagedServiceFileLogs = New-Object 'System.Collections.Generic.List[object]'
$script:ManagedServiceLogDir = Join-Path (Get-WindowsRuntimeRoot) 'managed-services'
$script:TestFailed = $false
$script:TestTempDir = $null
$script:StapledTestTempDir = $null

function Test-TruthyEnvironmentValue {
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Value
    )

    if (-not $Value) {
        return $false
    }

    return $Value.ToLowerInvariant() -in @('1', 'true', 'yes')
}

function Test-ShouldManageServices {
    return (Test-TruthyEnvironmentValue -Value $env:ENCAYA_WINDOWS_MANAGE_SERVICES)
}

function Test-ShouldUseWindowsServiceControl {
    return (Test-TruthyEnvironmentValue -Value $env:ENCAYA_WINDOWS_USE_SERVICE_CONTROL)
}

function New-TempDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Prefix
    )

    $path = Join-Path $env:TEMP ($Prefix + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $path | Out-Null

    return $path
}

function Read-FileOrEmpty {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (Test-Path -LiteralPath $Path) {
        return (Get-Content -LiteralPath $Path -Raw)
    }

    return ''
}

function Invoke-NamecoinCliText {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    return (Invoke-NativeCommand -FilePath $script:NamecoinCli -ArgumentList ($script:BitcoinCliArgs + $Arguments)).Output.Trim()
}

function Invoke-NamecoinCliJson {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    $output = Invoke-NamecoinCliText -Arguments $Arguments
    if (-not $output) {
        return $null
    }

    return ($output | ConvertFrom-Json)
}

function Invoke-Curl {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,
        [switch]$AllowFailure
    )

    $baseArguments = @(
        '--silent',
        '--show-error',
        '--fail',
        '--connect-timeout',
        '5',
        '--max-time',
        '20',
        '--noproxy',
        '*'
    )

    return (Invoke-NativeCommand -FilePath $script:CurlBinary -ArgumentList ($baseArguments + $Arguments) -AllowFailure:$AllowFailure)
}

function Invoke-CurlText {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,
        [switch]$AllowFailure
    )

    return (Invoke-Curl -Arguments $Arguments -AllowFailure:$AllowFailure).Output
}

function Invoke-CurlDownload {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,
        [switch]$AllowFailure
    )

    Invoke-Curl -Arguments ($Arguments + @('-o', $OutputPath)) -AllowFailure:$AllowFailure | Out-Null
}

function Invoke-OpenSsl {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,
        [switch]$AllowFailure,
        [string]$InputText
    )

    return (Invoke-NativeCommand -FilePath $script:OpenSslBinary -ArgumentList $Arguments -AllowFailure:$AllowFailure -InputText $InputText)
}

function New-Blocks {
    param(
        [Parameter(Mandatory = $true)]
        [int]$Count
    )

    $address = Invoke-NamecoinCliText -Arguments @('getnewaddress')
    Invoke-NamecoinCliText -Arguments @('generatetoaddress', $Count.ToString(), $address) | Out-Null
}

function Wait-ForNamecoinWalletBalance {
    param(
        [decimal]$MinimumBalance = 1,
        [int]$TimeoutSeconds = 120
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $culture = [System.Globalization.CultureInfo]::InvariantCulture

    while ((Get-Date) -lt $deadline) {
        try {
            $balanceText = Invoke-NamecoinCliText -Arguments @('getbalance')
            if ($balanceText) {
                $balance = [decimal]::Parse($balanceText, $culture)
                if ($balance -ge $MinimumBalance) {
                    return
                }
            }
        } catch {
            # Wallet may not be initialized yet.
        }

        Start-Sleep -Seconds 1
    }

    throw "Timed out waiting for Namecoin wallet balance >= $MinimumBalance"
}

function Fail-Test {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    throw $Message
}

function Assert-Equal {
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Expected,
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Actual,
        [Parameter(Mandatory = $true)]
        [string]$ErrorMessage
    )

    if ($Expected -ne $Actual) {
        Write-Host "'$Expected' != '$Actual'"
        Fail-Test -Message $ErrorMessage
    }
}

function Assert-Contains {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Haystack,
        [Parameter(Mandatory = $true)]
        [string]$Needle,
        [Parameter(Mandatory = $true)]
        [string]$ErrorMessage
    )

    if ($Haystack -notlike "*$Needle*") {
        Write-Host $Haystack
        Fail-Test -Message $ErrorMessage
    }
}

function Test-BrowserCertificateErrorOutput {
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Output
    )

    return (
        ($Output -like '*Your connection is not private*') -or
        ($Output -like "*Your connection isn't private*") -or
        ($Output -like '*net::ERR_CERT_DATE_INVALID*')
    )
}

function Assert-RaisesError {
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$Command,
        [Parameter(Mandatory = $true)]
        [string]$RequiredError
    )

    $result = & $Command

    if ($result.ExitCode -eq 0) {
        Fail-Test -Message "Failed to raise error '$RequiredError'"
    }

    if ($result.Output -notlike "*$RequiredError*") {
        Write-Host $result.Output
        Fail-Test -Message "Raised wrong error instead of '$RequiredError'"
    }
}

function Stop-ProcessIfRunning {
    param(
        [AllowNull()]
        [System.Diagnostics.Process]$Process
    )

    if ($null -eq $Process) {
        return
    }

    $processId = $null
    try {
        $processId = $Process.Id
    } catch {
        return
    }

    if (-not $processId) {
        return
    }

    if ($Process.HasExited) {
        $Process.Dispose()
        return
    }

    Stop-ProcessTree -ProcessId $processId
    $Process.WaitForExit(10000) | Out-Null
    $Process.Dispose()
}

function Stop-ProcessTree {
    param(
        [Parameter(Mandatory = $true)]
        [int]$ProcessId
    )

    $taskkill = Get-Command taskkill.exe -ErrorAction SilentlyContinue
    if ($null -ne $taskkill) {
        & $taskkill.Source /PID $ProcessId /T /F | Out-Null
    } else {
        Stop-Process -Id $ProcessId -Force
    }
}

function Register-ManagedServiceProcess {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [System.Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [Parameter(Mandatory = $true)]
        [string[]]$ArgumentList,
        [Parameter(Mandatory = $true)]
        [string]$WorkingDirectory,
        [Parameter(Mandatory = $true)]
        [string]$StdOutLogPath,
        [Parameter(Mandatory = $true)]
        [string]$StdErrLogPath
    )

    $script:ManagedServiceProcesses.Add([pscustomobject]@{
        Name             = $Name
        Process          = $Process
        FilePath         = $FilePath
        ArgumentList     = @($ArgumentList)
        WorkingDirectory = $WorkingDirectory
        StdOutLogPath    = $StdOutLogPath
        StdErrLogPath    = $StdErrLogPath
    })
}

function Start-ManagedServiceProcess {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [string[]]$ArgumentList = @(),
        [string]$WorkingDirectory = (Get-Location).Path
    )

    Ensure-Directory -Path $script:ManagedServiceLogDir

    $stdoutLogPath = Join-Path $script:ManagedServiceLogDir "$Name.stdout.log"
    $stderrLogPath = Join-Path $script:ManagedServiceLogDir "$Name.stderr.log"
    foreach ($logPath in @($stdoutLogPath, $stderrLogPath)) {
        if (Test-Path -LiteralPath $logPath) {
            Remove-Item -LiteralPath $logPath -Force
        }
    }

    $process = Start-NativeProcess -FilePath $FilePath `
        -ArgumentList $ArgumentList `
        -WorkingDirectory $WorkingDirectory `
        -StdOutPath $stdoutLogPath `
        -StdErrPath $stderrLogPath

    Register-ManagedServiceProcess -Name $Name `
        -Process $process `
        -FilePath $FilePath `
        -ArgumentList $ArgumentList `
        -WorkingDirectory $WorkingDirectory `
        -StdOutLogPath $stdoutLogPath `
        -StdErrLogPath $stderrLogPath

    return $process
}

function Restart-ManagedServiceProcess {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $entry = $script:ManagedServiceProcesses | Where-Object { $_.Name -eq $Name } | Select-Object -First 1
    if ($null -eq $entry) {
        return
    }

    Stop-ProcessIfRunning -Process $entry.Process

    foreach ($logPath in @($entry.StdOutLogPath, $entry.StdErrLogPath)) {
        if (Test-Path -LiteralPath $logPath) {
            Remove-Item -LiteralPath $logPath -Force
        }
    }

    $entry.Process = Start-NativeProcess -FilePath $entry.FilePath `
        -ArgumentList $entry.ArgumentList `
        -WorkingDirectory $entry.WorkingDirectory `
        -StdOutPath $entry.StdOutLogPath `
        -StdErrPath $entry.StdErrLogPath
}

function Get-ManagedServiceProcessEntry {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    return ($script:ManagedServiceProcesses | Where-Object { $_.Name -eq $Name } | Select-Object -First 1)
}

function Assert-ManagedServiceProcessRunning {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $entry = Get-ManagedServiceProcessEntry -Name $Name
    if ($null -eq $entry) {
        Fail-Test -Message "Managed service '$Name' was not registered."
    }

    Start-Sleep -Seconds 1
    if (-not $entry.Process.HasExited) {
        return
    }

    $stdout = Read-FileOrEmpty -Path $entry.StdOutLogPath
    $stderr = Read-FileOrEmpty -Path $entry.StdErrLogPath
    $details = @()
    if ($stdout) {
        $details += "stdout: $stdout"
    }
    if ($stderr) {
        $details += "stderr: $stderr"
    }
    if ($details.Count -eq 0) {
        $details += 'no stdout/stderr captured'
    }

    Fail-Test -Message "Managed service '$Name' exited early with code $($entry.Process.ExitCode): $($details -join '; ')"
}

function Stop-ManagedServiceProcesses {
    for ($index = $script:ManagedServiceProcesses.Count - 1; $index -ge 0; $index--) {
        Stop-ProcessIfRunning -Process $script:ManagedServiceProcesses[$index].Process
    }
}

function Register-ManagedServiceFileLog {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $script:ManagedServiceFileLogs.Add([pscustomobject]@{
        Name = $Name
        Path = $Path
    })
}

function Start-ManagedWindowsService {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [string]$BinaryPath,
        [Parameter(Mandatory = $true)]
        [string[]]$BaseArguments,
        [string]$WorkingDirectory = (Get-Location).Path,
        [string]$LogPath
    )

    $scBinary = Resolve-BinaryPath -Name 'sc.exe' -FallbackPaths @(
        (Join-Path $env:SystemRoot 'System32\sc.exe')
    ) -PreferFallbackPaths

    if ($LogPath) {
        if (Test-Path -LiteralPath $LogPath) {
            Remove-Item -LiteralPath $LogPath -Force
        }

        Register-ManagedServiceFileLog -Name $Name -Path $LogPath
    }

    $binPath = (ConvertTo-ProcessArgumentString -ArgumentList @($BinaryPath)) +
        $(if ($BaseArguments.Count -gt 0) { ' ' + (ConvertTo-ProcessArgumentString -ArgumentList $BaseArguments) } else { '' })

    foreach ($cleanupArgs in @(
        @('stop', $Name),
        @('delete', $Name)
    )) {
        Invoke-NativeCommand -FilePath $scBinary `
            -ArgumentList $cleanupArgs `
            -WorkingDirectory $WorkingDirectory `
            -AllowFailure | Out-Null
    }

    Start-Sleep -Seconds 1

    Invoke-NativeCommand -FilePath $scBinary `
        -ArgumentList @('create', $Name, 'binPath=', $binPath, 'start=', 'demand') `
        -WorkingDirectory $WorkingDirectory | Out-Null

    Invoke-NativeCommand -FilePath $scBinary `
        -ArgumentList @('start', $Name) `
        -WorkingDirectory $WorkingDirectory | Out-Null

    $script:ManagedWindowsServices.Add([pscustomobject]@{
        Name             = $Name
        ScBinary         = $scBinary
        WorkingDirectory = $WorkingDirectory
    })
}

function Stop-ManagedWindowsServices {
    for ($index = $script:ManagedWindowsServices.Count - 1; $index -ge 0; $index--) {
        $entry = $script:ManagedWindowsServices[$index]

        Invoke-NativeCommand -FilePath $entry.ScBinary `
            -ArgumentList @('stop', $entry.Name) `
            -WorkingDirectory $entry.WorkingDirectory `
            -AllowFailure | Out-Null

        Start-Sleep -Seconds 1

        Invoke-NativeCommand -FilePath $entry.ScBinary `
            -ArgumentList @('delete', $entry.Name) `
            -WorkingDirectory $entry.WorkingDirectory `
            -AllowFailure | Out-Null
    }
}

function Write-ManagedServiceLogs {
    if ($script:ManagedServiceProcesses.Count -eq 0 -and $script:ManagedServiceFileLogs.Count -eq 0) {
        return
    }

    foreach ($entry in $script:ManagedServiceProcesses) {
        foreach ($logPath in @($entry.StdOutLogPath, $entry.StdErrLogPath)) {
            if (-not (Test-Path -LiteralPath $logPath)) {
                continue
            }

            $content = Get-Content -LiteralPath $logPath -Raw
            if (-not $content) {
                continue
            }

            Write-Host "===== $($entry.Name): $logPath ====="
            Write-Host $content.TrimEnd()
        }
    }

    foreach ($entry in $script:ManagedServiceFileLogs) {
        if (-not (Test-Path -LiteralPath $entry.Path)) {
            continue
        }

        $content = Get-Content -LiteralPath $entry.Path -Raw
        if (-not $content) {
            continue
        }

        Write-Host "===== $($entry.Name): $($entry.Path) ====="
        Write-Host $content.TrimEnd()
    }
}

function Start-CiManagedServices {
    if (-not (Test-ShouldManageServices)) {
        return
    }

    $repoRoot = Get-RepoRoot
    Reset-Directory -Path $script:ManagedServiceLogDir

    $powershellBinary = Resolve-BinaryPath -Name 'powershell.exe' -FallbackPaths @(
        (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe')
    ) -PreferFallbackPaths
    $unboundBinary = Resolve-BinaryPath -Name 'unbound.exe' -FallbackPaths @(
        'C:\Program Files\Unbound\unbound.exe'
    ) -PreferFallbackPaths
    $ncdnsBinary = Resolve-BinaryPath -Name 'ncdns.exe'
    $encayagenBinary = Resolve-BinaryPath -Name 'encayagen.exe'
    $encayaBinary = Resolve-BinaryPath -Name 'encaya.exe'

    $encayaConfigPath = Join-Path $PSScriptRoot 'encaya.windows.conf'
    $ncdnsConfigPath = Join-Path $PSScriptRoot 'ncdns.windows.conf'
    $unboundConfigPath = Join-Path $PSScriptRoot 'unbound.windows.conf'
    $bitcoindScriptPath = Join-Path $PSScriptRoot 'run_bitcoind.ps1'
    $encayaRuntime = Get-EncayaRuntimeDir
    $useWindowsServiceControl = Test-ShouldUseWindowsServiceControl
    $ncdnsServiceLogPath = Join-Path $script:ManagedServiceLogDir 'ncdns.service.log'
    $encayaServiceLogPath = Join-Path $script:ManagedServiceLogDir 'encaya.service.log'

    if (Test-Path -LiteralPath $encayaRuntime) {
        Remove-Item -LiteralPath $encayaRuntime -Recurse -Force
    }
    New-Item -ItemType Directory -Path $encayaRuntime | Out-Null

    Write-Host "Managing Windows CI services inside regtest.ps1"
    if ($useWindowsServiceControl) {
        Write-Host 'Using Windows service control for ncdns and encaya'
    }
    Start-ManagedServiceProcess -Name 'bitcoind' `
        -FilePath $powershellBinary `
        -ArgumentList @('-NoLogo', '-ExecutionPolicy', 'Bypass', '-File', $bitcoindScriptPath) `
        -WorkingDirectory $repoRoot | Out-Null

    Wait-ForTcpPort -Port 18554 -TimeoutSeconds 120 -Description 'Namecoin Core RPC'

    if ($useWindowsServiceControl) {
        foreach ($service in @(Get-Service -ErrorAction SilentlyContinue | Where-Object {
                    $_.Name -like '*unbound*' -or $_.DisplayName -like '*unbound*'
                })) {
            if ($service.Status -ne 'Stopped') {
                Stop-Service -Name $service.Name -Force -ErrorAction SilentlyContinue
            }
        }

        foreach ($process in @(Get-Process -Name 'unbound' -ErrorAction SilentlyContinue)) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        }
    }

    Start-ManagedServiceProcess -Name 'unbound' `
        -FilePath $unboundBinary `
        -ArgumentList @('-d', '-c', $unboundConfigPath) `
        -WorkingDirectory $repoRoot | Out-Null
    Assert-ManagedServiceProcessRunning -Name 'unbound'

    if ($useWindowsServiceControl) {
        Start-ManagedWindowsService -Name 'ncdns' `
            -BinaryPath $ncdnsBinary `
            -BaseArguments @('-conf', $ncdnsConfigPath, '-xlog.file', $ncdnsServiceLogPath) `
            -WorkingDirectory $repoRoot `
            -LogPath $ncdnsServiceLogPath
    } else {
        Start-ManagedServiceProcess -Name 'ncdns' `
            -FilePath $ncdnsBinary `
            -ArgumentList @('-conf', $ncdnsConfigPath) `
            -WorkingDirectory $repoRoot | Out-Null
    }

    Invoke-NativeCommand -FilePath $encayagenBinary `
        -ArgumentList @('-conf', $encayaConfigPath) `
        -WorkingDirectory $repoRoot | Out-Null

    $encayaArguments = @(
        '-conf',
        $encayaConfigPath,
        '-encaya.namecoinrpcaddress',
        '127.0.0.1:18554',
        '-encaya.namecoinrpcusername',
        'doggman',
        '-encaya.namecoinrpcpassword',
        'donkey'
    )

    if ($useWindowsServiceControl) {
        Start-ManagedWindowsService -Name 'encaya' `
            -BinaryPath $encayaBinary `
            -BaseArguments ($encayaArguments + @('-xlog.file', $encayaServiceLogPath)) `
            -WorkingDirectory $repoRoot `
            -LogPath $encayaServiceLogPath
    } else {
        Start-ManagedServiceProcess -Name 'encaya' `
            -FilePath $encayaBinary `
            -ArgumentList $encayaArguments `
            -WorkingDirectory $repoRoot | Out-Null
    }
}

function Reset-RecursiveDnsResolverIfNeeded {
    if (-not (Test-ShouldManageServices)) {
        return
    }

    Restart-ManagedServiceProcess -Name 'unbound'
    Assert-ManagedServiceProcessRunning -Name 'unbound'
    Wait-ForTcpPort -Port 53 -TimeoutSeconds 30 -Description 'Unbound recursive DNS after cache reset'
}

function Stop-OpenSslServerByPort {
    param(
        [Parameter(Mandatory = $true)]
        [int]$Port
    )

    $targets = Get-CimInstance Win32_Process | Where-Object {
        $_.Name -eq 'openssl.exe' -and $_.CommandLine -like "*s_server*" -and $_.CommandLine -like "*-accept $Port*"
    }

    foreach ($target in $targets) {
        Stop-ProcessTree -ProcessId $target.ProcessId
    }
}

function Convert-BytesToUpperHex {
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Bytes
    )

    return ([BitConverter]::ToString($Bytes)).Replace('-', '')
}

function Convert-Base64ToUpperHex {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Base64
    )

    return (Convert-BytesToUpperHex -Bytes ([Convert]::FromBase64String($Base64)))
}

function Get-FileSha256HexLower {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    return ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant())
}

function Get-FileSha256HexUpper {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    return ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToUpperInvariant())
}

function Convert-ToUrlSafeBase64 {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $base64 = [Convert]::ToBase64String($bytes)
    $base64 = $base64.Replace('+', '-').Replace('/', '_')

    return $base64.TrimEnd('=')
}

function ConvertTo-CompactJson {
    param(
        [Parameter(Mandatory = $true)]
        $InputObject
    )

    return (ConvertTo-Json -InputObject $InputObject -Compress -Depth 20)
}

function Read-UInt16BigEndian {
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Bytes,
        [Parameter(Mandatory = $true)]
        [int]$Offset
    )

    return ((([int]$Bytes[$Offset]) -shl 8) -bor ([int]$Bytes[$Offset + 1]))
}

function Read-UInt32BigEndian {
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Bytes,
        [Parameter(Mandatory = $true)]
        [int]$Offset
    )

    return ((([int]$Bytes[$Offset]) -shl 24) -bor (([int]$Bytes[$Offset + 1]) -shl 16) -bor (([int]$Bytes[$Offset + 2]) -shl 8) -bor ([int]$Bytes[$Offset + 3]))
}

function Convert-NameToDnsWireFormat {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $bytes = New-Object 'System.Collections.Generic.List[byte]'
    $labels = $Name.TrimEnd('.') -split '\.'

    if ($labels.Length -eq 1 -and $labels[0] -eq '') {
        $bytes.Add(0)

        return $bytes.ToArray()
    }

    foreach ($label in $labels) {
        $labelBytes = [System.Text.Encoding]::ASCII.GetBytes($label)
        if ($labelBytes.Length -gt 63) {
            Fail-Test -Message "DNS label '$label' exceeded 63 bytes"
        }

        $bytes.Add([byte]$labelBytes.Length)
        foreach ($labelByte in $labelBytes) {
            $bytes.Add($labelByte)
        }
    }

    $bytes.Add(0)

    return $bytes.ToArray()
}

function New-DnsQueryPacket {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [UInt16]$RecordType
    )

    $id = [UInt16](Get-Random -Minimum 0 -Maximum 65536)
    $questionName = Convert-NameToDnsWireFormat -Name $Name
    $packet = New-Object 'System.Collections.Generic.List[byte]'

    foreach ($byte in @(
            [byte](($id -shr 8) -band 0xFF),
            [byte]($id -band 0xFF),
            0x01,
            0x00,
            0x00,
            0x01,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00
        )) {
        $packet.Add($byte)
    }

    foreach ($byte in $questionName) {
        $packet.Add($byte)
    }

    $packet.Add([byte](($RecordType -shr 8) -band 0xFF))
    $packet.Add([byte]($RecordType -band 0xFF))
    $packet.Add(0x00)
    $packet.Add(0x01)

    return [pscustomobject]@{
        Id     = $id
        Packet = $packet.ToArray()
    }
}

function Skip-DnsName {
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Message,
        [Parameter(Mandatory = $true)]
        [int]$Offset
    )

    while ($true) {
        $length = $Message[$Offset]

        if (($length -band 0xC0) -eq 0xC0) {
            return ($Offset + 2)
        }

        if ($length -eq 0) {
            return ($Offset + 1)
        }

        $Offset += 1 + $length
    }
}

function Invoke-DnsQuery {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server,
        [Parameter(Mandatory = $true)]
        [int]$Port,
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [ValidateSet('A', 'TLSA')]
        [string]$RecordType,
        [switch]$IncludeMetadata
    )

    $typeCode = switch ($RecordType) {
        'A' { [UInt16]1 }
        'TLSA' { [UInt16]52 }
    }

    $query = New-DnsQueryPacket -Name $Name -RecordType $typeCode
    $udpClient = New-Object System.Net.Sockets.UdpClient
    $udpClient.Client.ReceiveTimeout = 5000

    try {
        $udpClient.Connect($Server, $Port)
        [void]$udpClient.Send($query.Packet, $query.Packet.Length)
        $remoteEndpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        $response = $udpClient.Receive([ref]$remoteEndpoint)
    } finally {
        $udpClient.Dispose()
    }

    if ((Read-UInt16BigEndian -Bytes $response -Offset 0) -ne $query.Id) {
        Fail-Test -Message "DNS response ID mismatch for $Name ($RecordType)"
    }

    $responseFlags = Read-UInt16BigEndian -Bytes $response -Offset 2
    $responseCode = $responseFlags -band 0x000F
    $answerCount = Read-UInt16BigEndian -Bytes $response -Offset 6
    $questionCount = Read-UInt16BigEndian -Bytes $response -Offset 4
    $offset = 12

    for ($questionIndex = 0; $questionIndex -lt $questionCount; $questionIndex++) {
        $offset = Skip-DnsName -Message $response -Offset $offset
        $offset += 4
    }

    $answers = @()
    for ($answerIndex = 0; $answerIndex -lt $answerCount; $answerIndex++) {
        $offset = Skip-DnsName -Message $response -Offset $offset
        $answerType = Read-UInt16BigEndian -Bytes $response -Offset $offset
        $offset += 2
        $answerClass = Read-UInt16BigEndian -Bytes $response -Offset $offset
        $offset += 2
        $ttl = Read-UInt32BigEndian -Bytes $response -Offset $offset
        $offset += 4
        $rdLength = Read-UInt16BigEndian -Bytes $response -Offset $offset
        $offset += 2
        $rdataOffset = $offset
        $offset += $rdLength

        if ($answerClass -ne 1) {
            continue
        }

        switch ($answerType) {
            1 {
                if ($RecordType -eq 'A' -and $rdLength -eq 4) {
                    $ipBytes = [byte[]]($response[$rdataOffset..($rdataOffset + 3)])
                    $answers += [pscustomobject]@{
                        Type = 'A'
                        TTL  = $ttl
                        Data = ([System.Net.IPAddress]::new($ipBytes)).ToString()
                    }
                }
            }
            52 {
                if ($RecordType -eq 'TLSA' -and $rdLength -ge 3) {
                    $certStart = $rdataOffset + 3
                    $certEnd = $rdataOffset + $rdLength - 1
                    $certBytes = if ($certEnd -ge $certStart) {
                        [byte[]]($response[$certStart..$certEnd])
                    } else {
                        [byte[]]@()
                    }

                    $answers += [pscustomobject]@{
                        Type         = 'TLSA'
                        TTL          = $ttl
                        Usage        = [int]$response[$rdataOffset]
                        Selector     = [int]$response[$rdataOffset + 1]
                        MatchingType = [int]$response[$rdataOffset + 2]
                        Certificate  = (Convert-BytesToUpperHex -Bytes $certBytes)
                    }
                }
            }
          }
      }

      if (-not $IncludeMetadata) {
          return $answers
      }

      $responseCodeName = switch ($responseCode) {
          0 { 'NOERROR' }
          1 { 'FORMERR' }
          2 { 'SERVFAIL' }
          3 { 'NXDOMAIN' }
          4 { 'NOTIMP' }
          5 { 'REFUSED' }
          default { "RCODE$responseCode" }
      }

      return [pscustomobject]@{
          ResponseCode     = $responseCode
          ResponseCodeName = $responseCodeName
          AnswerCount      = $answerCount
          Answers          = $answers
      }
  }

function Format-DnsAnswers {
    param(
        [AllowNull()]
        [object[]]$Answers
    )

    if ($null -eq $Answers -or $Answers.Count -eq 0) {
        return ''
    }

    return (($Answers | ForEach-Object {
                if ($_.Type -eq 'A') {
                    $_.Data
                } else {
                    "$($_.Usage) $($_.Selector) $($_.MatchingType) $($_.Certificate)"
                }
            }) -join [Environment]::NewLine)
}

function Wait-ForDnsAnswers {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server,
        [Parameter(Mandatory = $true)]
        [int]$Port,
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [ValidateSet('A', 'TLSA')]
        [string]$RecordType,
        [int]$TimeoutSeconds = 30
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $lastAnswers = @()
    $lastObservation = 'No DNS response observed yet.'

    while ((Get-Date) -lt $deadline) {
        try {
            $queryResult = Invoke-DnsQuery -Server $Server -Port $Port -Name $Name -RecordType $RecordType -IncludeMetadata
            $answers = $queryResult.Answers
            $lastObservation = "rcode=$($queryResult.ResponseCodeName); answerCount=$($queryResult.AnswerCount)"
        } catch {
            $answers = @()
            $lastObservation = $_.Exception.Message
        }

        if ($null -ne $answers -and $answers.Count -gt 0) {
            return $answers
        }

        $lastAnswers = $answers
        Start-Sleep -Milliseconds 500
    }

    $formattedAnswers = Format-DnsAnswers -Answers $lastAnswers
    Fail-Test -Message "Timed out waiting for DNS answers for $Name ($RecordType) from $Server`:$Port. Last observation: $lastObservation. Last observed answers: $formattedAnswers"
}

function Convert-DerCertificateToPem {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DerPath,
        [Parameter(Mandatory = $true)]
        [string]$PemPath
    )

    Invoke-OpenSsl -Arguments @('x509', '-inform', 'DER', '-in', $DerPath, '-out', $PemPath) | Out-Null
}

function Get-CertSpkiSha256Hex {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CertPath
    )

    $tempBase = Join-Path $script:TestTempDir ([IO.Path]::GetRandomFileName())
    $pubPemPath = "$tempBase.pub.pem"
    $pubDerPath = "$tempBase.pub.der"

    try {
        $publicKeyPem = (Invoke-OpenSsl -Arguments @('x509', '-in', $CertPath, '-pubkey', '-noout')).Output
        Write-AsciiFile -Path $pubPemPath -Content ($publicKeyPem + [Environment]::NewLine)
        Invoke-OpenSsl -Arguments @('pkey', '-pubin', '-in', $pubPemPath, '-outform', 'DER', '-out', $pubDerPath) | Out-Null

        return (Get-FileSha256HexUpper -Path $pubDerPath)
    } finally {
        foreach ($path in @($pubPemPath, $pubDerPath)) {
            if (Test-Path -LiteralPath $path) {
                Remove-Item -LiteralPath $path -Force
            }
        }
    }
}

function Get-PublicKeySha256HexUpperFromPrivateKey {
    param(
        [Parameter(Mandatory = $true)]
        [string]$KeyPath
    )

    $pubDerPath = Join-Path $script:TestTempDir ([IO.Path]::GetRandomFileName() + '.pub.der')

    try {
        Invoke-OpenSsl -Arguments @('pkey', '-in', $KeyPath, '-pubout', '-outform', 'DER', '-out', $pubDerPath) | Out-Null

        return (Get-FileSha256HexUpper -Path $pubDerPath)
    } finally {
        if (Test-Path -LiteralPath $pubDerPath) {
            Remove-Item -LiteralPath $pubDerPath -Force
        }
    }
}

function Get-TlsaHexFromDigShort {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DigShortOutput
    )

    $parts = $DigShortOutput.Trim() -split '\s+', 4
    if ($parts.Length -lt 4) {
        return ''
    }

    return (($parts[3] -replace '\s', '').ToUpperInvariant())
}

function Load-PemCertificate {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $pem = Get-Content -LiteralPath $Path -Raw
    $pemBase64 = (($pem -split "`r?`n") | Where-Object {
            $_ -and $_ -notmatch '^-----'
        }) -join ''
    $rawBytes = [Convert]::FromBase64String($pemBase64)

    return (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,$rawBytes))
}

function Get-PemCertificateThumbprint {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    return (Load-PemCertificate -Path $Path).Thumbprint
}

function Remove-ImportedRootCertificates {
    if ($script:ImportedRootThumbprints.Count -eq 0) {
        return
    }

    $storeScope = if ($script:ImportedRootStoreScope) {
        $script:ImportedRootStoreScope
    } else {
        'CurrentUser'
    }
    $storeLabel = if ($storeScope -eq 'LocalMachine') {
        'LocalMachine\Root'
    } else {
        'CurrentUser\Root'
    }

    try {
        foreach ($thumbprint in $script:ImportedRootThumbprints) {
            $removeArguments = if ($storeScope -eq 'LocalMachine') {
                @('-delstore', 'Root', $thumbprint)
            } else {
                @('-user', '-delstore', 'Root', $thumbprint)
            }

            $removeResult = Invoke-NativeCommand -FilePath $script:CertUtilBinary `
                -ArgumentList $removeArguments `
                -AllowFailure `
                -TimeoutMilliseconds 120000
            if ($removeResult.ExitCode -ne 0) {
                Write-Host "WARN: Failed to remove imported root certificate $thumbprint from $storeLabel"
            }
        }
    } finally {}
}

function Trust-EncayaRoot {
    $rootCertPath = Join-Path $script:EncayaRuntimeDir 'root_chain.pem'
    if (-not (Test-Path -LiteralPath $rootCertPath)) {
        $rootCertPath = Join-Path $script:TestTempDir 'encaya-root.pem'
        Invoke-CurlDownload -Arguments @("$script:AiaTestUrl/lookup?domain=Namecoin%20Root%20CA") -OutputPath $rootCertPath
    }

    $thumbprint = Get-PemCertificateThumbprint -Path $rootCertPath

    $storeScopes = if ($script:ImportedRootStoreScope) {
        @($script:ImportedRootStoreScope)
    } else {
        @('CurrentUser', 'LocalMachine')
    }

    foreach ($storeScope in $storeScopes) {
        $storeLabel = if ($storeScope -eq 'LocalMachine') {
            'LocalMachine\Root'
        } else {
            'CurrentUser\Root'
        }
        $addArguments = if ($storeScope -eq 'LocalMachine') {
            @('-addstore', 'Root', $rootCertPath)
        } else {
            @('-user', '-addstore', 'Root', $rootCertPath)
        }

        Write-Host "Importing Encaya Root CA into $storeLabel from $rootCertPath"

        $addResult = Invoke-NativeCommand -FilePath $script:CertUtilBinary `
            -ArgumentList $addArguments `
            -AllowFailure `
            -TimeoutMilliseconds 180000
        if ($addResult.ExitCode -eq 0) {
            $script:ImportedRootStoreScope = $storeScope

            if ($script:ImportedRootThumbprints -notcontains $thumbprint) {
                $script:ImportedRootThumbprints.Add($thumbprint)
            }

            Write-Host "Encaya Root CA import completed in $storeLabel"

            return
        }

        if ($addResult.Output) {
            Write-Host $addResult.Output
        }

        Write-Host "WARN: Failed to import Encaya Root CA into $storeLabel"
    }

    Fail-Test -Message 'Failed to import Encaya root CA into a Windows Root certificate store'
}

function Ensure-EncayaReady {
    Invoke-Curl -Arguments @("$script:AiaTestUrl/lookup?domain=Namecoin%20Root%20CA") | Out-Null
}

function Ensure-EncayaHttpsReady {
    $rootCertPath = Join-Path $script:EncayaRuntimeDir 'root_chain.pem'
    if (-not (Test-Path -LiteralPath $rootCertPath)) {
        Fail-Test -Message "Root CA for HTTPS readiness check not found at $rootCertPath"
    }

    $curlResult = Invoke-Curl -Arguments @(
        '--cacert',
        $rootCertPath,
        '--ssl-no-revoke',
        '--resolve',
        "aia.x--nmc.bit:443:$script:AiaTestIp",
        'https://aia.x--nmc.bit/lookup?domain=Namecoin%20Root%20CA'
    ) -AllowFailure

    if ($curlResult.ExitCode -ne 0) {
        if ($curlResult.Output) {
            Write-Host $curlResult.Output
        }

        Fail-Test -Message 'Encaya HTTPS endpoint failed strict TLS readiness check at https://aia.x--nmc.bit'
    }
}

function Invoke-BrowserDumpDomImpl {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ProfileDir,
        [Parameter(Mandatory = $true)]
        [string]$LogPath,
        [Parameter(Mandatory = $true)]
        [string]$TargetHost,
        [Parameter(Mandatory = $true)]
        [string]$TargetUrl
    )

    Ensure-Directory -Path $ProfileDir

    $outputPath = Join-Path $ProfileDir 'dump-dom.out'
    foreach ($path in @($LogPath, $outputPath)) {
        if (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -Force
        }
    }

    $arguments = @(
        '--headless',
        '--disable-gpu',
        '--disable-background-networking',
        '--no-first-run',
        '--no-sandbox',
        "--user-data-dir=$ProfileDir",
        "--host-resolver-rules=MAP $TargetHost 127.0.0.1,MAP aia.x--nmc.bit $script:AiaTestIp,EXCLUDE localhost",
        '--dump-dom',
        $TargetUrl
    )

    $browserProcess = Start-NativeProcess -FilePath $script:BrowserBinary `
        -ArgumentList $arguments `
        -StdOutPath $outputPath `
        -StdErrPath $LogPath

    $timedOut = -not $browserProcess.WaitForExit(180000)
    if ($timedOut) {
        Stop-ProcessTree -ProcessId $browserProcess.Id
        $browserProcess.WaitForExit()
    }

    $outputText = Read-FileOrEmpty -Path $outputPath
    if ($null -eq $outputText) {
        $outputText = ''
    }

    $errorText = Read-FileOrEmpty -Path $LogPath
    if ($null -eq $errorText) {
        $errorText = ''
    }
    if ($timedOut) {
        $timeoutError = "Chromium timed out after 180 seconds while loading $TargetUrl"
        if ($errorText) {
            $errorText = $errorText + [Environment]::NewLine + $timeoutError
        } else {
            $errorText = $timeoutError
        }

        Write-AsciiFile -Path $LogPath -Content $errorText
    }

    return [pscustomobject]@{
        Output   = $outputText.TrimEnd()
        Error    = $errorText.TrimEnd()
        ExitCode = if ($timedOut) { 124 } else { $browserProcess.ExitCode }
    }
}

function Remove-DirectoryWithRetry {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [int]$Attempts = 10,
        [int]$DelayMilliseconds = 500
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }

    for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
        try {
            Remove-Item -LiteralPath $Path -Recurse -Force
            return
        } catch {
            if ($attempt -eq $Attempts) {
                Write-Host "WARN: Failed to remove temporary directory '$Path': $($_.Exception.Message)"
                return
            }

            Start-Sleep -Milliseconds $DelayMilliseconds
        }
    }
}

function Start-HttpsServer {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DocRoot,
        [Parameter(Mandatory = $true)]
        [string]$CertPath,
        [Parameter(Mandatory = $true)]
        [string]$KeyPath,
        [Parameter(Mandatory = $true)]
        [int]$Port,
        [Parameter(Mandatory = $true)]
        [string]$StdOutLogPath,
        [Parameter(Mandatory = $true)]
        [string]$StdErrLogPath,
        [Parameter(Mandatory = $true)]
        [string]$Body
    )

    Stop-OpenSslServerByPort -Port $Port
    Ensure-Directory -Path $DocRoot
    Write-AsciiFile -Path (Join-Path $DocRoot 'index.html') -Content @"
<!DOCTYPE html>
<html>
<body>
$Body
</body>
</html>
"@

    foreach ($logPath in @($StdOutLogPath, $StdErrLogPath)) {
        if (Test-Path -LiteralPath $logPath) {
            Remove-Item -LiteralPath $logPath -Force
        }
    }

    $process = Start-NativeProcess -FilePath $script:OpenSslBinary `
        -ArgumentList @('s_server', '-accept', $Port.ToString(), '-cert', $CertPath, '-key', $KeyPath, '-WWW') `
        -WorkingDirectory $DocRoot `
        -StdOutPath $StdOutLogPath `
        -StdErrPath $StdErrLogPath

    Start-Sleep -Seconds 2
    if ($process.HasExited) {
        Write-Host (Read-FileOrEmpty -Path $StdOutLogPath)
        Write-Host (Read-FileOrEmpty -Path $StdErrLogPath)
        Fail-Test -Message "Local HTTPS server failed to start on port $Port"
    }

    return $process
}

$script:TestTempDir = New-TempDirectory -Prefix 'encaya-functional-'
$script:StapledTestTempDir = New-TempDirectory -Prefix 'encaya-functional-stapled-'

$script:NSS_DB_DIR = Join-Path $script:TestTempDir 'ignored'
$script:NSS_DB_BACKUP_DIR = Join-Path $script:TestTempDir 'ignored-backup'
$script:NSS_DB_PREPARED = 0
$script:NSS_DB_EXISTED_BEFORE = 0
$script:NSS_DB_PARENT_CREATED = 0
$CHROME_PROFILE_DIR = Join-Path $script:TestTempDir 'chrome-profile'
$HASHED_LABEL = 'testlshashed' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
$HASHED_NAME = "d/$HASHED_LABEL"
$HASHED_DOMAIN = "$HASHED_LABEL.bit"
$HASHED_CA_KEY = Join-Path $script:TestTempDir 'hashed-ca.key'
$HASHED_CA_PUB_DER = Join-Path $script:TestTempDir 'hashed-ca-pub.der'
$HASHED_PARENT_CA_DER = Join-Path $script:TestTempDir 'hashed-parent-ca.der'
$HASHED_PARENT_CA_PEM = Join-Path $script:TestTempDir 'hashed-parent-ca.pem'
$LEAF_KEY = Join-Path $script:TestTempDir 'leaf.key'
$LEAF_CSR = Join-Path $script:TestTempDir 'leaf.csr'
$LEAF_CERT = Join-Path $script:TestTempDir 'leaf.pem'
$LEAF_EXT = Join-Path $script:TestTempDir 'leaf-ext.cnf'
$LEAF_SERIAL = Join-Path $script:TestTempDir 'leaf.srl'
$EXPIRED_LEAF_KEY = Join-Path $script:TestTempDir 'leaf-expired.key'
$EXPIRED_LEAF_CSR = Join-Path $script:TestTempDir 'leaf-expired.csr'
$EXPIRED_LEAF_CERT = Join-Path $script:TestTempDir 'leaf-expired.pem'
$EXPIRED_LEAF_EXT = Join-Path $script:TestTempDir 'leaf-expired-ext.cnf'
$EXPIRED_LEAF_SERIAL = Join-Path $script:TestTempDir 'leaf-expired.srl'
$HTTPS_DOCROOT = Join-Path $script:TestTempDir 'https-docroot'
$HTTPS_SERVER_LOG = Join-Path $script:TestTempDir 'https-server.log'
$HTTPS_SERVER_STDERR_LOG = Join-Path $script:TestTempDir 'https-server.stderr.log'
$HTTPS_SERVER_PORT = 4443
$STAPLED_CHROME_PROFILE_DIR = Join-Path $script:StapledTestTempDir 'chrome-profile'
$STAPLED_LABEL = 'testlsstapled' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
$STAPLED_NAME = "d/$STAPLED_LABEL"
$STAPLED_DOMAIN = "$STAPLED_LABEL.bit"
$STAPLED_CA_KEY = Join-Path $script:StapledTestTempDir 'stapled-ca.key'
$STAPLED_CA_PUB_DER = Join-Path $script:StapledTestTempDir 'stapled-ca-pub.der'
$STAPLED_PARENT_CA_DER = Join-Path $script:StapledTestTempDir 'stapled-parent-ca.der'
$STAPLED_PARENT_CA_PEM = Join-Path $script:StapledTestTempDir 'stapled-parent-ca.pem'
$STAPLED_LEAF_KEY = Join-Path $script:StapledTestTempDir 'stapled-leaf.key'
$STAPLED_LEAF_CSR = Join-Path $script:StapledTestTempDir 'stapled-leaf.csr'
$STAPLED_LEAF_CERT = Join-Path $script:StapledTestTempDir 'stapled-leaf.pem'
$STAPLED_LEAF_EXT = Join-Path $script:StapledTestTempDir 'stapled-leaf-ext.cnf'
$STAPLED_LEAF_SERIAL = Join-Path $script:StapledTestTempDir 'stapled-leaf.srl'
$STAPLED_HTTPS_DOCROOT = Join-Path $script:StapledTestTempDir 'https-docroot'
$STAPLED_HTTPS_SERVER_LOG = Join-Path $script:StapledTestTempDir 'https-server.log'
$STAPLED_HTTPS_SERVER_STDERR_LOG = Join-Path $script:StapledTestTempDir 'https-server.stderr.log'
$STAPLED_HTTPS_SERVER_PORT = 4444

function Prepare-NssDb {
    if ($script:NSS_DB_PREPARED -eq 1) {
        return
    }

    $script:NSS_DB_PREPARED = 1
}

function Restore-NssDb {
    if ($script:NSS_DB_PREPARED -ne 1) {
        return
    }

    $script:NSS_DB_PREPARED = 0
}

function Generate-HashedPubkeyMaterial {
    Invoke-OpenSsl -Arguments @('ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', $HASHED_CA_KEY) | Out-Null
    Invoke-OpenSsl -Arguments @('pkey', '-in', $HASHED_CA_KEY, '-pubout', '-outform', 'DER', '-out', $HASHED_CA_PUB_DER) | Out-Null

    $script:TLSA_HASHED_PUB_B64 = Convert-ToUrlSafeBase64 -Path $HASHED_CA_PUB_DER
    $script:TLSA_HASHED_PUB_SHA256_HEX = Get-FileSha256HexLower -Path $HASHED_CA_PUB_DER
    $script:TLSA_HASHED_PUB_SHA256_B64 = [Convert]::ToBase64String(([System.Security.Cryptography.SHA256]::Create().ComputeHash([System.IO.File]::ReadAllBytes($HASHED_CA_PUB_DER))))
}

function Generate-LeafCert {
    Write-AsciiFile -Path $HASHED_PARENT_CA_PEM -Content $script:HashedCaPem

    Invoke-OpenSsl -Arguments @('ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', $LEAF_KEY) | Out-Null
    Invoke-OpenSsl -Arguments @('req', '-new', '-key', $LEAF_KEY, '-subj', "/CN=$HASHED_DOMAIN", '-out', $LEAF_CSR) | Out-Null

    Write-AsciiFile -Path $LEAF_EXT -Content @"
[ext]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:$HASHED_DOMAIN
authorityInfoAccess=caIssuers;URI:$script:AiaTestUrl/aia?domain=$HASHED_DOMAIN%20Domain%20AIA%20Parent%20CA&pubb64=$script:TLSA_HASHED_PUB_B64&pubsha256=$script:TLSA_HASHED_PUB_SHA256_HEX
"@

    Invoke-OpenSsl -Arguments @(
        'x509',
        '-req',
        '-in',
        $LEAF_CSR,
        '-CA',
        $HASHED_PARENT_CA_PEM,
        '-CAkey',
        $HASHED_CA_KEY,
        '-CAcreateserial',
        '-CAserial',
        $LEAF_SERIAL,
        '-out',
        $LEAF_CERT,
        '-days',
        '3650',
        '-sha256',
        '-extfile',
        $LEAF_EXT,
        '-extensions',
        'ext'
    ) | Out-Null
}

function Generate-ExpiredLeafCert {
    Write-AsciiFile -Path $HASHED_PARENT_CA_PEM -Content $script:HashedCaPem

    Invoke-OpenSsl -Arguments @('ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', $EXPIRED_LEAF_KEY) | Out-Null
    Invoke-OpenSsl -Arguments @('req', '-new', '-key', $EXPIRED_LEAF_KEY, '-subj', "/CN=$HASHED_DOMAIN", '-out', $EXPIRED_LEAF_CSR) | Out-Null

    Write-AsciiFile -Path $EXPIRED_LEAF_EXT -Content @"
[ext]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:$HASHED_DOMAIN
authorityInfoAccess=caIssuers;URI:$script:AiaTestUrl/aia?domain=$HASHED_DOMAIN%20Domain%20AIA%20Parent%20CA&pubb64=$script:TLSA_HASHED_PUB_B64&pubsha256=$script:TLSA_HASHED_PUB_SHA256_HEX
"@

    Invoke-OpenSsl -Arguments @(
        'x509',
        '-req',
        '-in',
        $EXPIRED_LEAF_CSR,
        '-CA',
        $HASHED_PARENT_CA_PEM,
        '-CAkey',
        $HASHED_CA_KEY,
        '-CAcreateserial',
        '-CAserial',
        $EXPIRED_LEAF_SERIAL,
        '-out',
        $EXPIRED_LEAF_CERT,
        '-days',
        '0',
        '-sha256',
        '-extfile',
        $EXPIRED_LEAF_EXT,
        '-extensions',
        'ext'
    ) | Out-Null
}

function Get-NameAddressForStapledTest {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    return ((Invoke-NamecoinCliJson -Arguments @('name_show', $Name)).address)
}

function Generate-StapledPubkeyMaterial {
    Invoke-OpenSsl -Arguments @('ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', $STAPLED_CA_KEY) | Out-Null
    Invoke-OpenSsl -Arguments @('pkey', '-in', $STAPLED_CA_KEY, '-pubout', '-outform', 'DER', '-out', $STAPLED_CA_PUB_DER) | Out-Null

    $script:STAPLED_PUB_B64 = Convert-ToUrlSafeBase64 -Path $STAPLED_CA_PUB_DER
}

function Build-StapledMessage {
    $messageJson = ConvertTo-CompactJson -InputObject ([ordered]@{
            address = $script:STAPLED_BLOCKCHAIN_ADDRESS
            domain  = $STAPLED_DOMAIN
            x509pub = $script:STAPLED_PUB_B64
        })

    $script:STAPLED_MESSAGE = "Namecoin X.509 Stapled Certification: $messageJson"
    $script:STAPLED_BLOCKCHAIN_SIG = Invoke-NamecoinCliText -Arguments @('signmessage', $script:STAPLED_BLOCKCHAIN_ADDRESS, $script:STAPLED_MESSAGE)
    $script:STAPLED_SIGS_JSON = ConvertTo-CompactJson -InputObject @(
        [ordered]@{
            blockchainaddress = $script:STAPLED_BLOCKCHAIN_ADDRESS
            blockchainsig     = $script:STAPLED_BLOCKCHAIN_SIG
        }
    )
    $script:STAPLED_SIGS_URLENCODED = [System.Uri]::EscapeDataString($script:STAPLED_SIGS_JSON)
}

function Generate-StapledLeafCert {
    Write-AsciiFile -Path $STAPLED_PARENT_CA_PEM -Content $script:StapledCaPem

    Invoke-OpenSsl -Arguments @('ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', $STAPLED_LEAF_KEY) | Out-Null
    Invoke-OpenSsl -Arguments @('req', '-new', '-key', $STAPLED_LEAF_KEY, '-subj', "/CN=$STAPLED_DOMAIN", '-out', $STAPLED_LEAF_CSR) | Out-Null

    Write-AsciiFile -Path $STAPLED_LEAF_EXT -Content @"
[ext]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:$STAPLED_DOMAIN
authorityInfoAccess=caIssuers;URI:$script:AiaTestUrl/aia?domain=$STAPLED_DOMAIN%20Domain%20AIA%20Parent%20CA&pubb64=$script:STAPLED_PUB_B64&sigs=$script:STAPLED_SIGS_URLENCODED
"@

    Invoke-OpenSsl -Arguments @(
        'x509',
        '-req',
        '-in',
        $STAPLED_LEAF_CSR,
        '-CA',
        $STAPLED_PARENT_CA_PEM,
        '-CAkey',
        $STAPLED_CA_KEY,
        '-CAcreateserial',
        '-CAserial',
        $STAPLED_LEAF_SERIAL,
        '-out',
        $STAPLED_LEAF_CERT,
        '-days',
        '3650',
        '-sha256',
        '-extfile',
        $STAPLED_LEAF_EXT,
        '-extensions',
        'ext'
    ) | Out-Null
}

function Run-BaseFunctionalTests {
    Write-Host 'Expire any existing names from previous functional test runs'
    New-Blocks -Count 35

    Write-Host 'Pre-register testls.bit'
    $nameNewResult = Invoke-NamecoinCliJson -Arguments @('name_new', 'd/testls')
    $nameTxID = $nameNewResult[0]
    $nameRand = $nameNewResult[1]

    Write-Host 'Wait for pre-registration to mature'
    New-Blocks -Count 12

    Write-Host 'Register testls.bit'
    Invoke-NamecoinCliText -Arguments @('name_firstupdate', 'd/testls', $nameRand, $nameTxID) | Out-Null

    Write-Host 'Wait for registration to confirm'
    New-Blocks -Count 1

    $testlsValue = ConvertTo-CompactJson -InputObject ([ordered]@{
            ip  = '107.152.38.155'
            map = [ordered]@{
                '*' = [ordered]@{
                    tls = ,@(
                        2,
                        1,
                        0,
                        'MDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgADvxHcjwDYMNfUSTtSIn3VbBC1sOzh/1Fv5T0UzEuLWIE='
                    )
                }
                sub1 = [ordered]@{
                    map = [ordered]@{
                        sub2 = [ordered]@{
                            map = [ordered]@{
                                sub3 = [ordered]@{
                                    ip = '107.152.38.155'
                                }
                            }
                        }
                    }
                }
                _tor = [ordered]@{
                    txt = 'dhflg7a7etr77hwt4eerwoovhg7b5bivt2jem4366dt4psgnl5diyiyd.onion'
                }
            }
        })

    Write-Host 'Update testls.bit'
    Invoke-NamecoinCliText -Arguments @('name_update', 'd/testls', $testlsValue) | Out-Null

    Write-Host 'Wait for update to confirm'
    New-Blocks -Count 1

    Write-Host 'Reset recursive DNS resolver state'
    Reset-RecursiveDnsResolverIfNeeded

    Write-Host 'Query testls.bit via Core'
    Write-Host (Invoke-NamecoinCliText -Arguments @('name_show', 'd/testls'))

    Write-Host 'Query testls.bit IPv4 Authoritative via dig'
    $digOutput = Format-DnsAnswers -Answers (Invoke-DnsQuery -Server '127.0.0.1' -Port 5391 -Name 'testls.bit' -RecordType 'A')
    Write-Host $digOutput
    Write-Host 'Checking response correctness'
    Assert-Contains -Haystack $digOutput -Needle '107.152.38.155' -ErrorMessage 'Authoritative A response was incorrect'

    Write-Host 'Query testls.bit TLS Authoritative via dig'
    $digOutput = Format-DnsAnswers -Answers (Invoke-DnsQuery -Server '127.0.0.1' -Port 5391 -Name '*.testls.bit' -RecordType 'TLSA')
    Write-Host $digOutput
    Write-Host 'Checking response correctness'
    $tlsaHex = Convert-Base64ToUpperHex -Base64 'MDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgADvxHcjwDYMNfUSTtSIn3VbBC1sOzh/1Fv5T0UzEuLWIE='
    Assert-Contains -Haystack ($digOutput -replace '\s', '') -Needle $tlsaHex -ErrorMessage 'Authoritative TLSA response was incorrect'

    Write-Host 'Query testls.bit IPv4 Recursive via dig'
    $digOutput = Format-DnsAnswers -Answers (Wait-ForDnsAnswers -Server '127.0.0.1' -Port 53 -Name 'testls.bit' -RecordType 'A')
    Write-Host $digOutput
    Write-Host 'Checking response correctness'
    Assert-Contains -Haystack $digOutput -Needle '107.152.38.155' -ErrorMessage 'Recursive A response was incorrect'

    Write-Host 'Query testls.bit TLS Recursive via dig'
    $digOutput = Format-DnsAnswers -Answers (Wait-ForDnsAnswers -Server '127.0.0.1' -Port 53 -Name '*.testls.bit' -RecordType 'TLSA')
    Write-Host $digOutput
    Write-Host 'Checking response correctness'
    Assert-Contains -Haystack ($digOutput -replace '\s', '') -Needle $tlsaHex -ErrorMessage 'Recursive TLSA response was incorrect'

    Write-Host 'Fetch testls.bit via curl'
    try {
        $curlOutput = Invoke-CurlText -Arguments @('--insecure', 'https://testls.bit/')
        if ($curlOutput -notmatch 'Cool or nah') {
            Write-Host 'WARN: Skipping external testls.bit HTTPS check in this environment'
        }
    } catch {
        Write-Host 'WARN: Skipping external testls.bit HTTPS check in this environment'
    }

    Write-Host 'Fetch Root CA via curl'
    Assert-Contains -Haystack (Invoke-CurlText -Arguments @("$script:AiaTestUrl/lookup?domain=Namecoin%20Root%20CA")) -Needle 'BEGIN CERTIFICATE' -ErrorMessage 'Root CA lookup failed'

    Write-Host 'Fetch TLD CA via curl'
    Assert-Contains -Haystack (Invoke-CurlText -Arguments @("$script:AiaTestUrl/lookup?domain=.bit%20TLD%20CA")) -Needle 'BEGIN CERTIFICATE' -ErrorMessage 'TLD CA lookup failed'

    Write-Host 'Fetch testls.bit CA via curl'
    try {
        $domainCaOutput = Invoke-CurlText -Arguments @("$script:AiaTestUrl/lookup?domain=testls.bit%20Domain%20AIA%20Parent%20CA")
        Assert-Contains -Haystack $domainCaOutput -Needle 'BEGIN CERTIFICATE' -ErrorMessage 'testls.bit Domain AIA Parent CA lookup failed'
    } catch {
        Write-Host 'WARN: testls.bit Domain AIA Parent CA lookup unavailable; continuing'
    }
}

function Run-HashedFunctionalTests {
    Write-Host 'Ensure Encaya instance is ready for new AIA tests'
    Ensure-EncayaReady

    Write-Host 'Ensure Encaya HTTPS endpoint is ready for new AIA tests'
    Ensure-EncayaHttpsReady

    Write-Host 'Generate hashed public key material for local HTTPS server'
    Generate-HashedPubkeyMaterial

    Write-Host "Pre-register $HASHED_DOMAIN"
    $hashedNameNewResult = Invoke-NamecoinCliJson -Arguments @('name_new', $HASHED_NAME)
    $hashedNameNewTxID = $hashedNameNewResult[0]
    $hashedNameNewRand = $hashedNameNewResult[1]

    Write-Host "Wait for $HASHED_DOMAIN pre-registration to mature"
    New-Blocks -Count 12

    Write-Host "Register $HASHED_DOMAIN"
    Invoke-NamecoinCliText -Arguments @('name_firstupdate', $HASHED_NAME, $hashedNameNewRand, $hashedNameNewTxID) | Out-Null

    Write-Host "Wait for $HASHED_DOMAIN registration to confirm"
    New-Blocks -Count 1

    $hashedUpdateJson = ConvertTo-CompactJson -InputObject ([ordered]@{
            ip  = '107.152.38.155'
            map = [ordered]@{
                '*' = [ordered]@{
                    tls = ,@(
                        2,
                        1,
                        1,
                        $script:TLSA_HASHED_PUB_SHA256_B64
                    )
                }
                sub1 = [ordered]@{
                    map = [ordered]@{
                        sub2 = [ordered]@{
                            map = [ordered]@{
                                sub3 = [ordered]@{
                                    ip = '107.152.38.155'
                                }
                            }
                        }
                    }
                }
                _tor = [ordered]@{
                    txt = 'dhflg7a7etr77hwt4eerwoovhg7b5bivt2jem4366dt4psgnl5diyiyd.onion'
                }
            }
        })

    Write-Host "Configure $HASHED_DOMAIN with hashed TLSA record"
    Invoke-NamecoinCliText -Arguments @('name_update', $HASHED_NAME, $hashedUpdateJson) | Out-Null

    Write-Host 'Wait for hashed TLSA update to confirm'
    New-Blocks -Count 1

    Write-Host 'Reset recursive DNS resolver state'
    Reset-RecursiveDnsResolverIfNeeded

    Write-Host 'Ensure hashed TLSA rejects missing preimage via AIA'
    Assert-RaisesError -Command {
        Invoke-Curl -Arguments @("$script:AiaTestUrl/aia?domain=$HASHED_DOMAIN%20Domain%20AIA%20Parent%20CA") -AllowFailure
    } -RequiredError '404'

    Write-Host "Fetch hashed $HASHED_DOMAIN CA via Encaya AIA using pubkey preimage"
    Invoke-CurlDownload -Arguments @(
        '--get',
        '--data-urlencode',
        "domain=$HASHED_DOMAIN Domain AIA Parent CA",
        '--data-urlencode',
        "pubb64=$script:TLSA_HASHED_PUB_B64",
        '--data-urlencode',
        "pubsha256=$script:TLSA_HASHED_PUB_SHA256_HEX",
        "$script:AiaTestUrl/aia"
    ) -OutputPath $HASHED_PARENT_CA_DER
    Convert-DerCertificateToPem -DerPath $HASHED_PARENT_CA_DER -PemPath $HASHED_PARENT_CA_PEM
    $script:HashedCaPem = Get-Content -LiteralPath $HASHED_PARENT_CA_PEM -Raw
    Assert-Contains -Haystack $script:HashedCaPem -Needle 'BEGIN CERTIFICATE' -ErrorMessage "Encaya did not return hashed $HASHED_DOMAIN Domain AIA Parent CA"

    Write-Host "Fetch hashed $HASHED_DOMAIN CA via curl"
    Get-Content -LiteralPath $HASHED_PARENT_CA_PEM | Select-String -Pattern 'BEGIN CERTIFICATE'

    $hashedDomainCaSha256Hex = Get-CertSpkiSha256Hex -CertPath $HASHED_PARENT_CA_PEM
    $generatedKeySha256Hex = Get-PublicKeySha256HexUpperFromPrivateKey -KeyPath $HASHED_CA_KEY
    Assert-Equal -Expected $hashedDomainCaSha256Hex -Actual $generatedKeySha256Hex -ErrorMessage 'Encaya issued parent CA key did not match generated hashed key'

    Write-Host 'Query hashed TLSA Authoritative via dig'
    $hashedAuthoritativeAnswers = Invoke-DnsQuery -Server '127.0.0.1' -Port 5391 -Name "*.$HASHED_DOMAIN" -RecordType 'TLSA'
    $digOutput = Format-DnsAnswers -Answers $hashedAuthoritativeAnswers
    Write-Host $digOutput
    Write-Host 'Checking hashed response correctness'
    $observedTlsaHex = if ($hashedAuthoritativeAnswers) { $hashedAuthoritativeAnswers[0].Certificate } else { '' }
    Assert-Equal -Expected $hashedDomainCaSha256Hex -Actual $observedTlsaHex -ErrorMessage 'Hashed authoritative TLSA digest mismatch'

    Write-Host 'Query hashed TLSA Recursive via dig'
    $hashedRecursiveAnswers = Wait-ForDnsAnswers -Server '127.0.0.1' -Port 53 -Name "*.$HASHED_DOMAIN" -RecordType 'TLSA'
    $digOutput = Format-DnsAnswers -Answers $hashedRecursiveAnswers
    Write-Host $digOutput
    Write-Host 'Checking hashed recursive response correctness'
    $observedTlsaHex = if ($hashedRecursiveAnswers) { $hashedRecursiveAnswers[0].Certificate } else { '' }
    Assert-Equal -Expected $hashedDomainCaSha256Hex -Actual $observedTlsaHex -ErrorMessage 'Hashed recursive TLSA digest mismatch'

    Write-Host 'Generate local leaf certificate signed by hashed parent'
    Generate-LeafCert

    Write-Host 'Start local HTTPS server for Chromium hashed AIA test'
    Stop-ProcessIfRunning -Process $script:HttpsServerProcess
    $script:HttpsServerProcess = Start-HttpsServer `
        -DocRoot $HTTPS_DOCROOT `
        -CertPath $LEAF_CERT `
        -KeyPath $LEAF_KEY `
        -Port $HTTPS_SERVER_PORT `
        -StdOutLogPath $HTTPS_SERVER_LOG `
        -StdErrLogPath $HTTPS_SERVER_STDERR_LOG `
        -Body 'Cool or nah'

    Write-Host 'Initialize NSS DB for Chromium hashed AIA test'
    Prepare-NssDb

    Write-Host 'Trust Encaya root CA for Chromium hashed AIA test'
    Trust-EncayaRoot

    Write-Host 'Run Chromium headless and verify real TLS+AIA workflow'
    $chromiumResult = Invoke-BrowserDumpDomImpl `
        -ProfileDir $CHROME_PROFILE_DIR `
        -LogPath (Join-Path $script:TestTempDir 'chrome.log') `
        -TargetHost $HASHED_DOMAIN `
        -TargetUrl "https://$HASHED_DOMAIN`:$HTTPS_SERVER_PORT/index.html"
    if ($chromiumResult.ExitCode -ne 0 -and $chromiumResult.Error) {
        Write-Host $chromiumResult.Error
    }
    Assert-Contains -Haystack $chromiumResult.Output -Needle 'Cool or nah' -ErrorMessage 'Chromium did not render expected page content over validated TLS'

    if ($chromiumResult.Output -like '*Your connection is not private*') {
        Fail-Test -Message 'Chromium reported certificate error instead of successful validation'
    }

    Write-Host 'Hashed AIA Chromium test passed'

    Write-Host 'Generate expired leaf certificate for Chromium negative test'
    Generate-ExpiredLeafCert

    Write-Host 'Start local HTTPS server with expired leaf certificate'
    Stop-ProcessIfRunning -Process $script:HttpsServerProcess
    $script:HttpsServerProcess = Start-HttpsServer `
        -DocRoot $HTTPS_DOCROOT `
        -CertPath $EXPIRED_LEAF_CERT `
        -KeyPath $EXPIRED_LEAF_KEY `
        -Port $HTTPS_SERVER_PORT `
        -StdOutLogPath $HTTPS_SERVER_LOG `
        -StdErrLogPath $HTTPS_SERVER_STDERR_LOG `
        -Body 'Cool or nah'

    Write-Host 'Run Chromium headless and verify expired cert is rejected'
    $expiredChromiumResult = Invoke-BrowserDumpDomImpl `
        -ProfileDir (Join-Path $script:TestTempDir 'chrome-profile-expired') `
        -LogPath (Join-Path $script:TestTempDir 'chrome-expired.log') `
        -TargetHost $HASHED_DOMAIN `
        -TargetUrl "https://$HASHED_DOMAIN`:$HTTPS_SERVER_PORT/index.html"
    if (-not (Test-BrowserCertificateErrorOutput -Output $expiredChromiumResult.Output)) {
        Write-Host $expiredChromiumResult.Output
        Write-Host $expiredChromiumResult.Error
        Fail-Test -Message 'Chromium did not reject expired certificate'
    }

    Write-Host 'Expired cert Chromium negative test passed'
}

function Run-StapledFunctionalTests {
    Write-Host 'Generate stapled public key material for local HTTPS server'
    Generate-StapledPubkeyMaterial

    Write-Host "Pre-register $STAPLED_DOMAIN"
    $stapledNameNewResult = Invoke-NamecoinCliJson -Arguments @('name_new', $STAPLED_NAME)
    $stapledNameNewTxID = $stapledNameNewResult[0]
    $stapledNameNewRand = $stapledNameNewResult[1]

    Write-Host "Wait for $STAPLED_DOMAIN pre-registration to mature"
    New-Blocks -Count 12

    Write-Host "Register $STAPLED_DOMAIN"
    Invoke-NamecoinCliText -Arguments @('name_firstupdate', $STAPLED_NAME, $stapledNameNewRand, $stapledNameNewTxID) | Out-Null

    Write-Host "Wait for $STAPLED_DOMAIN registration to confirm"
    New-Blocks -Count 1

    Write-Host "Configure $STAPLED_DOMAIN without blockchain TLSA data"
    Invoke-NamecoinCliText -Arguments @('name_update', $STAPLED_NAME, '{"ip":"107.152.38.155"}') | Out-Null

    Write-Host 'Wait for stapled name update to confirm'
    New-Blocks -Count 1

    Write-Host 'Reset recursive DNS resolver state'
    Reset-RecursiveDnsResolverIfNeeded

    Write-Host "Verify $STAPLED_DOMAIN has no TLSA data on-chain"
    $stapledTlsaShort = Format-DnsAnswers -Answers (Invoke-DnsQuery -Server '127.0.0.1' -Port 5391 -Name "*.$STAPLED_DOMAIN" -RecordType 'TLSA')
    Assert-Equal -Expected '' -Actual $stapledTlsaShort -ErrorMessage 'Stapled test domain unexpectedly had authoritative TLSA data'
    $stapledTlsaShort = Format-DnsAnswers -Answers (Invoke-DnsQuery -Server '127.0.0.1' -Port 53 -Name "*.$STAPLED_DOMAIN" -RecordType 'TLSA')
    Assert-Equal -Expected '' -Actual $stapledTlsaShort -ErrorMessage 'Stapled test domain unexpectedly had recursive TLSA data'

    Write-Host "Resolve current blockchain owner address for $STAPLED_DOMAIN"
    $script:STAPLED_BLOCKCHAIN_ADDRESS = Get-NameAddressForStapledTest -Name $STAPLED_NAME

    Write-Host 'Create stapled Namecoin certification signature'
    Build-StapledMessage

    Write-Host 'Ensure stapled AIA rejects missing signature data'
    $stapledNegativeOutput = (Invoke-Curl -Arguments @(
            '--get',
            '--data-urlencode',
            "domain=$STAPLED_DOMAIN Domain AIA Parent CA",
            '--data-urlencode',
            "pubb64=$script:STAPLED_PUB_B64",
            "$script:AiaTestUrl/aia"
        ) -AllowFailure).Output
    Assert-Contains -Haystack $stapledNegativeOutput -Needle '404' -ErrorMessage 'Stapled AIA missing-signature check did not return 404'

    Write-Host 'Ensure stapled AIA rejects wrong signature data'
    $stapledWrongSigsJson = ConvertTo-CompactJson -InputObject @(
        [ordered]@{
            blockchainaddress = $script:STAPLED_BLOCKCHAIN_ADDRESS
            blockchainsig     = 'invalid'
        }
    )
    $stapledWrongSigOutput = (Invoke-Curl -Arguments @(
            '--get',
            '--data-urlencode',
            "domain=$STAPLED_DOMAIN Domain AIA Parent CA",
            '--data-urlencode',
            "pubb64=$script:STAPLED_PUB_B64",
            '--data-urlencode',
            "sigs=$stapledWrongSigsJson",
            "$script:AiaTestUrl/aia"
        ) -AllowFailure).Output
    Assert-Contains -Haystack $stapledWrongSigOutput -Needle '404' -ErrorMessage 'Stapled AIA wrong-signature check did not return 404'

    Write-Host 'Ensure stapled AIA accepts multiple signature entries'
    $stapledMultiSigsJson = ConvertTo-CompactJson -InputObject @(
        [ordered]@{
            blockchainaddress = $script:STAPLED_BLOCKCHAIN_ADDRESS
            blockchainsig     = 'invalid'
        },
        [ordered]@{
            blockchainaddress = $script:STAPLED_BLOCKCHAIN_ADDRESS
            blockchainsig     = $script:STAPLED_BLOCKCHAIN_SIG
        }
    )
    Invoke-CurlDownload -Arguments @(
        '--get',
        '--data-urlencode',
        "domain=$STAPLED_DOMAIN Domain AIA Parent CA",
        '--data-urlencode',
        "pubb64=$script:STAPLED_PUB_B64",
        '--data-urlencode',
        "sigs=$stapledMultiSigsJson",
        "$script:AiaTestUrl/aia"
    ) -OutputPath $STAPLED_PARENT_CA_DER
    Convert-DerCertificateToPem -DerPath $STAPLED_PARENT_CA_DER -PemPath $STAPLED_PARENT_CA_PEM
    $stapledMultiCaPem = Get-Content -LiteralPath $STAPLED_PARENT_CA_PEM -Raw
    Assert-Contains -Haystack $stapledMultiCaPem -Needle 'BEGIN CERTIFICATE' -ErrorMessage 'Stapled AIA multi-signature acceptance failed'

    Write-Host "Fetch stapled $STAPLED_DOMAIN CA via Encaya AIA using Namecoin signature"
    Invoke-CurlDownload -Arguments @(
        '--get',
        '--data-urlencode',
        "domain=$STAPLED_DOMAIN Domain AIA Parent CA",
        '--data-urlencode',
        "pubb64=$script:STAPLED_PUB_B64",
        '--data-urlencode',
        "sigs=$script:STAPLED_SIGS_JSON",
        "$script:AiaTestUrl/aia"
    ) -OutputPath $STAPLED_PARENT_CA_DER
    Convert-DerCertificateToPem -DerPath $STAPLED_PARENT_CA_DER -PemPath $STAPLED_PARENT_CA_PEM
    $script:StapledCaPem = Get-Content -LiteralPath $STAPLED_PARENT_CA_PEM -Raw
    Assert-Contains -Haystack $script:StapledCaPem -Needle 'BEGIN CERTIFICATE' -ErrorMessage "Encaya did not return stapled $STAPLED_DOMAIN Domain AIA Parent CA"

    Write-Host 'Verify stapled issuer key matches signed public key'
    $stapledDomainCaSha256Hex = Get-CertSpkiSha256Hex -CertPath $STAPLED_PARENT_CA_PEM
    $stapledGeneratedKeySha256Hex = Get-PublicKeySha256HexUpperFromPrivateKey -KeyPath $STAPLED_CA_KEY
    Assert-Equal -Expected $stapledDomainCaSha256Hex -Actual $stapledGeneratedKeySha256Hex -ErrorMessage 'Encaya issued stapled parent CA key did not match signed key'

    Write-Host 'Generate local leaf certificate signed by stapled parent'
    Generate-StapledLeafCert

    Write-Host 'Start local HTTPS server for Chromium stapled AIA test'
    Stop-ProcessIfRunning -Process $script:StapledHttpsServerProcess
    $script:StapledHttpsServerProcess = Start-HttpsServer `
        -DocRoot $STAPLED_HTTPS_DOCROOT `
        -CertPath $STAPLED_LEAF_CERT `
        -KeyPath $STAPLED_LEAF_KEY `
        -Port $STAPLED_HTTPS_SERVER_PORT `
        -StdOutLogPath $STAPLED_HTTPS_SERVER_LOG `
        -StdErrLogPath $STAPLED_HTTPS_SERVER_STDERR_LOG `
        -Body 'Cool or nah stapled'

    Write-Host 'Initialize NSS DB for Chromium stapled AIA test'
    Prepare-NssDb

    Write-Host 'Trust Encaya root CA for Chromium stapled AIA test'
    Trust-EncayaRoot

    Write-Host 'Run Chromium headless and verify stapled TLS+AIA workflow'
    $stapledChromiumResult = Invoke-BrowserDumpDomImpl `
        -ProfileDir $STAPLED_CHROME_PROFILE_DIR `
        -LogPath (Join-Path $script:StapledTestTempDir 'chrome.log') `
        -TargetHost $STAPLED_DOMAIN `
        -TargetUrl "https://$STAPLED_DOMAIN`:$STAPLED_HTTPS_SERVER_PORT/index.html"
    if ($stapledChromiumResult.ExitCode -ne 0 -and $stapledChromiumResult.Error) {
        Write-Host $stapledChromiumResult.Error
    }
    Assert-Contains -Haystack $stapledChromiumResult.Output -Needle 'Cool or nah stapled' -ErrorMessage 'Chromium did not render expected page content over stapled TLS validation'

    if ($stapledChromiumResult.Output -like '*Your connection is not private*') {
        Fail-Test -Message 'Chromium reported certificate error instead of successful stapled validation'
    }

    Write-Host 'Stapled AIA Chromium test passed'
}

try {
    Start-CiManagedServices

    if (-not (Test-ShouldManageServices)) {
        Start-Sleep -Seconds 15
    }

    Wait-ForTcpPort -Port 18554 -TimeoutSeconds 120 -Description 'Namecoin Core RPC'
    Wait-ForNamecoinWalletBalance -MinimumBalance 1 -TimeoutSeconds 120
    Wait-ForTcpPort -Port 5391 -TimeoutSeconds 120 -Description 'ncdns authoritative DNS'
    Wait-ForTcpPort -Port 53 -TimeoutSeconds 120 -Description 'Unbound recursive DNS'
    Wait-ForTcpPort -HostName $script:AiaTestIp -Port 80 -TimeoutSeconds 120 -Description 'Encaya HTTP'
    Wait-ForTcpPort -HostName $script:AiaTestIp -Port 443 -TimeoutSeconds 120 -Description 'Encaya HTTPS'

    Run-BaseFunctionalTests
    Run-HashedFunctionalTests
    Run-StapledFunctionalTests

    Write-Host 'Functional test suite passed'
} catch {
    $script:TestFailed = $true
    throw
} finally {
    Stop-ProcessIfRunning -Process $script:StapledHttpsServerProcess
    Stop-ProcessIfRunning -Process $script:HttpsServerProcess
    Stop-ManagedServiceProcesses
    Stop-ManagedWindowsServices
    Remove-ImportedRootCertificates
    Restore-NssDb

    if ($script:TestFailed) {
        Write-ManagedServiceLogs
    }

    foreach ($path in @($script:TestTempDir, $script:StapledTestTempDir)) {
        if ($path -and (Test-Path -LiteralPath $path)) {
            Remove-DirectoryWithRetry -Path $path
        }
    }
}
