Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. "$PSScriptRoot\windows-testlib.ps1"

$namecoind = Resolve-BinaryPath -Name 'namecoind.exe'
$namecoinCli = Resolve-BinaryPath -Name 'namecoin-cli.exe'
$namecoinDataDir = Get-NamecoinDataDir
$namecoinConfigPath = Join-Path $namecoinDataDir 'namecoin.conf'
$debugLogPath = Join-Path $namecoinDataDir 'regtest\debug.log'

Reset-Directory $namecoinDataDir

$namecoinConfig = @"
regtest=1
txindex=1
printtoconsole=1
rpcuser=doggman
rpcpassword=donkey
rpcallowip=127.0.0.1
zmqpubrawblock=tcp://127.0.0.1:28332
zmqpubrawtx=tcp://127.0.0.1:28333
fallbackfee=0.0002
[regtest]
rpcbind=0.0.0.0
rpcport=18554
"@

Write-AsciiFile -Path $namecoinConfigPath -Content $namecoinConfig

$namecoindProcess = Start-NativeProcess -FilePath $namecoind `
    -ArgumentList @('-regtest', "-datadir=$namecoinDataDir") `
    -WorkingDirectory (Split-Path $namecoind -Parent)

Wait-ForTcpPort -Port 18554 -TimeoutSeconds 120 -Description 'Namecoin Core RPC'

$bitcoinCliArgs = @(
    "-datadir=$namecoinDataDir",
    '-rpcuser=doggman',
    '-rpcpassword=donkey',
    '-rpcport=18554',
    '-regtest'
)

Invoke-NativeCommand -FilePath $namecoinCli -ArgumentList ($bitcoinCliArgs + @('createwallet', 'test_wallet')) | Out-Null
$address = (Invoke-NativeCommand -FilePath $namecoinCli -ArgumentList ($bitcoinCliArgs + @('getnewaddress'))).Output.Trim()
Invoke-NativeCommand -FilePath $namecoinCli -ArgumentList ($bitcoinCliArgs + @('generatetoaddress', '150', $address)) | Out-Null

while (-not (Test-Path -LiteralPath $debugLogPath)) {
    if ($namecoindProcess.HasExited) {
        throw "namecoind exited unexpectedly with code $($namecoindProcess.ExitCode)"
    }

    Start-Sleep -Seconds 1
}

Get-Content -LiteralPath $debugLogPath -Wait
