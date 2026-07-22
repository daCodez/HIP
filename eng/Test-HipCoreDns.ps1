[CmdletBinding()]
param(
    [ValidateRange(1024, 65535)]
    [int]$Port = 10553
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$containerName = "hip-coredns-tests-$PID"
$coreFile = Join-Path $PSScriptRoot 'coredns/Corefile'
$zoneFile = Join-Path $PSScriptRoot 'coredns/hip.test.zone'

try {
    docker version --format '{{.Server.Version}}' | Out-Null
    docker run --detach --rm `
        --name $containerName `
        --publish "127.0.0.1:${Port}:53/tcp" `
        --volume "${coreFile}:/etc/coredns/Corefile:ro" `
        --volume "${zoneFile}:/zones/hip.test.zone:ro" `
        coredns/coredns:latest -conf /etc/coredns/Corefile | Out-Null

    $env:HIP_TEST_COREDNS_HOST = '127.0.0.1'
    $env:HIP_TEST_COREDNS_PORT = $Port.ToString([Globalization.CultureInfo]::InvariantCulture)
    dotnet test (Join-Path $repositoryRoot 'tests/HIP.Tests/HIP.Tests.csproj') `
        --no-restore `
        --results-directory (Join-Path $repositoryRoot '.test-results/hip0704-live') `
        --filter 'Category=CoreDnsLive'
    if ($LASTEXITCODE -ne 0) {
        throw "CoreDNS integration tests failed with exit code $LASTEXITCODE."
    }
}
finally {
    Remove-Item Env:HIP_TEST_COREDNS_HOST -ErrorAction SilentlyContinue
    Remove-Item Env:HIP_TEST_COREDNS_PORT -ErrorAction SilentlyContinue
    docker rm --force $containerName 2>$null | Out-Null
}
