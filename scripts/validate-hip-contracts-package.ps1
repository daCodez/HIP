[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$packageOutput = Join-Path $repositoryRoot 'artifacts/hip-contracts-package'
$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("hip-contracts-consumer-" + [Guid]::NewGuid().ToString('N'))
$originalNugetPackages = $env:NUGET_PACKAGES

try {
    New-Item -ItemType Directory -Force -Path $packageOutput | Out-Null
    New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
    $env:NUGET_PACKAGES = Join-Path $temporaryRoot '.packages'

    dotnet pack (Join-Path $repositoryRoot 'src/HIP.Contracts/HIP.Contracts.csproj') `
        -c Release `
        -p:HipContractsLicenseApproved=true `
        -o $packageOutput
    if ($LASTEXITCODE -ne 0) { throw 'HIP.Contracts package creation failed.' }

    $packages = @(Get-ChildItem -LiteralPath $packageOutput -Filter 'HumanInteractiveProtocol.Contracts.0.1.0.nupkg')
    if ($packages.Count -ne 1) { throw 'Exactly one expected HIP.Contracts package must be created.' }
    $package = $packages[0]

    $packageArchive = [System.IO.Compression.ZipFile]::OpenRead($package.FullName)
    try {
        $archiveEntries = @($packageArchive.Entries | ForEach-Object FullName)
    }
    finally {
        $packageArchive.Dispose()
    }
    foreach ($requiredEntry in @(
        'LICENSE.txt',
        'NOTICE.txt',
        'TRADEMARKS.md',
        'README.md',
        'PUBLIC-API.md',
        'lib/net10.0/HIP.Contracts.dll',
        'lib/net10.0/HIP.Contracts.xml')) {
        if ($archiveEntries -notcontains $requiredEntry) {
            throw "Package is missing required entry '$requiredEntry'."
        }
    }

    dotnet new console --framework net10.0 --output $temporaryRoot --force
    if ($LASTEXITCODE -ne 0) { throw 'Temporary package consumer creation failed.' }
    $consumerProjects = @(Get-ChildItem -LiteralPath $temporaryRoot -Filter '*.csproj')
    if ($consumerProjects.Count -ne 1) { throw 'Exactly one temporary consumer project must exist.' }
    $consumerProject = $consumerProjects[0]
    dotnet add $consumerProject.FullName package HumanInteractiveProtocol.Contracts `
        --version 0.1.0 `
        --source $packageOutput
    if ($LASTEXITCODE -ne 0) { throw 'Temporary package consumer restore failed.' }

    @'
using HIP.Application.Protocol;

const string json = """{"version":"1.0","messageId":"consumer-test","nonce":"AAECAwQFBgcICQoLDA0ODw","issuer":{"id":"hip:domain:issuer.example"},"subject":{"type":"website","id":"example.com"},"contentDigest":{"algorithm":"sha256","value":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"claims":{},"signature":{"scope":"origin-and-integrity","keyId":"key-1","algorithm":"test","algorithmFamily":"unknown","canonicalization":"RFC8785","value":"signature"},"issuedAtUtc":"2026-08-12T12:00:00.000Z","expiresAtUtc":"2026-08-12T12:05:00.000Z"}""";
var envelope = HipProtocolEnvelopeDocumentJson.Deserialize(json);
if (envelope.MessageId != "consumer-test" || HipProtocolEnvelopeDocumentJson.Serialize(envelope) != json)
{
    throw new InvalidOperationException("HIP.Contracts package consumer validation failed.");
}

Console.WriteLine("HIP.Contracts package consumer validation passed.");
'@ | Set-Content -LiteralPath (Join-Path $temporaryRoot 'Program.cs') -Encoding utf8

    dotnet run --project $temporaryRoot --no-restore
    if ($LASTEXITCODE -ne 0) { throw 'Temporary package consumer execution failed.' }

    Write-Output "Validated package: $($package.FullName)"
}
finally {
    $env:NUGET_PACKAGES = $originalNugetPackages
    $resolvedTemporaryRoot = [System.IO.Path]::GetFullPath($temporaryRoot)
    $resolvedSystemTemp = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
    if ($resolvedTemporaryRoot.StartsWith($resolvedSystemTemp, [StringComparison]::OrdinalIgnoreCase) -and
        (Test-Path -LiteralPath $resolvedTemporaryRoot)) {
        Remove-Item -LiteralPath $resolvedTemporaryRoot -Recurse -Force
    }
}
