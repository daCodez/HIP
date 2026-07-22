[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$DatabaseHost,
    [int]$DatabasePort = 5432,
    [Parameter(Mandatory = $true)][string]$SourceDatabase,
    [Parameter(Mandatory = $true)][string]$RestoreDatabase,
    [Parameter(Mandatory = $true)][string]$DatabaseUser,
    [Parameter(Mandatory = $true)][string]$PasswordFile,
    [Parameter(Mandatory = $true)][string]$KeyMetadataPath,
    [Parameter(Mandatory = $true)][string]$OutputDirectory,
    [switch]$ConfirmIsolatedRestore
)

$ErrorActionPreference = 'Stop'
if (-not $ConfirmIsolatedRestore) { throw 'Pass -ConfirmIsolatedRestore after verifying the target is an isolated drill database.' }
if ($RestoreDatabase -notmatch '^[a-zA-Z0-9_]+_restore_drill_[a-zA-Z0-9_]+$') { throw 'RestoreDatabase must include the isolated _restore_drill_ marker.' }
if ($RestoreDatabase -eq $SourceDatabase) { throw 'The restore database must never equal the source database.' }

$resolvedPasswordFile = (Resolve-Path -LiteralPath $PasswordFile).Path
$resolvedKeyMetadata = (Resolve-Path -LiteralPath $KeyMetadataPath).Path
$resolvedOutput = [System.IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $resolvedOutput -Force | Out-Null

$timestamp = [DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssZ')
$dumpPath = Join-Path $resolvedOutput "hip-$timestamp.dump"
$metadataBackupPath = Join-Path $resolvedOutput "hip-key-metadata-$timestamp.json"
$manifestPath = Join-Path $resolvedOutput "hip-backup-manifest-$timestamp.json"
$env:PGPASSFILE = $resolvedPasswordFile

try {
    & pg_dump --host $DatabaseHost --port $DatabasePort --username $DatabaseUser --dbname $SourceDatabase --format custom --no-owner --no-acl --file $dumpPath
    if ($LASTEXITCODE -ne 0) { throw "pg_dump failed with exit code $LASTEXITCODE." }

    Copy-Item -LiteralPath $resolvedKeyMetadata -Destination $metadataBackupPath
    $dumpHash = (Get-FileHash -LiteralPath $dumpPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $metadataHash = (Get-FileHash -LiteralPath $metadataBackupPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $manifest = [ordered]@{
        schemaVersion = 1
        createdAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
        sourceDatabase = $SourceDatabase
        restoreDatabase = $RestoreDatabase
        dumpFile = [System.IO.Path]::GetFileName($dumpPath)
        dumpSha256 = $dumpHash
        keyMetadataFile = [System.IO.Path]::GetFileName($metadataBackupPath)
        keyMetadataSha256 = $metadataHash
        containsSecretKeyMaterial = $false
    }
    $manifest | ConvertTo-Json | Set-Content -LiteralPath $manifestPath -Encoding utf8NoBOM

    & createdb --host $DatabaseHost --port $DatabasePort --username $DatabaseUser $RestoreDatabase
    if ($LASTEXITCODE -ne 0) { throw 'createdb failed. The drill refuses to reuse or overwrite an existing restore database.' }

    & pg_restore --host $DatabaseHost --port $DatabasePort --username $DatabaseUser --dbname $RestoreDatabase --no-owner --no-acl --exit-on-error $dumpPath
    if ($LASTEXITCODE -ne 0) { throw "pg_restore failed with exit code $LASTEXITCODE." }

    $recordCount = & psql --host $DatabaseHost --port $DatabasePort --username $DatabaseUser --dbname $RestoreDatabase --tuples-only --no-align --command 'SELECT COUNT(*) FROM "Records";'
    if ($LASTEXITCODE -ne 0) { throw 'Restore verification query failed.' }

    [pscustomobject]@{
        BackupManifest = $manifestPath
        RestoreDatabase = $RestoreDatabase
        RestoredRecordCount = [long]($recordCount.Trim())
        CleanupRequired = $true
    }
}
finally {
    Remove-Item Env:PGPASSFILE -ErrorAction SilentlyContinue
}
