<#
.SYNOPSIS
Starts HIP locally when Aspire DCP is unavailable or wedged.

.DESCRIPTION
Starts the production-like local dependencies through Docker Compose, then runs
HIP.ApiService and HIP.Web directly on the stable development ports used by the
browser plugin. This script is intentionally scoped to HIP processes and HIP
Compose services so it does not disturb unrelated local development work.

.PARAMETER SkipBuild
Skips the solution build before launching HIP services.

.PARAMETER Clean
Stops existing HIP.ApiService and HIP.Web dotnet processes before launching.
#>
[CmdletBinding()]
param(
    [switch]$SkipBuild,
    [switch]$Clean
)

$ErrorActionPreference = "Stop"

# Gets the repository root from the script location.
function Get-HipRepositoryRoot {
    return (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
}

# Stops only HIP-owned project processes so stale local runs do not hold ports.
function Stop-HipProjectProcesses {
    Get-CimInstance Win32_Process -Filter "name = 'dotnet.exe'" |
        Where-Object {
            $_.CommandLine -match 'HIP\.ApiService\.csproj|HIP\.Web\.csproj|HIP\.ApiService\.dll|HIP\.Web\.dll'
        } |
        ForEach-Object {
            Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
        }
}

# Sets a process-scoped default value without overwriting caller-provided configuration.
function Set-HipDefaultEnvironmentVariable {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$Value
    )

    if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($Name, "Process"))) {
        [Environment]::SetEnvironmentVariable($Name, $Value, "Process")
    }
}

# Sets development-only environment variables for the current PowerShell process and its child HIP processes.
function Set-HipDevelopmentEnvironment {
    Set-HipDefaultEnvironmentVariable -Name "HIP_POSTGRES_DB" -Value "hip"
    Set-HipDefaultEnvironmentVariable -Name "HIP_POSTGRES_USER" -Value "hip"
    Set-HipDefaultEnvironmentVariable -Name "HIP_POSTGRES_PASSWORD" -Value "hip-local-dev-password"
    Set-HipDefaultEnvironmentVariable -Name "HIP_RABBITMQ_USER" -Value "hip"
    Set-HipDefaultEnvironmentVariable -Name "HIP_RABBITMQ_PASSWORD" -Value "hip-local-dev-password"
    Set-HipDefaultEnvironmentVariable -Name "HIP_RECORD_ENCRYPTION_KEY" -Value "hip-local-dev-record-key-32bytes!"
    Set-HipDefaultEnvironmentVariable -Name "HIP_PRIVACY_HASHING_KEY" -Value "hip-local-dev-privacy-key-32bytes"
    Set-HipDefaultEnvironmentVariable -Name "HIP_API_PORT" -Value "5099"
    Set-HipDefaultEnvironmentVariable -Name "HIP_WEB_PORT" -Value "5123"
    Set-HipDefaultEnvironmentVariable -Name "HIP_POSTGRES_PORT" -Value "5432"
    Set-HipDefaultEnvironmentVariable -Name "HIP_REDIS_PORT" -Value "6379"
    Set-HipDefaultEnvironmentVariable -Name "HIP_RABBITMQ_PORT" -Value "5672"
    Set-HipDefaultEnvironmentVariable -Name "HIP_RABBITMQ_MANAGEMENT_PORT" -Value "15672"
    $env:ConnectionStrings__HipDatabase = "Host=localhost;Port=$($env:HIP_POSTGRES_PORT);Database=$($env:HIP_POSTGRES_DB);Username=$($env:HIP_POSTGRES_USER);Password=$($env:HIP_POSTGRES_PASSWORD)"
    $env:HipInfrastructure__DatabaseProvider = "PostgreSQL"
    $env:HipSecurity__RecordEncryptionKey = $env:HIP_RECORD_ENCRYPTION_KEY
    $env:HipSecurity__PrivacyHashingKey = $env:HIP_PRIVACY_HASHING_KEY
    $env:ExternalSiteEvidence__ExternalProvidersEnabled = "true"
    $env:ExternalSiteEvidence__SslLabs__Enabled = "true"
    $env:ExternalSiteEvidence__GoogleWebRisk__Enabled = "false"
    $env:ExternalSiteEvidence__VirusTotal__Enabled = "false"
    [Environment]::SetEnvironmentVariable("services__hip-api__http__0", "http://localhost:$($env:HIP_API_PORT)", "Process")
}

# Starts HIP dependency containers through Docker Compose with explicit local development defaults.
function Start-HipDependencies {
    docker compose up -d hip-postgres hip-redis hip-queue | Out-Host
    Wait-HipContainerHealthy -ContainerName "hip-postgres"
    Wait-HipContainerHealthy -ContainerName "hip-redis"
    Wait-HipContainerHealthy -ContainerName "hip-queue"
}

# Waits for a Docker container health check so HIP services do not race database startup.
function Wait-HipContainerHealthy {
    param(
        [Parameter(Mandatory)]
        [string]$ContainerName,

        [int]$Attempts = 60
    )

    for ($i = 0; $i -lt $Attempts; $i++) {
        $status = docker inspect --format "{{.State.Health.Status}}" $ContainerName 2>$null
        if ($LASTEXITCODE -eq 0 -and $status -eq "healthy") {
            return
        }

        Start-Sleep -Seconds 1
    }

    throw "Container '$ContainerName' did not become healthy."
}

# Starts one HIP project with redirected logs and inherited privacy-safe development configuration.
function Start-HipProject {
    param(
        [Parameter(Mandatory)]
        [string]$ProjectPath,

        [Parameter(Mandatory)]
        [string]$LogPrefix
    )

    $stdout = Join-Path $script:HipLocalLogDirectory "$LogPrefix-stdout.log"
    $stderr = Join-Path $script:HipLocalLogDirectory "$LogPrefix-stderr.log"
    Remove-Item -LiteralPath $stdout, $stderr -ErrorAction SilentlyContinue

    return Start-Process -FilePath "dotnet" `
        -ArgumentList @("run", "--project", $ProjectPath, "--launch-profile", "http", "--no-build") `
        -WorkingDirectory $root `
        -RedirectStandardOutput $stdout `
        -RedirectStandardError $stderr `
        -PassThru `
        -WindowStyle Hidden
}

# Waits for an HTTP health endpoint and returns false instead of throwing so startup diagnostics remain readable.
function Wait-HipEndpoint {
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [int]$Attempts = 45
    )

    for ($i = 0; $i -lt $Attempts; $i++) {
        try {
            $response = Invoke-WebRequest -Uri $Uri -UseBasicParsing -TimeoutSec 2
            if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 500) {
                return $true
            }
        }
        catch {
            Start-Sleep -Seconds 1
        }
    }

    return $false
}

# Prints the tail of a service log when startup fails so the cause is visible immediately.
function Write-HipLogTail {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (Test-Path $Path) {
        Write-Host "--- $Path ---"
        Get-Content -LiteralPath $Path -Tail 80
    }
}

$root = Get-HipRepositoryRoot
Set-Location $root
$script:HipLocalLogDirectory = Join-Path $root ".hip-local\logs"
New-Item -ItemType Directory -Path $script:HipLocalLogDirectory -Force | Out-Null

if ($Clean) {
    Stop-HipProjectProcesses
}

Set-HipDevelopmentEnvironment
Start-HipDependencies

if (-not $SkipBuild) {
    dotnet build HIP.slnx --no-restore --verbosity:minimal
}

$api = Start-HipProject -ProjectPath "src/HIP.ApiService/HIP.ApiService.csproj" -LogPrefix "hip-api"
$web = Start-HipProject -ProjectPath "src/HIP.Web/HIP.Web.csproj" -LogPrefix "hip-web"

$apiReady = Wait-HipEndpoint -Uri "http://localhost:$($env:HIP_API_PORT)/alive"
$webReady = Wait-HipEndpoint -Uri "http://localhost:$($env:HIP_WEB_PORT)/alive"

if (-not $apiReady -or -not $webReady) {
    Write-Warning "HIP local startup did not complete."
    Write-HipLogTail -Path (Join-Path $script:HipLocalLogDirectory "hip-api-stderr.log")
    Write-HipLogTail -Path (Join-Path $script:HipLocalLogDirectory "hip-api-stdout.log")
    Write-HipLogTail -Path (Join-Path $script:HipLocalLogDirectory "hip-web-stderr.log")
    Write-HipLogTail -Path (Join-Path $script:HipLocalLogDirectory "hip-web-stdout.log")
    exit 1
}

Write-Host "HIP local services are running."
Write-Host "API: http://localhost:$($env:HIP_API_PORT)"
Write-Host "Web: http://localhost:$($env:HIP_WEB_PORT)"
Write-Host "API PID: $($api.Id)"
Write-Host "Web PID: $($web.Id)"
