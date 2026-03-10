[CmdletBinding()]
param(
  [string]$Configuration = "Release",
  [string]$Version = "0.1.0",
  [string]$Runtime = "win-x64",
  [string]$Manufacturer = "HIP Team",
  [string]$UpgradeCode = "{D7A8F5C0-6C71-4F02-873A-9B3A68A0C4B1}"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Require-Command {
  param([Parameter(Mandatory = $true)][string]$Name)
  if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
    throw "Required command '$Name' was not found in PATH."
  }
}

function Get-WixTooling {
  $wix = Get-Command wix -ErrorAction SilentlyContinue
  if ($wix) {
    try {
      $versionOutput = & wix --version 2>$null
      if ($LASTEXITCODE -eq 0 -and $versionOutput) {
        return @{ Kind = "wix4"; Version = ($versionOutput | Select-Object -First 1) }
      }
    } catch { }
  }

  $candle = Get-Command candle -ErrorAction SilentlyContinue
  $light = Get-Command light -ErrorAction SilentlyContinue
  if ($candle -and $light) {
    return @{ Kind = "wix3"; Version = "3.x (candle/light)" }
  }

  return $null
}

function New-Id([string]$prefix, [int]$index) {
  return "{0}_{1}" -f $prefix, $index
}

function XmlEscape([string]$value) {
  return [System.Security.SecurityElement]::Escape($value)
}

function Build-WxsSource {
  param(
    [Parameter(Mandatory = $true)][string]$Schema,
    [Parameter(Mandatory = $true)][string]$PublishDir,
    [Parameter(Mandatory = $true)][string]$Version,
    [Parameter(Mandatory = $true)][string]$Manufacturer,
    [Parameter(Mandatory = $true)][string]$UpgradeCode
  )

  $files = Get-ChildItem -Path $PublishDir -File -Recurse | Sort-Object FullName
  if (-not $files) {
    throw "Publish output is empty: $PublishDir"
  }

  $dirChildren = @{}
  $dirChildren[""] = New-Object System.Collections.Generic.List[string]
  $dirNameMap = @{}
  $dirIdMap = @{}
  $componentsByDir = @{}
  $componentRefs = New-Object System.Collections.Generic.List[string]

  $dirCounter = 0
  $componentCounter = 0
  $fileCounter = 0

  foreach ($file in $files) {
    $relativePath = [System.IO.Path]::GetRelativePath($PublishDir, $file.FullName)
    $relativeDir = [System.IO.Path]::GetDirectoryName($relativePath)
    if ([string]::IsNullOrEmpty($relativeDir)) { $relativeDir = "" }

    if (-not $componentsByDir.ContainsKey($relativeDir)) {
      $componentsByDir[$relativeDir] = New-Object System.Collections.Generic.List[string]
    }

    if ($relativeDir -ne "") {
      $parts = $relativeDir -split "[\\/]"
      $current = ""
      for ($i = 0; $i -lt $parts.Length; $i++) {
        $part = $parts[$i]
        $next = if ($current -eq "") { $part } else { "$current/$part" }

        if (-not $dirIdMap.ContainsKey($next)) {
          $dirCounter++
          $dirIdMap[$next] = New-Id "Dir" $dirCounter
          $dirNameMap[$next] = $part

          if (-not $dirChildren.ContainsKey($current)) {
            $dirChildren[$current] = New-Object System.Collections.Generic.List[string]
          }
          if (-not $dirChildren[$current].Contains($next)) {
            $dirChildren[$current].Add($next)
          }

          if (-not $dirChildren.ContainsKey($next)) {
            $dirChildren[$next] = New-Object System.Collections.Generic.List[string]
          }
        }

        $current = $next
      }
    }

    $componentCounter++
    $fileCounter++
    $componentId = New-Id "Cmp" $componentCounter
    $fileId = New-Id "Fil" $fileCounter
    $sourceEscaped = XmlEscape($file.FullName)

    $component = if ($Schema -eq "v4") {
      "<Component Id=`"$componentId`" Guid=`"*`"><File Id=`"$fileId`" Source=`"$sourceEscaped`" KeyPath=`"yes`" /></Component>"
    } else {
      "<Component Id=`"$componentId`" Guid=`"*`" Win64=`"yes`"><File Id=`"$fileId`" Source=`"$sourceEscaped`" KeyPath=`"yes`" /></Component>"
    }

    $componentsByDir[$relativeDir].Add($component)
    $componentRefs.Add("<ComponentRef Id=`"$componentId`" />")
  }

  function Render-Directory {
    param(
      [string]$PathKey,
      [int]$Indent
    )

    $pad = " " * $Indent
    $out = New-Object System.Collections.Generic.List[string]

    if ($PathKey -ne "") {
      $dirId = $dirIdMap[$PathKey]
      $name = XmlEscape($dirNameMap[$PathKey])
      $out.Add("$pad<Directory Id=`"$dirId`" Name=`"$name`">")
      $pad = " " * ($Indent + 2)
    }

    if ($componentsByDir.ContainsKey($PathKey)) {
      foreach ($cmp in $componentsByDir[$PathKey]) {
        $out.Add("$pad$cmp")
      }
    }

    if ($dirChildren.ContainsKey($PathKey)) {
      foreach ($child in ($dirChildren[$PathKey] | Sort-Object)) {
        $childLines = Render-Directory -PathKey $child -Indent ($pad.Length)
        foreach ($line in $childLines) { $out.Add($line) }
      }
    }

    if ($PathKey -ne "") {
      $out.Add((" " * $Indent) + "</Directory>")
    }

    return $out
  }

  $installDirInner = Render-Directory -PathKey "" -Indent 8
  $componentRefLines = $componentRefs | Sort-Object

  $productName = "HIP Agent Worker"
  $manufacturerEscaped = XmlEscape($Manufacturer)
  $upgradeCodeEscaped = XmlEscape($UpgradeCode)

  if ($Schema -eq "v4") {
@"
<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs">
  <Package Name="$productName" Manufacturer="$manufacturerEscaped" Version="$Version" UpgradeCode="$upgradeCodeEscaped" InstallerVersion="500" Scope="perMachine">
    <MajorUpgrade DowngradeErrorMessage="A newer version of $productName is already installed." />
    <MediaTemplate EmbedCab="yes" />

    <StandardDirectory Id="ProgramFiles64Folder">
      <Directory Id="INSTALLFOLDER" Name="$productName">
$($installDirInner -join "`n")
      </Directory>
    </StandardDirectory>

    <Feature Id="MainFeature" Title="$productName" Level="1">
      <ComponentGroupRef Id="ProductComponents" />
    </Feature>
  </Package>

  <Fragment>
    <ComponentGroup Id="ProductComponents">
$((($componentRefLines | ForEach-Object { "      $_" }) -join "`n"))
    </ComponentGroup>
  </Fragment>
</Wix>
"@
  }
  else {
@"
<?xml version="1.0" encoding="UTF-8"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
  <Product Id="*" Name="$productName" Language="1033" Version="$Version" Manufacturer="$manufacturerEscaped" UpgradeCode="$upgradeCodeEscaped">
    <Package InstallerVersion="500" Compressed="yes" InstallScope="perMachine" Platform="x64" />
    <MajorUpgrade DowngradeErrorMessage="A newer version of $productName is already installed." />
    <MediaTemplate EmbedCab="yes" />

    <Directory Id="TARGETDIR" Name="SourceDir">
      <Directory Id="ProgramFiles64Folder">
        <Directory Id="INSTALLFOLDER" Name="$productName">
$($installDirInner -join "`n")
        </Directory>
      </Directory>
    </Directory>

    <Feature Id="MainFeature" Title="$productName" Level="1">
      <ComponentGroupRef Id="ProductComponents" />
    </Feature>
  </Product>

  <Fragment>
    <ComponentGroup Id="ProductComponents">
$((($componentRefLines | ForEach-Object { "      $_" }) -join "`n"))
    </ComponentGroup>
  </Fragment>
</Wix>
"@
  }
}

if ($Runtime -notlike "win-*") {
  throw "Runtime '$Runtime' is invalid for MSI packaging. Use a Windows RID (for example: win-x64)."
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = (Resolve-Path (Join-Path $scriptDir "../../..")).Path
$project = Join-Path $repoRoot "HIP.Agent.Worker/HIP.Agent.Worker.csproj"
$outRoot = Join-Path $repoRoot "out/windows"
$publishDir = Join-Path $outRoot "publish"
$tempRoot = Join-Path $outRoot "_wix"
$msiPath = Join-Path $outRoot ("hip-agent-worker_{0}_{1}.msi" -f $Version, $Runtime)

New-Item -Path $outRoot -ItemType Directory -Force | Out-Null
Remove-Item -Path $publishDir,$tempRoot -Recurse -Force -ErrorAction SilentlyContinue
New-Item -Path $publishDir,$tempRoot -ItemType Directory -Force | Out-Null

Write-Host "Publishing HIP.Agent.Worker ($Configuration, $Runtime)..."
Require-Command -Name dotnet
& dotnet publish $project -c $Configuration -r $Runtime --self-contained true -o $publishDir
if ($LASTEXITCODE -ne 0) {
  throw "dotnet publish failed (exit code $LASTEXITCODE)."
}

$wix = Get-WixTooling
if (-not $wix) {
  Write-Error @"
WiX toolset was not found. MSI compilation cannot continue.

Install one of the following and rerun:
  - WiX v4+: winget install WiXToolset.WiXToolset
  - WiX v3:  choco install wixtoolset

Expected output path after success:
  $msiPath
"@
  exit 2
}

$schema = if ($wix.Kind -eq "wix4") { "v4" } else { "v3" }
$wxsPath = Join-Path $tempRoot "HIP.Agent.Worker.$schema.wxs"
$wxs = Build-WxsSource -Schema $schema -PublishDir $publishDir -Version $Version -Manufacturer $Manufacturer -UpgradeCode $UpgradeCode
Set-Content -Path $wxsPath -Value $wxs -Encoding UTF8

Write-Host "Building MSI with $($wix.Kind) [$($wix.Version)]..."
if ($wix.Kind -eq "wix4") {
  & wix build $wxsPath -arch x64 -o $msiPath
  if ($LASTEXITCODE -ne 0) {
    throw "wix build failed (exit code $LASTEXITCODE)."
  }
}
else {
  $wixObj = Join-Path $tempRoot "HIP.Agent.Worker.wixobj"
  & candle -nologo -arch x64 -out $wixObj $wxsPath
  if ($LASTEXITCODE -ne 0) {
    throw "candle failed (exit code $LASTEXITCODE)."
  }

  & light -nologo -sval -out $msiPath $wixObj
  if ($LASTEXITCODE -ne 0) {
    throw "light failed (exit code $LASTEXITCODE)."
  }
}

Write-Host "MSI generated: $msiPath"
