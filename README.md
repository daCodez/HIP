# HIP: Human Interactive Protocol

HIP is the open interoperability layer for portable digital trust evidence. This repository contains the public protocol contracts, certificate-verification boundaries, browser extension, plug-in contracts, examples, and developer documentation.

HIP adds origin, integrity, identity, and risk evidence above connectivity and transport encryption. A valid signature proves origin and integrity; it does not by itself prove safety or reputation.

## Repository contents

- `src/HIP.Contracts`: dependency-free .NET protocol, verification, plug-in, browser, DNS, reporting, and client contracts.
- `clients/browser-extension`: the Apache-licensed HIP browser extension.
- `docs`: public protocol and integration documentation.
- `scripts/validate-hip-contracts-package.ps1`: package and clean-consumer validation.

HIP's hosted scoring engine, certificate issuance and private-key systems, administration, infrastructure, subscriptions, and plug-in hosting are maintained separately in the private HIP Platform.

## Build the public contracts

```powershell
dotnet restore HIP.slnx
dotnet build HIP.slnx -c Release
```

## Test the browser extension

```powershell
cd clients/browser-extension
npm ci
npm test
```

## Validate the package

Packaging remains explicit so an accidental build cannot publish a release:

```powershell
.\scripts\validate-hip-contracts-package.ps1
```

## License

The source in this repository is licensed under the [Apache License 2.0](LICENSE). HIP names, logos, badges, certification marks, and other brand assets are subject to the separate [trademark policy](TRADEMARKS.md). The license does not imply that a product or website is verified, certified, sponsored, or endorsed by HIP.
