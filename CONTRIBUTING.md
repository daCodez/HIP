# Contributing to HIP

Thank you for contributing to the Human Interactive Protocol.

## Scope

This repository accepts changes to public contracts, protocol documentation, verification boundaries, public plug-in contracts, examples, and the browser extension. Hosted scoring policy, certificate issuance, private keys, infrastructure, billing, and administrative controls are not developed here.

## Expectations

1. Keep changes focused and backward compatible.
2. Add tests for behavior changes.
3. Treat all external data as untrusted.
4. Do not collect or submit passwords, tokens, cookies, private messages, form values, or unrelated browsing history.
5. Explain security, privacy, and compatibility effects in the pull request.

## Validation

```powershell
dotnet build HIP.slnx -c Release
cd clients/browser-extension
npm ci
npm test
```

Use responsible disclosure rather than a public issue for suspected vulnerabilities.
