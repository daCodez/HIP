# Contributing to HIP

Thanks for your interest in **HIP (Human Identity Protocol)**.
We welcome contributors who care about security, privacy, protocol quality, and practical trust tooling.

## What HIP needs most

- Protocol and architecture improvements
- Security hardening and validation
- Test coverage (unit/integration/e2e)
- Documentation clarity
- Client integration quality (browser extension, virtual-world client)

## Ground rules

1. Be respectful and constructive.
2. Keep changes focused and reviewable.
3. Prefer small pull requests over large “everything” PRs.
4. Include tests for behavior changes whenever possible.
5. Document security/privacy implications for trust-related changes.

## Before you start

- Read `README.md`
- Review docs under `docs/`
- Check existing issues/PRs to avoid duplication
- Open an issue/discussion first for major design changes

## Development setup

```powershell
dotnet restore HIP.slnx
dotnet build HIP.slnx
dotnet test HIP.slnx
```

Run local orchestration via AppHost (recommended):

```powershell
dotnet run --project src/HIP.AppHost/HIP.AppHost.csproj --launch-profile http
```

## Branch and commit guidance

- Branch naming:
  - `feat/<short-name>`
  - `fix/<short-name>`
  - `docs/<short-name>`
  - `test/<short-name>`
- Commit style (recommended Conventional Commits):
  - `feat: ...`
  - `fix: ...`
  - `docs: ...`
  - `test: ...`
  - `refactor: ...`
  - `chore: ...`

## Pull request checklist

Please include:

- Clear problem statement
- Summary of your approach
- Screenshots/UI notes (if relevant)
- Test evidence (what you ran)
- Security/privacy notes
- Backward-compatibility impact

## Security and privacy expectations

HIP is trust/security-sensitive. Treat all external input as untrusted.

- Validate and normalize inputs
- Avoid collecting unnecessary sensitive data
- Keep secrets/tokens out of source, logs, and test fixtures
- Do not submit raw private user content in sample payloads

If you discover a vulnerability, use responsible disclosure (see `SECURITY.md` if available).

## Good first contributions

- Docs cleanup and examples
- Test additions for risk/status mapping
- Input validation improvements
- Safer defaults in client settings
- Better error messages and operator visibility

## Questions?

Open a GitHub Discussion or Issue with:

- context,
- expected behavior,
- current behavior,
- and proposed direction.
