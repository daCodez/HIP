# HIP Browser Extension MVP

This is the first Chromium Manifest V3 client for HIP. It checks the current website domain, scans links on the page, shows risk badges only when attention is needed, and routes high-risk links through the HIP safety page.

## Configuration

The default local endpoints are in `src/hipApiClient.js`:

```js
apiBaseUrl: "https://localhost:7257"
webBaseUrl: "https://localhost:7053"
```

Update those values if your local launch profile uses different ports.

## Manual Test Steps

1. Start the HIP API:
   ```powershell
   dotnet run --project src/HIP.ApiService/HIP.ApiService.csproj --launch-profile https
   ```
2. Start the HIP Web app:
   ```powershell
   dotnet run --project src/HIP.Web/HIP.Web.csproj --launch-profile https
   ```
3. Open Chrome or Edge.
4. Go to `chrome://extensions` or `edge://extensions`.
5. Enable developer mode.
6. Select **Load unpacked**.
7. Choose `clients/browser-extension`.
8. Visit a normal test page with external links.
9. Open the HIP extension popup and confirm the website score appears.
10. Add or visit links containing test domains such as `danger-example.com`, `new-short-example.com`, or `verified-example.com`.
11. Confirm risky link badges appear beside risky links.
12. Click a risky link and confirm routing to `/safety?url=...`.

## Behavior

- Sends only domains to the HIP lookup API during page scanning.
- Does not send page body text, form contents, private messages, or full chat logs.
- Sends the original URL only when constructing the safety page route.
- If HIP is unavailable, the popup shows `HIP unavailable`, page behavior is not blocked, and links continue to work.

## Known Limitations

- No packaged image icons yet; SVG placeholders are used.
- No download scanning, form scanning, webmail parsing, social post parsing, or AI analysis.
- Link lookups are per target domain, not per full URL.
- Safety page risk details are query-string based until a richer backend risk lookup exists.
- Local HTTPS development certificates may need to be trusted before the extension can call HIP.
