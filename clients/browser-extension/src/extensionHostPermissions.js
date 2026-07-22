/**
 * Converts a configured HIP service URL into the narrowest host permission
 * supported by Chromium match patterns. Ports cannot be restricted by a
 * match pattern, so the permission is limited to the selected scheme and host.
 */
export function hipHostPermissionPattern(baseUrl) {
  let url;
  try {
    url = new URL(baseUrl);
  } catch {
    throw new Error("Enter a valid HIP service URL.");
  }

  if (url.username || url.password) {
    throw new Error("HIP service URLs cannot contain credentials.");
  }

  if (url.protocol === "https:") {
    return `https://${url.hostname}/*`;
  }

  if (url.protocol === "http:" && isLoopbackHost(url.hostname)) {
    return `http://${url.hostname}/*`;
  }

  throw new Error("HIP service URLs must use HTTPS. HTTP is allowed only for local development.");
}

/**
 * Requests access only to the HIP service hosts selected in the options form.
 * Chromium requires this call to originate from a user action, so callers use
 * it directly from the Save Settings event handler.
 */
export async function ensureHipHostPermissions(baseUrls, permissionsApi = globalThis.chrome?.permissions) {
  const origins = [...new Set(baseUrls.map(hipHostPermissionPattern))];
  if (!permissionsApi?.contains || !permissionsApi?.request) {
    throw new Error("Browser host-permission controls are unavailable.");
  }

  const request = { origins };
  if (await permissionsApi.contains(request)) {
    return true;
  }

  return permissionsApi.request(request);
}

function isLoopbackHost(hostname) {
  const normalized = hostname.toLowerCase();
  return normalized === "localhost" || normalized === "127.0.0.1" || normalized === "[::1]";
}
