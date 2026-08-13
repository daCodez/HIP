import assert from "node:assert/strict";
import test from "node:test";
import { HipApiClient } from "../src/hipApiClient.js";

test("extension verifies signed badge state then retrieves the certificate directly from HIP", async () => {
  const calls = [];
  const originalFetch = globalThis.fetch;
  const certificateState = {
    certificateId: "hip-domain-cert-0001",
    domain: "example.com",
    level: "Verified",
    status: "Active",
    signatureStatus: "Verified",
    expiresAtUtc: "2026-08-24T00:00:00Z",
    publicCertificateUrl: "https://hiptrust.com/certificate/hip-domain-cert-0001",
    isActive: true
  };  globalThis.fetch = async (url, options = {}) => {
    calls.push({ url, options });
    if (url.endsWith("/badge/domain/example.com")) {
      return response({
        domain: "example.com",
        signedBadge: { payload: { domain: "example.com", certificate: certificateState }, signature: { value: "signed" } },
        certificate: certificateState
      });
    }
    if (url.endsWith("/badge/verify")) {
      return response({ isVerified: true, status: "Verified" });
    }
    return response({
      signedCertificate: {
        payload: {
          certificateId: "hip-domain-cert-0001",
          domain: "example.com",
          level: 1,
          status: 3,
          expiresAtUtc: "2026-08-23T20:00:00-04:00",
          publicCertificateUrl: "https://hiptrust.com/certificate/hip-domain-cert-0001"
        }
      },
      currentStatus: 3,
      signatureStatus: 0,
      validityStatus: 0,
      isActive: true
    });
  };

  try {
    const client = new HipApiClient({
      apiBaseUrl: "http://localhost:5099",
      webBaseUrl: "http://localhost:5123"
    });

    const result = await client.verifyDomainCertificate("example.com");

    assert.deepEqual(result, {
      certificateId: "hip-domain-cert-0001",
      domain: "example.com",
      level: "Verified",
      status: "Active",
      signatureStatus: "Verified",
      validityStatus: "Current",
      expiresAtUtc: "2026-08-23T20:00:00-04:00",
      publicCertificateUrl: "https://hiptrust.com/certificate/hip-domain-cert-0001",
      isActive: true
    });
    assert.equal(calls.length, 3);
    assert.match(calls[0].url, /\/api\/v1\/public\/badge\/domain\/example\.com$/);
    assert.match(calls[1].url, /\/api\/v1\/public\/badge\/verify$/);
    assert.match(calls[2].url, /\/api\/v1\/public\/certificates\/hip-domain-cert-0001$/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("extension recognizes the certified certificate level returned by production", async () => {
  const originalFetch = globalThis.fetch;
  const certificateState = {
    certificateId: "hip-domain-cert-certified",
    domain: "example.com",
    level: "Certified",
    status: "Active",
    signatureStatus: "Verified",
    expiresAtUtc: "2027-08-11T00:00:00Z",
    publicCertificateUrl: "https://guardwithhip.com/certificate/hip-domain-cert-certified",
    isActive: true
  };
  globalThis.fetch = async url => {
    if (url.endsWith("/badge/domain/example.com")) {
      return response({
        domain: "example.com",
        signedBadge: { payload: { domain: "example.com", certificate: certificateState }, signature: { value: "signed" } },
        certificate: certificateState
      });
    }
    if (url.endsWith("/badge/verify")) return response({ isVerified: true, status: "Verified" });
    return response({
      signedCertificate: {
        payload: {
          certificateId: certificateState.certificateId,
          domain: certificateState.domain,
          level: 3,
          status: 3,
          expiresAtUtc: certificateState.expiresAtUtc,
          publicCertificateUrl: certificateState.publicCertificateUrl
        }
      },
      currentStatus: 3,
      signatureStatus: 0,
      validityStatus: 0,
      isActive: true
    });
  };

  try {
    const client = new HipApiClient({ apiBaseUrl: "http://localhost:5099", webBaseUrl: "http://localhost:5123" });
    const result = await client.verifyDomainCertificate("example.com");
    assert.equal(result.level, "Certified");
    assert.equal(result.isActive, true);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("extension rejects certificate presentation fields that differ from the signed badge", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => response({
    domain: "example.com",
    signedBadge: {
      payload: {
        domain: "example.com",
        certificate: {
          certificateId: "hip-domain-cert-0001",
          domain: "example.com",
          level: "Verified",
          status: "Active",
          signatureStatus: "Verified",
          expiresAtUtc: "2026-08-24T00:00:00Z",
          publicCertificateUrl: "https://hiptrust.com/certificate/hip-domain-cert-0001",
          isActive: true
        }
      },
      signature: { value: "signed" }
    },
    certificate: {
      certificateId: "hip-domain-cert-0001",
      domain: "example.com",
      level: "Monitored",
      status: "Active",
      signatureStatus: "Verified",
      expiresAtUtc: "2026-08-24T00:00:00Z",
      publicCertificateUrl: "https://hiptrust.com/certificate/hip-domain-cert-0001",
      isActive: true
    }
  });

  try {
    const client = new HipApiClient({
      apiBaseUrl: "http://localhost:5099",
      webBaseUrl: "http://localhost:5123"
    });

    await assert.rejects(
      client.verifyDomainCertificate("example.com"),
      /no domain-matching certificate/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("extension verifies a changed lifecycle state without rewriting the signed issuance record", async () => {
  const originalFetch = globalThis.fetch;
  const currentCertificateState = {
    certificateId: "hip-domain-cert-0001",
    domain: "example.com",
    level: "Verified",
    status: "Suspended",
    signatureStatus: "Verified",
    expiresAtUtc: "2026-08-24T00:00:00Z",
    publicCertificateUrl: "https://hiptrust.com/certificate/hip-domain-cert-0001",
    isActive: false
  };
  globalThis.fetch = async url => {
    if (url.endsWith("/badge/domain/example.com")) {
      return response({
        domain: "example.com",
        signedBadge: {
          payload: { domain: "example.com", certificate: currentCertificateState },
          signature: { value: "signed" }
        },
        certificate: currentCertificateState
      });
    }
    if (url.endsWith("/badge/verify")) {
      return response({ isVerified: true, status: "Verified" });
    }
    return response({
      signedCertificate: {
        payload: {
          certificateId: "hip-domain-cert-0001",
          domain: "example.com",
          level: 1,
          status: 3,
          expiresAtUtc: "2026-08-24T00:00:00Z",
          publicCertificateUrl: "https://hiptrust.com/certificate/hip-domain-cert-0001"
        }
      },
      currentStatus: 4,
      signatureStatus: 0,
      validityStatus: 0,
      isActive: false
    });
  };

  try {
    const client = new HipApiClient({
      apiBaseUrl: "http://localhost:5099",
      webBaseUrl: "http://localhost:5123"
    });

    const result = await client.verifyDomainCertificate("example.com");

    assert.equal(result.status, "Suspended");
    assert.equal(result.isActive, false);
    assert.equal(result.signatureStatus, "Verified");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("extension rejects an active claim that conflicts with current lifecycle validity", async () => {
  const originalFetch = globalThis.fetch;
  const activeCertificateState = {
    certificateId: "hip-domain-cert-0001",
    domain: "example.com",
    level: "Verified",
    status: "Active",
    signatureStatus: "Verified",
    expiresAtUtc: "2026-08-24T00:00:00Z",
    publicCertificateUrl: "https://hiptrust.com/certificate/hip-domain-cert-0001",
    isActive: true
  };
  globalThis.fetch = async url => {
    if (url.endsWith("/badge/domain/example.com")) {
      return response({
        domain: "example.com",
        signedBadge: {
          payload: { domain: "example.com", certificate: activeCertificateState },
          signature: { value: "signed" }
        },
        certificate: activeCertificateState
      });
    }
    if (url.endsWith("/badge/verify")) {
      return response({ isVerified: true, status: "Verified" });
    }
    return response({
      signedCertificate: {
        payload: {
          certificateId: "hip-domain-cert-0001",
          domain: "example.com",
          level: 1,
          status: 3,
          expiresAtUtc: "2026-08-24T00:00:00Z",
          publicCertificateUrl: "https://hiptrust.com/certificate/hip-domain-cert-0001"
        }
      },
      currentStatus: 3,
      signatureStatus: 0,
      validityStatus: 2,
      isActive: true
    });
  };

  try {
    const client = new HipApiClient({
      apiBaseUrl: "http://localhost:5099",
      webBaseUrl: "http://localhost:5123"
    });

    await assert.rejects(
      client.verifyDomainCertificate("example.com"),
      /certificate state is unavailable or inconsistent/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
function response(body) {
  return {
    ok: true,
    status: 200,
    json: async () => body
  };
}
