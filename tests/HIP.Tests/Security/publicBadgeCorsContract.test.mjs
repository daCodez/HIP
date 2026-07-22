import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("embedded badge verification uses a public non-mutating CORS policy", async () => {
  const securityOptions = await readFile(
    new URL("../../../src/HIP.Application/Security/HipSecurityOptions.cs", import.meta.url),
    "utf8"
  );
  const webProgram = await readFile(
    new URL("../../../src/HIP.Web/Program.cs", import.meta.url),
    "utf8"
  );

  assert.match(securityOptions, /PublicBadgeVerification = "PublicHipBadgeVerification"/);
  assert.match(
    webProgram,
    /AddPolicy\(HipCorsPolicies\.PublicBadgeVerification[\s\S]*?AllowAnyOrigin\(\)[\s\S]*?WithMethods\("POST"\)/
  );
  assert.equal(
    (webProgram.match(/RequireCors\(HipCorsPolicies\.PublicBadgeVerification\)/g) || []).length,
    2
  );
});
