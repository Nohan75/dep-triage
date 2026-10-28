// Runs against the real Node.js data on GitHub. Not part of `npm test`: run it with `npm run test:live`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { checkNode, fetchNodeData } from "../../skills/dep-triage/scripts/node.mjs";

test("Node.js 24.18.0 is reported as vulnerable to CVE-2026-111497, 24.22.1 is not", async () => {
  const data = await fetchNodeData();
  const [old, patched] = checkNode([{ source: "a", value: "24.18.0" }, { source: "b", value: "24.22.1" }], data, new Date()).versions;
  assert.ok(old.vulnerabilities.some((v) => v.id === "CVE-2026-111497"));
  assert.ok(!patched.vulnerabilities.some((v) => v.id === "CVE-2026-111497"));
  assert.equal(typeof data.schedule.v24.end, "string");
});
