// Runs against the real OSV.dev API. Not part of `npm test`: run it with `npm run test:live`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { queryBatch, fetchDetails } from "../../skills/dep-triage/scripts/osv.mjs";

test("chalk 5.6.1 is reported as malicious, react 19.0.0 is clean", async () => {
  const ids = await queryBatch([{ name: "chalk", version: "5.6.1" }, { name: "react", version: "19.0.0" }]);
  assert.ok(ids[0].includes("MAL-2025-46969"));
  assert.deepEqual(ids[1], []);
  assert.equal((await fetchDetails(ids[0])).get("MAL-2025-46969").id, "MAL-2025-46969");
});
