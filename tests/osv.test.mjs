import { test } from "node:test";
import assert from "node:assert/strict";
import { queryBatch, fetchDetails } from "../skills/dep-triage/scripts/osv.mjs";
import { json, recordingFetch, fixtureFetch } from "./helpers.mjs";

const fast = (fetchFn) => ({ fetchFn, retryDelayMs: 0 });
const pkgs = (n) => Array.from({ length: n }, (_, i) => ({ name: `p${i}`, version: "1.0.0" }));
const queries = (call) => JSON.parse(call.init.body).queries;
const empty = (init) => json({ results: JSON.parse(init.body).queries.map(() => ({})) });
const failing = { code: "OSV_UNAVAILABLE" };

test("queryBatch posts name, ecosystem and version, and returns ids per package", async () => {
  const f = fixtureFetch();
  const ids = await queryBatch([{ name: "chalk", version: "5.6.1" }, { name: "ora", version: "8.2.0" }], fast(f));
  assert.deepEqual(ids, [["MAL-2025-46969"], []]);
  assert.equal(f.calls[0].url, "https://api.osv.dev/v1/querybatch");
  assert.equal(f.calls[0].init.method, "POST");
  assert.deepEqual(queries(f.calls[0])[0], { package: { name: "chalk", ecosystem: "npm" }, version: "5.6.1" });
  assert.ok(f.calls[0].init.signal instanceof AbortSignal);
});

test("queryBatch makes no call for an empty list", async () => {
  const f = recordingFetch((url, init) => empty(init));
  assert.deepEqual(await queryBatch([], fast(f)), []);
  assert.equal(f.calls.length, 0);
});

test("queryBatch splits into lots of 1000", async () => {
  const f = recordingFetch((url, init) => empty(init));
  const ids = await queryBatch(pkgs(2500), fast(f));
  assert.deepEqual(f.calls.map((c) => queries(c).length), [1000, 1000, 500]);
  assert.equal(ids.length, 2500);
});

test("queryBatch follows next_page_token", async () => {
  const pages = [
    { results: [{ vulns: [{ id: "A" }], next_page_token: "t1" }, { vulns: [{ id: "C" }] }] },
    { results: [{ vulns: [{ id: "B" }] }] },
  ];
  const f = recordingFetch(() => json(pages.shift()));
  assert.deepEqual(await queryBatch(pkgs(2), fast(f)), [["A", "B"], ["C"]]);
  assert.deepEqual(queries(f.calls[1]), [{ package: { name: "p0", ecosystem: "npm" }, version: "1.0.0", page_token: "t1" }]);
});

test("queryBatch stops when the pages never end", async () => {
  const f = recordingFetch(() => json({ results: [{ vulns: [{ id: "A" }], next_page_token: "again" }] }));
  await assert.rejects(queryBatch(pkgs(1), fast(f)), failing);
  assert.ok(f.calls.length <= 100);
});

test("queryBatch retries once on 503, 429 and network errors", async () => {
  for (const fail of [() => json({}, 503), () => json({}, 429), () => { throw new TypeError("fetch failed"); }]) {
    let n = 0;
    const f = recordingFetch((url, init) => (n++ === 0 ? fail() : empty(init)));
    assert.deepEqual(await queryBatch(pkgs(1), fast(f)), [[]]);
    assert.equal(f.calls.length, 2);
  }
});

test("queryBatch gives up after the second failure", async () => {
  const f = recordingFetch(() => json({}, 503));
  await assert.rejects(queryBatch(pkgs(1), fast(f)), failing);
  assert.equal(f.calls.length, 2);
});

test("queryBatch does not retry a 400", async () => {
  const f = recordingFetch(() => json({}, 400));
  await assert.rejects(queryBatch(pkgs(1), fast(f)), failing);
  assert.equal(f.calls.length, 1);
});

test("queryBatch rejects an unreadable or mismatched body", async () => {
  await assert.rejects(queryBatch(pkgs(1), fast(recordingFetch(() => new Response("not json")))), failing);
  await assert.rejects(queryBatch(pkgs(1), fast(recordingFetch(() => json({ results: [] })))), failing);
});

test("fetchDetails returns one record per distinct id", async () => {
  const f = fixtureFetch();
  const map = await fetchDetails(["MAL-2025-46969", "MAL-2025-46969", "GHSA-xvch-5gv4-984h"], fast(f));
  assert.equal(map.size, 2);
  assert.equal(map.get("GHSA-xvch-5gv4-984h").id, "GHSA-xvch-5gv4-984h");
  assert.deepEqual(f.calls.map((c) => c.url).sort(), [
    "https://api.osv.dev/v1/vulns/GHSA-xvch-5gv4-984h",
    "https://api.osv.dev/v1/vulns/MAL-2025-46969",
  ]);
});

test("fetchDetails marks a failing id as null and keeps the others", async () => {
  const f = recordingFetch((url) => (url.endsWith("/BAD") ? json({}, 500) : json({ id: "OK" })));
  const map = await fetchDetails(["BAD", "OK"], fast(f));
  assert.equal(map.get("BAD"), null);
  assert.equal(map.get("OK").id, "OK");
  assert.equal(f.calls.filter((c) => c.url.endsWith("/BAD")).length, 2);
});

test("fetchDetails runs at most 8 requests at once", async () => {
  let inFlight = 0, max = 0;
  const f = recordingFetch(async () => {
    max = Math.max(max, ++inFlight);
    await new Promise((r) => setTimeout(r, 5));
    inFlight--;
    return json({ id: "x" });
  });
  await fetchDetails(Array.from({ length: 20 }, (_, i) => `ID-${i}`), fast(f));
  assert.equal(max, 8);
});
