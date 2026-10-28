import { test } from "node:test";
import assert from "node:assert/strict";
import { checkNode, fetchNodeData, readNodeDeclarations, satisfies } from "../skills/dep-triage/scripts/node.mjs";
import { fixtureFetch, json, makeProject, nodeFixtureResponse, recordingFetch } from "./helpers.mjs";

const fast = (fetchFn) => ({ fetchFn, retryDelayMs: 0 });
const TODAY = new Date("2026-10-28T09:00:00.000Z");
const data = () => fetchNodeData(fast(fixtureFetch()));
const declared = (...values) => values.map((value, i) => ({ source: `s${i}`, value }));
const ids = (version) => version.vulnerabilities.map((v) => v.id);
const failing = { code: "NODE_DATA_UNAVAILABLE" };

test("satisfies reads every range shape of the Node.js advisories", () => {
  const cases = [
    ["24.18.0", "22.x || 24.x || 26.x", true],
    ["25.0.0", "22.x || 24.x || 26.x", false],
    ["24.22.1", "^22.23.4 || ^24.22.1 || ^26.12.1", true],
    ["24.22.0", "^22.23.4 || ^24.22.1 || ^26.12.1", false],
    ["25.0.0", "^24.22.1", false],
    ["10.9.0", ">= 10.9.0", true],
    ["10.8.9", ">= 10.9.0", false],
    ["6.1.9", ">=6.0.0 <6.2.0 || 5.x || 4.x", true],
    ["6.2.0", ">=6.0.0 <6.2.0 || 5.x || 4.x", false],
    ["10.99.0", "<= 10", true],
    ["11.0.0", "<= 10", false],
    ["8.11.3", "8.11.x", true],
    ["8.12.0", "8.11.x", false],
    ["10.1.0", "10.1.0", true],
    ["10.1.1", "10.1.0", false],
    ["0.10.48", "^0.10.0", true],
    ["0.11.0", "^0.10.0", false],
    ["1.2.9", "~1.2.3", true],
    ["1.3.0", "~1.2.3", false],
    ["2.0.0", ">1.9.9", true],
    ["24.0.0", "not a range", false],
    ["24", "24.x", false],
  ];
  for (const [version, range, expected] of cases) assert.equal(satisfies(version, range), expected, `${version} in ${range}`);
});

test("readNodeDeclarations reads version files, volta and root Dockerfiles", () => {
  const dir = makeProject({
    "package.json": {},
    ".nvmrc": "# pinned for the team\nv24.18.0 # LTS\n",
    ".node-version": "22.23.4\n",
    ".tool-versions": "python 3.13.1\nnodejs 24.20.0 24.19.0\n",
    Dockerfile: [
      "ARG NODE_VERSION=24.18.0",
      "FROM --platform=linux/amd64 node:${NODE_VERSION}-alpine AS build",
      "FROM nginx:1.27",
      "FROM docker.io/library/node:20-slim@sha256:abc",
      "FROM build",
    ].join("\n"),
    "web.Dockerfile": "FROM node\n",
    "docs/Dockerfile": "FROM node:18\n",
  });
  assert.deepEqual(readNodeDeclarations(dir, { volta: { node: "26.12.1" } }), [
    { source: ".nvmrc", value: "v24.18.0" },
    { source: ".node-version", value: "22.23.4" },
    { source: ".tool-versions", value: "24.20.0" },
    { source: "package.json (volta)", value: "26.12.1" },
    { source: "Dockerfile:2", value: "24.18.0" },
    { source: "Dockerfile:4", value: "20" },
    { source: "web.Dockerfile:1", value: "latest" },
  ]);
});

test("a project that declares no Node.js version gives no declaration", () => {
  const dir = makeProject({ "package.json": { engines: { node: ">=22" } }, ".nvmrc": "\n# nothing\n" });
  assert.deepEqual(readNodeDeclarations(dir, { engines: { node: ">=22" } }), []);
});

test("fetchNodeData reads the index, then the files past it until a 404", async () => {
  const f = fixtureFetch();
  const { advisories, schedule } = await fetchNodeData(fast(f));
  assert.deepEqual(advisories.map((a) => a.number), [193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204]);
  assert.equal(advisories.at(-1).cve[0], "CVE-2026-111497");
  assert.equal(schedule.v24.end, "2028-04-30");
  assert.ok(f.calls.at(-1).url.endsWith("/vuln/core/205.json"));
});

test("each download failure gives NODE_DATA_UNAVAILABLE", async () => {
  const handlers = [
    () => json({}, 503),
    (url) => (url.endsWith("schedule.json") ? new Response("404: Not Found", { status: 404 }) : nodeFixtureResponse(url)),
    (url) => (url.endsWith("index.json") ? new Response("not json") : nodeFixtureResponse(url)),
    (url) => (url.endsWith("index.json") ? json([]) : nodeFixtureResponse(url)),
    (url) => (url.endsWith("/197.json") ? json({}, 500) : nodeFixtureResponse(url)),
    () => {
      throw new TypeError("fetch failed");
    },
  ];
  for (const handler of handlers) await assert.rejects(fetchNodeData(fast(recordingFetch(handler))), failing);
});

test("an advisory list that never ends is refused", async () => {
  const endless = recordingFetch((url) => (url.endsWith("index.json") || url.endsWith("schedule.json") ? nodeFixtureResponse(url) : json({ cve: [] })));
  await assert.rejects(fetchNodeData(fast(endless)), failing);
});

test("a pinned version lists the advisories it is not patched for, and the release that fixes them all", async () => {
  const [v24] = checkNode([{ source: ".nvmrc", value: "24.18.0" }, { source: "runtime", value: "v24.18.0" }], await data(), TODAY).versions;
  assert.deepEqual([v24.version, v24.pinned, v24.sources, v24.endOfLife, v24.endOfLifeDate, v24.fixedIn], ["24.18.0", true, [".nvmrc", "runtime"], false, "2028-04-30", "24.22.1"]);
  assert.deepEqual(ids(v24), [
    "CVE-2026-105482", "CVE-2026-105483", "CVE-2026-106069", "CVE-2026-111497",
    "CVE-2026-105481", "CVE-2026-106072", "CVE-2026-106074", "CVE-2026-58045",
    "CVE-2026-106073", "CVE-2026-58044",
  ]);
  assert.deepEqual(v24.vulnerabilities[3], {
    id: "CVE-2026-111497", aliases: [], severity: "high",
    summary: v24.vulnerabilities[3].summary, platforms: ["all"],
    url: "https://nodejs.org/en/blog/vulnerability/october-2026-security-releases",
  });
  assert.equal(typeof v24.vulnerabilities[3].summary, "string");
  assert.equal(v24.vulnerabilities[4].severity, "moderate");
});

test("each release line gets its own advisories and fix", async () => {
  const { versions } = checkNode(declared("22.23.2", "26.5.0", "24.22.1"), await data(), TODAY);
  const [v22, v26, patched] = versions;
  assert.deepEqual([ids(v22).length, ids(v22).includes("CVE-2026-105483"), v22.fixedIn], [7, false, "22.23.4"]);
  assert.deepEqual([ids(v26).length, v26.fixedIn], [12, "26.12.1"]);
  assert.deepEqual([patched.vulnerabilities, patched.fixedIn], [[], null]);
});

test("an end-of-life line is flagged, with no fix to offer on it", async () => {
  const { versions, supportedLines } = checkNode(declared("20.11.0", "lts/iron", "24"), await data(), TODAY);
  assert.deepEqual(versions.map((v) => [v.version, v.pinned, v.endOfLife, v.endOfLifeDate, v.fixedIn]), [
    ["20.11.0", true, true, "2026-04-30", null],
    ["20", false, true, "2026-04-30", null],
    ["24", false, false, "2028-04-30", null],
  ]);
  assert.deepEqual(supportedLines, ["22", "24", "26"]);
});

test("values that name no version are not checked, and a line outside the calendar has no end date", async () => {
  const { versions, notChecked } = checkNode(declared("lts/*", "latest", "99.0.0"), await data(), TODAY);
  assert.deepEqual(notChecked, [{ source: "s0", value: "lts/*" }, { source: "s1", value: "latest" }]);
  assert.deepEqual(versions.map((v) => [v.version, v.endOfLife, v.endOfLifeDate]), [["99.0.0", null, null]]);
});
