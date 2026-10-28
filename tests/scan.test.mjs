import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { compareVersions, buildFindings, scan } from "../skills/dep-triage/scripts/scan.mjs";
import { fixtureFetch, json, loadVuln, makeProject, nodeFixtureResponse, recordingFetch } from "./helpers.mjs";

const pkg = (name, version, extra = {}) => ({ name, version, direct: true, scope: "prod", introducedBy: [name], origin: "registry", ...extra });
const details = (...ids) => new Map(ids.map((id) => [id, loadVuln(id)]));
const LODASH = ["GHSA-29mw-wpgm-hmr9", "GHSA-35jh-r3h4-6jhm", "GHSA-f23m-r3pf-42rh", "GHSA-p6mc-m468-83gw", "GHSA-r5fr-rjxr-66jc", "GHSA-xxjr-mmjv-4gpg"];
const MINIMIST = "GHSA-xvch-5gv4-984h";
const CHALK = "MAL-2025-46969";
const synthetic = (id, extra = {}) => ({ id, summary: "s", details: "d", affected: [{ package: { name: "x", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.0.0" }] }] }], ...extra });

test("compareVersions orders releases, pre-releases and short versions", () => {
  assert.ok(compareVersions("4.17.15", "4.17.21") < 0);
  assert.ok(compareVersions("4.18.0", "4.17.23") > 0);
  assert.equal(compareVersions("1.2.6", "1.2.6"), 0);
  assert.ok(compareVersions("1.0.0-rc.1", "1.0.0") < 0);
  assert.ok(compareVersions("1.0.0-alpha", "1.0.0-beta") < 0);
  assert.ok(compareVersions("1.0.0-rc.2", "1.0.0-rc.10") < 0);
  assert.equal(compareVersions("1.0.0+build.5", "1.0.0"), 0);
  assert.equal(compareVersions("1.0", "1.0.0"), 0);
  assert.ok(compareVersions("0", "0.0.1") < 0);
  assert.equal(typeof compareVersions("not-a-version", "1.0.0"), "number");
});

test("aliases merge into one finding with the highest severity and fix", () => {
  const f = buildFindings([pkg("lodash", "4.17.15")], [LODASH], details(...LODASH));
  assert.deepEqual(f.map((x) => [x.id, x.severity, x.fixedIn]), [
    ["GHSA-35jh-r3h4-6jhm", "high", "4.18.0"],
    ["GHSA-p6mc-m468-83gw", "high", "4.17.19"],
    ["GHSA-29mw-wpgm-hmr9", "moderate", "4.17.21"],
    ["GHSA-f23m-r3pf-42rh", "moderate", "4.18.0"],
  ]);
  assert.deepEqual(f[0].aliases, ["CVE-2021-23337", "CVE-2026-4800", "GHSA-r5fr-rjxr-66jc"]);
});

test("a finding carries the package fields and the advisory fields", () => {
  const [f] = buildFindings([pkg("minimist", "1.2.5", { scope: "dev" })], [[MINIMIST]], details(MINIMIST));
  assert.equal(typeof f.details, "string");
  assert.deepEqual({ ...f, details: null }, {
    type: "vulnerability", id: MINIMIST, aliases: ["CVE-2021-44906"],
    package: "minimist", version: "1.2.5", direct: true, scope: "dev", introducedBy: ["minimist"],
    severity: "critical", summary: "Prototype Pollution in minimist", details: null, fixedIn: "1.2.6",
    url: "https://osv.dev/vulnerability/GHSA-xvch-5gv4-984h", detailsAvailable: true,
  });
});

test("fixedIn is the smallest fix above the installed version", () => {
  const [f] = buildFindings([pkg("minimist", "0.2.3")], [[MINIMIST]], details(MINIMIST));
  assert.equal(f.fixedIn, "0.2.4");
});

test("a malicious package is critical malware with no fix", () => {
  const [f] = buildFindings([pkg("chalk", "5.6.1")], [[CHALK]], details(CHALK));
  assert.deepEqual([f.type, f.id, f.severity, f.fixedIn, f.aliases], ["malware", CHALK, "critical", null, ["GHSA-2v46-p5h4-248w"]]);
});

test("an advisory shared by two packages gives one finding each", () => {
  const f = buildFindings([pkg("lodash", "4.17.15"), pkg("lodash-es", "4.17.15")], [["GHSA-35jh-r3h4-6jhm"], ["GHSA-35jh-r3h4-6jhm"]], details("GHSA-35jh-r3h4-6jhm"));
  assert.deepEqual(f.map((x) => [x.package, x.fixedIn]), [["lodash", "4.17.21"], ["lodash-es", "4.17.21"]]);
});

test("advisories sharing an alias merge even without citing each other", () => {
  const map = new Map([["GHSA-a", synthetic("GHSA-a", { aliases: ["CVE-1"] })], ["GHSA-b", synthetic("GHSA-b", { aliases: ["CVE-1"] })]]);
  const f = buildFindings([pkg("x", "1.0.0")], [["GHSA-b", "GHSA-a"]], map);
  assert.deepEqual(f.map((x) => [x.id, x.aliases]), [["GHSA-a", ["CVE-1", "GHSA-b"]]]);
});

test("unavailable details still give a finding", () => {
  const [f] = buildFindings([pkg("x", "1.0.0")], [["GHSA-gone"]], new Map([["GHSA-gone", null]]));
  assert.deepEqual([f.type, f.severity, f.summary, f.details, f.fixedIn, f.aliases, f.detailsAvailable], ["vulnerability", "unknown", null, null, null, [], false]);
  assert.equal(f.url, "https://osv.dev/vulnerability/GHSA-gone");
});

test("a group takes its text from a member whose details arrived", () => {
  const map = new Map([["GHSA-a", null], ["GHSA-b", synthetic("GHSA-b", { aliases: ["GHSA-a"], summary: "from b" })]]);
  const [f, ...rest] = buildFindings([pkg("x", "1.0.0")], [["GHSA-a", "GHSA-b"]], map);
  assert.deepEqual([rest.length, f.id, f.aliases, f.summary, f.fixedIn, f.detailsAvailable], [0, "GHSA-a", ["GHSA-b"], "from b", "2.0.0", true]);
});

test("a last_affected or git range has no fix, and long details are cut at 2000", () => {
  const ranges = [
    { type: "SEMVER", events: [{ introduced: "0" }, { last_affected: "1.5.0" }] },
    { type: "GIT", repo: "https://example.com/x.git", events: [{ introduced: "0" }, { fixed: "9f8e7d6c5b4a39281706f5e4d3c2b1a098765432" }] },
  ];
  const v = synthetic("GHSA-long", { details: "x".repeat(5000), affected: [{ package: { name: "x", ecosystem: "npm" }, ranges }] });
  const [f] = buildFindings([pkg("x", "1.0.0")], [["GHSA-long"]], new Map([["GHSA-long", v]]));
  assert.deepEqual([f.fixedIn, f.details.length, f.severity], [null, 2000, "unknown"]);
});

test("findings are sorted: malware, then severity, then package, then id", () => {
  const f = buildFindings(
    [pkg("lodash", "4.17.15"), pkg("minimist", "1.2.5"), pkg("chalk", "5.6.1")],
    [LODASH, [MINIMIST], [CHALK]],
    details(...LODASH, MINIMIST, CHALK),
  );
  assert.deepEqual(f.map((x) => x.id), [CHALK, MINIMIST, "GHSA-35jh-r3h4-6jhm", "GHSA-p6mc-m468-83gw", "GHSA-29mw-wpgm-hmr9", "GHSA-f23m-r3pf-42rh"]);
});

const FIXTURE = fileURLToPath(new URL("./fixtures/vulnerable-app", import.meta.url));
const SCRIPT = fileURLToPath(new URL("../skills/dep-triage/scripts/scan.mjs", import.meta.url));
const REG = (n, v) => `https://registry.npmjs.org/${n}/-/${n}-${v}.tgz`;
// The Node.js running the scan is pinned to a patched release, so that the tests do not depend on the machine.
const opts = (fetchFn) => ({ fetchFn, retryDelayMs: 0, now: () => new Date("2026-10-10T15:00:00.000Z"), nodeVersion: "v24.22.1" });
const project = (packages, pkg = {}) => makeProject({ "package.json": pkg, "package-lock.json": { lockfileVersion: 3, packages: { "": {}, ...packages } } });

test("scan reports the three cases of the example project", async () => {
  const { exitCode, output } = await scan(FIXTURE, opts(fixtureFetch()));
  assert.equal(exitCode, 1);
  assert.deepEqual([output.schemaVersion, output.project, output.scannedAt], [1, FIXTURE, "2026-10-10T15:00:00.000Z"]);
  assert.deepEqual(output.summary, { packagesChecked: 4, packagesSkipped: 0, malware: 1, vulnerabilities: 5, nodeVulnerabilities: 10, nodeEndOfLife: 0 });
  assert.deepEqual(output.findings.map((x) => x.id), [CHALK, MINIMIST, "GHSA-35jh-r3h4-6jhm", "GHSA-p6mc-m468-83gw", "GHSA-29mw-wpgm-hmr9", "GHSA-f23m-r3pf-42rh"]);
  const [chalk, minimist] = output.findings;
  assert.deepEqual([chalk.direct, chalk.scope, chalk.introducedBy], [false, "prod", ["ora", "chalk"]]);
  assert.deepEqual([minimist.direct, minimist.scope], [true, "dev"]);
  assert.deepEqual(output.node.versions.map((v) => [v.version, v.sources, v.vulnerabilities.length, v.fixedIn]), [
    ["24.18.0", [".nvmrc"], 10, "24.22.1"],
    ["24.22.1", ["runtime"], 0, null],
  ]);
  assert.deepEqual([output.node.supportedLines, output.node.notChecked], [["22", "24", "26"], []]);
  assert.deepEqual(Object.keys(output), ["schemaVersion", "project", "scannedAt", "summary", "findings", "node", "skipped"]);
  assert.deepEqual(output.skipped, []);
});

test("a path to package.json works like its folder", async () => {
  const { output } = await scan(path.join(FIXTURE, "package.json"), opts(fixtureFetch()));
  assert.equal(output.project, FIXTURE);
});

test("a clean project exits 0", async () => {
  const dir = project({ "node_modules/ora": { version: "8.2.0", resolved: REG("ora", "8.2.0") } }, { dependencies: { ora: "8.2.0" } });
  const { exitCode, output } = await scan(dir, opts(fixtureFetch()));
  assert.deepEqual([exitCode, output.findings, output.summary.packagesChecked], [0, [], 1]);
});

test("a project without dependencies exits 0 without calling OSV", async () => {
  const f = fixtureFetch();
  const { exitCode, output } = await scan(project({}), opts(f));
  const osvCalls = f.calls.filter((c) => c.url.startsWith("https://api.osv.dev/"));
  assert.deepEqual([exitCode, output.summary.packagesChecked, osvCalls.length], [0, 0, 0]);
});

test("a vulnerable or end-of-life Node.js alone exits 1", async () => {
  for (const [nvmrc, summary] of [["24.18.0", [10, 0]], ["20", [0, 1]]]) {
    const dir = makeProject({ "package.json": {}, "package-lock.json": { lockfileVersion: 3, packages: { "": {} } }, ".nvmrc": nvmrc });
    const { exitCode, output } = await scan(dir, opts(fixtureFetch()));
    assert.deepEqual([exitCode, output.findings, output.summary.nodeVulnerabilities, output.summary.nodeEndOfLife], [1, [], ...summary]);
  }
});

test("nodeVersion null leaves the running Node.js out", async () => {
  const { output } = await scan(project({}), { ...opts(fixtureFetch()), nodeVersion: null });
  assert.deepEqual(output.node.versions, []);
});

test("non-registry packages are skipped and never sent to OSV", async () => {
  const f = fixtureFetch();
  const dir = project({
    "node_modules/@acme/internal": { version: "1.0.0", resolved: "https://npm.acme.internal/@acme/internal/-/internal-1.0.0.tgz" },
    "node_modules/forked": { version: "2.0.0", resolved: "git+ssh://git@github.com/acme/forked.git#abc123" },
    "node_modules/ora": { version: "8.2.0", resolved: REG("ora", "8.2.0") },
  });
  const { output } = await scan(dir, opts(f));
  assert.deepEqual(output.skipped, [
    { package: "@acme/internal", version: "1.0.0", reason: "private-registry" },
    { package: "forked", version: "2.0.0", reason: "git" },
  ]);
  assert.deepEqual([output.summary.packagesChecked, output.summary.packagesSkipped], [1, 2]);
  const sent = f.calls.map((c) => c.url + (c.init?.body ?? "")).join("\n");
  assert.ok(!sent.includes("acme") && !sent.includes("forked"));
});

test("each failure exits 2 with its error code", async () => {
  const down = recordingFetch(() => json({}, 503));
  const cases = [
    [makeProject({}), "NO_PACKAGE_JSON"],
    [makeProject({ "package.json": {} }), "NO_LOCKFILE"],
    [makeProject({ "package.json": {}, "package-lock.json": "{ not json" }), "INVALID_JSON"],
    [makeProject({ "package.json": {}, "package-lock.json": { lockfileVersion: 1, dependencies: {} } }), "UNSUPPORTED_LOCKFILE"],
    [FIXTURE, "OSV_UNAVAILABLE"],
  ];
  for (const [dir, code] of cases) {
    const { exitCode, output } = await scan(dir, opts(down));
    assert.deepEqual([exitCode, output.error.code], [2, code]);
    assert.equal(typeof output.error.message, "string");
    assert.equal(typeof output.error.hint, "string");
  }
});

test("Node.js data that cannot be downloaded exits 2, even when OSV answered", async () => {
  const osv = fixtureFetch();
  const f = recordingFetch((url, init) => (nodeFixtureResponse(url) !== null ? json({}, 503) : osv(url, init)));
  const { exitCode, output } = await scan(FIXTURE, opts(f));
  assert.deepEqual([exitCode, output.error.code], [2, "NODE_DATA_UNAVAILABLE"]);
  assert.ok(output.error.hint.includes("NODE_USE_ENV_PROXY"));
});

test("NO_LOCKFILE gives the command, INVALID_JSON names the file", async () => {
  const a = await scan(makeProject({ "package.json": {} }), opts(fixtureFetch()));
  assert.equal(a.output.error.hint, "npm install --package-lock-only --ignore-scripts");
  const b = await scan(makeProject({ "package.json": {}, "package-lock.json": "{ not json" }), opts(fixtureFetch()));
  assert.ok(b.output.error.message.includes("package-lock.json"));
});

test("an unexpected exception exits 2, not 1", async () => {
  const { exitCode, output } = await scan(FIXTURE, { ...opts(fixtureFetch()), now: () => { throw new Error("boom"); } });
  assert.deepEqual([exitCode, output.error.code], [2, "INTERNAL_ERROR"]);
});

test("importing the script runs nothing, whatever the command line holds", () => {
  const code = `await import(${JSON.stringify(new URL("../skills/dep-triage/scripts/scan.mjs", import.meta.url).href)})`;
  const run = spawnSync(process.execPath, ["--input-type=module", "-e", code, "no-such-file"], { encoding: "utf8" });
  assert.deepEqual([run.status, run.stdout], [0, ""]);
});

test("the CLI prints JSON and sets the exit code", () => {
  const dir = makeProject({});
  for (const run of [spawnSync(process.execPath, [SCRIPT, dir], { encoding: "utf8" }), spawnSync(process.execPath, [SCRIPT], { cwd: dir, encoding: "utf8" })]) {
    assert.equal(run.status, 2);
    assert.equal(JSON.parse(run.stdout).error.code, "NO_PACKAGE_JSON");
  }
});
