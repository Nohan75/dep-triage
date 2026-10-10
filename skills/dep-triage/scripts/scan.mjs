// Entry point of the scanner: reads a project's lockfile, asks OSV.dev about every public
// package, and prints the findings as JSON. Read-only: it never installs or runs anything.
//
// Usage: node scan.mjs [project-folder | path/to/package.json]
// Exit code: 0 = no finding, 1 = at least one finding, 2 = the scan could not be completed.

import { readFileSync, realpathSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { listPackages } from "./lockfile.mjs";
import { fetchDetails, queryBatch } from "./osv.mjs";

const HINTS = {
  NO_PACKAGE_JSON: "Check the path: it must be a folder that contains a package.json.",
  NO_LOCKFILE: "npm install --package-lock-only --ignore-scripts",
  UNSUPPORTED_LOCKFILE: "Regenerate the lockfile with npm 7 or later: npm install --package-lock-only --ignore-scripts",
  INVALID_JSON: "Fix or regenerate the file named in the message.",
  OSV_UNAVAILABLE: "Try again later. Behind a proxy, set NODE_USE_ENV_PROXY=1 so that Node uses it.",
  INTERNAL_ERROR: "This is a bug in dep-triage. Please report it at https://github.com/Nohan75/dep-triage/issues.",
};

const SEVERITY_RANK = { critical: 4, high: 3, moderate: 2, low: 1, unknown: 0 };
const DETAILS_LIMIT = 2000;
// A fix in a GIT range is a commit hash, not a version that can be installed.
const VERSIONED_RANGE_TYPES = new Set(["SEMVER", "ECOSYSTEM"]);

function parseVersion(version) {
  const [core, ...rest] = String(version).trim().replace(/^v/, "").split("+")[0].split("-");
  const numbers = core.split(".").map((part) => Number.parseInt(part, 10) || 0);
  return { numbers, prerelease: rest.length > 0 ? rest.join("-").split(".") : [] };
}

/**
 * Semver ordering, tolerant of short or odd versions (it never throws).
 * @returns {number} negative when a < b, 0 when equal, positive when a > b
 */
export function compareVersions(a, b) {
  const x = parseVersion(a);
  const y = parseVersion(b);
  for (let i = 0; i < Math.max(x.numbers.length, y.numbers.length); i++) {
    const difference = (x.numbers[i] ?? 0) - (y.numbers[i] ?? 0);
    if (difference !== 0) return difference;
  }
  // A release is newer than any of its pre-releases.
  if (x.prerelease.length === 0 || y.prerelease.length === 0) return y.prerelease.length - x.prerelease.length;
  for (let i = 0; i < Math.max(x.prerelease.length, y.prerelease.length); i++) {
    const p = x.prerelease[i];
    const q = y.prerelease[i];
    if (p === undefined) return -1;
    if (q === undefined) return 1;
    const pIsNumber = /^\d+$/.test(p);
    const qIsNumber = /^\d+$/.test(q);
    if (pIsNumber && qIsNumber) {
      if (Number(p) !== Number(q)) return Number(p) - Number(q);
    } else if (pIsNumber !== qIsNumber) {
      return pIsNumber ? -1 : 1;
    } else if (p !== q) {
      return p < q ? -1 : 1;
    }
  }
  return 0;
}

function compareText(a, b) {
  if (a === b) return 0;
  return a < b ? -1 : 1;
}

function severityOf(record) {
  const severity = String(record?.database_specific?.severity ?? "").toLowerCase();
  return Object.hasOwn(SEVERITY_RANK, severity) ? severity : "unknown";
}

// The smallest published fix above the installed version, or null.
function fixedInOf(record, pkg) {
  let best = null;
  for (const affected of record?.affected ?? []) {
    if (affected?.package?.ecosystem !== "npm" || affected.package.name !== pkg.name) continue;
    for (const range of affected.ranges ?? []) {
      if (!VERSIONED_RANGE_TYPES.has(range?.type)) continue;
      for (const event of range.events ?? []) {
        const fixed = event?.fixed;
        if (typeof fixed !== "string" || compareVersions(fixed, pkg.version) <= 0) continue;
        if (best === null || compareVersions(fixed, best) < 0) best = fixed;
      }
    }
  }
  return best;
}

// OSV often returns several advisories for one flaw. Two advisories belong together
// when one names the other in its aliases, or when they share an alias.
function groupByAlias(ids, details) {
  const parent = new Map(ids.map((id) => [id, id]));
  const find = (id) => {
    while (parent.get(id) !== id) id = parent.get(id);
    return id;
  };
  const firstCarrier = new Map();
  for (const id of ids) {
    for (const name of [id, ...(details.get(id)?.aliases ?? [])]) {
      if (firstCarrier.has(name)) parent.set(find(id), find(firstCarrier.get(name)));
      else firstCarrier.set(name, id);
    }
  }
  const groups = new Map();
  for (const id of ids) {
    const root = find(id);
    if (!groups.has(root)) groups.set(root, []);
    groups.get(root).push(id);
  }
  return [...groups.values()];
}

function toFinding(pkg, group, details) {
  const members = [...group].sort(compareText);
  const id = members.find((member) => member.startsWith("MAL-")) ?? members[0];
  const records = members.map((member) => details.get(member)).filter(Boolean);
  // The text comes from the representative when its details arrived, otherwise from another member.
  const source = details.get(id) ?? records[0] ?? null;

  const names = new Set(members);
  for (const record of records) for (const alias of record.aliases ?? []) names.add(alias);
  names.delete(id);
  const aliases = [...names].sort(compareText);

  const isMalware = id.startsWith("MAL-") || aliases.some((alias) => alias.startsWith("MAL-"));
  let severity = "unknown";
  let fixedIn = null;
  for (const record of records) {
    const recordSeverity = severityOf(record);
    if (SEVERITY_RANK[recordSeverity] > SEVERITY_RANK[severity]) severity = recordSeverity;
    const recordFix = fixedInOf(record, pkg);
    if (recordFix !== null && (fixedIn === null || compareVersions(recordFix, fixedIn) > 0)) fixedIn = recordFix;
  }

  return {
    type: isMalware ? "malware" : "vulnerability",
    id,
    aliases,
    package: pkg.name,
    version: pkg.version,
    direct: pkg.direct,
    scope: pkg.scope,
    introducedBy: pkg.introducedBy,
    severity: isMalware ? "critical" : severity,
    summary: typeof source?.summary === "string" ? source.summary : null,
    details: typeof source?.details === "string" ? source.details.slice(0, DETAILS_LIMIT) : null,
    fixedIn,
    url: `https://osv.dev/vulnerability/${id}`,
    detailsAvailable: source !== null,
  };
}

/**
 * @param {import("./lockfile.mjs").Pkg[]} packages
 * @param {string[][]} idsByPackage advisory ids of packages[i]
 * @param {Map<string, object | null>} details raw OSV record per id, null when it could not be fetched
 * @returns {object[]} findings: malware first, then by severity, package name and id
 */
export function buildFindings(packages, idsByPackage, details) {
  const findings = [];
  packages.forEach((pkg, i) => {
    const ids = [...new Set(idsByPackage[i] ?? [])];
    for (const group of groupByAlias(ids, details)) findings.push(toFinding(pkg, group, details));
  });
  return findings.sort(
    (a, b) =>
      (b.type === "malware") - (a.type === "malware") ||
      SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
      compareText(a.package, b.package) ||
      compareText(a.id, b.id),
  );
}

function failure(code, message) {
  return Object.assign(new Error(message), { code });
}

// Accepts the project folder, or the path of its package.json.
function projectFolder(projectPath) {
  const resolved = path.resolve(projectPath);
  const isPackageJson = path.basename(resolved) === "package.json" && statSync(resolved, { throwIfNoEntry: false })?.isFile();
  return isPackageJson ? path.dirname(resolved) : resolved;
}

function readJson(folder, file, missingCode) {
  let text;
  try {
    text = readFileSync(path.join(folder, file), "utf8");
  } catch (error) {
    if (error.code === "ENOENT" || error.code === "ENOTDIR") {
      const monorepo = missingCode === "NO_LOCKFILE" ? " In a monorepo, scan the root folder: that is where the lockfile lives." : "";
      throw failure(missingCode, `No ${file} found in ${folder}.${monorepo}`);
    }
    throw error;
  }
  try {
    return JSON.parse(text);
  } catch {
    throw failure("INVALID_JSON", `${file} in ${folder} is not valid JSON.`);
  }
}

/**
 * Scans one project. Never throws: a failure becomes exit code 2 with an `error` object,
 * so that a crash can never be mistaken for "no finding".
 * @param {string} [projectPath] the project folder or its package.json; defaults to the current folder
 * @param {{ fetchFn?: typeof fetch, retryDelayMs?: number, now?: () => Date }} [options]
 * @returns {Promise<{ exitCode: 0 | 1 | 2, output: object }>}
 */
export async function scan(projectPath = process.cwd(), { fetchFn, retryDelayMs, now = () => new Date() } = {}) {
  try {
    const folder = projectFolder(projectPath);
    const packageJson = readJson(folder, "package.json", "NO_PACKAGE_JSON");
    const lockfile = readJson(folder, "package-lock.json", "NO_LOCKFILE");

    const packages = listPackages(packageJson, lockfile);
    const checked = packages.filter((pkg) => pkg.origin === "registry");
    const skipped = packages
      .filter((pkg) => pkg.origin !== "registry")
      .map((pkg) => ({ package: pkg.name, version: pkg.version, reason: pkg.origin }));

    const idsByPackage = await queryBatch(checked, { fetchFn, retryDelayMs });
    const details = await fetchDetails(idsByPackage.flat(), { fetchFn, retryDelayMs });
    const findings = buildFindings(checked, idsByPackage, details);
    const malware = findings.filter((finding) => finding.type === "malware").length;

    const output = {
      schemaVersion: 1,
      project: folder,
      scannedAt: now().toISOString(),
      summary: {
        packagesChecked: checked.length,
        packagesSkipped: skipped.length,
        malware,
        vulnerabilities: findings.length - malware,
      },
      findings,
      skipped,
    };
    return { exitCode: findings.length > 0 ? 1 : 0, output };
  } catch (error) {
    const known = typeof error?.code === "string" && Object.hasOwn(HINTS, error.code);
    const code = known ? error.code : "INTERNAL_ERROR";
    const message = error instanceof Error ? error.message : String(error);
    return { exitCode: 2, output: { error: { code, message, hint: HINTS[code] } } };
  }
}

function isRunAsCommand() {
  try {
    return realpathSync(process.argv[1]) === fileURLToPath(import.meta.url);
  } catch {
    return false;
  }
}

// `process.exitCode` lets stdout drain; `process.exit()` could cut the JSON short.
if (isRunAsCommand()) {
  const { exitCode, output } = await scan(process.argv[2] ?? process.cwd());
  console.log(JSON.stringify(output, null, 2));
  process.exitCode = exitCode;
}
