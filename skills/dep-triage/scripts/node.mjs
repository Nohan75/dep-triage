// Checks the Node.js versions a project runs on against the advisories of the Node.js security team
// and the Node.js release calendar. It downloads two public data sets and sends nothing about the project.

import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { request } from "./http.mjs";

const CORE_VULNS = "https://raw.githubusercontent.com/nodejs/security-wg/main/vuln/core/";
const SCHEDULE = "https://raw.githubusercontent.com/nodejs/Release/main/schedule.json";
// index.json is regenerated days after new advisory files land, so the numbered files past it are read one by one.
const MAX_FILES_PAST_INDEX = 100;
const SEVERITIES = { critical: "critical", high: "high", medium: "moderate", low: "low" };
const SEVERITY_ORDER = ["critical", "high", "moderate", "low", "unknown"];
const DOCKERFILE = /^(Dockerfile|Containerfile)(\..+)?$|\.(Dockerfile|Containerfile)$/i;

function unavailable(message, cause) {
  return Object.assign(new Error(message, { cause }), { code: "NODE_DATA_UNAVAILABLE" });
}

function isEntry(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

// The text of a file at the project root, or null when there is none.
function readText(folder, file) {
  try {
    return readFileSync(path.join(folder, file), "utf8");
  } catch (error) {
    if (error.code === "ENOENT" || error.code === "ENOTDIR") return null;
    throw error;
  }
}

// The first line that is neither empty nor a comment, as nvm and its peers read it.
function firstValue(text) {
  for (const line of text.split(/\r?\n/)) {
    const value = line.split("#")[0].trim();
    if (value !== "") return value;
  }
  return null;
}

// asdf and mise: `nodejs 24.18.0`; extra versions after the first are fallbacks.
function toolVersionsValue(text) {
  for (const line of text.split(/\r?\n/)) {
    const [tool, version] = line.split("#")[0].trim().split(/\s+/);
    if ((tool === "nodejs" || tool === "node") && version !== undefined) return version;
  }
  return null;
}

// One declaration per `FROM <...>/node:<tag>` line. `ARG` defaults fill in `${NAME}` and `$NAME`.
function dockerfileValues(text, file) {
  const args = new Map();
  const found = [];
  text.split(/\r?\n/).forEach((line, i) => {
    const arg = /^\s*ARG\s+([A-Za-z_]\w*)=("?)([^"\s]*)\2\s*$/i.exec(line);
    if (arg) {
      args.set(arg[1], arg[3]);
      return;
    }
    const from = /^\s*FROM\s+(?:--\S+\s+)*(\S+)/i.exec(line);
    if (!from) return;
    const image = from[1].replace(/\$\{?([A-Za-z_]\w*)\}?/g, (whole, name) => args.get(name) ?? whole);
    const ref = image.split("@")[0];
    const colon = ref.indexOf(":", ref.lastIndexOf("/") + 1);
    const repository = colon === -1 ? ref : ref.slice(0, colon);
    if (repository.split("/").pop().toLowerCase() !== "node") return;
    const tag = colon === -1 ? "latest" : ref.slice(colon + 1);
    // `24.18.0-alpine3.20` names Node.js 24.18.0; the variant after the dash does not matter here.
    found.push({ source: `${file}:${i + 1}`, value: tag.split("-")[0] });
  });
  return found;
}

/**
 * Reads the Node.js versions a project declares. `engines` is left out: it is the range a package
 * accepts, not the version that runs.
 * @param {string} folder the project folder
 * @param {object} packageJson parsed package.json
 * @returns {{ source: string, value: string }[]} in the order: version files, volta, Dockerfiles
 */
export function readNodeDeclarations(folder, packageJson) {
  const declarations = [];
  for (const file of [".nvmrc", ".node-version"]) {
    const text = readText(folder, file);
    const value = text === null ? null : firstValue(text);
    if (value !== null) declarations.push({ source: file, value });
  }
  const toolVersions = readText(folder, ".tool-versions");
  const toolValue = toolVersions === null ? null : toolVersionsValue(toolVersions);
  if (toolValue !== null) declarations.push({ source: ".tool-versions", value: toolValue });
  if (typeof packageJson?.volta?.node === "string") declarations.push({ source: "package.json (volta)", value: packageJson.volta.node });

  const dockerfiles = readdirSync(folder, { withFileTypes: true })
    .filter((entry) => entry.isFile() && DOCKERFILE.test(entry.name))
    .map((entry) => entry.name)
    .sort();
  for (const file of dockerfiles) declarations.push(...dockerfileValues(readText(folder, file) ?? "", file));
  return declarations;
}

// The parsed JSON, or null on a 404 when `missingIsEnd` is set.
async function getJson(url, options, { missingIsEnd = false } = {}) {
  let response;
  try {
    response = await request(url, {}, options);
  } catch (error) {
    throw unavailable("The Node.js security data could not be downloaded.", error);
  }
  if (missingIsEnd && response.status === 404) return null;
  if (!response.ok) throw unavailable(`GitHub answered with HTTP ${response.status} for ${url}.`);
  try {
    return await response.json();
  } catch (error) {
    throw unavailable(`${url} is not JSON.`, error);
  }
}

/**
 * Downloads the Node.js core advisories and the release calendar.
 * @param {{ fetchFn?: typeof fetch, retryDelayMs?: number, timeoutMs?: number }} [options]
 * @returns {Promise<{ advisories: object[], schedule: object }>} each advisory carries its file `number`
 * @throws an Error with code "NODE_DATA_UNAVAILABLE" when a download fails
 */
export async function fetchNodeData({ fetchFn = fetch, retryDelayMs = 2000, timeoutMs = 15000 } = {}) {
  const options = { fetchFn, retryDelayMs, timeoutMs };
  const index = await getJson(`${CORE_VULNS}index.json`, options);
  const schedule = await getJson(SCHEDULE, options);
  if (!isEntry(index) || !isEntry(schedule)) throw unavailable("The Node.js security data is not in the expected format.");

  const advisories = Object.entries(index)
    .filter(([, entry]) => isEntry(entry))
    .map(([key, entry]) => ({ ...entry, number: Number(key) }));
  let next = Math.max(0, ...advisories.map((advisory) => advisory.number).filter(Number.isInteger)) + 1;
  for (let read = 0; ; read++, next++) {
    if (read === MAX_FILES_PAST_INDEX) throw unavailable("The Node.js advisory list kept going further than expected.");
    const entry = await getJson(`${CORE_VULNS}${next}.json`, options, { missingIsEnd: true });
    if (entry === null) break;
    if (isEntry(entry)) advisories.push({ ...entry, number: next });
  }
  return { advisories, schedule };
}

// "24", "24.1", "24.1.2", "24.x", "*" → the numbers given before any wildcard; null when not a version.
function parseParts(text) {
  const match = /^v?(\d+|[xX*])(?:\.(\d+|[xX*]))?(?:\.(\d+|[xX*]))?$/.exec(text);
  if (!match) return null;
  const parts = [];
  for (const part of match.slice(1)) {
    if (part === undefined || !/^\d+$/.test(part)) break;
    parts.push(Number(part));
  }
  return parts;
}

const ZERO = [0, 0, 0];

function pad(parts) {
  return [parts[0] ?? 0, parts[1] ?? 0, parts[2] ?? 0];
}

// The first version above every version that starts with `parts`: 24 → 25.0.0, 24.1 → 24.2.0, 24.1.2 → 24.1.3.
function after(parts) {
  const bumped = pad(parts);
  bumped[parts.length - 1] += 1;
  return bumped;
}

function compare(a, b) {
  return a[0] - b[0] || a[1] - b[1] || a[2] - b[2];
}

// One comparator as a half-open interval [min, max); max null means no upper bound.
function comparatorInterval(text) {
  const [, operator, rest] = /^(\^|~|>=|<=|>|<|=)?(.*)$/.exec(text);
  const parts = parseParts(rest);
  if (parts === null) return null;
  if (parts.length === 0) return operator === undefined || operator === "=" ? { min: ZERO, max: null } : null;
  switch (operator) {
    case undefined:
    case "=":
      return { min: pad(parts), max: after(parts) };
    case "^": {
      const firstNonZero = parts.findIndex((part) => part !== 0);
      return { min: pad(parts), max: after(parts.slice(0, firstNonZero === -1 ? parts.length : firstNonZero + 1)) };
    }
    case "~":
      return { min: pad(parts), max: after(parts.slice(0, Math.min(parts.length, 2))) };
    case ">=":
      return { min: pad(parts), max: null };
    case ">":
      return { min: after(parts), max: null };
    case "<":
      return { min: ZERO, max: pad(parts) };
    default:
      return { min: ZERO, max: after(parts) };
  }
}

// A semver range such as "^22.23.4 || >=24.0.0 <24.22.1" as a list of intervals.
// A set holding a comparator this parser does not know becomes null and matches nothing.
function parseRange(range) {
  if (typeof range !== "string") return [];
  return range.split("||").map((set) => {
    const comparators = set.replace(/(\^|~|>=|<=|>|<|=)\s+/g, "$1").trim().split(/\s+/);
    let interval = { min: ZERO, max: null };
    for (const comparator of comparators) {
      const next = comparatorInterval(comparator);
      if (next === null) return null;
      const min = compare(next.min, interval.min) > 0 ? next.min : interval.min;
      const max = interval.max === null || (next.max !== null && compare(next.max, interval.max) < 0) ? next.max : interval.max;
      interval = { min, max };
    }
    return interval;
  });
}

function inInterval(version, interval) {
  return interval !== null && compare(version, interval.min) >= 0 && (interval.max === null || compare(version, interval.max) < 0);
}

/**
 * @param {string} version a full version such as "24.18.0"
 * @param {string} range a semver range in the syntax of the Node.js advisories
 */
export function satisfies(version, range) {
  const parts = parseParts(version);
  if (parts === null || parts.length !== 3) return false;
  return parseRange(range).some((interval) => inInterval(parts, interval));
}

function majorOfCodename(codename, schedule) {
  for (const [key, line] of Object.entries(schedule)) {
    if (/^v\d+$/.test(key) && String(line?.codename ?? "").toLowerCase() === codename.toLowerCase()) return Number(key.slice(1));
  }
  return null;
}

// "24.18.0" → a pinned version; "24", "24.18", "lts/krypton" → a release line; "lts/*", "latest" → null.
function parseDeclared(value, schedule) {
  const lts = /^lts\/(.+)$/i.exec(value.trim());
  if (lts) {
    const major = majorOfCodename(lts[1], schedule);
    return major === null ? null : { key: String(major), major, parts: null };
  }
  const parts = parseParts(value.trim());
  if (parts === null || parts.length === 0) return null;
  if (parts.length < 3) return { key: String(parts[0]), major: parts[0], parts: null };
  return { key: parts.join("."), major: parts[0], parts };
}

function toVulnerability(advisory) {
  const cves = Array.isArray(advisory.cve) ? advisory.cve.filter((cve) => typeof cve === "string") : [];
  return {
    id: cves[0] ?? `node-core-${advisory.number}`,
    aliases: cves.slice(1),
    severity: SEVERITIES[advisory.severity] ?? "unknown",
    summary: typeof advisory.description === "string" ? advisory.description : null,
    platforms: Array.isArray(advisory.affectedEnvironments) ? advisory.affectedEnvironments : ["all"],
    url: typeof advisory.ref === "string" ? advisory.ref : null,
  };
}

// The lowest release on the same line that fixes every advisory, or null when one has no fix there.
function fixedInOf(parts, advisories) {
  let highest = null;
  for (const advisory of advisories) {
    const fixes = parseRange(advisory.patched)
      .filter((interval) => interval !== null && interval.min[0] === parts[0] && compare(interval.min, parts) > 0)
      .map((interval) => interval.min)
      .sort(compare);
    if (fixes.length === 0) return null;
    if (highest === null || compare(fixes[0], highest) > 0) highest = fixes[0];
  }
  return highest === null ? null : highest.join(".");
}

/**
 * @param {{ source: string, value: string }[]} declarations
 * @param {{ advisories: object[], schedule: object }} data from fetchNodeData
 * @param {Date} today
 * @returns {{ versions: object[], supportedLines: string[], notChecked: { source: string, value: string }[] }}
 */
export function checkNode(declarations, { advisories, schedule }, today) {
  const date = today.toISOString().slice(0, 10);
  const supportedLines = Object.entries(schedule)
    .filter(([key, line]) => /^v\d+$/.test(key) && line?.start <= date && date < line?.end)
    .map(([key]) => key.slice(1))
    .sort((a, b) => a - b);

  const groups = new Map();
  const notChecked = [];
  for (const { source, value } of declarations) {
    const parsed = parseDeclared(value, schedule);
    if (parsed === null) {
      notChecked.push({ source, value });
      continue;
    }
    if (!groups.has(parsed.key)) groups.set(parsed.key, { ...parsed, sources: [] });
    const group = groups.get(parsed.key);
    if (!group.sources.includes(source)) group.sources.push(source);
  }

  const versions = [...groups.values()].map(({ key, major, parts, sources }) => {
    const end = schedule[`v${major}`]?.end;
    const endOfLife = typeof end === "string" ? date >= end : null;
    const affecting =
      parts === null
        ? []
        : advisories.filter((advisory) => {
            const isVulnerable = parseRange(advisory.vulnerable).some((interval) => inInterval(parts, interval));
            return isVulnerable && !parseRange(advisory.patched).some((interval) => inInterval(parts, interval));
          });
    const vulnerabilities = affecting
      .map(toVulnerability)
      .sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
    return {
      version: key,
      pinned: parts !== null,
      sources,
      endOfLife,
      endOfLifeDate: typeof end === "string" ? end : null,
      // On an end-of-life line, a fix for the old advisories still leaves the new ones open.
      fixedIn: endOfLife === true || affecting.length === 0 ? null : fixedInOf(parts, affecting),
      vulnerabilities,
    };
  });
  return { versions, supportedLines, notChecked };
}
