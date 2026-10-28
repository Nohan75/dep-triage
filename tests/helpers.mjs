import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const OSV_FIXTURES = fileURLToPath(new URL("./fixtures/osv/", import.meta.url));
const NODE_FIXTURES = fileURLToPath(new URL("./fixtures/node/", import.meta.url));
const CORE_VULNS = "https://raw.githubusercontent.com/nodejs/security-wg/main/vuln/core/";
const SCHEDULE = "https://raw.githubusercontent.com/nodejs/Release/main/schedule.json";

export function json(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

// A fetch stand-in that records every call in `calls`. A handler that throws becomes a rejection.
export function recordingFetch(handler) {
  const calls = [];
  const fetchFn = async (url, init) => {
    const call = { url: String(url), init };
    calls.push(call);
    return handler(call.url, init);
  };
  fetchFn.calls = calls;
  return fetchFn;
}

export function loadVuln(id) {
  return JSON.parse(readFileSync(path.join(OSV_FIXTURES, "vulns", `${id}.json`), "utf8"));
}

function readFixture(file) {
  try {
    return json(JSON.parse(readFileSync(file, "utf8")));
  } catch {
    return new Response("404: Not Found", { status: 404 });
  }
}

// Serves the Node.js data recorded by fixtures/node/record.sh, or null for another URL.
export function nodeFixtureResponse(url) {
  if (url === SCHEDULE) return readFixture(path.join(NODE_FIXTURES, "schedule.json"));
  if (url === `${CORE_VULNS}index.json`) return readFixture(path.join(NODE_FIXTURES, "index.json"));
  if (url.startsWith(CORE_VULNS)) return readFixture(path.join(NODE_FIXTURES, "vulns", url.slice(CORE_VULNS.length)));
  return null;
}

// Serves the advisories recorded from the real APIs by fixtures/osv/record.sh and fixtures/node/record.sh.
export function fixtureFetch() {
  const batch = JSON.parse(readFileSync(path.join(OSV_FIXTURES, "batch.json"), "utf8"));
  return recordingFetch((url, init) => {
    const node = nodeFixtureResponse(url);
    if (node !== null) return node;
    if (url === "https://api.osv.dev/v1/querybatch") {
      const results = JSON.parse(init.body).queries.map((query) => {
        const ids = batch[`${query.package.name}@${query.version}`];
        return ids ? { vulns: ids.map((id) => ({ id, modified: "2026-10-10T00:00:00Z" })) } : {};
      });
      return json({ results });
    }
    try {
      return json(loadVuln(decodeURIComponent(url.slice(url.lastIndexOf("/") + 1))));
    } catch {
      return json({ code: 5, message: "Bug not found." }, 404);
    }
  });
}

const projects = [];
process.on("exit", () => {
  for (const dir of projects) rmSync(dir, { recursive: true, force: true });
});

// Creates a throwaway project folder. An object value is written as JSON, a string as is.
export function makeProject(files) {
  const dir = mkdtempSync(path.join(os.tmpdir(), "dep-triage-"));
  projects.push(dir);
  for (const [name, content] of Object.entries(files)) {
    const file = path.join(dir, name);
    mkdirSync(path.dirname(file), { recursive: true });
    writeFileSync(file, typeof content === "string" ? content : JSON.stringify(content, null, 2));
  }
  return dir;
}
