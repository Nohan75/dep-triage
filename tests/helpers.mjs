import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const OSV_FIXTURES = fileURLToPath(new URL("./fixtures/osv/", import.meta.url));

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

// Serves the advisories recorded from the real API by fixtures/osv/record.sh.
export function osvFixtureFetch() {
  const batch = JSON.parse(readFileSync(path.join(OSV_FIXTURES, "batch.json"), "utf8"));
  return recordingFetch((url, init) => {
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

// Creates a throwaway project folder. An object value is written as JSON, a string as is.
export function makeProject(files) {
  const dir = mkdtempSync(path.join(os.tmpdir(), "dep-triage-"));
  process.on("exit", () => rmSync(dir, { recursive: true, force: true }));
  for (const [name, content] of Object.entries(files)) {
    const file = path.join(dir, name);
    mkdirSync(path.dirname(file), { recursive: true });
    writeFileSync(file, typeof content === "string" ? content : JSON.stringify(content, null, 2));
  }
  return dir;
}
