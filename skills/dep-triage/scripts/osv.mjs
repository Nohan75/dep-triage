// Client for the OSV.dev API (free, no key). Only package names and versions are sent.

const API = "https://api.osv.dev/v1";
const BATCH_SIZE = 1000;
const CONCURRENCY = 8;
// OSV pages the advisories of one package; a package never needs this many pages.
const MAX_PAGES = 50;

function unavailable(message, cause) {
  return Object.assign(new Error(message, { cause }), { code: "OSV_UNAVAILABLE" });
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// One request, retried once on a network error, a 429 or a 5xx.
// Returns the last response (which may still be an error status), or throws the last network error.
async function request(url, init, { fetchFn, retryDelayMs, timeoutMs }) {
  for (let attempt = 1; ; attempt++) {
    let response;
    let networkError;
    try {
      response = await fetchFn(url, { ...init, signal: AbortSignal.timeout(timeoutMs) });
    } catch (error) {
      networkError = error;
    }
    const retryable = networkError !== undefined || response.status === 429 || response.status >= 500;
    if (!retryable || attempt === 2) {
      if (networkError !== undefined) throw networkError;
      return response;
    }
    await sleep(retryDelayMs);
  }
}

async function postBatch(queries, options) {
  let response;
  try {
    response = await request(
      `${API}/querybatch`,
      { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ queries }) },
      options,
    );
  } catch (error) {
    throw unavailable("OSV.dev could not be reached.", error);
  }
  if (!response.ok) throw unavailable(`OSV.dev answered with HTTP ${response.status}.`);

  let body;
  try {
    body = await response.json();
  } catch (error) {
    throw unavailable("OSV.dev sent an answer that is not JSON.", error);
  }
  if (!Array.isArray(body?.results) || body.results.length !== queries.length) {
    throw unavailable("OSV.dev sent an answer that does not match the request.");
  }
  return body.results;
}

/**
 * Looks up every package in one go.
 * @param {{ name: string, version: string }[]} packages
 * @param {{ fetchFn?: typeof fetch, retryDelayMs?: number, timeoutMs?: number }} [options]
 * @returns {Promise<string[][]>} advisory ids per package, in the same order
 * @throws an Error with code "OSV_UNAVAILABLE" when the lookup could not be completed
 */
export async function queryBatch(packages, { fetchFn = fetch, retryDelayMs = 2000, timeoutMs = 15000 } = {}) {
  const options = { fetchFn, retryDelayMs, timeoutMs };
  const ids = packages.map(() => []);
  let pending = packages.map((_, index) => ({ index }));

  for (let page = 1; pending.length > 0; page++) {
    if (page > MAX_PAGES) throw unavailable("OSV.dev kept returning more pages than expected.");
    const nextPages = [];
    for (let start = 0; start < pending.length; start += BATCH_SIZE) {
      const lot = pending.slice(start, start + BATCH_SIZE);
      const queries = lot.map(({ index, pageToken }) => ({
        package: { name: packages[index].name, ecosystem: "npm" },
        version: packages[index].version,
        ...(pageToken === undefined ? {} : { page_token: pageToken }),
      }));
      const results = await postBatch(queries, options);
      results.forEach((result, i) => {
        const { index } = lot[i];
        for (const vuln of result?.vulns ?? []) {
          if (typeof vuln?.id === "string") ids[index].push(vuln.id);
        }
        if (result?.next_page_token) nextPages.push({ index, pageToken: result.next_page_token });
      });
    }
    pending = nextPages;
  }
  return ids;
}

async function fetchOne(id, options) {
  try {
    const response = await request(`${API}/vulns/${encodeURIComponent(id)}`, {}, options);
    if (!response.ok) return null;
    const body = await response.json();
    return body !== null && typeof body === "object" ? body : null;
  } catch {
    return null;
  }
}

/**
 * Fetches the full advisory behind each id.
 * @param {string[]} ids
 * @param {{ fetchFn?: typeof fetch, retryDelayMs?: number, timeoutMs?: number }} [options]
 * @returns {Promise<Map<string, object | null>>} the raw OSV record per distinct id, or null when it could not be fetched
 */
export async function fetchDetails(ids, { fetchFn = fetch, retryDelayMs = 2000, timeoutMs = 15000 } = {}) {
  const options = { fetchFn, retryDelayMs, timeoutMs };
  const distinct = [...new Set(ids)];
  const details = new Map(distinct.map((id) => [id, null]));

  let next = 0;
  const worker = async () => {
    while (next < distinct.length) {
      const id = distinct[next++];
      details.set(id, await fetchOne(id, options));
    }
  };
  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, distinct.length) }, worker));
  return details;
}
