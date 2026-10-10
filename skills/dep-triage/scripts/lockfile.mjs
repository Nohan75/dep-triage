// Reads the list of installed packages out of an npm lockfile (lockfileVersion 2 or 3).
// Pure: it takes parsed JSON and touches neither the disk nor the network.

const REGISTRY = "https://registry.npmjs.org/";
const NODE_MODULES = "node_modules/";
// A root (the project, or a workspace package) also brings in its devDependencies.
const ROOT_DEPENDENCY_FIELDS = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"];
const DEPENDENCY_FIELDS = ["dependencies", "optionalDependencies", "peerDependencies"];

function unsupportedLockfile() {
  const message = "Unsupported lockfile: dep-triage needs a package-lock.json with lockfileVersion 2 or 3.";
  return Object.assign(new Error(message), { code: "UNSUPPORTED_LOCKFILE" });
}

// Index where the last `node_modules/` path segment of a lockfile key starts, or -1.
function lastNodeModules(key) {
  const nested = key.lastIndexOf(`/${NODE_MODULES}`);
  if (nested !== -1) return nested + 1;
  return key.startsWith(NODE_MODULES) ? 0 : -1;
}

// Workspace packages, and the links that point to them, are the project's own code.
function isLocal(key, entry) {
  return entry.link === true || lastNodeModules(key) === -1;
}

// An npm alias (`"my-lodash": "npm:lodash@4"`) carries the real name in `name`.
function nameOf(key, entry) {
  if (typeof entry.name === "string") return entry.name;
  return key.slice(lastNodeModules(key) + NODE_MODULES.length);
}

// Hosts that serve a git repository's tarball. `npm.pkg.github.com` is not one: it is a private registry.
const GIT_TARBALL_HOSTS = new Set(["github.com", "codeload.github.com"]);

function hostOf(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return "";
  }
}

// Only `registry` packages are public: nothing is sent to OSV about the others.
function originOf(entry) {
  const { resolved } = entry;
  if (typeof resolved === "string" && resolved.startsWith(REGISTRY)) return "registry";
  if (entry.inBundle === true) return "registry";
  if (typeof resolved !== "string" || resolved === "") return "no-resolved";
  if (resolved.startsWith("git") || GIT_TARBALL_HOSTS.has(hostOf(resolved))) return "git";
  if (resolved.startsWith("file:")) return "file";
  return "private-registry";
}

function isEntry(value) {
  return value !== null && typeof value === "object";
}

function declaredNames(source, fields) {
  return fields.flatMap((field) => (isEntry(source?.[field]) ? Object.keys(source[field]) : []));
}

// The folder Node looks in next: one `node_modules/<name>` up, or one directory up.
function parentOf(key) {
  const start = lastNodeModules(key);
  if (start !== -1) return key.slice(0, start).replace(/\/$/, "");
  const slash = key.lastIndexOf("/");
  return slash === -1 ? "" : key.slice(0, slash);
}

// Finds the lockfile key that `depName` resolves to when required from `fromKey`, the way Node does.
function resolveDependency(packages, fromKey, depName) {
  let base = fromKey;
  for (;;) {
    const candidate = `${base === "" ? "" : `${base}/`}${NODE_MODULES}${depName}`;
    if (Object.hasOwn(packages, candidate)) return candidate;
    if (base === "") return null;
    base = parentOf(base);
  }
}

// Breadth-first walk from the roots: the first visit of a key is its shortest chain of names.
function shortestChains(packageJson, packages) {
  const chains = new Map();
  const queue = [];
  const visit = (fromKey, depNames, parentChain) => {
    for (const depName of depNames) {
      const key = resolveDependency(packages, fromKey, depName);
      if (key === null || chains.has(key)) continue;
      const entry = packages[key];
      if (!isEntry(entry) || isLocal(key, entry)) continue;
      chains.set(key, [...parentChain, nameOf(key, entry)]);
      queue.push(key);
    }
  };

  visit("", declaredNames(packageJson, ROOT_DEPENDENCY_FIELDS), []);
  for (const [key, entry] of Object.entries(packages)) {
    const isWorkspacePackage = key !== "" && lastNodeModules(key) === -1;
    if (isWorkspacePackage) visit(key, declaredNames(entry, ROOT_DEPENDENCY_FIELDS), []);
  }
  for (let i = 0; i < queue.length; i++) {
    const key = queue[i];
    visit(key, declaredNames(packages[key], DEPENDENCY_FIELDS), chains.get(key));
  }
  return chains;
}

/**
 * @typedef {object} Pkg
 * @property {string} name real package name (not the alias)
 * @property {string} version
 * @property {boolean} direct declared by the project or by one of its workspace packages
 * @property {"prod" | "dev"} scope
 * @property {string[]} introducedBy names from a direct dependency down to this package; [] if nothing leads to it
 * @property {"registry" | "git" | "file" | "private-registry" | "no-resolved"} origin
 */

/**
 * @param {object} packageJson parsed package.json
 * @param {object} lockfile parsed package-lock.json
 * @returns {Pkg[]} one item per name and version, in lockfile order
 */
export function listPackages(packageJson, lockfile) {
  const packages = lockfile?.packages;
  if (lockfile?.lockfileVersion === 1 || !isEntry(packages)) throw unsupportedLockfile();

  const chains = shortestChains(packageJson, packages);
  const byId = new Map();
  for (const [key, entry] of Object.entries(packages)) {
    if (key === "" || !isEntry(entry) || isLocal(key, entry)) continue;
    // npm writes a version for every installed package; without one there is nothing to look up.
    if (typeof entry.version !== "string") continue;

    const name = nameOf(key, entry);
    const introducedBy = chains.get(key) ?? [];
    const pkg = {
      name,
      version: entry.version,
      direct: introducedBy.length === 1,
      scope: entry.dev === true ? "dev" : "prod",
      introducedBy,
      origin: originOf(entry),
    };

    const id = `${name}@${entry.version}`;
    const seen = byId.get(id);
    if (seen === undefined) {
      byId.set(id, pkg);
      continue;
    }
    // The same name and version installed in several places: keep the most exposed reading.
    if (pkg.scope === "prod") seen.scope = "prod";
    if (pkg.direct) seen.direct = true;
    const isShorter = seen.introducedBy.length === 0 || pkg.introducedBy.length < seen.introducedBy.length;
    if (pkg.introducedBy.length > 0 && isShorter) seen.introducedBy = pkg.introducedBy;
  }
  return [...byId.values()];
}
