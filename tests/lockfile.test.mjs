import { test } from "node:test";
import assert from "node:assert/strict";
import { listPackages } from "../skills/dep-triage/scripts/lockfile.mjs";

const R = (name, v = "1.0.0") => `https://registry.npmjs.org/${name}/-/${name.split("/").pop()}-${v}.tgz`;
const lock = (packages) => ({ lockfileVersion: 3, packages: { "": {}, ...packages } });
const ids = (list) => list.map((p) => `${p.name}@${p.version}`);

test("name is the text after the last node_modules/", () => {
  const list = listPackages({}, lock({
    "node_modules/@scope/a": { version: "1.0.0", resolved: R("@scope/a") },
    "node_modules/@scope/a/node_modules/@other/b": { version: "2.0.0", resolved: R("@other/b", "2.0.0") },
  }));
  assert.deepEqual(ids(list), ["@scope/a@1.0.0", "@other/b@2.0.0"]);
});

test("an npm alias reports the real name", () => {
  const list = listPackages({}, lock({ "node_modules/my-lodash": { name: "lodash", version: "4.17.15", resolved: R("lodash", "4.17.15") } }));
  assert.deepEqual(ids(list), ["lodash@4.17.15"]);
});

test("scope is dev only when the entry has dev: true", () => {
  const list = listPackages({}, lock({
    "node_modules/a": { version: "1.0.0", resolved: R("a"), dev: true },
    "node_modules/b": { version: "1.0.0", resolved: R("b"), devOptional: true },
    "node_modules/c": { version: "1.0.0", resolved: R("c"), optional: true },
    "node_modules/d": { version: "1.0.0", resolved: R("d") },
  }));
  assert.deepEqual(list.map((p) => p.scope), ["dev", "prod", "prod", "prod"]);
});

test("origin follows the classification table", () => {
  const cases = [
    [{ resolved: R("x") }, "registry"],
    [{ inBundle: true }, "registry"],
    [{ resolved: "git+ssh://git@github.com/acme/x.git#abc123" }, "git"],
    [{ resolved: "https://codeload.github.com/acme/x/tar.gz/abc123" }, "git"],
    [{ resolved: "file:../x" }, "file"],
    [{ resolved: "https://npm.acme.internal/x/-/x-1.0.0.tgz" }, "private-registry"],
    [{ resolved: "https://npm.pkg.github.com/download/@acme/x/1.0.0/abc123" }, "private-registry"],
    [{}, "no-resolved"],
  ];
  for (const [entry, origin] of cases) {
    const [p] = listPackages({}, lock({ "node_modules/x": { version: "1.0.0", ...entry } }));
    assert.equal(p.origin, origin);
  }
});

test("workspace packages and links are left out", () => {
  const list = listPackages({}, lock({
    "packages/app": { version: "1.0.0" },
    "node_modules/app": { resolved: "packages/app", link: true },
  }));
  assert.deepEqual(list, []);
});

test("the same name and version is listed once, and prod wins over dev", () => {
  const list = listPackages({}, lock({
    "node_modules/a/node_modules/x": { version: "1.0.0", resolved: R("x"), dev: true },
    "node_modules/x": { version: "1.0.0", resolved: R("x") },
    "node_modules/b/node_modules/x": { version: "2.0.0", resolved: R("x", "2.0.0") },
  }));
  assert.deepEqual(list.map((p) => [p.name, p.version, p.scope]), [["x", "1.0.0", "prod"], ["x", "2.0.0", "prod"]]);
});

test("an unsupported lockfile is rejected", () => {
  assert.throws(() => listPackages({}, { lockfileVersion: 1, dependencies: {} }), { code: "UNSUPPORTED_LOCKFILE" });
  assert.throws(() => listPackages({}, { lockfileVersion: 3 }), { code: "UNSUPPORTED_LOCKFILE" });
});

const E = (name, extra = {}) => ({ version: "1.0.0", resolved: R(name), ...extra });
const by = (list, name, version = "1.0.0") => list.find((p) => p.name === name && p.version === version);

test("direct dependencies and the shortest chain", () => {
  const list = listPackages({ dependencies: { a: "^1" }, devDependencies: { d: "^1" } }, lock({
    "node_modules/a": E("a", { dependencies: { b: "^1" } }),
    "node_modules/b": E("b", { dependencies: { c: "^1" } }),
    "node_modules/c": E("c"),
    "node_modules/d": E("d", { dev: true, dependencies: { c: "^1" } }),
  }));
  assert.deepEqual([by(list, "a").direct, by(list, "a").introducedBy], [true, ["a"]]);
  assert.deepEqual([by(list, "b").direct, by(list, "b").introducedBy], [false, ["a", "b"]]);
  assert.deepEqual(by(list, "c").introducedBy, ["d", "c"]);
});

test("a nested copy is resolved before the top-level one", () => {
  const list = listPackages({ dependencies: { a: "^1", c: "^1" } }, lock({
    "node_modules/a": E("a", { dependencies: { c: "^2" } }),
    "node_modules/a/node_modules/c": { version: "2.0.0", resolved: R("c", "2.0.0") },
    "node_modules/c": E("c"),
  }));
  assert.deepEqual([by(list, "c", "2.0.0").direct, by(list, "c", "2.0.0").introducedBy], [false, ["a", "c"]]);
  assert.deepEqual([by(list, "c").direct, by(list, "c").introducedBy], [true, ["c"]]);
});

test("optional and peer dependencies are followed, an absent one is ignored", () => {
  const list = listPackages({ dependencies: { a: "^1" } }, lock({
    "node_modules/a": E("a", { optionalDependencies: { o: "^1" }, peerDependencies: { p: "^1", missing: "^1" } }),
    "node_modules/o": E("o", { optional: true }),
    "node_modules/p": E("p", { peer: true }),
  }));
  assert.deepEqual([by(list, "o").introducedBy, by(list, "p").introducedBy], [["a", "o"], ["a", "p"]]);
});

test("a dependency cycle terminates", () => {
  const list = listPackages({ dependencies: { a: "^1" } }, lock({
    "node_modules/a": E("a", { dependencies: { b: "^1" } }),
    "node_modules/b": E("b", { dependencies: { a: "^1" } }),
  }));
  assert.deepEqual(by(list, "b").introducedBy, ["a", "b"]);
});

test("a package nothing leads to gets an empty chain", () => {
  const [x] = listPackages({}, lock({ "node_modules/x": E("x") }));
  assert.deepEqual([x.direct, x.introducedBy], [false, []]);
});

test("workspace packages are roots", () => {
  const list = listPackages({ workspaces: ["packages/*"] }, lock({
    "packages/app": { version: "1.0.0", dependencies: { a: "^1", z: "^1" } },
    "node_modules/app": { resolved: "packages/app", link: true },
    "node_modules/a": E("a"),
    "packages/app/node_modules/z": E("z"),
  }));
  assert.deepEqual([by(list, "a").direct, by(list, "a").introducedBy], [true, ["a"]]);
  assert.deepEqual([by(list, "z").direct, by(list, "z").introducedBy], [true, ["z"]]);
});

test("an alias appears under its real name in the chain", () => {
  const [p] = listPackages({ dependencies: { "my-lodash": "npm:lodash@4.17.15" } }, lock({
    "node_modules/my-lodash": { name: "lodash", version: "4.17.15", resolved: R("lodash", "4.17.15") },
  }));
  assert.deepEqual([p.direct, p.introducedBy], [true, ["lodash"]]);
});

test("a duplicate keeps the shortest chain, and direct wins", () => {
  const list = listPackages({ dependencies: { a: "^1", x: "^1" } }, lock({
    "node_modules/a": E("a", { dependencies: { b: "^1" } }),
    "node_modules/b": E("b", { dependencies: { x: "^1" } }),
    "node_modules/b/node_modules/x": E("x"),
    "node_modules/x": E("x"),
  }));
  assert.deepEqual([by(list, "x").direct, by(list, "x").introducedBy], [true, ["x"]]);
});
