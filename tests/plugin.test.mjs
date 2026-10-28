import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const read = (p) => readFileSync(new URL(`../${p}`, import.meta.url), "utf8");
const readJson = (p) => JSON.parse(read(p));

test("the repository declares no dependency", () => {
  const pkg = readJson("package.json");
  for (const key of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) assert.equal(pkg[key], undefined);
  assert.equal(pkg.engines.node, ">=22");
});

test("the manifests name the plugin and its marketplace", () => {
  const plugin = readJson(".claude-plugin/plugin.json");
  const market = readJson(".claude-plugin/marketplace.json");
  assert.deepEqual([plugin.name, plugin.version, plugin.license], ["dep-triage", "0.2.0", "MIT"]);
  assert.deepEqual([market.name, market.plugins[0].name, market.plugins[0].source], ["dep-triage", "dep-triage", "./"]);
});

test("SKILL.md has its frontmatter and its guardrails", () => {
  const skill = read("skills/dep-triage/SKILL.md");
  assert.match(skill, /^---\nname: dep-triage\ndescription: .+\n---\n/);
  for (const phrase of ["scripts/scan.mjs", "EXPOSED", "NOT REACHED", "UNDETERMINED", "overrides", "api.osv.dev", "raw.githubusercontent.com", "node.versions"]) assert.ok(skill.includes(phrase), phrase);
});
