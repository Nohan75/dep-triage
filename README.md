# dep-triage

A Claude Code plugin that scans the dependencies of an npm project, and the Node.js versions it runs on, for security advisories, then tells you which ones actually matter for your code.

## What it does

1. **Detect.** A small script reads `package-lock.json` and asks [OSV.dev](https://osv.dev) about every installed package, direct or transitive. It reports known vulnerabilities (GHSA and CVE advisories) and packages flagged as malicious (`MAL-` advisories, such as a compromised release). It also checks the Node.js versions the project runs on against the advisories of the [Node.js security team](https://github.com/nodejs/security-wg), and flags release lines past their end of life.
2. **Triage.** The agent then reads your code and gives each vulnerability an exposure level:

   | Level | Meaning |
   |---|---|
   | EXPOSED | Your code calls the vulnerable part. The report cites the file and line. |
   | NOT REACHED | The package is never imported, the vulnerable part is never called, or it is a dev-only dependency. The report gives the reason. |
   | UNDETERMINED | No proof either way. The advisory keeps its original severity. |

Malicious packages are never triaged down: they are listed first, with what to do about them. Node.js vulnerabilities are not triaged either: one upgrade of Node.js fixes them all.

`npm audit` stops at the list of advisories. dep-triage adds the second step, so that you know where to start. The scanner itself has no dependency and is read-only: it never installs anything and never runs code from the project it scans.

## Install

Requirements: Node.js 22 or later, and a project with a `package-lock.json`.

```text
/plugin marketplace add Nohan75/dep-triage
/plugin install dep-triage@dep-triage
```

Then ask Claude Code something like "audit my dependencies".

## Example report

This is the report for the example project in [`tests/fixtures/vulnerable-app`](tests/fixtures/vulnerable-app). The agent writes it, so the wording varies from run to run.

```text
Scan: 4 packages checked, 0 not checked · 6 alerts

MALICIOUS PACKAGES
  chalk 5.6.1 (MAL-2025-46969), brought in by ora
  → Move off this version before any install, then rotate the secrets
    of every machine where it was installed.

NODE.JS
  24.18.0 (.nvmrc) · 19 vulnerabilities, the most severe high,
  among them CVE-2026-111497 (Brotli decoder, remote code execution)
  → upgrade to 24.22.1

VULNERABILITIES
  1. lodash 4.17.15 · high · EXPOSED
     src/render.js:7 passes a value from the request as the `variable` option of _.template
     → npm install lodash@4.18.0
  ...
  5. minimist 1.2.5 · critical · NOT REACHED
     dev dependency, never imported by the project's code
     → npm install --save-dev minimist@1.2.6

Exposure levels are a judgement from reading the code, not a proof.
```

## Running the scanner without an agent

```bash
node skills/dep-triage/scripts/scan.mjs path/to/project
```

It prints one JSON document: a `summary`, the `findings`, the `node` versions, and the `skipped` packages. On failure it prints an `error` object with a `code`, a `message` and a `hint`.

| Exit code | Meaning |
|---|---|
| 0 | Scan complete, no finding |
| 1 | Scan complete, at least one finding: a package advisory, or a Node.js version that is vulnerable or past its end of life |
| 2 | The scan could not be completed |

Behind a proxy, run it with `NODE_USE_ENV_PROXY=1` so that Node uses your proxy settings.

## What is sent over the network

The scanner sends OSV.dev the **name and version** of the packages that come from the public npm registry. That is all it sends.

Packages from a private registry, a git URL or a local path are never sent. They appear under `skipped` in the JSON and under "not checked" in the report.

For the Node.js check, it downloads public files from `raw.githubusercontent.com`: the advisories of the Node.js security team ([nodejs/security-wg](https://github.com/nodejs/security-wg/tree/main/vuln/core)) and the release calendar ([nodejs/Release](https://github.com/nodejs/Release)). These requests carry nothing about your project.

## Limits

- Only npm projects with a `package-lock.json` at `lockfileVersion` 2 or 3 (npm 7 or later). pnpm and yarn lockfiles are not supported yet.
- The exposure level is the agent's judgement. npm advisories rarely name the vulnerable function in a structured way, so the agent works from the advisory text.
- Above 20 vulnerabilities, only the critical and high ones get a detailed analysis. The others are reported as UNDETERMINED.
- The scan is only as current as OSV.dev. A package compromised a few minutes ago may not be flagged yet.
- The Node.js versions are read from `.nvmrc`, `.node-version`, `.tool-versions`, `volta` in `package.json` and the Dockerfiles at the project root, plus the Node.js that runs the scan. `engines` is not read: it is the range a package accepts, not the version that runs. A version set elsewhere, such as in a CI workflow or a hosting dashboard, is not seen.
- A source that names a release line, such as `24` or `node:24-alpine`, is only checked for end of life, since each install takes the latest release of the line.
- A Node.js line past its end of life no longer appears in new advisories, so its list of vulnerabilities is incomplete. The report says so and points to a supported line.

## About the test fixtures

`tests/fixtures/vulnerable-app/package-lock.json` deliberately names vulnerable versions and one known malicious version. It is never installed, and the malicious version has been removed from the npm registry, so it cannot be installed. The rule for adding such a version is in that folder's README. GitHub may show Dependabot alerts for this repository because of that file: they are expected.

## Development

There is nothing to install.

```bash
npm test            # unit tests, no network
npm run test:live   # one check against the real OSV.dev API
```

## License

MIT
