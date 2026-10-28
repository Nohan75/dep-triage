# vulnerable-app (test data)

This folder is test data for dep-triage, not a real application.
Its lockfile deliberately names vulnerable versions and one known malicious version (`chalk 5.6.1`).
Its `.nvmrc` names a Node.js release with known vulnerabilities (`24.18.0`).
Never run `npm install` here.

## Rule for malicious versions

Only name a malicious version in this folder once the npm registry has removed it, so that it can never be installed from here. Check before adding one:

```bash
curl -s -o /dev/null -w "%{http_code}\n" https://registry.npmjs.org/<package>/<version>
```

`404` means the version is gone. `chalk 5.6.1` returned `404` on 2026-10-11.
