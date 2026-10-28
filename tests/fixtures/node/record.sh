#!/bin/sh
# Re-records the Node.js data used by the tests. Needs network access to raw.githubusercontent.com.
# index.json keeps two advisories, so that the tests also read the numbered files past it.
set -eu
cd "$(dirname "$0")"
mkdir -p vulns
RAW=https://raw.githubusercontent.com
curl -sS --fail -m 20 "$RAW/nodejs/Release/main/schedule.json" -o schedule.json
curl -sS --fail -m 30 "$RAW/nodejs/security-wg/main/vuln/core/index.json" |
  node -e 'let s = ""; process.stdin.on("data", (d) => (s += d)).on("end", () => {
    const index = JSON.parse(s);
    console.log(JSON.stringify({ 193: index[193], 194: index[194] }, null, 2));
  })' > index.json
for n in 195 196 197 198 199 200 201 202 203 204; do
  curl -sS --fail -m 20 "$RAW/nodejs/security-wg/main/vuln/core/$n.json" -o "vulns/$n.json"
done
