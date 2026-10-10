#!/bin/sh
# Re-records the OSV advisories used by the tests. Needs network access to api.osv.dev.
set -eu
mkdir -p "$(dirname "$0")/vulns" && cd "$(dirname "$0")/vulns"
for id in GHSA-29mw-wpgm-hmr9 GHSA-35jh-r3h4-6jhm GHSA-f23m-r3pf-42rh GHSA-p6mc-m468-83gw \
  GHSA-r5fr-rjxr-66jc GHSA-xxjr-mmjv-4gpg GHSA-xvch-5gv4-984h MAL-2025-46969; do
  curl -sS --fail -m 20 "https://api.osv.dev/v1/vulns/$id" -o "$id.json"
done
