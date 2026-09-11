#!/usr/bin/env bash
# Offline self-check for secver.py against fixed advisories (fixtures/). See README.md.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIX="$HERE/fixtures/advisories.json"
fail=0

check() {
  local name="$1" version="$2" expect="$3" got
  got=$(python3 "$HERE/secver.py" "$version" "$FIX" 2>/dev/null)
  # shellcheck disable=SC2053  # glob is intentional: '*' captures the verdict details
  if [[ "$got" == $expect ]]; then
    echo "✅ $name"
  else
    echo "❌ $name : attendu '$expect', obtenu '$got'"; fail=1
  fi
}

check "vulnérable branche 63"        "0.63.4"  'VULN|0.63.10|*'
check "à jour branche 63"            "0.63.10" 'OK'
check "vulnérable branche 50"        "0.50.19" 'VULN|0.50.20|*'
check "à jour branche 50"            "0.50.20" 'OK'
check "version illisible -> UNKNOWN" "latest"  'UNKNOWN'
check "branche sans advisory -> OK"  "0.99.0"  'OK'
check "nouveau schéma vulnérable"    "55.10"   'VULN|55.13|*'
check "nouveau schéma à jour"        "55.13"   'OK'
check "cross-schéma (0.55.x)"        "0.55.9"  'VULN|0.55.13|*'
check "seuil wildcard (x.60.5)"      "0.60.4"  'VULN|0.60.5|*'
check "seuil avec comparateur (>=)"  "0.63.4"  'VULN|0.63.10|*'

exit "$fail"
