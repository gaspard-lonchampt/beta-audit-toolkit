#!/usr/bin/env bash
# Audit Metabase hardening across accessible Scalingo apps. See README.md.
set -uo pipefail
REGION="${SCALINGO_REGION:-osc-fr1}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
API="https://api.github.com/repos/metabase/metabase/security-advisories"

if ! scalingo whoami >/dev/null 2>&1; then
  echo "CLI Scalingo non authentifiée — lancez 'scalingo login' (ou posez SCALINGO_API_TOKEN)." >&2
  exit 2
fi

GHSA=$(mktemp)
PAGE_TMP=$(mktemp)
trap 'rm -f "$GHSA" "$PAGE_TMP"' EXIT
echo '[]' >"$GHSA"
page=1
while :; do
  # Token via a curl config on stdin: never in argv (visible in ps otherwise).
  if ! curl -sf -m 10 -K - "$API?per_page=100&page=$page" -o "$PAGE_TMP" <<EOF
${GITHUB_TOKEN:+header = "Authorization: Bearer $GITHUB_TOKEN"}
EOF
  then
    echo "GitHub advisories inaccessibles (rate-limit ? pose GITHUB_TOKEN)"; exit 2
  fi
  n=$(python3 - "$GHSA" "$PAGE_TMP" <<'PY'
import json, sys
acc = json.load(open(sys.argv[1]))
page = json.load(open(sys.argv[2]))
if not isinstance(page, list):
    sys.exit(1)
acc.extend(page)
json.dump(acc, open(sys.argv[1], "w"))
print(len(page))
PY
) || { echo "GitHub advisories inaccessibles (rate-limit ? pose GITHUB_TOKEN)"; exit 2; }
  [ "$n" -lt 100 ] && break
  page=$((page + 1))
done
python3 -c "import json,sys; sys.exit(0 if json.load(open('$GHSA')) else 1)" \
  || { echo "GitHub advisories inaccessibles (rate-limit ? pose GITHUB_TOKEN)"; exit 2; }

to_fix=0; apps_mb=0

while read -r app; do
    env=$(scalingo -a "$app" env 2>/dev/null) || continue

    is_mb=""
    echo "$env" | grep -qE '^(MB_|METABASE_)' && is_mb=1
    [ -z "$is_mb" ] && scalingo -a "$app" ps 2>/dev/null | grep -qE 'bin/start' && is_mb=1
    [ -z "$is_mb" ] && continue
    apps_mb=$((apps_mb+1))

    actions=()

    echo "$env" | grep -q '^MB_ENCRYPTION_SECRET_KEY=' \
      || actions+=("🔴 Poser MB_ENCRYPTION_SECRET_KEY (rotation requise si des secrets sont déjà stockés)")

    realver=""
    mbtmp=$(mktemp)
    if curl -s -m 8 -o "$mbtmp" "https://${app}.${REGION}.scalingo.io/api/session/properties" 2>/dev/null; then
      realver=$(python3 -c "import json;print(json.load(open('$mbtmp')).get('version',{}).get('tag',''))" 2>/dev/null)
      [ -n "$realver" ] && actions+=("🔴 API Metabase accessible sans authentification -> placer un proxy d'auth devant (l'URL Scalingo par défaut n'est pas protégée)")
    fi
    rm -f "$mbtmp"

    ver=$(echo "$env" | grep '^METABASE_VERSION=' | cut -d= -f2)
    src="pin"; [ -z "$ver" ] && { ver="$realver"; src="API"; }
    if [ -z "$ver" ]; then
      actions+=("🟠 Version inconnue (non pinnée + API injoignable) -> pinner METABASE_VERSION")
    else
      verdict=$(python3 "$HERE/secver.py" "$ver" "$GHSA")
      if [ "$verdict" = "UNKNOWN" ]; then
        actions+=("🟠 Version $ver ($src) illisible -> vérifier manuellement vs advisories (format non reconnu)")
      elif [ "$verdict" != "OK" ]; then
        seuil=$(echo "$verdict" | cut -d'|' -f2); det=$(echo "$verdict" | cut -d'|' -f3)
        actions+=("🔴 Version $ver ($src) VULNÉRABLE -> mettre à jour vers >= $seuil (manque : $det)")
      fi
    fi

    echo "$env" | grep -qiE '^MB_ENABLE_EMBEDDING=(true|1)' \
      && actions+=("🟡 Embedding activé -> vérifier l'usage, sinon désactiver + tourner embedding-secret-key")

    if [ ${#actions[@]} -eq 0 ]; then
      echo "✅ $app : OK${ver:+ ($ver, sécu à jour)}"
    else
      to_fix=$((to_fix+1)); echo "⚠️  $app :"
      for a in "${actions[@]}"; do echo "      - $a"; done
    fi
done < <(scalingo apps 2>/dev/null | awk -F'│' 'NF>2 {gsub(/^[ \t]+|[ \t]+$/,"",$2); if($2!="" && $2!="NAME") print $2}')

echo "=================================================="
echo "Résumé : $to_fix app(s) à traiter sur $apps_mb instance(s) Metabase détectée(s)."
[ "$to_fix" -gt 0 ] && exit 1 || exit 0
