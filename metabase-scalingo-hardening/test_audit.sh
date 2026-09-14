#!/usr/bin/env bash
# Spec-first tests for audit.sh: stub scalingo/curl on PATH, assert findings + exit codes.
# Expected values derived from the security rules (header of audit.sh), not from its output.
set -uo pipefail
cd "$(dirname "$0")" || exit 1
TD=$(mktemp -d); trap 'rm -rf "$TD"' EXIT
mkdir "$TD/bin"
REAL_SCALINGO=$(command -v scalingo || true)   # before PATH override, for the contract test

# --- GHSA fixture: old-scheme advisory (0.49.10), new-scheme advisory (55.13),
# --- plus one deliberately unparseable threshold ("55") to exercise stderr logging.
export STUB_GHSA_FILE="$TD/ghsa.json"
cat > "$STUB_GHSA_FILE" <<'EOF'
[{"ghsa_id":"GHSA-test-0001","cve_id":"CVE-2024-0001","severity":"high",
  "vulnerabilities":[{"patched_versions":"x.49.10, >= 1.49.10"}]},
 {"ghsa_id":"GHSA-test-0002","cve_id":"CVE-2025-0002","severity":"critical",
  "vulnerabilities":[{"patched_versions":"55.13, 55"}]}]
EOF

# --- stubs ---
cat > "$TD/bin/scalingo" <<'EOF'
#!/usr/bin/env bash
if [ "$1" = whoami ]; then
  [ "${STUB_UNAUTH:-0}" = 1 ] && exit 1
  echo "logged in as tester"
elif [ "$1" = apps ]; then
  echo "│ NAME │ STATUS │"
  echo "│ testapp │ running │"
elif [ "${3:-}" = env ]; then
  cat "$STUB_ENV_FILE"
elif [ "${3:-}" = ps ]; then
  echo "web: bin/start"
fi
EOF
cat > "$TD/bin/curl" <<'EOF'
#!/usr/bin/env bash
out=""; url=""
args=("$@")
for ((i=0; i<$#; i++)); do
  case "${args[i]}" in
    -o) out="${args[i+1]}" ;;
    http*) url="${args[i]}" ;;
  esac
done
case "$url" in
  *api.github.com*)
    if [ "${STUB_GHSA_FAIL:-0}" = 1 ]; then printf '{"message":"API rate limit exceeded"}' > "$out"
    else cp "$STUB_GHSA_FILE" "$out"; fi ;;
  *scalingo.io*)
    [ "${STUB_API_EXPOSED:-0}" = 1 ] || exit 1
    printf '{"version":{"tag":"%s"}}' "$STUB_API_VERSION" > "$out" ;;
esac
EOF
chmod +x "$TD/bin/scalingo" "$TD/bin/curl"
export PATH="$TD/bin:$PATH"

fail=0
expect() { # desc pattern file
  if grep -q "$2" "$3"; then echo "  ok: $1"; else echo "  FAIL: $1 (pattern: $2)"; fail=1; fi
}
expect_rc() { # desc want got
  if [ "$3" -eq "$2" ]; then echo "  ok: $1"; else echo "  FAIL: $1 (want $2, got $3)"; fail=1; fi
}

echo "Case A: hardened app, patched pinned version -> OK, exit 0"
printf 'MB_ENCRYPTION_SECRET_KEY=xxx\nMB_SESSION_SECRET_KEY=xxx\nMETABASE_VERSION=0.49.10\n' > "$TD/env_ok"
STUB_ENV_FILE="$TD/env_ok" STUB_API_EXPOSED=0 bash ./audit.sh > "$TD/out_a" 2>&1; rc=$?
expect "app reported healthy"        "✅ testapp"          "$TD/out_a"
expect "version noted as up to date" "0.49.10, sécu à jour" "$TD/out_a"
expect_rc "exit code 0" 0 "$rc"

echo "Case B: no encryption key, exposed API, vulnerable version (via API) -> exit 1"
printf 'MB_SITE_NAME=x\n' > "$TD/env_bad"
STUB_ENV_FILE="$TD/env_bad" STUB_API_EXPOSED=1 STUB_API_VERSION=v0.49.5 \
  bash ./audit.sh > "$TD/out_b" 2>&1; rc=$?
expect "missing encryption key flagged" "Poser MB_ENCRYPTION_SECRET_KEY" "$TD/out_b"
expect "unauthenticated API flagged"    "sans authentification"          "$TD/out_b"
expect "vulnerable version flagged"     "0.49.5 (API) VULNÉRABLE"        "$TD/out_b"
expect "patch threshold from advisory"  ">= 0.49.10"                     "$TD/out_b"
expect "1 app to fix in summary"        "Résumé : 1 app"                 "$TD/out_b"
expect_rc "exit code 1" 1 "$rc"

echo "Case C: unpinned + API unreachable -> version unknown, exit 1"
printf 'MB_ENCRYPTION_SECRET_KEY=xxx\n' > "$TD/env_unpinned"
STUB_ENV_FILE="$TD/env_unpinned" STUB_API_EXPOSED=0 bash ./audit.sh > "$TD/out_c" 2>&1; rc=$?
expect "unknown version flagged" "pinner METABASE_VERSION" "$TD/out_c"
expect_rc "exit code 1" 1 "$rc"

echo "Case D: embedding enabled on otherwise hardened app -> flagged, exit 1"
printf 'MB_ENCRYPTION_SECRET_KEY=xxx\nMETABASE_VERSION=0.49.10\nMB_ENABLE_EMBEDDING=true\n' > "$TD/env_embed"
STUB_ENV_FILE="$TD/env_embed" STUB_API_EXPOSED=0 bash ./audit.sh > "$TD/out_d" 2>&1; rc=$?
expect "embedding flagged" "Embedding activé" "$TD/out_d"
expect_rc "exit code 1" 1 "$rc"

echo "Case D2: embedding explicitly disabled -> not flagged, app healthy"
printf 'MB_ENCRYPTION_SECRET_KEY=xxx\nMB_SESSION_SECRET_KEY=xxx\nMETABASE_VERSION=0.49.10\nMB_ENABLE_EMBEDDING=false\n' > "$TD/env_embed_off"
STUB_ENV_FILE="$TD/env_embed_off" STUB_API_EXPOSED=0 bash ./audit.sh > "$TD/out_d2" 2>&1; rc=$?
expect "app reported healthy" "✅ testapp" "$TD/out_d2"
expect_rc "exit code 0" 0 "$rc"

echo "Case E: no MB_ env vars, detected via ps (bin/start) -> still audited"
printf 'DATABASE_URL=postgres://x\n' > "$TD/env_nomb"
STUB_ENV_FILE="$TD/env_nomb" STUB_API_EXPOSED=0 bash ./audit.sh > "$TD/out_e" 2>&1; rc=$?
expect "detected as Metabase instance"  "1 instance(s) Metabase"        "$TD/out_e"
expect "missing encryption key flagged" "Poser MB_ENCRYPTION_SECRET_KEY" "$TD/out_e"
expect_rc "exit code 1" 1 "$rc"

echo "Case F: GitHub advisories unreachable (rate limit) -> abort, exit 2"
STUB_ENV_FILE="$TD/env_ok" STUB_GHSA_FAIL=1 bash ./audit.sh > "$TD/out_f" 2>&1; rc=$?
expect "rate-limit message" "GitHub advisories inaccessibles" "$TD/out_f"
expect_rc "exit code 2" 2 "$rc"

echo "Case L: Scalingo CLI not authenticated -> abort exit 2, no false all-clear"
STUB_ENV_FILE="$TD/env_ok" STUB_UNAUTH=1 bash ./audit.sh > "$TD/out_l" 2>&1; rc=$?
expect "auth failure message" "non authentifiée" "$TD/out_l"
expect_rc "exit code 2" 2 "$rc"
if grep -q "Résumé" "$TD/out_l"; then
  echo "  FAIL: false all-clear (Résumé printed while unauthenticated)"; fail=1
else
  echo "  ok: no false summary while unauthenticated"
fi

echo "Case H: new version scheme (55.x), vulnerable pin -> flagged, exit 1"
printf 'MB_ENCRYPTION_SECRET_KEY=xxx\nMETABASE_VERSION=55.5\n' > "$TD/env_new_vuln"
STUB_ENV_FILE="$TD/env_new_vuln" STUB_API_EXPOSED=0 bash ./audit.sh > "$TD/out_h" 2>&1; rc=$?
expect "new-scheme version flagged"     "55.5 (pin) VULNÉRABLE"          "$TD/out_h"
expect "new-scheme threshold"           ">= 55.13"                       "$TD/out_h"
expect "bad advisory format logged"     "seuil d'advisory illisible"     "$TD/out_h"
expect_rc "exit code 1" 1 "$rc"

echo "Case I: unreadable pinned version -> flagged orange, never silent OK"
printf 'MB_ENCRYPTION_SECRET_KEY=xxx\nMETABASE_VERSION=latest\n' > "$TD/env_badver"
STUB_ENV_FILE="$TD/env_badver" STUB_API_EXPOSED=0 bash ./audit.sh > "$TD/out_i" 2>&1; rc=$?
expect "unreadable version flagged" "🟠 Version latest (pin) illisible" "$TD/out_i"
expect_rc "exit code 1" 1 "$rc"

echo "Case J: old-scheme instance vs new-scheme advisory (cross-scheme match)"
printf 'MB_ENCRYPTION_SECRET_KEY=xxx\nMETABASE_VERSION=0.55.5\n' > "$TD/env_cross"
STUB_ENV_FILE="$TD/env_cross" STUB_API_EXPOSED=0 bash ./audit.sh > "$TD/out_j" 2>&1; rc=$?
expect "cross-scheme vuln flagged" "0.55.5 (pin) VULNÉRABLE" "$TD/out_j"
expect "threshold in instance scheme" ">= 0.55.13" "$TD/out_j"
expect_rc "exit code 1" 1 "$rc"

echo "Case K: new-scheme version at patch threshold -> OK, exit 0"
printf 'MB_ENCRYPTION_SECRET_KEY=xxx\nMB_SESSION_SECRET_KEY=xxx\nMETABASE_VERSION=55.13\n' > "$TD/env_new_ok"
STUB_ENV_FILE="$TD/env_new_ok" STUB_API_EXPOSED=0 bash ./audit.sh > "$TD/out_k" 2>&1; rc=$?
expect "app reported healthy" "✅ testapp : OK (55.13, sécu à jour)" "$TD/out_k"
expect_rc "exit code 0" 0 "$rc"

echo "Case M: no session secret key on otherwise hardened app -> flagged, exit 1"
printf 'MB_ENCRYPTION_SECRET_KEY=xxx\nMETABASE_VERSION=0.49.10\n' > "$TD/env_nosession"
STUB_ENV_FILE="$TD/env_nosession" STUB_API_EXPOSED=0 bash ./audit.sh > "$TD/out_m" 2>&1; rc=$?
expect "missing session key flagged" "MB_SESSION_SECRET_KEY" "$TD/out_m"
expect_rc "exit code 1" 1 "$rc"

echo "Case G: real scalingo CLI table format matches the parser (contract)"
# Extract the awk program from audit.sh itself so the test never drifts from the code.
awk_prog=$(sed -n "s/.*awk -F'│' '\(.*\)')$/\1/p" audit.sh)
if [ -z "$awk_prog" ]; then
  echo "  FAIL: could not extract awk parser from audit.sh (parser moved?)"; fail=1
elif [ -n "$REAL_SCALINGO" ] && real_out=$("$REAL_SCALINGO" apps 2>/dev/null) && [ -n "$real_out" ]; then
  names=$(echo "$real_out" | awk -F'│' "$awk_prog")
  if [ -n "$names" ] && ! echo "$names" | grep -qE '[[:space:]│]|^NAME$'; then
    echo "  ok: parsed $(echo "$names" | wc -l) clean app name(s) from real CLI output"
  else
    echo "  FAIL: parser yields empty or malformed names from real CLI output"; fail=1
  fi
else
  echo "  skip: scalingo CLI unavailable or not authenticated"
fi

[ $fail -eq 0 ] && echo "ALL TESTS PASSED" || echo "TESTS FAILED"
exit $fail
