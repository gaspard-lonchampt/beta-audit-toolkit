#!/usr/bin/env python3
"""Security verdict of a Metabase version against GitHub Security Advisories.

Usage: secver.py <version> <advisories.json>
Stdout: "OK" | "VULN|<threshold>|<details>" | "UNKNOWN"
Unparsable patched_versions are skipped and reported on stderr.
"""
import json
import sys


def parse(v):
    # Old scheme: edition.branch.patch (0.49.10 / 1.49.10 / x.49.10, x = any edition).
    # New scheme (>= 55): branch.patch. Advisories may prefix a comparator (">= 1.54.22").
    p = v.strip().lstrip(">=< ").lstrip("vV").split(".")
    if len(p) >= 3:
        return p[0], int(p[1]), int(p[2])
    if len(p) == 2 and p[0] not in ("0", "1", "x"):
        return "x", int(p[0]), int(p[1])
    raise ValueError(f"format de version non géré: {v!r}")


def main():
    version, ghsa = sys.argv[1], sys.argv[2]
    adv = json.load(open(ghsa))
    try:
        ed, br, pt = parse(version)
    except Exception:
        print("UNKNOWN")
        return
    req = 0
    hits = []
    for a in adv:
        for vuln in a.get("vulnerabilities", []):
            for pv in (vuln.get("patched_versions") or "").split(","):
                pv = pv.strip()
                if not pv:
                    continue
                try:
                    ped, pbr, ppt = parse(pv)
                except Exception:
                    print(f"seuil d'advisory illisible, ignoré : {pv!r}", file=sys.stderr)
                    continue
                if pbr != br or ("x" not in (ed, ped) and ped != ed):
                    continue
                req = max(req, ppt)
                if pt < ppt:
                    hits.append(f"{a.get('ghsa_id')} {a.get('cve_id') or ''} ({a.get('severity')})")
    # Threshold rendered in the instance's own scheme.
    threshold = f"{br}.{req}" if ed == "x" else f"{ed}.{br}.{req}"
    print("OK" if not hits else "VULN|%s|%s" % (threshold, "; ".join(sorted(set(hits)))))


if __name__ == "__main__":
    main()
