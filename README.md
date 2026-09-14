# beta-audit-toolkit

[![CI](https://github.com/gaspard-lonchampt/beta-audit-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/gaspard-lonchampt/beta-audit-toolkit/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

Petite boîte à outils de scripts d'audit rapides pour les projets hébergés sur
[Scalingo](https://scalingo.com/) (typiquement les produits beta.gouv).

L'idée : des scripts courts, sans dépendance lourde, qui répondent en quelques
minutes à une question de sécurité ou de conformité sur l'ensemble de vos apps,
**sans jamais exposer de secret** (on teste la présence, pas la valeur).

## Installation

```bash
git clone https://github.com/gaspard-lonchampt/beta-audit-toolkit
cd beta-audit-toolkit
```

Aucun build : chaque outil est un script exécutable, lancé depuis son dossier.
Voir le `README.md` de l'outil pour le guide d'usage.

## Prérequis communs

- [CLI Scalingo](https://cli.scalingo.com/) authentifiée (`scalingo login`)
- `bash`, `curl`, `python3`

Chaque outil ne voit que les apps auxquelles votre compte a accès
(`scalingo apps`). Il n'y a pas de vue org-wide via le CLI : lancez depuis un
compte collaborateur/owner du périmètre à auditer, ou faites tourner chaque
équipe sur le sien.

## Outils

| Outil | Rôle |
|-------|------|
| [`metabase-scalingo-hardening`](./metabase-scalingo-hardening) | Audite le durcissement des instances Metabase : clé de chiffrement au repos, clé de signature de session, version vs advisories GitHub (patchs de sécurité), exposition de l'API, embedding. |

## Ajouter un outil

Un dossier par outil, avec son propre `README.md` et un script exécutable. Les
scripts renvoient un code de sortie ≠ 0 s'il y a quelque chose à traiter, pour
être branchables en cron/CI.

Questions ou bugs : ouvrez une [issue](https://github.com/gaspard-lonchampt/beta-audit-toolkit/issues).

## Licence

MIT, voir [LICENSE](./LICENSE).
