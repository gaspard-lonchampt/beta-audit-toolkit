# metabase-scalingo-hardening

[![CI](https://github.com/gaspard-lonchampt/beta-audit-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/gaspard-lonchampt/beta-audit-toolkit/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](../LICENSE)

Audit du durcissement des instances **Metabase** hébergées sur Scalingo, en une commande, **sans exposer aucun secret**.

## Sommaire

- [Pourquoi](#pourquoi)
- [Ce qu'il vérifie](#ce-quil-vérifie)
- [Prérequis](#prérequis)
- [Installation](#installation)
- [Utilisation](#utilisation)
- [Sortie](#sortie)
- [Codes de sortie](#codes-de-sortie)
- [Comment les versions sont comparées](#comment-les-versions-sont-comparées)
- [Conception et garanties](#conception-et-garanties)
- [Tests](#tests)
- [Limites](#limites)
- [Licence](#licence)

## Pourquoi

Une instance Metabase montée il y a longtemps peut passer à côté des points de durcissement clés sans que personne ne le sache. Motivation directe : la **CVE-2026-72898** (injection SQL non authentifiée, CVSS 10.0), exploitable **avant** l'écran de connexion, donc non couverte par le login natif de Metabase.

Cet outil répond en quelques minutes à « toutes mes instances sont-elles durcies ? » sur l'ensemble des apps d'un compte Scalingo.

## Ce qu'il vérifie

Pour chaque instance Metabase détectée (indépendamment du nom de l'app : présence de variables `MB_`/`METABASE_`, ou conteneur `bin/start`) :

| Point vérifié | Risque si absent |
|---|---|
| `MB_ENCRYPTION_SECRET_KEY` posée | secrets Metabase (mots de passe des sources) stockés en clair dans la base de métadonnées |
| Version ≥ patch de sécurité de sa branche ([GitHub Advisories](https://github.com/metabase/metabase/security/advisories)) | instance vulnérable |
| API non joignable sans authentification | vecteur pré-auth exploité par la CVE (l'URL Scalingo par défaut reste souvent joignable) |
| Embedding désactivé (`MB_ENABLE_EMBEDDING`) | surface d'attaque + clé de signature à protéger |

## Prérequis

- `bash`, `curl`, `python3`
- [CLI Scalingo](https://cli.scalingo.com/) **authentifiée** (`scalingo login`) — l'audit ne voit que les apps du compte
- `GITHUB_TOKEN` (recommandé) : sans lui, l'API GitHub Advisories est limitée à 60 req/h

## Installation

```bash
git clone https://github.com/gaspard-lonchampt/beta-audit-toolkit
cd beta-audit-toolkit/metabase-scalingo-hardening
```

Aucun build : `audit.sh` est directement exécutable.

## Utilisation

```bash
scalingo login                 # authentifie le CLI
export GITHUB_TOKEN=ghp_xxx    # recommandé (token lecture seule, aucun scope requis)
./audit.sh
```

Rien n'est écrit ni modifié : l'outil lit l'environnement des apps et teste la **présence** des variables, jamais leur valeur.

## Sortie

```
⚠️  mon-metabase :
      - 🔴 API Metabase accessible sans authentification -> placer un proxy d'auth devant
      - 🔴 Version v0.63.4 (pin) VULNÉRABLE -> mettre à jour vers >= 0.63.10 (manque : CVE-2026-72898)
✅ autre-metabase : OK (v0.63.10, sécu à jour)
==================================================
Résumé : 1 app(s) à traiter sur 2 instance(s) Metabase détectée(s).
```

Une ligne par instance ; chaque action porte une pastille :

| Pastille | Signification |
|---|---|
| 🔴 | À corriger : faille ou durcissement manquant |
| 🟠 | À vérifier à la main : l'outil n'a pas pu conclure (ex. version illisible) |
| 🟡 | Point d'attention non bloquant (ex. embedding activé) |
| ✅ | Conforme sur les points audités |

## Codes de sortie

Pensés pour l'alerte automatique en cron/CI.

| Code | Sens |
|---|---|
| `0` | Rien à traiter |
| `1` | Au moins une app à traiter |
| `2` | Audit impossible : CLI Scalingo non authentifiée, ou advisories GitHub injoignables (rate-limit) |

Deux options propres pour le `GITHUB_TOKEN` :

- **CI / Scheduler (recommandé)** : stockez `GITHUB_TOKEN` dans le coffre à secrets de la plateforme (secrets GitHub Actions, variables d'env Scalingo…), jamais inline.
- **Cron sur une machine** : token dans un fichier lisible par vous seul, sourcé au lancement :

  ```bash
  # ~/.config/beta-audit.env   (chmod 600)
  export GITHUB_TOKEN=ghp_xxx
  ```
  ```cron
  0 6 * * *  . "$HOME/.config/beta-audit.env" && cd /chemin/metabase-scalingo-hardening && ./audit.sh
  ```

## Comment les versions sont comparées

Metabase a changé de numérotation en 2025 ; les deux schémas sont reconnus :

| Schéma | Forme | Exemples | Lecture |
|---|---|---|---|
| Ancien | `édition.branche.patch` | `0.59.1` (OSS), `1.59.1` (Enterprise) | branche 59, patch 1 |
| Nouveau | `branche.patch` | `55.13` | branche 55, patch 13 |

La comparaison se fait au **patch de sécurité** de la branche, pas à la « dernière version » : une instance peut être en retard d'une version tout en ayant tous les correctifs de sécu (et inversement). Un advisory publié dans un schéma s'applique à une instance versionnée dans l'autre dès que la branche correspond (`0.55.9` est bien comparé à un seuil `55.13`).

## Conception et garanties

- **Zéro secret exposé** : on teste la présence, pas la valeur ; le `GITHUB_TOKEN` est passé à `curl` via un fichier de config sur stdin, jamais dans `argv` (invisible dans `ps`).
- **Fail-closed, jamais de faux « tout va bien »** : si le CLI Scalingo n'est pas authentifié ou si les advisories sont injoignables, l'audit s'arrête en code `2` au lieu de conclure à tort. De même, une version d'instance illisible (ex. `latest`) est signalée 🟠, et un seuil d'advisory illisible part en avertissement sur stderr : rien n'est ignoré en silence.
- **Détection robuste** : indépendante du nom de l'app, elle attrape même une instance non configurée (justement celle qu'on veut trouver).

## Tests

```bash
./test.sh        # self-check du comparateur de versions (secver.py), sans réseau
./test_audit.sh  # suite end-to-end : scalingo/curl stubbés, aucun appel réel
```

`shellcheck` + ces deux suites tournent en [CI](../.github/workflows/ci.yml) à chaque push.

## Limites

- Ne couvre que les apps accessibles par le compte qui lance (`scalingo apps`) : pas de vue org-wide.
- Le check **embedding** se base sur l'env ; s'il est activé en base (`setting`), il ne sera pas vu.
- Pour une instance **non pinnée**, la version réelle est lue via l'API, donc invisible si un proxy d'auth la protège (le cas souhaitable). Pinnez `METABASE_VERSION` pour pouvoir l'auditer.

## Licence

[MIT](../LICENSE)
