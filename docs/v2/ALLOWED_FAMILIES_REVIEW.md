# Reviewed Malware Family Allowlist (`ALLOWED_FAMILIES` Canonical Review Sheet)

**Policy Scope (`OD-V2-08`):** Hard-excludes ransomware, wipers, and self-propagating worms.  
**Recent Cleanup:** Removed `lime` and `limerat` from `ALLOWED_FAMILIES` and added them to `FORBIDDEN_MALWARE_FAMILIES_AND_TAGS` (USB-spreader / ransomware modules violate the hard exclusion).  
**Excluded Pending Supervisor Decision:** `njrat`, `bladabindi`, `qakbot`, `emotet`, `trickbot` (intentionally excluded pending review).  
**Canonical Grouping Rule:** Known closely linked names/aliases and direct rebrands (`arkei -> vidar`, `recordbreaker -> raccoon`) map to one canonical family key via [`canonicalize_family_name`](../../src/v2/pilot_staging.py) for `dev`/`blind_test` splits ([`assign_v2_splits`](../../src/v2/labeler_v2.py)), nested CV grouping ([`build_family_cluster_groups`](../../src/v2/training.py)), and per-family curation caps ([`select_pilot_families`](../../scripts/v2_curate_vault_manifest.py)). Close forks (`metastealer / redline`, `venomrat / quasarrat`) are flagged in `lineage_or_fork_notes` for split/clustering awareness.

> [!IMPORTANT]
> The **`spreader modules? (Mokh+supervisor to verify)`** column below is intentionally left **blank** for Mokh + Supervisor Marawan (AASTMT) to review and sign off directly before any Stage B scaling.

| # | Canonical Family | Known Aliases | lineage_or_fork_notes | spreader modules? (Mokh+supervisor to verify) |
| ---: | :--- | :--- | :--- | :--- |
| 1 | `agenttesla` | `—` | `—` | |
| 2 | `amadey` | `—` | `—` | |
| 3 | `asyncrat` | `—` | `—` | |
| 4 | `aurora` | `aurorastealer` | `—` | |
| 5 | `azorult` | `—` | `—` | |
| 6 | `bazarloader` | `—` | `—` | |
| 7 | `bitrat` | `—` | `—` | |
| 8 | `buer` | `buerloader` | `—` | |
| 9 | `bumblebee` | `—` | `—` | |
| 10 | `clipbanker` | `—` | `—` | |
| 11 | `cobaltstrike` | `—` | `—` | |
| 12 | `coinminer` | `—` | `—` | |
| 13 | `cryptobot` | `—` | `—` | |
| 14 | `darkcomet` | `—` | `—` | |
| 15 | `darkgate` | `—` | `—` | |
| 16 | `dbatloader` | `—` | `—` | |
| 17 | `dcrat` | `—` | `—` | |
| 18 | `formbook` | `xloader` | `—` | |
| 19 | `gh0st` | `ghostrat` | `—` | |
| 20 | `guloader` | `—` | `—` | |
| 21 | `hijackloader` | `—` | `—` | |
| 22 | `icedid` | `—` | `—` | |
| 23 | `laplasclipper` | `—` | `—` | |
| 24 | `latrodectus` | `—` | `—` | |
| 25 | `lokibot` | `—` | `—` | |
| 26 | `lumma` | `lummac2`, `lummastealer` | `—` | |
| 27 | `marsstealer` | `—` | `—` | |
| 28 | `masslogger` | `—` | `—` | |
| 29 | `matanbuchus` | `—` | `—` | |
| 30 | `metastealer` | `—` | Close fork / lineage with `redline` (keep split/clustering awareness) | |
| 31 | `modiloader` | `—` | `—` | |
| 32 | `nanocore` | `nanocorerat` | `—` | |
| 33 | `netwire` | `—` | `—` | |
| 34 | `orcus` | `orcusrat` | `—` | |
| 35 | `phantomrat` | `—` | `—` | |
| 36 | `phoenixkeylogger` | `—` | `—` | |
| 37 | `pikabot` | `—` | `—` | |
| 38 | `poisonivy` | `—` | `—` | |
| 39 | `pony` | `—` | `—` | |
| 40 | `predatorthethief` | `—` | `—` | |
| 41 | `privateloader` | `—` | `—` | |
| 42 | `purecrypter` | `—` | `—` | |
| 43 | `quasar` | `quasarrat` | Close fork / lineage with `venomrat` (keep split/clustering awareness) | |
| 44 | `raccoon` | `raccoonstealer`, `recordbreaker` | Direct rebrand alias (`recordbreaker -> raccoon`) | |
| 45 | `redline` | `redlinestealer` | Close fork / lineage with `metastealer` (keep split/clustering awareness) | |
| 46 | `remcos` | `remcosrat` | `—` | |
| 47 | `revenge` | `revengerat` | `—` | |
| 48 | `rhadamanthys` | `—` | `—` | |
| 49 | `risepro` | `—` | `—` | |
| 50 | `silentcryptominer` | `—` | `—` | |
| 51 | `smokeloader` | `—` | `—` | |
| 52 | `snakekeylogger` | `—` | `—` | |
| 53 | `stealc` | `—` | `—` | |
| 54 | `systembc` | `—` | `—` | |
| 55 | `venomrat` | `—` | Close fork / lineage with `quasarrat` (`quasar`, keep split/clustering awareness) | |
| 56 | `vidar` | `arkei` | Direct rebrand alias (`arkei -> vidar`) | |
| 57 | `warzone` | `avemaria`, `warzonerat` | `—` | |
| 58 | `whitesnake` | `—` | `—` | |
| 59 | `xmrig` | `—` | `—` | |
| 60 | `zloader` | `—` | `—` | |
