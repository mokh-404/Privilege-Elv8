# Reviewed Malware Family Allowlist (`ALLOWED_FAMILIES` Canonical Review Sheet)

**Policy Scope (`OD-V2-08`):** Hard-excludes ransomware, wipers, and self-propagating worms.  
**Recent Cleanup:** Removed `lime` and `limerat` from `ALLOWED_FAMILIES` and added them to `FORBIDDEN_MALWARE_FAMILIES_AND_TAGS` (USB-spreader / ransomware modules violate the hard exclusion).  
**Excluded Pending Supervisor Decision:** `njrat`, `bladabindi`, `qakbot`, `emotet`, `trickbot` (intentionally excluded pending review).  
**Canonical Grouping Rule:** Known closely linked names/aliases map to one canonical family key via [`canonicalize_family_name`](../../src/v2/pilot_staging.py) for `dev`/`blind_test` splits ([`assign_v2_splits`](../../src/v2/labeler_v2.py)), nested CV grouping ([`build_family_cluster_groups`](../../src/v2/training.py)), and per-family curation caps ([`select_pilot_families`](../../scripts/v2_curate_vault_manifest.py)).

> [!IMPORTANT]
> The **`spreader modules? (Mokh+supervisor to verify)`** column below is intentionally left **blank** for Mokh + Supervisor Marawan (AASTMT) to review and sign off directly before any Stage B scaling.

| # | Canonical Family | Known Aliases | spreader modules? (Mokh+supervisor to verify) |
| ---: | :--- | :--- | :--- |
| 1 | `agenttesla` | `—` | |
| 2 | `amadey` | `—` | |
| 3 | `arkei` | `—` | |
| 4 | `asyncrat` | `—` | |
| 5 | `aurora` | `aurorastealer` | |
| 6 | `azorult` | `—` | |
| 7 | `bazarloader` | `—` | |
| 8 | `bitrat` | `—` | |
| 9 | `buer` | `buerloader` | |
| 10 | `bumblebee` | `—` | |
| 11 | `clipbanker` | `—` | |
| 12 | `cobaltstrike` | `—` | |
| 13 | `coinminer` | `—` | |
| 14 | `cryptobot` | `—` | |
| 15 | `darkcomet` | `—` | |
| 16 | `darkgate` | `—` | |
| 17 | `dbatloader` | `—` | |
| 18 | `dcrat` | `—` | |
| 19 | `formbook` | `xloader` | |
| 20 | `gh0st` | `ghostrat` | |
| 21 | `guloader` | `—` | |
| 22 | `hijackloader` | `—` | |
| 23 | `icedid` | `—` | |
| 24 | `laplasclipper` | `—` | |
| 25 | `latrodectus` | `—` | |
| 26 | `lokibot` | `—` | |
| 27 | `lumma` | `lummac2`, `lummastealer` | |
| 28 | `marsstealer` | `—` | |
| 29 | `masslogger` | `—` | |
| 30 | `matanbuchus` | `—` | |
| 31 | `metastealer` | `—` | |
| 32 | `modiloader` | `—` | |
| 33 | `nanocore` | `nanocorerat` | |
| 34 | `netwire` | `—` | |
| 35 | `orcus` | `orcusrat` | |
| 36 | `phantomrat` | `—` | |
| 37 | `phoenixkeylogger` | `—` | |
| 38 | `pikabot` | `—` | |
| 39 | `poisonivy` | `—` | |
| 40 | `pony` | `—` | |
| 41 | `predatorthethief` | `—` | |
| 42 | `privateloader` | `—` | |
| 43 | `purecrypter` | `—` | |
| 44 | `quasar` | `quasarrat` | |
| 45 | `raccoon` | `raccoonstealer` | |
| 46 | `recordbreaker` | `—` | |
| 47 | `redline` | `redlinestealer` | |
| 48 | `remcos` | `remcosrat` | |
| 49 | `revenge` | `revengerat` | |
| 50 | `rhadamanthys` | `—` | |
| 51 | `risepro` | `—` | |
| 52 | `silentcryptominer` | `—` | |
| 53 | `smokeloader` | `—` | |
| 54 | `snakekeylogger` | `—` | |
| 55 | `stealc` | `—` | |
| 56 | `systembc` | `—` | |
| 57 | `venomrat` | `—` | |
| 58 | `vidar` | `—` | |
| 59 | `warzone` | `avemaria`, `warzonerat` | |
| 60 | `whitesnake` | `—` | |
| 61 | `xmrig` | `—` | |
| 62 | `zloader` | `—` | |
