"""Tests for Step C.6: real byte histograms, template-quantization gate, extractor predicates & pools."""
from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

from scripts.verify_stratified_shortcuts import (
    check_template_quantization,
    load_attack_rows,
    simulate_benign_rows,
    simulate_v2_benign_rows,
)
from scripts.v2_prepare_benign_pools import (
    evaluate_pool_quotas,
    index_and_validate_benign_pools,
    ingest_package_dir,
    main as prepare_pools_main,
)
from src.data.features import row_features
from src.v2.benign_generator_v2 import (
    BENIGN_AVOIDED_EXTS,
    RealBenignPoolRequiredError,
    WORKLOAD_PROFILES,
    _synth_unsigned_pe_bytes,
    generate_benign_workload_bundle,
    path_matches_extractor_scan_roots,
    path_passes_extractor_file_predicate,
    simulate_benign_generator_rows,
)
from src.v2.offline_extractor import _SKIP_DIR_FRAGS, _USER_SCAN_TARGET_EXTS


def test_real_histograms_and_no_uniform_placeholders():
    att = load_attack_rows(real_bytes=True)
    ben, _ = simulate_v2_benign_rows(profile="dev", n_runs=24)
    assert att and ben
    for r in att + ben:
        hist = r.get("file_head_histogram")
        if hist is not None:
            assert hist != [1] * 256
            assert len(hist) == 256
            assert sum(hist) == min(r["file_size"], 1 << 20)


def test_quantization_gate_passes_v2_and_fails_v1_templates():
    # Legacy v1 6-template simulation uses constant size=2048 -> MUST FAIL quantization check
    v1_rows, _ = simulate_benign_rows(n_seeds=24)
    v1_feats = pd.DataFrame([row_features(r) for r in v1_rows])
    v1_res = check_template_quantization(v1_feats)
    assert v1_res["passed"] is False
    assert v1_res["unique_size_ratio"] < 0.60

    # Upgraded v2 generator MUST PASS all quantization & diversity gates
    v2_rows, _ = simulate_v2_benign_rows(profile="dev", n_runs=24)
    v2_feats = pd.DataFrame([row_features(r) for r in v2_rows])
    v2_res = check_template_quantization(v2_feats)
    assert v2_res["passed"] is True
    assert v2_res["unique_size_ratio"] >= 0.60
    assert v2_res["unique_size_entropy_pair_ratio"] >= 0.75
    assert v2_res["max_single_size_share"] <= 0.10
    assert v2_res["benign_services"] > 0
    assert v2_res["benign_registry"] > 0
    assert v2_res["benign_unsigned_pes"] > 0


def test_disjoint_dev_and_blind_test_host_profiles():
    dev_rows, dev_keys = simulate_v2_benign_rows(profile="dev", n_runs=30, base_seed=1000)
    test_rows, test_keys = simulate_v2_benign_rows(profile="blind_test", n_runs=30, base_seed=2000)
    assert dev_keys.isdisjoint(test_keys)
    # Varied task triggers present in both
    dev_trigs = {r["task_triggers"] for r in dev_rows if r.get("task_triggers")}
    test_trigs = {r["task_triggers"] for r in test_rows if r.get("task_triggers")}
    assert len(dev_trigs) >= 3 and len(test_trigs) >= 3


def test_benign_generator_v2_passes_quantization_and_pool_disjointness(tmp_path):
    src_dev = tmp_path / "src_dev_pkg"
    src_test = tmp_path / "src_test_pkg"
    src_dev.mkdir()
    src_test.mkdir()
    for idx in range(110):
        (src_dev / f"dev_cli_{idx:03d}.exe").write_bytes(
            _synth_unsigned_pe_bytes(11 + idx, 16384 + idx * 137, is_dll=False, high_entropy=(idx % 2 == 1))
        )
        (src_test / f"test_agent_{idx:03d}.exe").write_bytes(
            _synth_unsigned_pe_bytes(501 + idx, 18432 + idx * 149, is_dll=False, high_entropy=(idx % 2 == 1))
        )
    for idx in range(30):
        (src_dev / f"dev_setup_{idx:02d}.msi").write_bytes(
            _synth_unsigned_pe_bytes(800 + idx, 40960 + idx * 251, is_dll=False, high_entropy=True)
        )
        (src_test / f"test_setup_{idx:02d}.msi").write_bytes(
            _synth_unsigned_pe_bytes(900 + idx, 45056 + idx * 263, is_dll=False, high_entropy=True)
        )
    for idx in range(10):
        (src_dev / f"dev_sync_{idx:02d}.ps1").write_text(
            f"Write-Output 'dev sync {idx} " + ("x" * (idx * 37)) + "'\n", encoding="utf-8"
        )
        (src_test / f"test_audit_{idx:02d}.ps1").write_text(
            f"Write-Output 'test audit {idx} " + ("y" * (idx * 41)) + "'\n", encoding="utf-8"
        )

    pools = tmp_path / "benign_pools"
    ingest_package_dir(src_dev, pools, split_pool="dev", package_name="devpkg")
    ingest_package_dir(src_test, pools, split_pool="blind_test", package_name="testpkg")
    summary = index_and_validate_benign_pools(pools, write_manifest=True)
    assert summary["disjointness_verified"] is True
    assert summary["dev"]["total_files"] == 150 and summary["blind_test"]["total_files"] == 150

    # Same filename across splits MUST be blocked
    coll_dir = tmp_path / "src_collide"
    coll_dir.mkdir()
    (coll_dir / "dev_cli_000.exe").write_bytes(b"different_bytes_same_name")
    with pytest.raises(ValueError, match="Cross-split"):
        ingest_package_dir(coll_dir, pools, split_pool="blind_test", package_name="otherpkg")

    dev_rows, dev_keys = simulate_benign_generator_rows(
        "dev", n_runs=24, base_seed=7000, benign_pools_root=pools, require_real_pools=True
    )
    test_rows, test_keys = simulate_benign_generator_rows(
        "blind_test", n_runs=24, base_seed=8000, benign_pools_root=pools, require_real_pools=True
    )
    assert dev_keys.isdisjoint(test_keys)
    assert len({tuple(r["file_head_histogram"]) for r in dev_rows if r.get("file_head_histogram")}) >= 20

    feats = pd.DataFrame([row_features(r) for r in dev_rows])
    qres = check_template_quantization(feats)
    assert qres["passed"] is True, qres
    assert qres["benign_unsigned_pes"] > 0 and qres["benign_services"] > 0 and qres["benign_registry"] > 0


def test_all_benign_profiles_pass_real_extractor_predicates(tmp_path):
    # Negative extractor predicate checks (must reject unwalked paths, skip dirs, and excess depth)
    assert path_matches_extractor_scan_roots(r"C:\Windows\System32\evil.exe") is False
    assert path_matches_extractor_scan_roots(r"C:\ProgramData\Microsoft\Windows Defender\x.exe") is False
    assert path_matches_extractor_scan_roots(r"C:\Users\alice_dev\AppData\Local\a\b\c\d\deep.exe") is False
    assert path_passes_extractor_file_predicate(r"C:\ProgramData\DevOpsTools\script.py") is False
    assert path_passes_extractor_file_predicate(r"C:\ProgramData\DevOpsTools\ok.ps1") is True

    # Populate pool including decoys with uncollected/avoided extensions (.py, .zip, .json, .log, .hta, .scr)
    pools = tmp_path / "pools_with_decoys"
    for sp in ("dev", "blind_test"):
        pdir = pools / sp / f"{sp}_pkg"
        pdir.mkdir(parents=True, exist_ok=True)
        for i in range(4):
            (pdir / f"{sp}_tool_{i}.exe").write_bytes(
                _synth_unsigned_pe_bytes(300 + i, 32768 + i * 2048, high_entropy=(i % 2 == 1))
            )
        (pdir / f"{sp}_inst.msi").write_bytes(_synth_unsigned_pe_bytes(999, 65536, high_entropy=True))
        for bad_ext in (".py", ".zip", ".json", ".log", ".hta", ".scr"):
            (pdir / f"{sp}_decoy{bad_ext}").write_bytes(b"decoy_bytes")

    empty_pools = tmp_path / "empty_pools"
    for pool_arg, expect_synth in ((empty_pools, True), (pools, False)):
        for sp in ("dev", "blind_test"):
            for i, pid in enumerate(WORKLOAD_PROFILES[sp]["profile_ids"]):
                bun = generate_benign_workload_bundle(
                    run_id=f"pred_{sp}_{i:02d}",
                    split_pool=sp,
                    benign_profile_id=pid,
                    run_seed=4000 + i,
                    benign_pools_root=pool_arg,
                    require_real_pools=(not expect_synth),
                )
                man = bun["benign_manifest"]
                assert man["synthetic_fallback"] is expect_synth
                if expect_synth:
                    assert man["synthetic_fallback_counts"] == {"unsigned_pe": 2, "high_entropy_pe": 3}
                    assert man["synthetic_fallback_count"] == 5
                else:
                    assert man["synthetic_fallback_counts"] == {"unsigned_pe": 0, "high_entropy_pe": 0}
                    assert man["synthetic_fallback_count"] == 0

                for frec in man["files"]:
                    fp = frec["path"]
                    ext = Path(fp.replace("\\", "/")).suffix.lower()
                    assert ext in _USER_SCAN_TARGET_EXTS
                    assert ext not in BENIGN_AVOIDED_EXTS
                    assert path_matches_extractor_scan_roots(fp)
                    dir_low = fp.rsplit("\\", 1)[0].lower() + "\\"
                    assert not any(frag in dir_low for frag in _SKIP_DIR_FRAGS)

    # require_real_pools=True MUST fail when pool empty OR lacks real .exe/.msi installers
    with pytest.raises(RealBenignPoolRequiredError):
        generate_benign_workload_bundle(
            run_id="req_empty",
            split_pool="dev",
            benign_pools_root=empty_pools,
            require_real_pools=True,
        )
    script_only_pool = tmp_path / "script_only_pool"
    (script_only_pool / "dev" / "s_pkg").mkdir(parents=True)
    (script_only_pool / "dev" / "s_pkg" / "only_script.ps1").write_text("Write-Output 'hi'\n", encoding="utf-8")
    with pytest.raises(RealBenignPoolRequiredError, match="installer"):
        generate_benign_workload_bundle(
            run_id="req_no_inst",
            split_pool="dev",
            benign_pools_root=script_only_pool,
            require_real_pools=True,
        )


def test_benign_pool_audit_enforce_quotas_cli_and_floors(tmp_path):
    pools = tmp_path / "pools_quota"
    assert prepare_pools_main(["--pools-root", str(pools), "--init-dirs", "--audit", "--enforce-quotas"]) == 2

    # Populate unsigned PEs + scripts + MSIs across dev and blind_test, still missing signed PEs (0 signed!)
    dev_dir = pools / "dev" / "git_for_windows"
    test_dir = pools / "blind_test" / "notepadplusplus"
    (dev_dir / "u1.exe").write_bytes(_synth_unsigned_pe_bytes(1, 20480, high_entropy=True))
    (dev_dir / "s1.ps1").write_text("Write-Output 1\n", encoding="utf-8")
    (test_dir / "u2.exe").write_bytes(_synth_unsigned_pe_bytes(2, 22528, high_entropy=True))
    (test_dir / "s2.ps1").write_text("Write-Output 2\n", encoding="utf-8")

    assert prepare_pools_main(["--pools-root", str(pools), "--audit"]) == 0
    assert prepare_pools_main(["--pools-root", str(pools), "--audit", "--enforce-quotas"]) == 2

    summary = index_and_validate_benign_pools(pools, write_manifest=False)
    # Without signed PEs, even lowered total floors fail due to dev/blind_test signed_pe == 0
    q_low_floors = evaluate_pool_quotas(
        summary,
        hard_floors={
            "total_files": 4,
            "unsigned_pe": 2,
            "signed_pe": 0,
            "script": 2,
            "high_entropy_installers": 2,
            "dev_signed_pe_min": 1,
            "dev_unsigned_pe_min": 1,
            "blind_test_signed_pe_min": 1,
            "blind_test_unsigned_pe_min": 1,
        },
    )
    assert q_low_floors["passed"] is False
    assert any("dev signed_pe" in f for f in q_low_floors["failures"])
    assert any("blind_test signed_pe" in f for f in q_low_floors["failures"])

    # Mocked Valid signed_pe + meeting floors passes cleanly
    synthetic_good = {
        "dev": {"categories": {"unsigned_pe": 150, "signed_pe": 150, "script": 250, "installer_msi": 100}},
        "blind_test": {"categories": {"unsigned_pe": 50, "signed_pe": 50, "script": 100, "installer_msi": 50}},
        "total": {
            "total_files": 1100,
            "high_entropy_installers": 260,
            "categories": {"unsigned_pe": 200, "signed_pe": 200, "script": 350, "installer_msi": 150},
        },
    }
    assert evaluate_pool_quotas(synthetic_good)["passed"] is True
