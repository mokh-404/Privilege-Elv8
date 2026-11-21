"""Tests for Track A hash-bucket helpers, Track B loader/splits, and run_track_b smoke."""
import pandas as pd
import pytest

from src import config
from src.data import cic_malmem, splits
from src.eval import run_track_b


# ---------------- Track A benign hash buckets ----------------
def test_artifact_key_bucket_deterministic_and_disjoint():
    keys = [f"file|c:\\users\\public\\item_{i}.exe|item_{i}.exe" for i in range(500)]
    dev_keys, test_keys = set(), set()
    for k in keys:
        b = splits.artifact_key_bucket(k)
        assert 0 <= b < 100
        assert b == splits.artifact_key_bucket(k)
        if splits.benign_pool(k) == "test":
            test_keys.add(k)
            with pytest.raises(ValueError):
                splits.benign_dev_fold(k)
        else:
            dev_keys.add(k)
            fold = splits.benign_dev_fold(k)
            assert 0 <= fold < config.N_DEV_FOLDS
    assert dev_keys and test_keys
    assert dev_keys.isdisjoint(test_keys)


# ---------------- Track B loader & EV-04 guards ----------------
def test_parse_category_raises_stop_and_ask_guard():
    with pytest.raises(NotImplementedError):
        cic_malmem.parse_category(pd.Series(["Benign", "Ransomware-Conti"]))


def test_load_raw_rejects_wrong_shape_and_drops_category_class(tmp_path):
    csv_p = tmp_path / "toy.csv"
    df = pd.DataFrame({
        "f1": [1.0, 2.0, 3.0, 4.0],
        "f2": [0.5, 0.6, 0.7, 0.8],
        "Category": ["Benign", "Benign", "Ransomware-Conti", "Trojan-Zeus"],
        "Class": ["Benign", "Benign", "Malware", "Malware"],
    })
    df.to_csv(csv_p, index=False)

    with pytest.raises(AssertionError):
        cic_malmem.load_raw(csv_p, check_shape=True)

    X, y, raw_cat, fcols = cic_malmem.load_raw(csv_p, check_shape=False)
    assert "Category" not in X.columns and "Class" not in X.columns
    assert fcols == ["f1", "f2"]
    assert list(y) == [0, 0, 1, 1]
    assert len(raw_cat) == 4


def test_split1_stratified_leaky_disjoint():
    X_df, y, _, _ = run_track_b.make_synthetic_track_b(300, seed=42)
    sp = splits.track_b_split1_leaky(y, seed=42)
    assert "LEAKY" in sp["split_note"]
    assert set(sp["train_all_idx"]).isdisjoint(sp["test_idx"])
    assert set(sp["train_idx"]).isdisjoint(sp["val_idx"])
    assert y[sp["test_idx"]].mean() == pytest.approx(y.mean(), abs=0.02)


def test_split2_family_grouped_and_rotations():
    X_df, y, raw_cat, _ = run_track_b.make_synthetic_track_b(600, seed=42)
    cats, fams = run_track_b._smoke_parse_category(raw_cat)
    cic_malmem.validate_parsed_families(cats, fams, y)

    sp = splits.track_b_split2_family_grouped(X_df, y, cats, fams, draw_seed=42, kmeans_seed=42, n_clusters=15)
    assert len(sp["held_out_families"]) == 3
    # Held-out families never appear in train/val
    held = set(sp["held_out_families"])
    assert set(fams.iloc[sp["train_all_malware_idx"]]).isdisjoint(held)
    assert set(fams.iloc[sp["val_idx"]]).isdisjoint(held)
    assert set(fams.iloc[sp["test_idx"][y[sp["test_idx"]] == 1]]) == held
    # Benign sets are disjoint
    assert set(sp["benign_train_idx"]).isdisjoint(sp["benign_val_idx"])
    assert set(sp["benign_train_idx"]).isdisjoint(sp["benign_test_idx"])
    assert set(sp["benign_val_idx"]).isdisjoint(sp["benign_test_idx"])

    # Deterministic
    sp2 = splits.track_b_split2_family_grouped(X_df, y, cats, fams, draw_seed=42, kmeans_seed=42, n_clusters=15)
    assert sp["held_out_families"] == sp2["held_out_families"]
    assert list(sp["test_idx"]) == list(sp2["test_idx"])

    # 5 rotations hold out every one of the 15 families once
    rots = splits.track_b_rotations(cats, fams, y)
    assert len(rots) == 5
    all_rot_fams = [f for r in rots for f in r]
    assert len(all_rot_fams) == 15 and len(set(all_rot_fams)) == 15


def test_run_track_b_smoke_end_to_end(tmp_path):
    X_df, y, raw_cat, fcols = run_track_b.make_synthetic_track_b(1000, seed=42)
    out = run_track_b.run_pipeline(
        X_df, y, raw_cat, fcols,
        arms=config.ARMS + ["lr"],
        do_split1=True, do_split2=True, do_rotate=False,
        category_parser=run_track_b._smoke_parse_category,
        out_tables_dir=tmp_path / "tables",
        logs_dir=tmp_path / "logs",
        max_epochs_override=2,
        is_smoke=True,
    )
    df1 = out["split1"]
    df2 = out["split2"]
    assert list(df1["arm"]) == config.ARMS + ["lr"]
    assert df1["split_note"].str.contains("LEAKY").all()
    assert list(df2["arm"]) == config.ARMS + ["lr"]
    assert df2["caveat"].str.contains("SMOTE").all()
    assert (tmp_path / "tables" / "track_b_split1_smoke.csv").exists()
    assert (tmp_path / "tables" / "track_b_split2_smoke.csv").exists()
    assert (tmp_path / "logs" / "track_b_smoke_meta.json").exists()
