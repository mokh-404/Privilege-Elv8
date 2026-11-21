"""CIC-MalMem-2022 loader, inspector, EV-04 guards, and Category-parser gate.

Non-negotiable rules (EV-04, doc 07 section 3, doc 10 section 3):
  - Assert shape (58596, 57) on the real CSV.
  - Label = Class (Benign vs Malware).
  - Drop Category and Class from X and assert neither is in X.
  - Inspect distinct Category values BEFORE writing the family parser; parse_category()
    intentionally raises NotImplementedError until the real strings are reviewed.
"""
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from src import config


def inspect_csv(path: str | Path = config.CIC_MALMEM_CSV) -> dict[str, Any]:
    """Print shape, columns, Class counts, distinct Category values, and ID-column check."""
    csv_path = Path(path)
    if not csv_path.exists():
        raise FileNotFoundError(
            f"CIC-MalMem-2022 CSV not found at {csv_path}.\n"
            f"Place Obfuscated-MalMem2022.csv at {config.CIC_MALMEM_CSV} and re-run."
        )

    df = pd.read_csv(csv_path)
    print(f"Path: {csv_path}")
    print(f"Shape: {df.shape} (expected {config.CIC_EXPECTED_SHAPE}, match={df.shape == config.CIC_EXPECTED_SHAPE})")
    print(f"Columns ({len(df.columns)}): {list(df.columns)}")
    if config.CIC_LABEL_COL in df.columns:
        print(f"Class counts:\n{df[config.CIC_LABEL_COL].value_counts(dropna=False).to_string()}")
    n_nan = int(df.isna().sum().sum())
    num_df = df.select_dtypes(include=[np.number])
    n_inf = int(np.isinf(num_df.to_numpy()).sum()) if len(num_df.columns) else 0
    print(f"Missing values: {n_nan}; infinite numeric values: {n_inf}")

    cat_counts = {}
    prefix_counts: dict[tuple[str, str], int] = {}
    if config.CIC_CATEGORY_COL in df.columns:
        vc = df[config.CIC_CATEGORY_COL].value_counts(dropna=False)
        cat_counts = {str(k): int(v) for k, v in vc.items()}
        for val, cnt in cat_counts.items():
            parts = val.split("-")
            key = ("Benign", "Benign") if val == "Benign" else (parts[0], parts[1] if len(parts) > 1 else "")
            prefix_counts[key] = prefix_counts.get(key, 0) + cnt
        print(f"Distinct raw {config.CIC_CATEGORY_COL} values: {len(vc)} (grouped into {len(prefix_counts)} category/family prefixes):")
        for (c_part, f_part), cnt in sorted(prefix_counts.items()):
            ex = next((k for k in sorted(cat_counts) if (k == "Benign" if c_part == "Benign" else k.startswith(f"{c_part}-{f_part}-"))), "")
            print(f"  {c_part:12s} | {f_part:16s} | rows={cnt:5d} | example={ex!r}")

    # Check if any column might identify individual source samples (doc 09 section 2)
    suspicious = []
    for col in df.columns:
        if col in (config.CIC_LABEL_COL, config.CIC_CATEGORY_COL):
            continue
        cl = col.lower()
        if any(tok in cl for tok in ("id", "sample", "hash", "md5", "sha", "file", "name")) and cl != "svcscan.nservices":
            suspicious.append((col, str(df[col].dtype), int(df[col].nunique())))
        elif not pd.api.types.is_numeric_dtype(df[col]):
            suspicious.append((col, str(df[col].dtype), int(df[col].nunique())))
    print(f"Potential ID / non-numeric columns (excluding Class/Category): {suspicious}")

    return {
        "shape": df.shape,
        "columns": list(df.columns),
        "n_nan": n_nan,
        "n_inf": n_inf,
        "category_counts": cat_counts,
        "suspicious_columns": suspicious,
    }


def load_raw(
    path: str | Path = config.CIC_MALMEM_CSV,
    check_shape: bool = True,
) -> tuple[pd.DataFrame, np.ndarray, pd.Series, list[str]]:
    """Load Obfuscated-MalMem2022.csv, drop Category & Class from X, and assert EV-04."""
    csv_path = Path(path)
    if not csv_path.exists():
        raise FileNotFoundError(
            f"CIC-MalMem-2022 CSV not found at {csv_path}. "
            f"Place Obfuscated-MalMem2022.csv there first."
        )
    df = pd.read_csv(csv_path)
    if check_shape and df.shape != config.CIC_EXPECTED_SHAPE:
        raise AssertionError(f"Expected shape {config.CIC_EXPECTED_SHAPE}, got {df.shape}")
    for req in (config.CIC_LABEL_COL, config.CIC_CATEGORY_COL):
        if req not in df.columns:
            raise KeyError(f"Required column {req!r} missing from {csv_path}")

    labels_raw = df[config.CIC_LABEL_COL].astype(str).str.strip()
    valid_labels = {config.CIC_NEGATIVE_CLASS, config.CIC_POSITIVE_CLASS}
    unexpected = set(labels_raw.unique()) - valid_labels
    if unexpected:
        raise ValueError(f"Unexpected values in {config.CIC_LABEL_COL}: {sorted(unexpected)}")

    feature_cols = [c for c in df.columns if c not in (config.CIC_LABEL_COL, config.CIC_CATEGORY_COL)]
    assert config.CIC_CATEGORY_COL not in feature_cols
    assert config.CIC_LABEL_COL not in feature_cols

    X = df[feature_cols].copy()
    assert config.CIC_CATEGORY_COL not in X.columns and config.CIC_LABEL_COL not in X.columns
    non_num = [c for c in X.columns if not pd.api.types.is_numeric_dtype(X[c])]
    if non_num:
        raise TypeError(f"Non-numeric feature columns in Track B X: {non_num}")

    y = (labels_raw == config.CIC_POSITIVE_CLASS).astype(int).to_numpy()
    raw_category = df[config.CIC_CATEGORY_COL].astype(str)
    return X, y, raw_category, feature_cols


def parse_category(series: pd.Series) -> tuple[pd.Series, pd.Series]:
    """Parse raw `Category` strings into `(malware_category, family)` Series.

    Intentionally NOT implemented until the real `Category` values from
    `Obfuscated-MalMem2022.csv` have been printed (`--inspect`) and confirmed by the
    operator (stop-and-ask rule, doc 07 section 3).
    """
    raise NotImplementedError(
        "Category parser is not implemented yet (stop-and-ask guard). "
        "Place Obfuscated-MalMem2022.csv at data/external/cic_malmem_2022/Obfuscated-MalMem2022.csv, "
        "run `python -m src.data.cic_malmem --inspect`, and confirm the Category format with the operator."
    )


def validate_parsed_families(categories: pd.Series, families: pd.Series, y: np.ndarray) -> None:
    """Assert exactly Benign for y==0 and 3 categories x 5 families = 15 families for y==1."""
    y_arr = np.asarray(y).astype(int).ravel()
    cats = pd.Series(categories).reset_index(drop=True)
    fams = pd.Series(families).reset_index(drop=True)

    benign_cats = set(cats[y_arr == 0].unique())
    benign_fams = set(fams[y_arr == 0].unique())
    assert benign_cats == {"Benign"}, f"Benign rows must have category 'Benign', got {benign_cats}"
    assert benign_fams == {"Benign"}, f"Benign rows must have family 'Benign', got {benign_fams}"

    mal_cats = cats[y_arr == 1]
    mal_fams = fams[y_arr == 1]
    assert "Benign" not in set(mal_cats.unique())
    assert "Benign" not in set(mal_fams.unique())
    assert mal_cats.nunique() == 3, f"Expected 3 malware categories, got {mal_cats.nunique()}: {sorted(mal_cats.unique())}"
    assert mal_fams.nunique() == config.CIC_N_FAMILIES, (
        f"Expected {config.CIC_N_FAMILIES} malware families, got {mal_fams.nunique()}: {sorted(mal_fams.unique())}"
    )
    for c in sorted(mal_cats.unique()):
        c_fams = set(mal_fams[mal_cats == c].unique())
        assert len(c_fams) == 5, f"Category {c!r} has {len(c_fams)} families (expected 5): {sorted(c_fams)}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Inspect CIC-MalMem-2022 CSV before parsing Category.")
    parser.add_argument("--inspect", action="store_true", help="Print shape, columns, and distinct Category strings.")
    parser.add_argument("--csv", type=Path, default=config.CIC_MALMEM_CSV, help="Path to Obfuscated-MalMem2022.csv.")
    args = parser.parse_args(argv)
    if args.inspect or True:
        inspect_csv(args.csv)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
