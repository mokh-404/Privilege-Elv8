"""300-DPI publication figures (Prompt D, doc 10 section 7).

Rules:
  - Read values ONLY from results/tables/*.csv (and shap_xgb_rows.parquet); zero hard-coded numbers.
  - Save PNG and PDF at dpi=300, column widths 3.5 in (single) or 7.0 in (double).
  - Consistent font, Okabe-Ito colour-blind-safe palette + line styles / markers.
  - No titles inside figures (captions belong in the paper); axis labels with units.
  - Write results/figures/figures_manifest.json mapping file, source CSVs, and commit hash.
"""
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from src import config
from src.utils.repro import get_commit_hash, utc_now_iso, write_json

plt.rcParams.update({
    "font.family": "sans-serif",
    "font.size": 8.5,
    "axes.labelsize": 8.5,
    "xtick.labelsize": 7.5,
    "ytick.labelsize": 7.5,
    "legend.fontsize": 7.5,
    "axes.spines.top": False,
    "axes.spines.right": False,
})

# Okabe-Ito colour-blind-safe palette + distinct line styles & markers per arm
ARM_STYLE = {
    "rf":      {"color": "#0072B2", "ls": "-",  "marker": "o"},
    "xgb":     {"color": "#D55E00", "ls": "--", "marker": "s"},
    "iforest": {"color": "#009E73", "ls": ":",  "marker": "^"},
    "mlp":     {"color": "#CC79A7", "ls": "-.", "marker": "D"},
    "ae":      {"color": "#E69F00", "ls": (0, (3, 1, 1, 1)), "marker": "v"},
    "lr":      {"color": "#56B4E9", "ls": (0, (1, 1)), "marker": "x"},
}


def _save(fig: plt.Figure, figures_dir: Path, stem: str, source_files: list[str], manifest: list[dict]) -> None:
    figures_dir.mkdir(parents=True, exist_ok=True)
    for ext in ("png", "pdf"):
        out = figures_dir / f"{stem}.{ext}"
        fig.savefig(out, dpi=300, bbox_inches="tight")
        manifest.append({
            "file": str(out),
            "figure": stem,
            "format": ext,
            "source_csvs": source_files,
            "dpi": 300,
            "commit": get_commit_hash(),
        })
    plt.close(fig)


def fig1_pr_curves(tables_dir: Path, figures_dir: Path, manifest: list[dict]) -> bool:
    src = tables_dir / "track_a_pr_curves.csv"
    if not src.exists():
        return False
    df = pd.read_csv(src)
    fig, ax = plt.subplots(figsize=(3.5, 2.8))
    for arm, grp in df.groupby("arm", sort=False):
        st = ARM_STYLE.get(arm, {"color": "#333333", "ls": "-", "marker": "o"})
        grp = grp.sort_values("recall")
        ax.plot(grp["recall"], grp["precision"], label=grp["arm_name"].iloc[0],
                color=st["color"], linestyle=st["ls"], linewidth=1.4)
    ax.set_xlabel("Recall (fraction of attacker artifacts)")
    ax.set_ylabel("Precision (fraction positive)")
    ax.set_xlim(0.0, 1.0)
    ax.set_ylim(0.0, 1.05)
    ax.legend(frameon=False, loc="lower left")
    _save(fig, figures_dir, "fig1_pr_curves", [src.name], manifest)
    return True


def fig2_precision_at_k(tables_dir: Path, figures_dir: Path, manifest: list[dict]) -> bool:
    src = tables_dir / "track_a_test_results.csv"
    if not src.exists():
        return False
    df = pd.read_csv(src)
    k_cols = [c for c in ("precision_at_10", "precision_at_50", "precision_at_100") if c in df.columns]
    if not k_cols:
        return False
    fig, ax = plt.subplots(figsize=(7.0, 2.8))
    x = np.arange(len(df))
    w = 0.25
    colors = ["#0072B2", "#E69F00", "#009E73"]
    for i, col in enumerate(k_cols):
        k = col.split("_")[-1]
        ax.bar(x + (i - (len(k_cols) - 1) / 2) * w, df[col], width=w,
               label=f"P@{k}", color=colors[i % len(colors)], edgecolor="black", linewidth=0.4)
    ax.set_xticks(x)
    ax.set_xticklabels(df["arm_name"], rotation=15, ha="right")
    ax.set_ylabel("Precision@k (fraction)")
    ax.set_ylim(0.0, 1.05)
    ax.legend(frameon=False, ncol=3)
    _save(fig, figures_dir, "fig2_precision_at_k", [src.name], manifest)
    return True


def fig3_fpr_at_recall(tables_dir: Path, figures_dir: Path, manifest: list[dict]) -> bool:
    src = tables_dir / "track_a_test_results.csv"
    if not src.exists():
        return False
    df = pd.read_csv(src)
    col = "fpr_at_recall_0.9_clean_baseline" if "fpr_at_recall_0.9_clean_baseline" in df.columns else "fpr_at_recall_0.9_all_benign"
    if col not in df.columns:
        return False
    fig, ax = plt.subplots(figsize=(3.5, 2.8))
    colors = [ARM_STYLE.get(a, {}).get("color", "#0072B2") for a in df["arm"]]
    ax.bar(np.arange(len(df)), df[col], color=colors, edgecolor="black", linewidth=0.5)
    ax.set_xticks(np.arange(len(df)))
    ax.set_xticklabels(df["arm_name"], rotation=20, ha="right")
    ax.set_ylabel("Benign FPR at Recall = 0.90 (ratio)")
    ax.set_ylim(0.0, max(0.05, float(df[col].max()) * 1.15))
    _save(fig, figures_dir, "fig3_fpr_at_recall", [src.name], manifest)
    return True


def fig4_training_size_curve(tables_dir: Path, figures_dir: Path, manifest: list[dict]) -> bool:
    src = tables_dir / "track_a_train_size.csv"
    if not src.exists():
        return False
    df = pd.read_csv(src)
    fig, ax = plt.subplots(figsize=(3.5, 2.8))
    for arm, grp in df.groupby("arm", sort=False):
        st = ARM_STYLE.get(arm, {"color": "#333333", "ls": "-", "marker": "o"})
        grp = grp.sort_values("train_fraction")
        ax.plot(grp["train_fraction"] * 100.0, grp["pr_auc"], label=grp["arm_name"].iloc[0],
                color=st["color"], linestyle=st["ls"], marker=st["marker"], markersize=4, linewidth=1.3)
    ax.set_xlabel("Development data fraction (%)")
    ax.set_ylabel("PR-AUC (average precision)")
    ax.set_ylim(0.0, 1.05)
    ax.legend(frameon=False, loc="lower right")
    _save(fig, figures_dir, "fig4_training_size_curve", [src.name], manifest)
    return True


def fig5_shap_xgb_summary(tables_dir: Path, figures_dir: Path, manifest: list[dict]) -> bool:
    rows_p = tables_dir / "shap_xgb_rows.parquet"
    sum_p = tables_dir / "shap_summary_all.csv"
    if not rows_p.exists() and not sum_p.exists():
        return False

    fig, ax = plt.subplots(figsize=(3.5, 3.2))
    if rows_p.exists():
        sv_df = pd.read_parquet(rows_p)
        top_feats = sv_df.abs().mean(axis=0).sort_values(ascending=True).tail(10).index.tolist()
        rng = np.random.default_rng(config.SEED)
        for y_i, feat in enumerate(top_feats):
            vals = sv_df[feat].to_numpy()
            jitter = rng.uniform(-0.18, 0.18, size=len(vals))
            ax.scatter(vals, np.full_like(vals, y_i) + jitter, s=7, alpha=0.55, color="#0072B2", edgecolors="none")
        ax.axvline(0.0, color="#666666", linewidth=0.8, linestyle="--")
        ax.set_yticks(np.arange(len(top_feats)))
        ax.set_yticklabels(top_feats)
        ax.set_xlabel("SHAP value (impact on logit)")
        sources = [rows_p.name]
    else:
        df = pd.read_csv(sum_p)
        sub = df[df["arm"] == "xgb"].sort_values("mean_abs_shap", ascending=True).tail(10)
        ax.barh(np.arange(len(sub)), sub["mean_abs_shap"], color="#D55E00", edgecolor="black", linewidth=0.4)
        ax.set_yticks(np.arange(len(sub)))
        ax.set_yticklabels(sub["feature"])
        ax.set_xlabel("Mean |SHAP| (XGBoost)")
        sources = [sum_p.name]
    _save(fig, figures_dir, "fig5_shap_xgb_summary", sources, manifest)
    return True


def fig6_shap_rank_comparison(tables_dir: Path, figures_dir: Path, manifest: list[dict]) -> bool:
    src = tables_dir / "shap_summary_all.csv"
    if not src.exists():
        return False
    df = pd.read_csv(src)
    top_feats = (
        df.groupby("feature")["mean_abs_shap"].mean()
        .sort_values(ascending=False).head(10).index.tolist()[::-1]
    )
    arms = [a for a in ("rf", "xgb", "mlp") if a in set(df["arm"])]
    if not arms:
        return False
    fig, ax = plt.subplots(figsize=(7.0, 3.4))
    y = np.arange(len(top_feats))
    h = 0.25
    for i, arm in enumerate(arms):
        sub = df[df["arm"] == arm].set_index("feature")["mean_abs_shap"].reindex(top_feats).fillna(0.0)
        # Normalize per arm to fraction of total |SHAP| so tree logits & MLP probabilities compare fairly
        tot = float(df[df["arm"] == arm]["mean_abs_shap"].sum()) or 1.0
        vals = sub.to_numpy() / tot
        ax.barh(y + (i - (len(arms) - 1) / 2) * h, vals, height=h,
                label=config.ARM_DISPLAY.get(arm, arm),
                color=ARM_STYLE.get(arm, {}).get("color", "#333333"), edgecolor="black", linewidth=0.3)
    ax.set_yticks(y)
    ax.set_yticklabels(top_feats)
    ax.set_xlabel("Share of Mean |SHAP| (fraction of total importance)")
    ax.legend(frameon=False, loc="lower right")
    _save(fig, figures_dir, "fig6_shap_rank_comparison", [src.name], manifest)
    return True


def fig7_track_b_comparison(tables_dir: Path, figures_dir: Path, manifest: list[dict]) -> bool:
    s1_p = tables_dir / "track_b_split1.csv"
    s2_p = tables_dir / "track_b_split2.csv"
    if not s1_p.exists() or not s2_p.exists():
        return False
    df1 = pd.read_csv(s1_p)
    df2 = pd.read_csv(s2_p)
    merged = df1[["arm", "arm_name", "pr_auc"]].merge(
        df2[["arm", "pr_auc"]], on="arm", suffixes=("_s1", "_s2"),
    )
    fig, ax = plt.subplots(figsize=(7.0, 2.8))
    x = np.arange(len(merged))
    w = 0.35
    ax.bar(x - w / 2, merged["pr_auc_s1"], width=w, label="Split 1: Stratified 80/20 (LEAKY)",
           color="#CC79A7", hatch="//", edgecolor="black", linewidth=0.5)
    ax.bar(x + w / 2, merged["pr_auc_s2"], width=w, label="Split 2: Family-grouped holdout",
           color="#0072B2", edgecolor="black", linewidth=0.5)
    ax.set_xticks(x)
    ax.set_xticklabels(merged["arm_name"], rotation=15, ha="right")
    ax.set_ylabel("PR-AUC (average precision)")
    ax.set_ylim(0.0, 1.08)
    ax.legend(frameon=False, loc="lower left")
    _save(fig, figures_dir, "fig7_track_b_comparison", [s1_p.name, s2_p.name], manifest)
    return True


def fig8_ablation_bars(tables_dir: Path, figures_dir: Path, manifest: list[dict]) -> bool:
    src = tables_dir / "track_a_ablations.csv"
    if not src.exists():
        return False
    df = pd.read_csv(src)
    # Show XGBoost or mean supervised PR-AUC per ablation
    target_arm = "xgb" if "xgb" in set(df["arm"]) else str(df["arm"].iloc[0])
    sub = df[df["arm"] == target_arm].copy()
    fig, ax = plt.subplots(figsize=(7.0, 3.0))
    labels = [
        f"{r['ablation']} (Oracle upper bound)" if "ORACLE" in str(r.get("ablation_tag", "")) else r["ablation"]
        for _, r in sub.iterrows()
    ]
    colors = ["#D55E00" if "ORACLE" in str(r.get("ablation_tag", "")) else "#0072B2" for _, r in sub.iterrows()]
    hatches = ["//" if "ORACLE" in str(r.get("ablation_tag", "")) else "" for _, r in sub.iterrows()]
    bars = ax.barh(np.arange(len(sub)), sub["pr_auc"], color=colors, edgecolor="black", linewidth=0.5)
    for b, h in zip(bars, hatches):
        if h:
            b.set_hatch(h)
    ax.set_yticks(np.arange(len(sub)))
    ax.set_yticklabels(labels)
    ax.set_xlabel(f"PR-AUC ({config.ARM_DISPLAY.get(target_arm, target_arm)})")
    ax.set_xlim(0.0, 1.05)
    _save(fig, figures_dir, "fig8_ablation_bars", [src.name], manifest)
    return True


def fig9_ae_recon_error(tables_dir: Path, figures_dir: Path, manifest: list[dict]) -> bool:
    src = tables_dir / "ae_recon_error.csv"
    if not src.exists():
        return False
    df = pd.read_csv(src).sort_values("mse_diff_attack_minus_benign", ascending=True).tail(12)
    fig, ax = plt.subplots(figsize=(3.5, 3.2))
    y = np.arange(len(df))
    h = 0.35
    ax.barh(y + h / 2, df["mean_mse_attack"], height=h, label="Attacker-induced", color="#D55E00", edgecolor="black", linewidth=0.4)
    ax.barh(y - h / 2, df["mean_mse_benign"], height=h, label="Benign", color="#009E73", edgecolor="black", linewidth=0.4)
    ax.set_yticks(y)
    ax.set_yticklabels(df["feature"])
    ax.set_xlabel("Mean Reconstruction MSE (units^2)")
    ax.legend(frameon=False, loc="lower right")
    _save(fig, figures_dir, "fig9_ae_recon_error", [src.name], manifest)
    return True


ALL_FIGURES = [
    fig1_pr_curves,
    fig2_precision_at_k,
    fig3_fpr_at_recall,
    fig4_training_size_curve,
    fig5_shap_xgb_summary,
    fig6_shap_rank_comparison,
    fig7_track_b_comparison,
    fig8_ablation_bars,
    fig9_ae_recon_error,
]


def generate_all_figures(
    tables_dir: Path = config.TABLES_DIR,
    figures_dir: Path = config.FIGURES_DIR,
) -> list[dict[str, Any]]:
    """Regenerate every available figure from results/tables/*.csv and write figures_manifest.json."""
    tables_dir = Path(tables_dir)
    figures_dir = Path(figures_dir)
    manifest: list[dict[str, Any]] = []
    for fn in ALL_FIGURES:
        fn(tables_dir, figures_dir, manifest)
    write_json({
        "generated_at_utc": utc_now_iso(),
        "commit": get_commit_hash(),
        "figures": manifest,
    }, figures_dir / "figures_manifest.json")
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate 300-DPI PNG/PDF figures from results/tables/*.csv.")
    parser.add_argument("--tables-dir", type=Path, default=config.TABLES_DIR)
    parser.add_argument("--figures-dir", type=Path, default=config.FIGURES_DIR)
    args = parser.parse_args(argv)
    m = generate_all_figures(args.tables_dir, args.figures_dir)
    print(f"Generated {len(m)} figure files into {args.figures_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
