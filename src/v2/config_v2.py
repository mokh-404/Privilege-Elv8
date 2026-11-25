"""v2 configuration: multi-seed schedules, widened equal-budget search spaces (OD-V2-06, IMP-08/09)."""
from __future__ import annotations

import numpy as np


V2_FINAL_SEEDS: list[int] = [42, 43, 44, 45, 46]
V2_N_SEARCH_TRIALS: int = 20
V2_N_SEARCH_TRIALS_FALLBACK: int = 20
V2_OUTER_FOLDS: int = 5
V2_INNER_FOLDS: int = 3

V2_UNSUP_SELECTION_MODES: tuple[str, ...] = ("label_free", "label_selected")
V2_REFIT_POLICIES: tuple[str, ...] = ("full_dev_median_epoch", "fold_ensemble")

V2_DEFAULT_PARAMS: dict[str, dict] = {
    "rf": {
        "n_estimators": 300,
        "max_depth": None,
        "min_samples_leaf": 1,
        "max_features": "sqrt",
    },
    "xgb": {
        "n_estimators": 400,
        "learning_rate": 0.1,
        "max_depth": 6,
        "subsample": 1.0,
        "colsample_bytree": 1.0,
    },
    "iforest": {
        "n_estimators": 200,
        "max_samples": "auto",
        "max_features": 1.0,
        "bootstrap": False,
    },
    "mlp": {
        "hidden_dims": (128, 64, 32),
        "dropout": 0.2,
        "norm": "batchnorm",
        "pos_weight_mode": "balanced",
        "batch_size": 256,
        "lr": 3e-3,
        "weight_decay": 1e-3,
        "max_epochs": 200,
        "patience": 10,
    },
    "ae": {
        "hidden_dims": (64, 32, 16),
        "dropout": 0.0,
        "batch_size": 256,
        "lr": 3e-3,
        "weight_decay": 1e-5,
        "max_epochs": 200,
        "patience": 10,
    },
    "lr": {
        "C": 1.0,
        "class_weight": "balanced",
    },
}

# Each tuned arm has >= 20 unique combinations so every arm receives an equal N_trials = 20 budget.
V2_SEARCH_SPACES: dict[str, dict[str, list]] = {
    "rf": {
        "n_estimators": [200, 300, 400, 500],
        "max_depth": [None, 10, 15, 20, 25, 30],
        "min_samples_leaf": [1, 2, 3, 4, 5],
        "max_features": ["sqrt", "log2", 0.5],
    },
    "xgb": {
        "n_estimators": [200, 300, 400, 500, 600],
        "learning_rate": [0.03, 0.05, 0.1, 0.15, 0.2],
        "max_depth": [3, 4, 5, 6, 7, 8],
        "subsample": [0.7, 0.85, 1.0],
        "colsample_bytree": [0.7, 0.85, 1.0],
    },
    "iforest": {
        "n_estimators": [100, 150, 200, 300, 400],
        "max_samples": ["auto", 128, 256, 512, 0.5, 0.75, 1.0],
        "max_features": [0.5, 0.75, 1.0],
        "bootstrap": [False, True],
    },
    "mlp": {
        "hidden_dims": [(64, 32), (128, 64, 32), (256, 128, 64)],
        "dropout": [0.1, 0.2, 0.3],
        "norm": ["batchnorm", "layernorm"],
        "pos_weight_mode": ["none", "sqrt", "balanced"],
        "batch_size": [128, 256, 512],
        "lr": [5e-4, 1e-3, 3e-3, 1e-2],
        "weight_decay": [1e-4, 1e-3, 1e-2],
    },
    "ae": {
        "hidden_dims": [(64, 32, 16), (96, 48, 16), (64, 32, 8), (128, 64, 24)],
        "dropout": [0.0, 0.1, 0.2],
        "batch_size": [128, 256, 512],
        "lr": [5e-4, 1e-3, 3e-3, 1e-2],
        "weight_decay": [0.0, 1e-5, 1e-4, 1e-3],
    },
    "lr": {
        "C": [float(x) for x in np.geomspace(1e-3, 1e2, 15)],
        "class_weight": ["balanced", None],
    },
}
