"""Shared preprocessing pipeline used by EVERY arm (ML-11).

- categorical: missing -> "na" level, then one-hot (unknown levels at transform time are ignored)
- numeric:     SimpleImputer(constant 0, add_indicator=True) + StandardScaler
- binary:      passthrough (missing -> 0)

Always fit on training data only. Unsupervised arms fit their own instance on benign
training rows only. The guard `assert_no_forbidden_inputs` refuses oracle/rule/meta/label
columns unless an ablation explicitly allows them.
"""
from __future__ import annotations

from typing import Iterable, Sequence

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, OneHotEncoder, StandardScaler

from src import config


class LeakageError(AssertionError):
    """A forbidden column (oracle/rule/meta/label) was offered as a model input."""


def assert_no_forbidden_inputs(columns: Iterable[str], allowed_extra: Iterable[str] = ()) -> None:
    """Refuse ORACLE_FEATURES, RULE_FEATURES, META_COLUMNS and the label as model inputs.

    `allowed_extra` is only used by clearly named ablations (e.g. ["rule_hit_count"]).
    The label and META columns can never be allowed.
    """
    allowed = set(allowed_extra)
    never = set(config.META_COLUMNS) | {config.LABEL_COL}
    if allowed & never:
        raise LeakageError(f"META/label columns can never be model inputs: {sorted(allowed & never)}")
    bad = (set(columns) & set(config.FORBIDDEN_MODEL_INPUTS)) - allowed
    if bad:
        raise LeakageError(f"Forbidden model inputs present: {sorted(bad)}")


def _fill_na_str(X):
    df = pd.DataFrame(X).astype(object)
    return df.where(df.notna(), "na").astype(str).replace({"nan": "na", "None": "na", "": "na"}).values


def _fill_zero(X):
    return pd.DataFrame(X).fillna(0).astype(float).values


def build_preprocessor(
    categorical: Sequence[str] = config.CATEGORICAL_FEATURES,
    numeric: Sequence[str] = config.NUMERIC_FEATURES,
    binary: Sequence[str] = config.BINARY_FEATURES,
    scale_numeric: bool = True,
) -> ColumnTransformer:
    """The single shared ColumnTransformer definition (unfitted)."""
    transformers = []
    if categorical:
        transformers.append((
            "cat",
            Pipeline([
                ("fillna", FunctionTransformer(_fill_na_str, feature_names_out="one-to-one")),
                ("onehot", OneHotEncoder(handle_unknown="ignore", sparse_output=False, dtype=np.float32)),
            ]),
            list(categorical),
        ))
    if numeric:
        steps = [("impute", SimpleImputer(strategy="constant", fill_value=0, add_indicator=True))]
        if scale_numeric:
            steps.append(("scale", StandardScaler()))
        transformers.append(("num", Pipeline(steps), list(numeric)))
    if binary:
        transformers.append(("bin", FunctionTransformer(_fill_zero, feature_names_out="one-to-one"), list(binary)))
    return ColumnTransformer(transformers, remainder="drop", verbose_feature_names_out=True)


def output_feature_origin(pre: ColumnTransformer) -> list[str]:
    """For each output column of a FITTED preprocessor, the original feature it came from.

    Used to aggregate SHAP values (one-hot levels and missing indicators) back to the 20 features.
    """
    origins: list[str] = []
    for name, trans, cols in pre.transformers_:
        if name == "remainder" or trans == "drop":
            continue
        cols = list(cols)
        if name == "cat":
            ohe = trans.named_steps["onehot"]
            for col, cats in zip(cols, ohe.categories_):
                origins.extend([col] * len(cats))
        elif name == "num":
            imp = trans.named_steps["impute"]
            origins.extend(cols)
            if imp.indicator_ is not None:
                origins.extend(cols[i] for i in imp.indicator_.features_)
        else:
            origins.extend(cols)
    return origins


class SharedPreprocessor:
    """Thin wrapper: column selection + leakage guard + the shared ColumnTransformer."""

    def __init__(
        self,
        categorical: Sequence[str] = config.CATEGORICAL_FEATURES,
        numeric: Sequence[str] = config.NUMERIC_FEATURES,
        binary: Sequence[str] = config.BINARY_FEATURES,
        allowed_extra: Iterable[str] = (),
    ):
        self.categorical = list(categorical)
        self.numeric = list(numeric)
        self.binary = list(binary)
        self.allowed_extra = list(allowed_extra)
        self.columns = self.categorical + self.numeric + self.binary
        assert_no_forbidden_inputs(self.columns, self.allowed_extra)
        self.ct = build_preprocessor(self.categorical, self.numeric, self.binary)
        self.fitted = False

    def _select(self, X: pd.DataFrame) -> pd.DataFrame:
        missing = [c for c in self.columns if c not in X.columns]
        if missing:
            raise KeyError(f"Missing input columns: {missing}")
        return X[self.columns]

    def fit(self, X: pd.DataFrame) -> "SharedPreprocessor":
        self.ct.fit(self._select(X))
        self.fitted = True
        self.feature_origin_ = output_feature_origin(self.ct)
        self.feature_names_ = list(self.ct.get_feature_names_out())
        return self

    def transform(self, X: pd.DataFrame) -> np.ndarray:
        if not self.fitted:
            raise RuntimeError("SharedPreprocessor must be fitted on training data first")
        return np.asarray(self.ct.transform(self._select(X)), dtype=np.float32)

    def fit_transform(self, X: pd.DataFrame) -> np.ndarray:
        return self.fit(X).transform(X)
