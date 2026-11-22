"""v2 model wrappers with configurable MLP/AE capacity, 100%-dev full refits, and safe IO."""
from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any, Sequence

import numpy as np
import torch
from sklearn.ensemble import IsolationForest
from sklearn.linear_model import LogisticRegression
from torch import nn
from torch.utils.data import DataLoader, TensorDataset

from src import config
from src.eval.metrics import pr_auc
from src.models.sklearn_models import BaseArm, RandomForestArm, XGBoostArm, _check_supervised_labels
from src.utils.repro import get_device, set_global_seed
from src.v2 import config_v2


def _norm_layer(norm: str, dim: int) -> nn.Module | None:
    if norm == "batchnorm":
        return nn.BatchNorm1d(dim)
    if norm == "layernorm":
        return nn.LayerNorm(dim)
    if norm == "none":
        return None
    raise ValueError(f"Unsupported norm layer {norm!r}; expected 'batchnorm', 'layernorm', or 'none'")


class TabularMLPNetV2(nn.Module):
    """Configurable-width tabular MLP supporting BatchNorm1d or LayerNorm."""

    def __init__(
        self,
        in_dim: int,
        hidden_dims: Sequence[int] = (128, 64, 32),
        dropout: float = 0.2,
        norm: str = "batchnorm",
    ):
        super().__init__()
        self.in_dim = int(in_dim)
        self.hidden_dims = tuple(int(h) for h in hidden_dims)
        self.dropout = float(dropout)
        self.norm = str(norm)

        layers: list[nn.Module] = []
        prev = self.in_dim
        for h in self.hidden_dims:
            layers.append(nn.Linear(prev, h))
            nl = _norm_layer(self.norm, h)
            if nl is not None:
                layers.append(nl)
            layers.append(nn.ReLU())
            if self.dropout > 0.0:
                layers.append(nn.Dropout(self.dropout))
            prev = h
        layers.append(nn.Linear(prev, 1))
        self.net = nn.Sequential(*layers)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


class TabularMLPArmV2:
    """v2 PyTorch MLP supporting inner-val early stopping and fixed-epoch full-dev refits."""

    name = "mlp"
    is_unsupervised = False
    uses_early_stopping = True

    def __init__(
        self,
        seed: int = config.SEED,
        device: str | None = None,
        fixed_epochs: int | None = None,
        **params: Any,
    ):
        self.seed = int(seed)
        self.device_pref = device
        self.fixed_epochs = int(fixed_epochs) if fixed_epochs is not None else None
        merged = dict(config_v2.V2_DEFAULT_PARAMS["mlp"])
        merged.update(params)
        merged["hidden_dims"] = tuple(int(x) for x in merged["hidden_dims"])
        self.params = merged
        self.net: TabularMLPNetV2 | None = None
        self.in_dim_: int | None = None
        self.pos_weight_: float | None = None
        self.best_epoch_: int = 0
        self.best_val_pr_auc_: float = float("nan")
        self.fit_mode_: str = ""
        self.history_: list[dict[str, float]] = []

    def _device(self) -> torch.device:
        return torch.device(self.device_pref if self.device_pref else get_device())

    @staticmethod
    def _compute_pos_weight(n_neg: int, n_pos: int, mode: str) -> float:
        if mode == "none":
            return 1.0
        if mode == "sqrt":
            return float(math.sqrt(n_neg / n_pos))
        if mode == "balanced":
            return float(n_neg / n_pos)
        raise ValueError(f"Unsupported pos_weight_mode {mode!r}")

    def _predict_logits(self, X: np.ndarray, batch_size: int = 2048) -> np.ndarray:
        if self.net is None:
            raise RuntimeError("TabularMLPArmV2 must be fitted before prediction")
        device = next(self.net.parameters()).device
        self.net.eval()
        X_t = torch.as_tensor(np.asarray(X, dtype=np.float32))
        preds = []
        with torch.no_grad():
            for start in range(0, len(X_t), batch_size):
                xb = X_t[start : start + batch_size].to(device)
                preds.append(self.net(xb).squeeze(-1).cpu().numpy())
        return np.concatenate(preds) if preds else np.empty(0, dtype=np.float32)

    def fit(self, X_train, y_train, X_val=None, y_val=None) -> "TabularMLPArmV2":
        if self.fixed_epochs is None and (X_val is None or y_val is None):
            raise ValueError(
                "TabularMLPArmV2 requires caller-supplied grouped inner validation (X_val, y_val) "
                "when fixed_epochs is None."
            )
        if self.fixed_epochs is not None and self.fixed_epochs < 1:
            raise ValueError(f"fixed_epochs must be >= 1, got {self.fixed_epochs}")

        X_tr = np.asarray(X_train, dtype=np.float32)
        y_tr = np.asarray(y_train, dtype=np.float32).ravel()
        n_pos = int((y_tr == 1).sum())
        n_neg = int((y_tr == 0).sum())
        if n_pos == 0 or n_neg == 0:
            raise ValueError(f"TabularMLPArmV2 requires both classes in train split; pos={n_pos}, neg={n_neg}")
        batch_size = int(self.params["batch_size"])
        if len(X_tr) < 2 or batch_size < 2:
            raise ValueError("TabularMLPArmV2 requires >= 2 rows and batch_size >= 2")

        set_global_seed(self.seed)
        device = self._device()
        self.in_dim_ = X_tr.shape[1]
        self.net = TabularMLPNetV2(
            self.in_dim_,
            hidden_dims=self.params["hidden_dims"],
            dropout=float(self.params["dropout"]),
            norm=str(self.params["norm"]),
        ).to(device)

        self.pos_weight_ = self._compute_pos_weight(n_neg, n_pos, str(self.params["pos_weight_mode"]))
        pos_w = torch.tensor([self.pos_weight_], dtype=torch.float32, device=device)
        criterion = nn.BCEWithLogitsLoss(pos_weight=pos_w)
        optimizer = torch.optim.AdamW(
            self.net.parameters(),
            lr=float(self.params["lr"]),
            weight_decay=float(self.params["weight_decay"]),
        )

        drop_last = self.params["norm"] == "batchnorm" and len(X_tr) > batch_size and (len(X_tr) % batch_size == 1)
        gen = torch.Generator().manual_seed(self.seed)
        loader = DataLoader(
            TensorDataset(torch.from_numpy(X_tr), torch.from_numpy(y_tr)),
            batch_size=min(batch_size, len(X_tr)),
            shuffle=True,
            drop_last=drop_last,
            generator=gen,
        )

        self.history_ = []
        if self.fixed_epochs is not None:
            self.fit_mode_ = "full_dev_fixed_epochs"
            for epoch in range(1, self.fixed_epochs + 1):
                self.net.train()
                tr_loss = 0.0
                n_seen = 0
                for xb, yb in loader:
                    xb = xb.to(device)
                    yb = yb.to(device).unsqueeze(-1)
                    optimizer.zero_grad(set_to_none=True)
                    loss = criterion(self.net(xb), yb)
                    loss.backward()
                    optimizer.step()
                    tr_loss += float(loss.item()) * len(xb)
                    n_seen += len(xb)
                self.history_.append({"epoch": float(epoch), "train_loss": tr_loss / max(1, n_seen)})
            self.best_epoch_ = self.fixed_epochs
            self.best_val_pr_auc_ = float("nan")
            self.net.eval()
            return self

        self.fit_mode_ = "inner_val_early_stop"
        X_va = np.asarray(X_val, dtype=np.float32)
        y_va = np.asarray(y_val, dtype=np.int64).ravel()
        has_val_pos = int(y_va.sum()) > 0
        max_epochs = int(self.params["max_epochs"])
        patience = int(self.params["patience"])
        best_metric = -float("inf")
        best_state = {k: v.detach().cpu().clone() for k, v in self.net.state_dict().items()}
        self.best_epoch_ = 0
        no_improve = 0

        for epoch in range(1, max_epochs + 1):
            self.net.train()
            tr_loss = 0.0
            n_seen = 0
            for xb, yb in loader:
                xb = xb.to(device)
                yb = yb.to(device).unsqueeze(-1)
                optimizer.zero_grad(set_to_none=True)
                loss = criterion(self.net(xb), yb)
                loss.backward()
                optimizer.step()
                tr_loss += float(loss.item()) * len(xb)
                n_seen += len(xb)

            val_logits = self._predict_logits(X_va)
            val_probs = 1.0 / (1.0 + np.exp(-np.clip(val_logits, -50.0, 50.0)))
            if has_val_pos:
                metric = pr_auc(y_va, val_probs)
            else:
                with torch.no_grad():
                    vt = torch.as_tensor(val_logits, dtype=torch.float32, device=device).unsqueeze(-1)
                    vy = torch.as_tensor(y_va, dtype=torch.float32, device=device).unsqueeze(-1)
                    metric = -float(criterion(vt, vy).item())

            self.history_.append({
                "epoch": float(epoch),
                "train_loss": tr_loss / max(1, n_seen),
                "val_pr_auc": float(metric) if has_val_pos else float("nan"),
            })
            if metric > best_metric + 1e-6:
                best_metric = metric
                best_state = {k: v.detach().cpu().clone() for k, v in self.net.state_dict().items()}
                self.best_epoch_ = epoch
                no_improve = 0
            else:
                no_improve += 1
                if no_improve >= patience:
                    break

        self.best_val_pr_auc_ = float(best_metric) if has_val_pos else float("nan")
        self.net.load_state_dict(best_state)
        self.net.to(device)
        self.net.eval()
        return self

    def predict_scores(self, X) -> np.ndarray:
        logits = self._predict_logits(np.asarray(X, dtype=np.float32))
        return (1.0 / (1.0 + np.exp(-np.clip(logits, -50.0, 50.0)))).astype(float)

    def save(self, path: str | Path) -> Path:
        if self.net is None:
            raise RuntimeError("Cannot save unfitted TabularMLPArmV2")
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        torch.save({k: v.detach().cpu() for k, v in self.net.state_dict().items()}, path)
        meta = {
            "in_dim": int(self.in_dim_),
            "seed": int(self.seed),
            "fixed_epochs": self.fixed_epochs,
            "params": {**self.params, "hidden_dims": list(self.params["hidden_dims"])},
            "pos_weight": float(self.pos_weight_) if self.pos_weight_ is not None else None,
            "best_epoch": int(self.best_epoch_),
            "best_val_pr_auc": None if math.isnan(self.best_val_pr_auc_) else float(self.best_val_pr_auc_),
            "fit_mode": self.fit_mode_,
        }
        Path(f"{path}.meta.json").write_text(json.dumps(meta, indent=2, sort_keys=True), encoding="utf-8")
        return path

    @classmethod
    def load(cls, path: str | Path, device: str | None = None) -> "TabularMLPArmV2":
        path = Path(path)
        meta = json.loads(Path(f"{path}.meta.json").read_text(encoding="utf-8"))
        state = torch.load(path, map_location="cpu", weights_only=True)
        arm = cls(
            seed=meta["seed"],
            device=device,
            fixed_epochs=meta.get("fixed_epochs"),
            **meta["params"],
        )
        arm.in_dim_ = int(meta["in_dim"])
        arm.pos_weight_ = meta.get("pos_weight")
        arm.best_epoch_ = int(meta.get("best_epoch", 0))
        bvp = meta.get("best_val_pr_auc")
        arm.best_val_pr_auc_ = float("nan") if bvp is None else float(bvp)
        arm.fit_mode_ = str(meta.get("fit_mode", ""))
        arm.net = TabularMLPNetV2(
            arm.in_dim_,
            hidden_dims=arm.params["hidden_dims"],
            dropout=float(arm.params["dropout"]),
            norm=str(arm.params["norm"]),
        )
        arm.net.load_state_dict(state)
        arm.net.to(arm._device())
        arm.net.eval()
        return arm


class DeepAutoencoderNetV2(nn.Module):
    """Configurable symmetric deep autoencoder."""

    def __init__(self, in_dim: int, hidden_dims: Sequence[int] = (64, 32, 16), dropout: float = 0.0):
        super().__init__()
        self.in_dim = int(in_dim)
        self.hidden_dims = tuple(int(h) for h in hidden_dims)
        self.dropout = float(dropout)

        enc: list[nn.Module] = []
        prev = self.in_dim
        for i, h in enumerate(self.hidden_dims):
            enc.append(nn.Linear(prev, h))
            if i < len(self.hidden_dims) - 1:
                enc.append(nn.ReLU())
                if self.dropout > 0.0:
                    enc.append(nn.Dropout(self.dropout))
            prev = h

        dec: list[nn.Module] = []
        rev = list(reversed(self.hidden_dims[:-1]))
        for h in rev:
            dec.append(nn.Linear(prev, h))
            dec.append(nn.ReLU())
            if self.dropout > 0.0:
                dec.append(nn.Dropout(self.dropout))
            prev = h
        dec.append(nn.Linear(prev, self.in_dim))

        self.net = nn.Sequential(*(enc + dec))

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


class DeepAutoencoderArmV2:
    """v2 strictly-benign autoencoder with inner-val early stopping or fixed-epoch full-dev refit."""

    name = "ae"
    is_unsupervised = True
    uses_early_stopping = True

    def __init__(
        self,
        seed: int = config.SEED,
        device: str | None = None,
        fixed_epochs: int | None = None,
        **params: Any,
    ):
        self.seed = int(seed)
        self.device_pref = device
        self.fixed_epochs = int(fixed_epochs) if fixed_epochs is not None else None
        merged = dict(config_v2.V2_DEFAULT_PARAMS["ae"])
        merged.update(params)
        merged["hidden_dims"] = tuple(int(x) for x in merged["hidden_dims"])
        self.params = merged
        self.net: DeepAutoencoderNetV2 | None = None
        self.in_dim_: int | None = None
        self.n_attack_seen_in_fit_: int = 0
        self.n_benign_fit_: int = 0
        self.best_epoch_: int = 0
        self.best_val_mse_: float = float("nan")
        self.fit_mode_: str = ""
        self.history_: list[dict[str, float]] = []

    def _device(self) -> torch.device:
        return torch.device(self.device_pref if self.device_pref else get_device())

    def fit(self, X_train, y_train, X_val=None, y_val=None) -> "DeepAutoencoderArmV2":
        if self.fixed_epochs is None and X_val is None:
            raise ValueError(
                "DeepAutoencoderArmV2 requires caller-supplied grouped inner validation (X_val) "
                "when fixed_epochs is None."
            )
        if self.fixed_epochs is not None and self.fixed_epochs < 1:
            raise ValueError(f"fixed_epochs must be >= 1, got {self.fixed_epochs}")

        X_arr = np.asarray(X_train, dtype=np.float32)
        y_arr = np.asarray(y_train, dtype=np.int64).ravel()
        X_tr_b = X_arr[y_arr == 0]
        if len(X_tr_b) == 0:
            raise ValueError("DeepAutoencoderArmV2 requires at least one benign row (y == 0)")

        self.n_attack_seen_in_fit_ = 0
        self.n_benign_fit_ = int(len(X_tr_b))
        set_global_seed(self.seed)
        device = self._device()
        self.in_dim_ = X_tr_b.shape[1]
        self.net = DeepAutoencoderNetV2(
            self.in_dim_,
            hidden_dims=self.params["hidden_dims"],
            dropout=float(self.params["dropout"]),
        ).to(device)

        criterion = nn.MSELoss()
        optimizer = torch.optim.AdamW(
            self.net.parameters(),
            lr=float(self.params["lr"]),
            weight_decay=float(self.params["weight_decay"]),
        )
        batch_size = min(int(self.params["batch_size"]), len(X_tr_b))
        gen = torch.Generator().manual_seed(self.seed)
        loader = DataLoader(
            TensorDataset(torch.from_numpy(X_tr_b)),
            batch_size=max(1, batch_size),
            shuffle=True,
            generator=gen,
        )

        self.history_ = []
        if self.fixed_epochs is not None:
            self.fit_mode_ = "full_dev_fixed_epochs"
            for epoch in range(1, self.fixed_epochs + 1):
                self.net.train()
                tr_loss = 0.0
                n_seen = 0
                for (xb,) in loader:
                    xb = xb.to(device)
                    optimizer.zero_grad(set_to_none=True)
                    loss = criterion(self.net(xb), xb)
                    loss.backward()
                    optimizer.step()
                    tr_loss += float(loss.item()) * len(xb)
                    n_seen += len(xb)
                self.history_.append({"epoch": float(epoch), "train_mse": tr_loss / max(1, n_seen)})
            self.best_epoch_ = self.fixed_epochs
            self.best_val_mse_ = float("nan")
            self.net.eval()
            return self

        self.fit_mode_ = "inner_val_early_stop"
        X_va_arr = np.asarray(X_val, dtype=np.float32)
        if y_val is not None:
            y_va_arr = np.asarray(y_val, dtype=np.int64).ravel()
            X_va_b = X_va_arr[y_va_arr == 0]
        else:
            X_va_b = X_va_arr
        if len(X_va_b) == 0:
            raise ValueError("DeepAutoencoderArmV2 validation split has zero benign rows (y == 0)")

        max_epochs = int(self.params["max_epochs"])
        patience = int(self.params["patience"])
        best_loss = float("inf")
        best_state = {k: v.detach().cpu().clone() for k, v in self.net.state_dict().items()}
        self.best_epoch_ = 0
        no_improve = 0

        for epoch in range(1, max_epochs + 1):
            self.net.train()
            tr_loss = 0.0
            n_seen = 0
            for (xb,) in loader:
                xb = xb.to(device)
                optimizer.zero_grad(set_to_none=True)
                loss = criterion(self.net(xb), xb)
                loss.backward()
                optimizer.step()
                tr_loss += float(loss.item()) * len(xb)
                n_seen += len(xb)
            tr_mse = tr_loss / max(1, n_seen)
            val_mse = float(self.per_feature_mse(X_va_b).mean())
            self.history_.append({"epoch": float(epoch), "train_mse": tr_mse, "val_mse": val_mse})
            if val_mse < best_loss - 1e-7:
                best_loss = val_mse
                best_state = {k: v.detach().cpu().clone() for k, v in self.net.state_dict().items()}
                self.best_epoch_ = epoch
                no_improve = 0
            else:
                no_improve += 1
                if no_improve >= patience:
                    break

        self.best_val_mse_ = float(best_loss)
        self.net.load_state_dict(best_state)
        self.net.to(device)
        self.net.eval()
        return self

    def per_feature_mse(self, X, batch_size: int = 2048) -> np.ndarray:
        if self.net is None:
            raise RuntimeError("DeepAutoencoderArmV2 must be fitted before inference")
        device = next(self.net.parameters()).device
        self.net.eval()
        X_t = torch.as_tensor(np.asarray(X, dtype=np.float32))
        sq_errs = []
        with torch.no_grad():
            for start in range(0, len(X_t), batch_size):
                xb = X_t[start : start + batch_size].to(device)
                recon = self.net(xb)
                sq_errs.append(((recon - xb) ** 2).cpu().numpy())
        return np.vstack(sq_errs).astype(float) if sq_errs else np.empty((0, self.in_dim_ or 0), dtype=np.float32)

    def predict_scores(self, X) -> np.ndarray:
        err = self.per_feature_mse(X)
        return err.mean(axis=1).astype(float) if len(err) else np.empty(0, dtype=float)

    def save(self, path: str | Path) -> Path:
        if self.net is None:
            raise RuntimeError("Cannot save unfitted DeepAutoencoderArmV2")
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        torch.save({k: v.detach().cpu() for k, v in self.net.state_dict().items()}, path)
        meta = {
            "in_dim": int(self.in_dim_),
            "seed": int(self.seed),
            "fixed_epochs": self.fixed_epochs,
            "params": {**self.params, "hidden_dims": list(self.params["hidden_dims"])},
            "n_benign_fit": int(self.n_benign_fit_),
            "best_epoch": int(self.best_epoch_),
            "best_val_mse": None if math.isnan(self.best_val_mse_) else float(self.best_val_mse_),
            "fit_mode": self.fit_mode_,
        }
        Path(f"{path}.meta.json").write_text(json.dumps(meta, indent=2, sort_keys=True), encoding="utf-8")
        return path

    @classmethod
    def load(cls, path: str | Path, device: str | None = None) -> "DeepAutoencoderArmV2":
        path = Path(path)
        meta = json.loads(Path(f"{path}.meta.json").read_text(encoding="utf-8"))
        state = torch.load(path, map_location="cpu", weights_only=True)
        arm = cls(
            seed=meta["seed"],
            device=device,
            fixed_epochs=meta.get("fixed_epochs"),
            **meta["params"],
        )
        arm.in_dim_ = int(meta["in_dim"])
        arm.n_benign_fit_ = int(meta.get("n_benign_fit", 0))
        arm.best_epoch_ = int(meta.get("best_epoch", 0))
        bvm = meta.get("best_val_mse")
        arm.best_val_mse_ = float("nan") if bvm is None else float(bvm)
        arm.fit_mode_ = str(meta.get("fit_mode", ""))
        arm.net = DeepAutoencoderNetV2(
            arm.in_dim_,
            hidden_dims=arm.params["hidden_dims"],
            dropout=float(arm.params["dropout"]),
        )
        arm.net.load_state_dict(state)
        arm.net.to(arm._device())
        arm.net.eval()
        return arm


class IsolationForestArmV2(BaseArm):
    """v2 strictly-benign IsolationForest accepting full widened params and fitting 100% benign rows."""

    name = "iforest"
    is_unsupervised = True
    uses_early_stopping = False

    def __init__(self, seed: int = config.SEED, **params: Any):
        self.seed = int(seed)
        merged = dict(config_v2.V2_DEFAULT_PARAMS["iforest"])
        merged.update(params)
        self.params = merged
        self.model: IsolationForest | None = None
        self.n_attack_seen_in_fit_: int = 0
        self.n_benign_fit_: int = 0

    def fit(self, X_train, y_train, X_val=None, y_val=None) -> "IsolationForestArmV2":
        X_arr = np.asarray(X_train)
        y_arr = np.asarray(y_train).astype(int).ravel()
        X_benign = X_arr[y_arr == 0]
        if len(X_benign) == 0:
            raise ValueError("IsolationForestArmV2 requires at least one benign row (y == 0)")
        self.n_attack_seen_in_fit_ = 0
        self.n_benign_fit_ = int(len(X_benign))
        cfg = dict(self.params)
        ms = cfg.get("max_samples", "auto")
        if isinstance(ms, int) and not isinstance(ms, bool) and ms > len(X_benign):
            cfg["max_samples"] = len(X_benign)
        self.model = IsolationForest(random_state=self.seed, n_jobs=-1, **cfg)
        self.model.fit(X_benign)
        return self

    def predict_scores(self, X) -> np.ndarray:
        if self.model is None:
            raise RuntimeError("IsolationForestArmV2 must be fitted before predict_scores")
        return (-self.model.score_samples(np.asarray(X))).astype(float)


class LogisticRegressionArmV2(BaseArm):
    """v2 logistic regression supporting explicit `class_weight` search parameter."""

    name = "lr"
    is_unsupervised = False
    uses_early_stopping = False

    def __init__(self, seed: int = config.SEED, **params: Any):
        self.seed = int(seed)
        merged = dict(config_v2.V2_DEFAULT_PARAMS["lr"])
        merged.update(params)
        self.params = merged
        self.model: LogisticRegression | None = None

    def fit(self, X_train, y_train, X_val=None, y_val=None) -> "LogisticRegressionArmV2":
        X_arr = np.asarray(X_train)
        y_arr = np.asarray(y_train).astype(int).ravel()
        _check_supervised_labels(y_arr)
        self.model = LogisticRegression(max_iter=1000, random_state=self.seed, **self.params)
        self.model.fit(X_arr, y_arr)
        return self

    def predict_scores(self, X) -> np.ndarray:
        if self.model is None:
            raise RuntimeError("LogisticRegressionArmV2 must be fitted before predict_scores")
        proba = self.model.predict_proba(np.asarray(X))
        pos_idx = list(self.model.classes_).index(1)
        return proba[:, pos_idx].astype(float)


def make_arm_v2(
    arm_name: str,
    seed: int = config.SEED,
    device: str | None = None,
    fixed_epochs: int | None = None,
    params: dict[str, Any] | None = None,
):
    """Instantiate a v2 model arm by canonical key."""
    cfg = dict(params or {})
    if arm_name == "rf":
        return RandomForestArm(seed=seed, **cfg)
    if arm_name == "xgb":
        return XGBoostArm(seed=seed, **cfg)
    if arm_name == "lr":
        return LogisticRegressionArmV2(seed=seed, **cfg)
    if arm_name == "iforest":
        return IsolationForestArmV2(seed=seed, **cfg)
    if arm_name == "mlp":
        return TabularMLPArmV2(seed=seed, device=device, fixed_epochs=fixed_epochs, **cfg)
    if arm_name == "ae":
        return DeepAutoencoderArmV2(seed=seed, device=device, fixed_epochs=fixed_epochs, **cfg)
    raise ValueError(f"Unknown v2 model arm: {arm_name!r}")
