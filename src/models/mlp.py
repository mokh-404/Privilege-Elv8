"""PyTorch tabular MLP ranking arm (ML-04, doc 04 section 4.1 & doc 10 section 6).

Exact architecture:
    Input -> Linear(128) -> BatchNorm1d -> ReLU -> Dropout(0.3)
          -> Linear(64)  -> BatchNorm1d -> ReLU -> Dropout(0.2)
          -> Linear(32)  -> ReLU -> Linear(1)

Loss: BCEWithLogitsLoss(pos_weight = num_benign / num_attack computed on training split).
Optimizer: AdamW. Early stopping on caller-supplied grouped validation PR-AUC.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import numpy as np
import torch
from torch import nn
from torch.utils.data import DataLoader, TensorDataset

from src import config
from src.eval.metrics import pr_auc
from src.utils.repro import get_device, set_global_seed


class TabularMLPNet(nn.Module):
    """Fixed-width tabular MLP outputting raw logits (shape: [N, 1])."""

    def __init__(self, in_dim: int):
        super().__init__()
        self.in_dim = int(in_dim)
        self.net = nn.Sequential(
            nn.Linear(self.in_dim, 128),
            nn.BatchNorm1d(128),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(128, 64),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Linear(32, 1),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


class TabularMLPArm:
    """Supervised PyTorch tabular MLP with grouped validation early stopping."""

    name = "mlp"
    is_unsupervised = False

    def __init__(self, seed: int = config.SEED, device: str | None = None, **params: Any):
        self.seed = int(seed)
        self.device_pref = device
        merged = dict(config.DEFAULT_PARAMS["mlp"])
        merged.update(params)
        self.params = merged
        self.net: TabularMLPNet | None = None
        self.in_dim_: int | None = None
        self.pos_weight_: float | None = None
        self.best_epoch_: int = 0
        self.best_val_pr_auc_: float = float("nan")
        self.history_: list[dict[str, float]] = []

    def _device(self) -> torch.device:
        return torch.device(self.device_pref if self.device_pref else get_device())

    def _predict_logits(self, X: np.ndarray, batch_size: int = 2048) -> np.ndarray:
        if self.net is None:
            raise RuntimeError("TabularMLPArm must be fitted before prediction")
        device = next(self.net.parameters()).device
        self.net.eval()
        X_t = torch.as_tensor(np.asarray(X, dtype=np.float32))
        preds = []
        with torch.no_grad():
            for start in range(0, len(X_t), batch_size):
                xb = X_t[start : start + batch_size].to(device)
                preds.append(self.net(xb).squeeze(-1).cpu().numpy())
        return np.concatenate(preds) if preds else np.empty(0, dtype=np.float32)

    def fit(self, X_train, y_train, X_val=None, y_val=None) -> "TabularMLPArm":
        if X_val is None or y_val is None:
            raise ValueError(
                "TabularMLPArm requires a caller-supplied grouped validation split (X_val, y_val) "
                "for early stopping; internal random splits are disallowed."
            )
        X_tr = np.asarray(X_train, dtype=np.float32)
        y_tr = np.asarray(y_train, dtype=np.float32).ravel()
        X_va = np.asarray(X_val, dtype=np.float32)
        y_va = np.asarray(y_val, dtype=np.int64).ravel()

        if len(X_tr) < 2:
            raise ValueError("TabularMLPArm requires at least 2 training samples for BatchNorm1d")
        n_pos = int((y_tr == 1).sum())
        n_neg = int((y_tr == 0).sum())
        if n_pos == 0 or n_neg == 0:
            raise ValueError(f"TabularMLPArm requires both classes in training split; pos={n_pos}, neg={n_neg}")

        batch_size = int(self.params["batch_size"])
        if batch_size < 2:
            raise ValueError(f"batch_size must be >= 2 for BatchNorm1d, got {batch_size}")

        set_global_seed(self.seed)
        device = self._device()
        self.in_dim_ = X_tr.shape[1]
        self.net = TabularMLPNet(self.in_dim_).to(device)

        self.pos_weight_ = float(n_neg / n_pos)
        pos_w = torch.tensor([self.pos_weight_], dtype=torch.float32, device=device)
        criterion = nn.BCEWithLogitsLoss(pos_weight=pos_w)
        optimizer = torch.optim.AdamW(
            self.net.parameters(),
            lr=float(self.params["lr"]),
            weight_decay=float(self.params["weight_decay"]),
        )

        # BatchNorm1d crashes in train mode if the final batch has size 1.
        drop_last = len(X_tr) > batch_size and (len(X_tr) % batch_size == 1)
        gen = torch.Generator().manual_seed(self.seed)
        loader = DataLoader(
            TensorDataset(torch.from_numpy(X_tr), torch.from_numpy(y_tr)),
            batch_size=min(batch_size, len(X_tr)),
            shuffle=True,
            drop_last=drop_last,
            generator=gen,
        )

        max_epochs = int(self.params["max_epochs"])
        patience = int(self.params["patience"])
        best_metric = -float("inf")
        best_state = {k: v.detach().cpu().clone() for k, v in self.net.state_dict().items()}
        self.best_epoch_ = 0
        self.history_ = []
        no_improve = 0
        has_val_pos = int(y_va.sum()) > 0

        for epoch in range(1, max_epochs + 1):
            self.net.train()
            tr_loss = 0.0
            n_seen = 0
            for xb, yb in loader:
                xb = xb.to(device)
                yb = yb.to(device).unsqueeze(-1)
                optimizer.zero_grad(set_to_none=True)
                logits = self.net(xb)
                loss = criterion(logits, yb)
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
            raise RuntimeError("Cannot save unfitted TabularMLPArm")
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "in_dim": self.in_dim_,
            "seed": self.seed,
            "params": self.params,
            "pos_weight": self.pos_weight_,
            "best_epoch": self.best_epoch_,
            "best_val_pr_auc": self.best_val_pr_auc_,
            "state_dict": {k: v.detach().cpu() for k, v in self.net.state_dict().items()},
        }
        torch.save(payload, path)
        return path

    @classmethod
    def load(cls, path: str | Path, device: str | None = None) -> "TabularMLPArm":
        payload = torch.load(path, map_location="cpu", weights_only=False)
        arm = cls(seed=payload["seed"], device=device, **payload["params"])
        arm.in_dim_ = int(payload["in_dim"])
        arm.pos_weight_ = payload.get("pos_weight")
        arm.best_epoch_ = int(payload.get("best_epoch", 0))
        arm.best_val_pr_auc_ = float(payload.get("best_val_pr_auc", float("nan")))
        arm.net = TabularMLPNet(arm.in_dim_)
        arm.net.load_state_dict(payload["state_dict"])
        arm.net.to(arm._device())
        arm.net.eval()
        return arm
