"""PyTorch deep autoencoder ranking arm (ML-05, doc 04 section 4.2 & doc 10 section 6).

Exact architecture:
    Input -> Linear(64) -> ReLU -> Linear(32) -> ReLU -> Linear(16)
          -> Linear(32) -> ReLU -> Linear(64) -> ReLU -> Linear(Input)

Trained STRICTLY on benign rows (y == 0) with MSE loss; early stops on benign
validation reconstruction MSE. Anomaly score = per-row mean squared error.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import numpy as np
import torch
from torch import nn
from torch.utils.data import DataLoader, TensorDataset

from src import config
from src.utils.repro import get_device, set_global_seed


class DeepAutoencoderNet(nn.Module):
    """Symmetric deep autoencoder with 16-unit bottleneck."""

    def __init__(self, in_dim: int):
        super().__init__()
        self.in_dim = int(in_dim)
        self.net = nn.Sequential(
            nn.Linear(self.in_dim, 64),
            nn.ReLU(),
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Linear(32, 16),
            nn.Linear(16, 32),
            nn.ReLU(),
            nn.Linear(32, 64),
            nn.ReLU(),
            nn.Linear(64, self.in_dim),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


class DeepAutoencoderArm:
    """Unsupervised PyTorch deep autoencoder trained strictly on benign rows."""

    name = "ae"
    is_unsupervised = True

    def __init__(self, seed: int = config.SEED, device: str | None = None, **params: Any):
        self.seed = int(seed)
        self.device_pref = device
        merged = dict(config.DEFAULT_PARAMS["ae"])
        merged.update(params)
        self.params = merged
        self.net: DeepAutoencoderNet | None = None
        self.in_dim_: int | None = None
        self.n_attack_seen_in_fit_: int = 0
        self.n_benign_fit_: int = 0
        self.best_epoch_: int = 0
        self.best_val_mse_: float = float("nan")
        self.history_: list[dict[str, float]] = []

    def _device(self) -> torch.device:
        return torch.device(self.device_pref if self.device_pref else get_device())

    def fit(self, X_train, y_train, X_val=None, y_val=None) -> "DeepAutoencoderArm":
        X_arr = np.asarray(X_train, dtype=np.float32)
        y_arr = np.asarray(y_train, dtype=np.int64).ravel()
        X_tr_b = X_arr[y_arr == 0]
        if len(X_tr_b) == 0:
            raise ValueError("DeepAutoencoderArm requires at least one benign training row (y == 0)")

        X_va_b: np.ndarray | None = None
        if X_val is not None:
            X_va_arr = np.asarray(X_val, dtype=np.float32)
            if y_val is not None:
                y_va_arr = np.asarray(y_val, dtype=np.int64).ravel()
                X_va_b = X_va_arr[y_va_arr == 0]
            else:
                X_va_b = X_va_arr
            if len(X_va_b) == 0:
                raise ValueError("DeepAutoencoderArm validation split has zero benign rows (y == 0)")

        self.n_attack_seen_in_fit_ = 0
        self.n_benign_fit_ = int(len(X_tr_b))

        set_global_seed(self.seed)
        device = self._device()
        self.in_dim_ = X_tr_b.shape[1]
        self.net = DeepAutoencoderNet(self.in_dim_).to(device)

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

        max_epochs = int(self.params["max_epochs"])
        patience = int(self.params["patience"])
        best_loss = float("inf")
        best_state = {k: v.detach().cpu().clone() for k, v in self.net.state_dict().items()}
        self.best_epoch_ = 0
        self.history_ = []
        no_improve = 0

        for epoch in range(1, max_epochs + 1):
            self.net.train()
            tr_loss = 0.0
            n_seen = 0
            for (xb,) in loader:
                xb = xb.to(device)
                optimizer.zero_grad(set_to_none=True)
                recon = self.net(xb)
                loss = criterion(recon, xb)
                loss.backward()
                optimizer.step()
                tr_loss += float(loss.item()) * len(xb)
                n_seen += len(xb)
            tr_mse = tr_loss / max(1, n_seen)

            if X_va_b is not None:
                val_mse = float(self.per_feature_mse(X_va_b).mean())
                monitor = val_mse
            else:
                val_mse = float("nan")
                monitor = tr_mse

            self.history_.append({"epoch": float(epoch), "train_mse": tr_mse, "val_mse": val_mse})
            if monitor < best_loss - 1e-7:
                best_loss = monitor
                best_state = {k: v.detach().cpu().clone() for k, v in self.net.state_dict().items()}
                self.best_epoch_ = epoch
                no_improve = 0
            else:
                no_improve += 1
                if no_improve >= patience:
                    break

        self.best_val_mse_ = float(best_loss) if X_va_b is not None else float("nan")
        self.net.load_state_dict(best_state)
        self.net.to(device)
        self.net.eval()
        return self

    def per_feature_mse(self, X, batch_size: int = 2048) -> np.ndarray:
        """Element-wise reconstruction squared error (shape: [N, in_dim])."""
        if self.net is None:
            raise RuntimeError("DeepAutoencoderArm must be fitted before inference")
        device = next(self.net.parameters()).device
        self.net.eval()
        X_t = torch.as_tensor(np.asarray(X, dtype=np.float32))
        sq_errs = []
        with torch.no_grad():
            for start in range(0, len(X_t), batch_size):
                xb = X_t[start : start + batch_size].to(device)
                recon = self.net(xb)
                sq_errs.append(((recon - xb) ** 2).cpu().numpy())
        if not sq_errs:
            return np.empty((0, self.in_dim_ or 0), dtype=np.float32)
        return np.vstack(sq_errs).astype(float)

    def predict_scores(self, X) -> np.ndarray:
        """Mean reconstruction MSE across features per row (higher = more anomalous)."""
        err = self.per_feature_mse(X)
        return err.mean(axis=1).astype(float) if len(err) else np.empty(0, dtype=float)

    def save(self, path: str | Path) -> Path:
        if self.net is None:
            raise RuntimeError("Cannot save unfitted DeepAutoencoderArm")
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "in_dim": self.in_dim_,
            "seed": self.seed,
            "params": self.params,
            "n_benign_fit": self.n_benign_fit_,
            "best_epoch": self.best_epoch_,
            "best_val_mse": self.best_val_mse_,
            "state_dict": {k: v.detach().cpu() for k, v in self.net.state_dict().items()},
        }
        torch.save(payload, path)
        return path

    @classmethod
    def load(cls, path: str | Path, device: str | None = None) -> "DeepAutoencoderArm":
        payload = torch.load(path, map_location="cpu", weights_only=False)
        arm = cls(seed=payload["seed"], device=device, **payload["params"])
        arm.in_dim_ = int(payload["in_dim"])
        arm.n_benign_fit_ = int(payload.get("n_benign_fit", 0))
        arm.best_epoch_ = int(payload.get("best_epoch", 0))
        arm.best_val_mse_ = float(payload.get("best_val_mse", float("nan")))
        arm.net = DeepAutoencoderNet(arm.in_dim_)
        arm.net.load_state_dict(payload["state_dict"])
        arm.net.to(arm._device())
        arm.net.eval()
        return arm
