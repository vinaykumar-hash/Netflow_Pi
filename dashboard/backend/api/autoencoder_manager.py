import json
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent.parent.parent
RUNTIME_SCRIPT = ROOT / "autoencoder_runtime.py"
RUNTIME_DIR = ROOT / "runtime"
MODEL_DIR = ROOT / "models" / "autoencoder"
STATUS_PATH = RUNTIME_DIR / "autoencoder_status.json"
TRAIN_LOG_PATH = ROOT / "autoencoder_train.log"
DETECT_LOG_PATH = ROOT / "autoencoder_detect.log"
MODEL_PATH = MODEL_DIR / "autoencoder.keras"
SCALER_PATH = MODEL_DIR / "scaler.pkl"
THRESHOLD_PATH = MODEL_DIR / "threshold.npy"
METADATA_PATH = MODEL_DIR / "metadata.json"

_LOCK = threading.Lock()
_TRAIN_PROCESS = None
_DETECT_PROCESS = None


def _venv_python():
    candidate = ROOT / ".venv" / "bin" / "python"
    return str(candidate if candidate.exists() else Path(sys.executable))


def _ensure_dirs():
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    MODEL_DIR.mkdir(parents=True, exist_ok=True)


def _preflight_runtime():
    result = subprocess.run(
        [
            _venv_python(),
            "-c",
            (
                "import tensorflow, joblib, numpy, pandas, requests; "
                "from sklearn.preprocessing import StandardScaler; "
                "print('runtime-ok')"
            ),
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode == 0:
        return
    detail = (result.stderr or result.stdout or "").strip()
    if not detail:
        detail = f"Runtime dependency check failed with exit code {result.returncode}"
    raise RuntimeError(detail)


def default_status():
    return {
        "engine": "heuristic",
        "enabled": False,
        "training": {
            "running": False,
            "started_at": None,
            "packets_seen": 0,
            "packets_trained": 0,
            "buffer_size": 1000,
            "current_buffer_count": 0,
            "batches_completed": 0,
            "last_threshold": None,
            "last_checkpoint_at": None,
            "last_error": None,
            "phase": "idle",
        },
        "detection": {
            "running": False,
            "model_loaded": False,
            "model_version": None,
            "last_alert_at": None,
            "last_error": None,
        },
        "model": {
            "exists": False,
            "version": None,
            "trained_at": None,
            "threshold": None,
            "feature_count": 12,
        },
    }


def _atomic_write_json(path: Path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        dir=str(path.parent),
        prefix=f"{path.name}.",
        suffix=".tmp",
    )
    tmp_path = Path(tmp_name)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(payload, f)
    os.replace(tmp_path, path)


def _read_status():
    if not STATUS_PATH.exists():
        return default_status()
    try:
        with open(STATUS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return default_status()
    merged = default_status()
    merged.update(data)
    merged["training"].update(data.get("training", {}))
    merged["detection"].update(data.get("detection", {}))
    merged["model"].update(data.get("model", {}))
    return merged


def _write_status(status):
    _atomic_write_json(STATUS_PATH, status)


def _refresh_processes():
    global _TRAIN_PROCESS, _DETECT_PROCESS
    status = _read_status()

    if _TRAIN_PROCESS is not None and _TRAIN_PROCESS.poll() is not None:
        _TRAIN_PROCESS = None
        status["training"]["running"] = False
        if status["training"]["phase"] not in {"stopped", "stopped_before_first_checkpoint", "error"}:
            status["training"]["phase"] = "stopped"

    if _DETECT_PROCESS is not None and _DETECT_PROCESS.poll() is not None:
        _DETECT_PROCESS = None
        status["detection"]["running"] = False
        status["enabled"] = False
        if status["engine"] == "autoencoder":
            status["engine"] = "heuristic"

    model_meta = {}
    if METADATA_PATH.exists():
        try:
            with open(METADATA_PATH, "r", encoding="utf-8") as f:
                model_meta = json.load(f)
        except Exception:
            model_meta = {}

    status["model"].update({
        "exists": all(path.exists() for path in (MODEL_PATH, SCALER_PATH, THRESHOLD_PATH, METADATA_PATH)),
        "version": model_meta.get("version"),
        "trained_at": model_meta.get("trained_at"),
        "threshold": model_meta.get("threshold"),
        "feature_count": model_meta.get("feature_count", 12),
    })
    status["training"]["running"] = _TRAIN_PROCESS is not None
    status["detection"]["running"] = _DETECT_PROCESS is not None
    _write_status(status)
    return status


def get_status():
    with _LOCK:
        _ensure_dirs()
        return _refresh_processes()


def _terminate_process(proc):
    if proc is None:
        return None
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)
    return None


def stop_training():
    global _TRAIN_PROCESS
    with _LOCK:
        _TRAIN_PROCESS = _terminate_process(_TRAIN_PROCESS)
        status = _refresh_processes()
        status["training"]["running"] = False
        if status["training"]["phase"] not in {"stopped_before_first_checkpoint", "error"}:
            status["training"]["phase"] = "stopped"
        _write_status(status)
        return status


def stop_detection():
    global _DETECT_PROCESS
    with _LOCK:
        _DETECT_PROCESS = _terminate_process(_DETECT_PROCESS)
        status = _refresh_processes()
        status["detection"]["running"] = False
        status["enabled"] = False
        status["engine"] = "heuristic"
        _write_status(status)
        return status


def _remove_model_artifacts():
    for path in (MODEL_PATH, SCALER_PATH, THRESHOLD_PATH, METADATA_PATH):
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def start_training(replace_existing=True):
    global _TRAIN_PROCESS, _DETECT_PROCESS
    with _LOCK:
        _ensure_dirs()
        _preflight_runtime()
        status = _refresh_processes()
        if _TRAIN_PROCESS is not None:
            raise RuntimeError("Training is already running")

        if _DETECT_PROCESS is not None:
            _DETECT_PROCESS = _terminate_process(_DETECT_PROCESS)
            status["detection"]["running"] = False
            status["enabled"] = False
            status["engine"] = "heuristic"

        if replace_existing:
            _remove_model_artifacts()
            status["model"] = default_status()["model"]

        status["training"] = default_status()["training"]
        status["training"]["running"] = True
        status["training"]["started_at"] = time.time()
        status["training"]["phase"] = "starting"
        status["detection"]["last_error"] = None
        _write_status(status)

        log_file = open(TRAIN_LOG_PATH, "w", encoding="utf-8")
        _TRAIN_PROCESS = subprocess.Popen(
            [_venv_python(), str(RUNTIME_SCRIPT), "train_live"],
            cwd=str(ROOT),
            stdout=log_file,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        return _refresh_processes()


def enable_detection():
    global _DETECT_PROCESS
    with _LOCK:
        _ensure_dirs()
        status = _refresh_processes()
        if _TRAIN_PROCESS is not None:
            raise RuntimeError("Stop training before enabling detection")
        if not status["model"]["exists"]:
            raise RuntimeError("No trained autoencoder model is available")
        if _DETECT_PROCESS is not None:
            status["enabled"] = True
            status["engine"] = "autoencoder"
            _write_status(status)
            return status

        log_file = open(DETECT_LOG_PATH, "a", encoding="utf-8")
        _DETECT_PROCESS = subprocess.Popen(
            [_venv_python(), str(RUNTIME_SCRIPT), "detect_live"],
            cwd=str(ROOT),
            stdout=log_file,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        status["enabled"] = True
        status["engine"] = "autoencoder"
        status["detection"]["running"] = True
        _write_status(status)
        return _refresh_processes()


def disable_detection():
    return stop_detection()
