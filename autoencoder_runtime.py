import json
import os
import signal
import sys
import tempfile
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import requests
from sklearn.preprocessing import StandardScaler


ROOT = Path(__file__).resolve().parent
STREAM_PATH = ROOT / "live_data" / "stream.jsonl"
MODEL_DIR = ROOT / "models" / "autoencoder"
RUNTIME_DIR = ROOT / "runtime"
MODEL_PATH = MODEL_DIR / "autoencoder.keras"
SCALER_PATH = MODEL_DIR / "scaler.pkl"
THRESHOLD_PATH = MODEL_DIR / "threshold.npy"
METADATA_PATH = MODEL_DIR / "metadata.json"
STATUS_PATH = RUNTIME_DIR / "autoencoder_status.json"
UPDATE_URL = "http://127.0.0.1:8000/api/update/"
STOP = False

BUFFER_SIZE = 1000
INITIAL_EPOCHS = 10
INCREMENTAL_EPOCHS = 3
THRESHOLD_PERCENTILE = 95
STATUS_UPDATE_INTERVAL = 1.0
DETECTION_FLUSH_INTERVAL = 2.0


def _handle_stop(signum, frame):
    global STOP
    STOP = True


signal.signal(signal.SIGTERM, _handle_stop)
signal.signal(signal.SIGINT, _handle_stop)
signal.signal(signal.SIGPIPE, signal.SIG_DFL)


def ensure_dirs():
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)


def default_status():
    return {
        "engine": "heuristic",
        "enabled": False,
        "training": {
            "running": False,
            "started_at": None,
            "packets_seen": 0,
            "packets_trained": 0,
            "buffer_size": BUFFER_SIZE,
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


def read_status():
    if not STATUS_PATH.exists():
        return default_status()
    try:
        with open(STATUS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        merged = default_status()
        merged.update(data)
        merged["training"].update(data.get("training", {}))
        merged["detection"].update(data.get("detection", {}))
        merged["model"].update(data.get("model", {}))
        return merged
    except Exception:
        return default_status()


def atomic_write_json(path: Path, payload):
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


def update_status(section, values):
    status = read_status()
    if section is None:
        status.update(values)
    else:
        status.setdefault(section, {})
        status[section].update(values)
    atomic_write_json(STATUS_PATH, status)


def write_model_metadata(threshold):
    metadata = {
        "version": str(int(time.time())),
        "trained_at": time.time(),
        "threshold": float(threshold),
        "feature_count": 12,
    }
    atomic_write_json(METADATA_PATH, metadata)
    update_status("model", {
        "exists": True,
        "version": metadata["version"],
        "trained_at": metadata["trained_at"],
        "threshold": metadata["threshold"],
        "feature_count": metadata["feature_count"],
    })
    return metadata


def load_metadata():
    if not METADATA_PATH.exists():
        return None
    try:
        with open(METADATA_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def packet_stream(start_at_end=True):
    while not STOP:
        try:
            with open(STREAM_PATH, "r", encoding="utf-8") as f:
                if start_at_end:
                    f.seek(0, os.SEEK_END)
                while not STOP:
                    line = f.readline()
                    if line:
                        yield line.strip()
                    else:
                        time.sleep(0.2)
        except FileNotFoundError:
            time.sleep(0.5)


def parse_packet(line):
    if not line:
        return None
    try:
        packet = json.loads(line)
    except json.JSONDecodeError:
        return None
    if packet.get("src_ip") == "127.0.0.1" and packet.get("dst_ip") == "127.0.0.1":
        return None
    return packet


def preprocess(df):
    df = df.copy()
    numeric_cols = [
        "packet_size", "payload_len",
        "tcp_window_size", "ttl_hop_limit",
        "src_port", "dst_port",
    ]
    for col in numeric_cols:
        df[col] = pd.to_numeric(df.get(col, 0), errors="coerce").fillna(0)

    flags = [
        "tcp_flags_syn", "tcp_flags_ack", "tcp_flags_fin",
        "tcp_flags_rst", "tcp_flags_psh", "tcp_flags_urg",
    ]
    for col in flags:
        df[col] = df.get(col, "False").astype(str).map({"True": 1, "False": 0}).fillna(0)

    return df[numeric_cols + flags]


def preprocess_single(packet):
    def to_int(value):
        try:
            return int(value)
        except Exception:
            return 0

    return np.array([[
        to_int(packet.get("packet_size", 0)),
        to_int(packet.get("payload_len", 0)),
        to_int(packet.get("tcp_window_size", 0)),
        to_int(packet.get("ttl_hop_limit", 0)),
        to_int(packet.get("src_port", 0)),
        to_int(packet.get("dst_port", 0)),
        1 if str(packet.get("tcp_flags_syn")) == "True" else 0,
        1 if str(packet.get("tcp_flags_ack")) == "True" else 0,
        1 if str(packet.get("tcp_flags_fin")) == "True" else 0,
        1 if str(packet.get("tcp_flags_rst")) == "True" else 0,
        1 if str(packet.get("tcp_flags_psh")) == "True" else 0,
        1 if str(packet.get("tcp_flags_urg")) == "True" else 0,
    ]])


def load_tensorflow():
    from tensorflow.keras.layers import Dense, Input
    from tensorflow.keras.models import Model, load_model
    return Input, Dense, Model, load_model


def build_autoencoder(input_dim):
    Input, Dense, Model, _ = load_tensorflow()
    inp = Input(shape=(input_dim,))
    x = Dense(16, activation="relu")(inp)
    x = Dense(8, activation="relu")(x)
    x = Dense(16, activation="relu")(x)
    out = Dense(input_dim, activation="linear")(x)
    model = Model(inp, out)
    model.compile(optimizer="adam", loss="mean_squared_error")
    return model


def load_model_bundle():
    if not (MODEL_PATH.exists() and SCALER_PATH.exists() and THRESHOLD_PATH.exists()):
        raise FileNotFoundError("Model artifacts are missing")
    _, _, _, load_model = load_tensorflow()
    model = load_model(MODEL_PATH, compile=False)
    model.compile(optimizer="adam", loss="mean_squared_error")
    scaler = joblib.load(SCALER_PATH)
    threshold = float(np.load(THRESHOLD_PATH))
    metadata = load_metadata() or {}
    return model, scaler, threshold, metadata


def canonical_flow(packet):
    sip = (packet.get("src_ip") or "").split(",")[0]
    dip = (packet.get("dst_ip") or "").split(",")[0]
    sport = packet.get("src_port") or "0"
    dport = packet.get("dst_port") or "0"
    proto = packet.get("protocols") or ""
    if not sip or not dip:
        return f"{sip or '?'}:{sport or '?'} -> {dip or '?'}:{dport or '?'}"
    forward = (sip, sport, dip, dport, proto)
    reverse = (dip, dport, sip, sport, proto)
    best = min(forward, reverse)
    return f"{best[0] or '?'}:{best[1] or '?'} -> {best[2] or '?'}:{best[3] or '?'}"


def flow_score(metrics, threshold):
    packet_count = max(metrics["packet_count"], 1)
    anomalous = metrics["anomalous_packet_count"]
    density = anomalous / packet_count
    max_ratio = 0.0 if threshold <= 0 else metrics["max_error"] / threshold
    capped_ratio = min(max(max_ratio, 0.0), 5.0) / 5.0
    return float(min(1.0, (capped_ratio * 0.7) + (density * 0.3)))


def post_update(payload):
    try:
        requests.post(UPDATE_URL, json=payload, timeout=3)
    except Exception:
        pass


def train_live():
    ensure_dirs()
    status = read_status()
    training_state = {
        "running": True,
        "started_at": time.time(),
        "packets_seen": 0,
        "packets_trained": 0,
        "buffer_size": BUFFER_SIZE,
        "current_buffer_count": 0,
        "batches_completed": 0,
        "last_threshold": None,
        "last_checkpoint_at": None,
        "last_error": None,
        "phase": "waiting_for_data",
    }
    status["training"].update(training_state)
    status["detection"].update({"running": False, "last_error": None})
    atomic_write_json(STATUS_PATH, status)

    scaler = StandardScaler()
    model = None
    buffer = []
    last_status_update = 0.0
    checkpoint_count = 0

    try:
        for line in packet_stream(start_at_end=True):
            if STOP:
                break
            packet = parse_packet(line)
            if packet is None:
                continue
            buffer.append(packet)
            training_state["packets_seen"] += 1
            training_state["current_buffer_count"] = len(buffer)

            now = time.time()
            if now - last_status_update >= STATUS_UPDATE_INTERVAL:
                update_status("training", training_state)
                last_status_update = now

            if len(buffer) < BUFFER_SIZE:
                continue

            df = pd.DataFrame(buffer)
            x = preprocess(df)
            if len(x) == 0:
                buffer = []
                training_state["current_buffer_count"] = 0
                update_status("training", training_state)
                continue

            if model is None:
                training_state["phase"] = "initial_training"
                x_scaled = scaler.fit_transform(x)
                model = build_autoencoder(x_scaled.shape[1])
                model.fit(x_scaled, x_scaled, epochs=INITIAL_EPOCHS, batch_size=32, verbose=0)
            else:
                training_state["phase"] = "incremental_training"
                x_scaled = scaler.transform(x)
                model.fit(x_scaled, x_scaled, epochs=INCREMENTAL_EPOCHS, batch_size=32, verbose=0)

            recon = model.predict(x_scaled, verbose=0)
            errors = np.mean((x_scaled - recon) ** 2, axis=1)
            threshold = float(np.percentile(errors, THRESHOLD_PERCENTILE))

            model.save(MODEL_PATH)
            joblib.dump(scaler, SCALER_PATH)
            np.save(THRESHOLD_PATH, threshold)
            metadata = write_model_metadata(threshold)

            checkpoint_count += 1
            training_state["packets_trained"] += len(buffer)
            training_state["batches_completed"] = checkpoint_count
            training_state["last_threshold"] = threshold
            training_state["last_checkpoint_at"] = time.time()
            training_state["phase"] = "waiting_for_data"
            training_state["current_buffer_count"] = 0
            update_status("training", training_state)
            update_status("model", {
                "exists": True,
                "version": metadata["version"],
                "trained_at": metadata["trained_at"],
                "threshold": metadata["threshold"],
                "feature_count": metadata["feature_count"],
            })
            buffer = []

        training_state["running"] = False
        if checkpoint_count == 0:
            training_state["phase"] = "stopped_before_first_checkpoint"
        else:
            training_state["phase"] = "stopped"
        update_status("training", training_state)
    except Exception as exc:
        training_state["running"] = False
        training_state["phase"] = "error"
        training_state["last_error"] = str(exc)
        update_status("training", training_state)
        raise


def detect_live():
    ensure_dirs()
    detection_state = {
        "running": True,
        "model_loaded": False,
        "model_version": None,
        "last_alert_at": None,
        "last_error": None,
    }
    update_status("detection", detection_state)
    last_flush = time.time()
    flows = {}

    try:
        model, scaler, threshold, metadata = load_model_bundle()
        detection_state["model_loaded"] = True
        detection_state["model_version"] = metadata.get("version")
        update_status("detection", detection_state)

        for line in packet_stream(start_at_end=True):
            if STOP:
                break
            packet = parse_packet(line)
            if packet is None:
                continue

            vector = preprocess_single(packet)
            scaled = scaler.transform(vector)
            recon = model.predict(scaled, verbose=0)
            error = float(np.mean((scaled - recon) ** 2))

            flow_id = canonical_flow(packet)
            entry = flows.setdefault(flow_id, {
                "packet_count": 0,
                "anomalous_packet_count": 0,
                "max_error": 0.0,
                "sum_error": 0.0,
                "last_packet_time": float(packet.get("timestamp") or time.time()),
            })
            entry["packet_count"] += 1
            entry["sum_error"] += error
            entry["max_error"] = max(entry["max_error"], error)
            entry["last_packet_time"] = float(packet.get("timestamp") or time.time())
            if error > threshold:
                entry["anomalous_packet_count"] += 1

            now = time.time()
            if now - last_flush < DETECTION_FLUSH_INTERVAL:
                continue

            payloads = []
            for flow, metrics in list(flows.items()):
                mean_error = metrics["sum_error"] / max(metrics["packet_count"], 1)
                score = flow_score(metrics, threshold)
                is_anomaly = metrics["anomalous_packet_count"] > 0 and score > 0
                payloads.append({
                    "type": "autoencoder_score",
                    "flow": flow,
                    "last_packet_time": metrics["last_packet_time"],
                    "anomaly_score": score,
                    "autoencoder_error": metrics["max_error"],
                    "autoencoder_mean_error": mean_error,
                    "anomalous_packet_count": metrics["anomalous_packet_count"],
                    "packet_count": metrics["packet_count"],
                    "last_packet_info": (
                        f"Autoencoder anomaly: {metrics['anomalous_packet_count']}/{metrics['packet_count']} packets above threshold "
                        f"(max error {metrics['max_error']:.4f})"
                        if is_anomaly else
                        f"Autoencoder normal: max error {metrics['max_error']:.4f}"
                    ),
                    "detector": "autoencoder",
                    "status": "anomaly" if is_anomaly else "ok",
                })
                if is_anomaly:
                    detection_state["last_alert_at"] = metrics["last_packet_time"]
            for payload in payloads:
                post_update(payload)
            flows.clear()
            update_status("detection", detection_state)
            last_flush = now

        detection_state["running"] = False
        update_status("detection", detection_state)
    except Exception as exc:
        detection_state["running"] = False
        detection_state["last_error"] = str(exc)
        update_status("detection", detection_state)
        raise


def main():
    ensure_dirs()
    if len(sys.argv) < 2:
        print("Usage: python autoencoder_runtime.py [train_live|detect_live]")
        sys.exit(1)

    mode = sys.argv[1]
    if mode == "train_live":
        train_live()
    elif mode == "detect_live":
        detect_live()
    else:
        print("Invalid mode")
        sys.exit(1)


if __name__ == "__main__":
    main()
