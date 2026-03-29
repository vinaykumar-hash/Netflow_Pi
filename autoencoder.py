import json
import ast
import numpy as np
import pandas as pd
import joblib
import sys
import signal

from sklearn.preprocessing import StandardScaler
from tensorflow.keras.models import Model, load_model
from tensorflow.keras.layers import Input, Dense

# Fix broken pipe crash
signal.signal(signal.SIGPIPE, signal.SIG_DFL)

MODEL_PATH = "autoencoder.keras"
SCALER_PATH = "scaler.pkl"
THRESHOLD_PATH = "threshold.npy"


# -------------------------------
# 1. CLEAN + LOAD DATA
# -------------------------------
def load_clean_data(file_path):
    data = []

    with open(file_path, "r") as f:
        for line in f:
            line = line.strip()

            if line.startswith("Dropped"):
                continue

            if not (line.startswith("{") and line.endswith("}")):
                continue

            try:
                packet = ast.literal_eval(line)

                # remove localhost noise
                if packet.get("src_ip") == "127.0.0.1" and packet.get("dst_ip") == "127.0.0.1":
                    continue

                data.append(packet)

            except Exception:
                continue

    return pd.DataFrame(data)


# -------------------------------
# 2. FEATURE ENGINEERING
# -------------------------------
def train_live(buffer_size=1000):
    scaler = StandardScaler()
    model = None
    buffer = []

    print("Live training started...")

    while True:
        try:
            line = sys.stdin.readline()
            if not line:
                break

            line = line.strip()

            if line.startswith("Dropped"):
                continue

            if not (line.startswith("{") and line.endswith("}")):
                continue

            try:
                packet = ast.literal_eval(line)
            except:
                continue

            buffer.append(packet)

            # Train when buffer full
            if len(buffer) >= buffer_size:
                df = pd.DataFrame(buffer)
                X = preprocess(df)

                if len(X) == 0:
                    buffer = []
                    continue

                # First time: fit scaler
                if model is None:
                    X_scaled = scaler.fit_transform(X)

                    model = build_autoencoder(X_scaled.shape[1])

                    print("Initial training...")
                    model.fit(X_scaled, X_scaled, epochs=10, batch_size=32, verbose=0)

                else:
                    X_scaled = scaler.transform(X)

                    print("Incremental training...")
                    model.fit(X_scaled, X_scaled, epochs=3, batch_size=32, verbose=0)

                # Compute threshold dynamically
                recon = model.predict(X_scaled, verbose=0)
                errors = np.mean((X_scaled - recon) ** 2, axis=1)
                threshold = np.percentile(errors, 95)

                # Save periodically
                model.save(MODEL_PATH)
                joblib.dump(scaler, SCALER_PATH)
                np.save(THRESHOLD_PATH, threshold)

                print(f"[TRAINED] buffer={buffer_size} threshold={threshold}")

                buffer = []

        except BrokenPipeError:
            break
        except Exception:
            continue
def preprocess(df):
    df = df.copy()

    numeric_cols = [
        "packet_size", "payload_len",
        "tcp_window_size", "ttl_hop_limit",
        "src_port", "dst_port"
    ]

    for col in numeric_cols:
        df[col] = pd.to_numeric(df.get(col, 0), errors="coerce").fillna(0)

    flags = [
        "tcp_flags_syn", "tcp_flags_ack", "tcp_flags_fin",
        "tcp_flags_rst", "tcp_flags_psh", "tcp_flags_urg"
    ]

    for col in flags:
        df[col] = df.get(col, "False").astype(str).map({"True": 1, "False": 0}).fillna(0)

    features = numeric_cols + flags
    return df[features]


def preprocess_single(packet):
    def to_int(x):
        try:
            return int(x)
        except:
            return 0

    return np.array([[
        to_int(packet.get("packet_size", 0)),
        to_int(packet.get("payload_len", 0)),
        to_int(packet.get("tcp_window_size", 0)),
        to_int(packet.get("ttl_hop_limit", 0)),
        to_int(packet.get("src_port", 0)),
        to_int(packet.get("dst_port", 0)),
        1 if packet.get("tcp_flags_syn") == "True" else 0,
        1 if packet.get("tcp_flags_ack") == "True" else 0,
        1 if packet.get("tcp_flags_fin") == "True" else 0,
        1 if packet.get("tcp_flags_rst") == "True" else 0,
        1 if packet.get("tcp_flags_psh") == "True" else 0,
        1 if packet.get("tcp_flags_urg") == "True" else 0,
    ]])


# -------------------------------
# 3. MODEL
# -------------------------------
def build_autoencoder(input_dim):
    inp = Input(shape=(input_dim,))

    x = Dense(16, activation="relu")(inp)
    x = Dense(8, activation="relu")(x)

    x = Dense(16, activation="relu")(x)
    out = Dense(input_dim, activation="linear")(x)

    model = Model(inp, out)
    model.compile(optimizer="adam", loss="mean_squared_error")
    return model


# -------------------------------
# 4. TRAINING
# -------------------------------
def train(file_path):
    print("Loading data...")
    df = load_clean_data(file_path)

    print(f"Loaded {len(df)} packets")

    print("Preprocessing...")
    X = preprocess(df)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    print("Training model...")
    model = build_autoencoder(X_scaled.shape[1])

    model.fit(
        X_scaled, X_scaled,
        epochs=20,
        batch_size=32,
        validation_split=0.1,
        shuffle=True,
        verbose=1
    )

    print("Calculating threshold...")
    recon = model.predict(X_scaled, verbose=0)
    errors = np.mean((X_scaled - recon) ** 2, axis=1)

    threshold = np.percentile(errors, 95)
    print("Threshold:", threshold)

    # Save
    model.save(MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    np.save(THRESHOLD_PATH, threshold)

    print("Training complete.")


# -------------------------------
# 5. LOAD MODEL
# -------------------------------
def load_all():
    model = load_model(MODEL_PATH, compile=False)
    model.compile(optimizer="adam", loss="mean_squared_error")

    scaler = joblib.load(SCALER_PATH)
    threshold = np.load(THRESHOLD_PATH)

    return model, scaler, threshold


# -------------------------------
# 6. STREAM DETECTION
# -------------------------------
def detect_stream():
    model, scaler, threshold = load_all()

    print("Listening for packets...")

    while True:
        try:
            line = sys.stdin.readline()

            if not line:
                break

            line = line.strip()

            if line.startswith("Dropped"):
                continue

            if not (line.startswith("{") and line.endswith("}")):
                continue

            try:
                packet = ast.literal_eval(line)
            except Exception:
                continue

            x = preprocess_single(packet)
            x = scaler.transform(x)

            recon = model.predict(x, verbose=0)
            error = np.mean((x - recon) ** 2)

            if error > threshold:
                print(f"[ALERT] {packet.get('src_ip')} → {packet.get('dst_ip')} | Score={error}", flush=True)
            else:
                print(f"[OK] Score={error}", flush=True)

        except BrokenPipeError:
            break
        except Exception:
            continue


# -------------------------------
# 7. ENTRY POINT
# -------------------------------
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage:")
        print("  Train:  python anomaly_autoencoder.py train data.txt")
        print("  Detect: python anomaly_autoencoder.py detect dummy")
        sys.exit(1)

    mode = sys.argv[1]

    if mode == "train":
        train(sys.argv[2])

    elif mode == "detect":
        detect_stream()
    elif mode == "train_live":
    	train_live()
    else:
        print("Invalid mode")