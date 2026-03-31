import pandas as pd
import uuid
import os
import requests
import json
import time
import pathway as pw
import datetime
from typing import Any
from dotenv import load_dotenv

from features.feature_tcp_flags import detect_abnormal_flags
from features.feature_ttl import analyze_ttl
from features.feature_small_packets import detect_small_packet_flow
from features.feature_sequence import analyze_sequence
from features.feature_encryption import get_encryption_label
from features.feature_flow_stats import compute_flow_stats
import uuid

load_dotenv()

_embedder_model = None
_semantic_search_util = None
_semantic_search_import_error = None


def _load_semantic_search_deps():
    global _semantic_search_util, _semantic_search_import_error
    if _semantic_search_util is not None:
        return _semantic_search_util
    if _semantic_search_import_error is not None:
        return None
    try:
        from sentence_transformers import SentenceTransformer, util
        _semantic_search_util = (SentenceTransformer, util)
        return _semantic_search_util
    except Exception as exc:
        _semantic_search_import_error = exc
        return None


def _get_embedder_model():
    global _embedder_model
    if _embedder_model is not None:
        return _embedder_model
    deps = _load_semantic_search_deps()
    if deps is None:
        return None
    SentenceTransformer, _ = deps
    _embedder_model = SentenceTransformer("all-MiniLM-L6-v2")
    return _embedder_model

class PacketSchema(pw.Schema):
    timestamp: float
    protocols: str
    src_ip: str | None
    dst_ip: str | None
    src_port: str | None
    dst_port: str | None
    packet_size: str | None
    payload_len: str | None
    raw_payload_hex: str | None
    info: str | None
    tcp_seq: str | None
    tcp_flags_syn: str | None
    tcp_flags_ack: str | None
    tcp_flags_fin: str | None
    tcp_flags_rst: str | None
    tcp_flags_psh: str | None
    tcp_flags_urg: str | None
    tcp_retransmission: str | None
    tcp_window_size: str | None
    ttl_hop_limit: str | None
    fragmentation: str | None


packets = pw.io.jsonlines.read(
    "live_data/stream.jsonl",
    schema=PacketSchema,
    mode="streaming"
)


# Log all raw traffic — gated by logging.all_packets flag
@pw.udf
def _gate_all_packets(_unused: float) -> bool:
    return _is_logging_enabled("all_packets")

pw.io.csv.write(
    packets.select(
        pw.this.timestamp,
        pw.this.src_ip,
        pw.this.dst_ip,
        pw.this.src_port,
        pw.this.dst_port,
        pw.this.protocols,
        pw.this.raw_payload_hex,
    ).filter(_gate_all_packets(pw.this.timestamp)),
    filename="logs/all_packets.csv"
)

# Load Whitelist Configuration
WHITELIST = {"ips": [], "ports": []}
LAST_WHITELIST_MTIME = 0
LAST_CHECK_TIME = 0
WHITELIST_FILE = "whitelist.json"

def _update_whitelist_if_needed():
    global WHITELIST, LAST_WHITELIST_MTIME, LAST_CHECK_TIME
    current_time = time.time()
    # Throttling: only check file stat at most once per second
    if current_time - LAST_CHECK_TIME > 1.0:
        LAST_CHECK_TIME = current_time
        if os.path.exists(WHITELIST_FILE):
            try:
                mtime = os.path.getmtime(WHITELIST_FILE)
                if mtime > LAST_WHITELIST_MTIME:
                    with open(WHITELIST_FILE, "r") as f:
                        WHITELIST = json.load(f)
                    LAST_WHITELIST_MTIME = mtime
            except Exception:
                pass

if os.path.exists(WHITELIST_FILE):
    _update_whitelist_if_needed()

def _is_logging_enabled(key: str) -> bool:
    _update_whitelist_if_needed()
    return bool(WHITELIST.get("logging", {}).get(key, True))

@pw.udf
def is_whitelisted(src_ip: str | None, dst_ip: str | None, src_port: str | None, dst_port: str | None) -> bool:
    # Always check if we need to reload whitelist
    _update_whitelist_if_needed()
    
    # 1. Whitelist Localhost and Link-Local (IPv6)
    # 1. Whitelist Link-Local (IPv6) - keep localhost separate
    if src_ip and (src_ip.startswith("fe80:") or src_ip.startswith("ff02:")):
        return True
    if dst_ip and (dst_ip.startswith("fe80:") or dst_ip.startswith("ff02:")):
        return True
        
    # 2. Whitelist Broadcast/Multicast
    if dst_ip and (dst_ip == "255.255.255.255" or dst_ip.startswith("224.")):
        return True

    # 3. Whitelist Common Safe Ports (DNS, mDNS, SSDP) if needed
    # (Optional: can be tunable)
    
    # Check against user-defined whitelist
    def check_ip_in_whitelist(ip):
        return ip in WHITELIST.get("ips", [])
    
    def check_port_in_whitelist(port):
        if not port: return False
        try:
            return int(port) in WHITELIST.get("ports", [])
        except ValueError:
            return False

    return (
        check_ip_in_whitelist(src_ip) or check_ip_in_whitelist(dst_ip) or 
        check_port_in_whitelist(src_port) or check_port_in_whitelist(dst_port)
    )

@pw.udf
def mask_if_whitelisted(value: Any, whitelisted: bool) -> Any:
    return None if whitelisted else value


@pw.udf
def has_flags(flags: list[str]) -> bool:
    return len(flags) > 0

@pw.udf
def check_anomaly(
    packet_count: int,
    mean_size: float,
    total_bytes: int,
    duration: float,
    dst_port: str | None
) -> str:
    reasons = []
    
    # Safe cast port
    dport = 0
    try:
        dport = int(dst_port) if dst_port else 0
    except ValueError:
        pass

    # 1. SYN Flood / Port Scan
    # Increase threshold to 500 for local high-traffic bursts
    rate = packet_count / max(duration, 0.001)
    # if(packet_count > 10):
    #     reasons.append("Potential SYN Flood / Scan")
    if rate > 20 and mean_size < 100:
        reasons.append("Potential SYN Flood / Scan")

    # 2. Data Exfiltration (simplified proxy check)
    if total_bytes > 50000 and packet_count > 100:
         reasons.append(f"High Volume Transfer (Potential Exfiltration)")

    # 3. Beaconing (Skipped - requires IAT)

    # 4. Slow DoS (Relaxed)
    if duration > 2.0 and packet_count > 20:
        reasons.append("Potential Slow DoS Pattern")


    return "; ".join(reasons) if reasons else ""

@pw.udf
def safe_float_udf(x: str | None) -> float:
    try:
        if x is not None and str(x).strip():
            return float(x)
    except (ValueError, TypeError):
        pass
    return 0.0
@pw.udf
def to_bool_udf(val: str | None) -> bool:
    if val is None: return False
    return str(val).lower() in ("1", "true", "yes")

@pw.udf
def format_flow_id_udf(s: str | None, d: str | None, sp: str | None, dp: str | None) -> str:
    return f"{s or '?'}:{sp or '?' } -> {d or '?'}:{dp or '?'}"

@pw.udf
def get_last_packet_info_udf(infos: tuple) -> str:
    return str(infos[-1]) if infos else "None"

@pw.udf
def get_last_encryption_udf(encs: tuple) -> str:
    return str(encs[-1]) if encs else "Unknown"

@pw.udf(return_type=str)
def safe_flags_stub(*args) -> str:
    return "OK"

# 2. Add individual packet features
packets = packets.select(
    *pw.this,
    abnormal_flags = pw.apply(
        detect_abnormal_flags,
        pw.this.protocols,
        pw.this.tcp_flags_syn, pw.this.tcp_flags_ack, pw.this.tcp_flags_fin, 
        pw.this.tcp_flags_rst, pw.this.tcp_flags_psh, pw.this.tcp_flags_urg
    ),
    # abnormal_flags = "OK",
    # is_encrypted="Unknown"
    is_encrypted = pw.apply(get_encryption_label, pw.this.protocols, pw.this.dst_port)
)



# 2. Canonical Flow Key (Bidirectional)
@pw.udf
def canonical_key(sip, dip, sport, dport, proto):
    if sip is None or dip is None:
        return (sip, dip, sport, dport, proto)

    sip = sip.split(",")[0]
    dip = dip.split(",")[0]
    sport = sport or "0"
    dport = dport or "0"

    forward = (sip, sport, dip, dport, proto)
    reverse = (dip, dport, sip, sport, proto)

    return min(forward, reverse)

@pw.udf(return_type=int)
def to_int_udf(x: str | None) -> int:
    try:
        return int(x) if x else 0
    except:
        return 0


packets_with_key = packets.select(
    *pw.this,
    flow_key = canonical_key(pw.this.src_ip, pw.this.dst_ip, pw.this.src_port, pw.this.dst_port, pw.this.protocols),
    # Ensure types for UDF
    ts_float = pw.this.timestamp,
    size_int = to_int_udf(pw.this.packet_size),
    seq_str = pw.apply(lambda x: str(x) if x else "0", pw.this.tcp_seq)
)


# 3. Window aggregation with Advanced Stats
flow_stats = packets_with_key.groupby(pw.this.flow_key).windowby(
    pw.this.timestamp,
    window=pw.temporal.sliding(hop=0.5, duration=5.0),
).reduce(
    packet_count=pw.reducers.count(),
    total_bytes=pw.reducers.sum(pw.this.size_int),
    mean_size=pw.reducers.avg(pw.this.size_int),
    min_time=pw.reducers.min(pw.this.timestamp),
    max_time=pw.reducers.max(pw.this.timestamp),
    event_time=pw.reducers.max(pw.this.timestamp),
    latest_raw_payload_hex=pw.reducers.max(pw.this.raw_payload_hex),

    src_ip=pw.reducers.max(pw.this.src_ip),
    dst_ip=pw.reducers.max(pw.this.dst_ip),
    src_port=pw.reducers.max(pw.this.src_port),
    dst_port=pw.reducers.max(pw.this.dst_port),
    is_encrypted=pw.reducers.max(pw.this.is_encrypted),
    flow_key=pw.reducers.max(pw.this.flow_key),
)


# Unpack logic
@pw.udf
def get_sip(key: tuple) -> str:
    return key[0]

@pw.udf
def get_sport(key: tuple) -> str:
    return key[1]

@pw.udf
def get_dip(key: tuple) -> str:
    return key[2]

@pw.udf
def get_dport(key: tuple) -> str:
    return key[3]

# Unpack logic
flow_features = flow_stats.select(
    flow_id=format_flow_id_udf(
        get_sip(pw.this.flow_key),
        get_dip(pw.this.flow_key),
        get_sport(pw.this.flow_key),
        get_dport(pw.this.flow_key)
    ),
    duration=pw.this.max_time - pw.this.min_time+0.001,
    packet_count=pw.this.packet_count,
    total_bytes=pw.this.total_bytes,
    mean_size=pw.this.mean_size,
    event_time=pw.this.event_time,

    src_ip=get_sip(pw.this.flow_key),
    dst_ip=get_dip(pw.this.flow_key),
    src_port=get_sport(pw.this.flow_key),
    dst_port=get_dport(pw.this.flow_key),
    is_encrypted=pw.this.is_encrypted,
    raw_payload_hex=pw.this.latest_raw_payload_hex,
).filter(
    pw.this.src_port != pw.this.dst_port
)
@pw.udf(return_type=bool)
def is_internal_ip(ip: str | None) -> bool:
    if not ip:
        return False
    return (
        ip == "127.0.0.1" or
        ip == "::1" or
        ip.startswith("192.168.") or
        ip.startswith("10.") or
        ip.startswith("172.16.") or
        ip.startswith("172.17.") or
        ip.startswith("172.18.") or
        ip.startswith("172.19.") or
        ip.startswith("172.20.") or
        ip.startswith("172.21.") or
        ip.startswith("172.22.") or
        ip.startswith("172.23.") or
        ip.startswith("172.24.") or
        ip.startswith("172.25.") or
        ip.startswith("172.26.") or
        ip.startswith("172.27.") or
        ip.startswith("172.28.") or
        ip.startswith("172.29.") or
        ip.startswith("172.30.") or
        ip.startswith("172.31.")
    )
flows_internal = flow_features.select(
    *pw.this,
    is_internal_target=is_internal_ip(pw.this.dst_ip),
    whitelisted=is_whitelisted(pw.this.src_ip, pw.this.dst_ip, pw.this.src_port, pw.this.dst_port)
)
threshold_flows = flows_internal.filter(
    (pw.this.is_internal_target) &
    (
        (pw.this.packet_count > 50) |
        (pw.this.total_bytes > 50000) |
        (pw.this.duration > 3.0)
    )
)

@pw.udf(return_type=float)
def anomaly_score(packet_count, mean_size, total_bytes, duration):
    rate = packet_count / max(duration, 0.001)

    score = 0.0
    # if packet_count > 5:
    #     return 1.0
    if packet_count > 50 and mean_size < 120:
        score += 0.4

    if total_bytes > 2000:
        score += 0.3

    if duration > 5:
        score += 0.3

    return min(score, 1.0)


@pw.udf(return_type=float)
def confidence(packet_count, duration):
    if duration == 0:
        return 0.0
    density = packet_count / duration
    if density > 50:
        return 0.9
    if density > 10:
        return 0.7
    return 0.5


@pw.udf
def filter_flags(flags: tuple[str | None, ...]) -> list[str]:
    return [f for f in flags if f is not None]

@pw.udf
def count_flags(flags: list[str] | None) -> int:
    if flags is None:
        return 0
    # Pathway might pass tuple if internal representation changes, handle gracefully
    return len(flags)

# 4. Apply Behavioral Analysis to Flows
flows_with_whitelist = flow_features.select(
    *pw.this,
    whitelisted = is_whitelisted(pw.this.src_ip, pw.this.dst_ip, pw.this.src_port, pw.this.dst_port)
)
@pw.udf(return_type=float)
def mask_score(score: float, whitelisted: bool) -> float:
    return 0.0 if whitelisted else score

flow_analysis = flows_with_whitelist.select(
    *pw.this,
    raw_score=anomaly_score(
        pw.this.packet_count,
        pw.this.mean_size,
        pw.this.total_bytes,
        pw.this.duration
    ),
    anomaly_reason=check_anomaly(
        pw.this.packet_count,
        pw.this.mean_size,
        pw.this.total_bytes,
        pw.this.duration,
        pw.this.dst_port
    ),
    latest_raw_payload_hex=pw.this.raw_payload_hex,
).select(
    *pw.this,
    anomaly_score=mask_score(
        pw.this.raw_score,
        pw.this.whitelisted
    ),
    confidence=confidence(
        pw.this.packet_count,
        pw.this.duration
    )
)
debug_8080 = flow_analysis.filter(
    pw.this.dst_port == "8080"
)

# 5. Push to Web Dashboard (Rate-Limited Pulse)
# We window the analysis to send updates every 2s for UI stability
flow_pulse = flow_analysis.windowby(
    pw.this.event_time,
    window=pw.temporal.tumbling(duration=2.0),
    instance=pw.this.flow_id
).reduce(
    flow_id=pw.reducers.max(pw.this.flow_id),
    anomaly_score=pw.reducers.max(pw.this.anomaly_score),
    anomaly_reason=pw.reducers.max(pw.this.anomaly_reason),
    last_packet_info=pw.reducers.max(pw.this.anomaly_reason),
    last_raw_payload_hex=pw.reducers.max(pw.this.latest_raw_payload_hex),
    confidence=pw.reducers.max(pw.this.confidence),
    packet_count=pw.reducers.max(pw.this.packet_count),
    total_bytes=pw.reducers.max(pw.this.total_bytes),
    duration=pw.reducers.max(pw.this.duration),
    event_time=pw.reducers.max(pw.this.event_time),
    # Aliases for Frontend
    flow=pw.reducers.max(pw.this.flow_id), 
    last_packet_time=pw.reducers.max(pw.this.event_time),
    encryption=pw.reducers.max(pw.this.is_encrypted),
    whitelisted=pw.reducers.max(pw.this.whitelisted),
)
flow_pulse = flow_pulse.select(
    *pw.this,
    type=pw.apply(lambda _: "flow_update", pw.this.flow),
    detector=pw.apply(lambda _: "heuristic", pw.this.flow),
    status=pw.apply(lambda reason: "anomaly" if str(reason or "").strip() else "ok", pw.this.anomaly_reason),
)


# Filter for anomalies only (Shared logic)
@pw.udf
def is_above_threshold(score: float) -> bool:
    _update_whitelist_if_needed()
    try:
        threshold = float(WHITELIST.get("anomaly_threshold", 0.0))
    except (ValueError, TypeError):
        threshold = 0.0
    return score >= threshold


@pw.udf
def should_emit_to_dashboard(score: float, whitelisted: bool) -> bool:
    _update_whitelist_if_needed()
    try:
        threshold = float(WHITELIST.get("anomaly_threshold", 0.0))
    except (ValueError, TypeError):
        threshold = 0.0
    if threshold <= 0.0:
        return True
    return (score >= threshold) and (not whitelisted)

# anomalous_pulse = flow_pulse.filter(
#     pw.this.anomaly_score > 0.5
# )
# anomalous_pulse = flow_pulse.filter(~pw.this.whitelisted)
anomalous_pulse = flow_pulse.filter(
    is_above_threshold(pw.this.anomaly_score) & (~pw.this.whitelisted)
)
dashboard_pulse = flow_pulse.filter(
    should_emit_to_dashboard(pw.this.anomaly_score, pw.this.whitelisted)
)
port_monitor = flows_internal.filter(
    pw.this.is_internal_target & (~pw.this.whitelisted)
).groupby(
    pw.this.dst_ip,
    pw.this.dst_port
).windowby(
    pw.this.event_time,
    window=pw.temporal.sliding(hop=1.0, duration=5.0),
).reduce(
    target=pw.reducers.max(pw.this.dst_ip),
    port=pw.reducers.max(pw.this.dst_port),
    packets=pw.reducers.sum(pw.this.packet_count),
    bytes=pw.reducers.sum(pw.this.total_bytes),
    event_time=pw.reducers.max(pw.this.event_time),
)
port_alerts = port_monitor.filter(
    pw.this.packets > 0
)

pw.io.http.write(
    dashboard_pulse,
    url="http://localhost:8000/api/update/",
    method="POST",
    headers={"Content-Type": "application/json"}
)

# --- Graph Edge Aggregation ---
# Group traffic by (source, target, port) to visualize connections
# Window: 10s sliding (smoother graph updates)
graph_edges = flows_with_whitelist.filter(
    ~pw.this.whitelisted
).groupby(
    pw.this.src_ip, pw.this.src_port, pw.this.dst_ip, pw.this.dst_port
).windowby(
    pw.this.event_time,
    window=pw.temporal.sliding(hop=2.0, duration=10.0),
).reduce(
    src_ip=pw.reducers.max(pw.this.src_ip),
    src_port=pw.reducers.max(pw.this.src_port),
    dst_ip=pw.reducers.max(pw.this.dst_ip),
    dst_port=pw.reducers.max(pw.this.dst_port),
    weight=pw.reducers.sum(pw.this.packet_count),
).select(
    source=pw.apply(lambda ip, port: f"{ip}:{port}", pw.this.src_ip, pw.this.src_port),
    target=pw.apply(lambda ip, port: f"{ip}:{port}", pw.this.dst_ip, pw.this.dst_port),
    dst_port=pw.this.dst_port,
    weight=pw.this.weight,
    type=pw.apply(lambda _: "graph_edge", pw.this.weight), # Tag for frontend
).filter(
    pw.this.weight > 0 # Filter noise (low packet counts)
)

# Graph edge log — gated by logging.graph_edges flag
@pw.udf
def _gate_graph_edges(_unused: float) -> bool:
    return _is_logging_enabled("graph_edges")

pw.io.csv.write(
    graph_edges.filter(_gate_graph_edges(pw.this.weight)),
    filename="logs/debug_graph_edges.csv"
)

# Stream Graph Updates to same endpoint
pw.io.http.write(
    graph_edges,
    url="http://localhost:8000/api/update/",
    method="POST",
    headers={"Content-Type": "application/json"}
)
# ------------------------------
port_alerts_stream = port_alerts.select(
    target=pw.this.target,
    port=pw.this.port,
    packets=pw.this.packets,
    bytes=pw.this.bytes,
    time=pw.this.event_time,
    type=pw.apply(lambda _: "port_alert", pw.this.port)
)

pw.io.http.write(
    port_alerts_stream,
    url="http://localhost:8000/api/update/",
    method="POST",
    headers={"Content-Type": "application/json"}
)


# Anomaly log — gated by logging.anomalies flag
@pw.udf
def _gate_anomalies(score: float) -> bool:
    return _is_logging_enabled("anomalies")

pw.io.csv.write(
    anomalous_pulse.filter(_gate_anomalies(pw.this.anomaly_score)),
    filename="docs/anomalies.csv"
)

# 6. Format for LLM Indexing (DocumentStore)
@pw.udf
def format_doc_udf(flow_id, score, confidence, packets, bytes_sent, duration, reason) -> str:
    return (
        f"Flow: {flow_id} | "
        f"Description: {reason} | "
        f"Score: {score:.2f} | "
        f"Confidence: {confidence:.2f} | "
        f"Packets: {packets} | "
        f"Bytes: {bytes_sent} | "
        f"Duration: {duration:.2f}s"
    )

live_docs = anomalous_pulse.select(
    data=format_doc_udf(
        pw.this.flow_id,
        pw.this.anomaly_score,
        pw.this.confidence,
        pw.this.packet_count,
        pw.this.total_bytes,
        pw.this.duration,
        pw.this.anomaly_reason,
    )
)

@pw.udf
def ensure_bytes(x) -> bytes:
    if isinstance(x, bytes):
        return x
    return str(x).encode("utf-8")

# FIX: Add static document to prevent Empty Index Panic during startup
static_df = pd.DataFrame([
    {
        "data": b"Sentinel System initialized. Monitoring network traffic...",
        "path": "static_init"
    }
])

static_docs = pw.debug.table_from_pandas(static_df).select(
    data=ensure_bytes(pw.this.data)
)

# --- SIDE-CAR RAG LOGIC ---
# We write anomalies to a CSV and read them in the LLM UDF to bypass Pathway engine panics.
# RAG context log — gated by logging.rag_context flag
@pw.udf
def _gate_rag(_unused: bytes) -> bool:
    return _is_logging_enabled("rag_context")

pw.io.csv.write(
    live_docs.filter(_gate_rag(pw.this.data)),
    filename="docs/rag_context.csv"
)

@pw.udf
def semantic_search_udf(query: str, context_list: tuple) -> list:
    if not context_list:
        return []
    
    # We maintain only the last 50 chunks for performance and relevance
    raw_list = list(context_list)
    active_context = raw_list[-50:]
    
    str_chunks = []
    for c in active_context:
        if isinstance(c, bytes):
            str_chunks.append(c.decode("utf-8", errors="ignore"))
        else:
            str_chunks.append(str(c))

    deps = _load_semantic_search_deps()
    embedder_model = _get_embedder_model()
    if deps is None or embedder_model is None:
        return [{"text": chunk} for chunk in str_chunks[:3]]
    _, util = deps

    query_emb = embedder_model.encode(query, convert_to_tensor=True)
    corpus_emb = embedder_model.encode(str_chunks, convert_to_tensor=True)
    
    # Compute similarity
    hits = util.semantic_search(query_emb, corpus_emb, top_k=3)[0]
    
    results = []
    for hit in hits:
        results.append({"text": str_chunks[hit["corpus_id"]]})
    
    return results

# Webserver & Queries
query_server = pw.io.http.PathwayWebserver(host="0.0.0.0", port=8011)


class QuerySchema(pw.Schema):
    messages: str
    model: str | None
    selected_row: str | None

queries, writer = pw.io.http.rest_connector(
    webserver=query_server,
    schema=QuerySchema,
    autocommit_duration_ms=1000,
    delete_completed_queries=True
)

# Process Queries
# We use a unique string ID to avoid u128 index panics in older Pathway versions
queries_pre = queries.select(
    query = pw.this.messages,
    model = pw.this.model,
    selected_row = pw.this.selected_row,
    k = 3,
    request_id = pw.apply_with_type(lambda _: str(uuid.uuid4()), str, pw.this.messages),
    dummy_key = pw.apply_with_type(lambda _: "global_context", str, pw.this.messages)
)
retrieved_documents = queries_pre.select(
    *pw.this,
    result = pw.apply(lambda _: [], pw.this.query)
)

import requests
import json

@pw.udf
def build_prompts_udf(documents, query) -> str:
    if not documents:
        return f"System: Network context is empty. \nUser: {query}"
    
    valid_docs = []
    for doc in documents:
        if doc is None: 
            continue
        try:
            # Extract text or data
            text = doc.get("text", "") if hasattr(doc, "get") else ""
            if not text and hasattr(doc, "get"):
                text = doc.get("data", "")
                
            if isinstance(text, bytes):
                text = text.decode("utf-8", errors="ignore")
            else:
                text = str(text)
                
            if text and text.strip():
                valid_docs.append(text)
        except Exception:
            pass
            
    if not valid_docs:
        return f"System: Network context is empty. \nUser: {query}"
        
    context = " | ".join(valid_docs)
    return f"System: Use this live network context to precisely answer the user: {context}\n\nUser: {query}"

prompts = retrieved_documents.select(
    prompt_text=pw.this.query,
    model=pw.this.model,
    selected_row=pw.this.selected_row
)

@pw.udf
def call_openrouter(query: str, model: str | None, selected_row: str | None) -> str:
    # --- RAG SIDE-CAR: READ FROM CSV ---
    context_str = ""
    try:
        csv_path = "docs/rag_context.csv"
        # Check if it's a directory (Pathway can write CSVs as directories of parts)
        if os.path.exists(csv_path):
            import csv
            all_rows = []
            if os.path.isdir(csv_path):
                import glob
                for part in glob.glob(os.path.join(csv_path, "*.csv")):
                    with open(part, "r") as f:
                        reader = csv.DictReader(f)
                        for row in reader:
                            # Only include active records (diff=1) and skip retracted ones
                            if row.get("diff") == "1" and "data" in row:
                                all_rows.append(row["data"])
            else:
                with open(csv_path, "r") as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        if row.get("diff") == "1" and "data" in row:
                            all_rows.append(row["data"])
            
            # Get last 200 for broader context coverage
            active_context: Any = all_rows[-200:]
            
            if active_context:
                # Keyword Boosting (IPs/Ports)
                query_tokens = query.replace(":", " ").replace("-", " ").replace(".", " ").split()
                keywords = [t for t in query_tokens if len(t) > 2] # Skip small tokens
                
                # Rows that exactly match a query token (IP, Port, etc.)
                priority_docs = []
                for doc in active_context:
                    if any(kw.lower() in doc.lower() for kw in keywords):
                        priority_docs.append(doc)
                
                semantic_docs = []
                deps = _load_semantic_search_deps()
                embedder_model = _get_embedder_model()
                if deps is not None and embedder_model is not None:
                    _, util = deps
                    query_emb = embedder_model.encode(query, convert_to_tensor=True)
                    corpus_emb = embedder_model.encode(active_context, convert_to_tensor=True)
                    hits = util.semantic_search(query_emb, corpus_emb, top_k=min(10, len(active_context)))[0]
                    semantic_docs = [str(active_context[hit["corpus_id"]]) for hit in hits]
                
                # Combine: Keywords first, then Semantic
                final_docs = []
                seen = set()
                # Prioritize keyword matches
                for doc in priority_docs:
                    if doc not in seen:
                        final_docs.append(doc)
                        seen.add(doc)
                # Add semantic matches
                for doc in semantic_docs:
                    if doc not in seen:
                        final_docs.append(doc)
                        seen.add(doc)
                
                # Limit final context to 15 chunks (balanced)
                context_str = " | ".join(final_docs[:15])
    except Exception as e:
        context_str = f"RAG Side-car Error: {str(e)}"

    selected_context = selected_row if selected_row else ""
    system_prompt = f"System: Network Context: {context_str}\n{selected_context}\n\nUse this context to answer precisely. If empty, answer generally."
    user_query = f"User: {query}"
    full_prompt = f"{system_prompt}\n\n{user_query}"
    
    api_key = os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        return "Error: OPENROUTER_API_KEY is not set."
    
    target_model = str(model) if model else "arcee-ai/trinity-large-preview:free"
    if target_model.startswith("openrouter/"):
        target_model = target_model.replace("openrouter/", "", 1)
        
    try:
        response = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": target_model,
                "messages": [{"role": "user", "content": full_prompt}],
            },
        )
        response.raise_for_status()
        result = response.json()
        return result["choices"][0]["message"]["content"]
    except requests.exceptions.RequestException as e:
        if e.response is not None:
            return f"LLM Error ({target_model}): {str(e)} - {e.response.text}"
        return f"LLM Error ({target_model}): {str(e)}"
    except Exception as e:
        return f"LLM Error ({target_model}): {str(e)}"

responses = prompts.select(
    result = call_openrouter(pw.this.prompt_text, pw.this.model, pw.this.selected_row)
)

writer(responses)
pw.run()
