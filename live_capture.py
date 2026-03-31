import subprocess
import json
import threading
import queue
import time
import sys
import os

# Field mapping consistent with PacketSchema in main.py
FIELDS = [
    "frame.time_epoch",
    "frame.protocols",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "tcp.seq",
    "tcp.flags.syn",
    "tcp.flags.ack",
    "tcp.flags.fin",
    "tcp.flags.reset",
    "tcp.flags.push",
    "tcp.flags.urg",
    "tcp.analysis.retransmission",
    "tcp.window_size_value",
    "ip.ttl",
    "ipv6.hlim",
    "ip.flags.mf",
    "ipv6.fragment",
    "frame.len",
    "tcp.len",
    "udp.length",
    "_ws.col.info",
    "tcp.payload",
    "udp.payload",
    "data.data",
]

FIELD_MAP = [
    "timestamp", "protocols", "src_ip_v4", "dst_ip_v4", "src_ip_v6", "dst_ip_v6",
    "src_port_tcp", "dst_port_tcp", "src_port_udp", "dst_port_udp",
    "tcp_seq", "tcp_flags_syn", "tcp_flags_ack", "tcp_flags_fin",
    "tcp_flags_rst", "tcp_flags_psh", "tcp_flags_urg", "tcp_retransmission",
    "tcp_window_size", "ttl_hop_limit_v4", "ttl_hop_limit_v6",
    "ip_flags_mf", "ipv6_fragment", "packet_size", "payload_len_tcp",
    "payload_len_udp", "info", "payload_hex_tcp", "payload_hex_udp", "payload_hex_data"
]

OUTPUT_FILE = "live_data/stream.jsonl"
packet_queue = queue.Queue(maxsize=100000)

def file_writer_worker():
    """Reads packets from queue and writes to JSONL file with buffering."""
    print(f"Writer thread started. Writing to {OUTPUT_FILE}...")
    
    # Ensure directory exists
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    
    # Buffering=1 means line buffered, ensuring data hits disk reasonably fast but not too slow.
    with open(OUTPUT_FILE, "a", buffering=1) as f:
        while True:
            try:
                # Get a batch if possible, or blocking get one
                packet = packet_queue.get()
                if packet is None: 
                    break
                
                # Write immediately
                f.write(json.dumps(packet) + "\n")
                packet_queue.task_done()
                
            except Exception as e:
                print(f"Writer error: {e}", file=sys.stderr)

def monitor_worker():
    """Prints queue statistics periodically."""
    while True:
        time.sleep(3)
        q_size = packet_queue.qsize()
        if q_size > 1000:
            print(f"[Monitor] Queue Size: {q_size} / {packet_queue.maxsize}")
        if q_size > 80000:
            print("[Monitor] WARNING: Queue critical! Disk I/O may be too slow.")

def main():
    # Rotate log file at startup
    if os.path.exists(OUTPUT_FILE):
        os.rename(OUTPUT_FILE, f"{OUTPUT_FILE}.bak")
    
    # Read capture interface from whitelist.json (falls back to any on Linux)
    WHITELIST_FILE = "whitelist.json"
    capture_interface = "any"
    try:
        if os.path.exists(WHITELIST_FILE):
            with open(WHITELIST_FILE, "r") as f:
                wl = json.load(f)
                capture_interface = wl.get("capture_interface", "any") or "any"
    except Exception:
        pass
    print(f"Capture interface: {capture_interface}")
    
    cmd = [
        "tshark", 
        "-i", capture_interface, 
        "-l", 
        "-T", "fields"
    ]
    for f in FIELDS:
        cmd.extend(["-e", f])

    print("Starting Sentinel Live Capture (File Streaming Mode)...")
    
    # Start writer thread
    writer = threading.Thread(target=file_writer_worker, daemon=True)
    writer.start()

    # Start monitor thread
    monitor = threading.Thread(target=monitor_worker, daemon=True)
    monitor.start()

    active_targets = []
    last_targets_check = 0.0
    last_targets_mtime = 0.0
    TARGETS_FILE = "active_targets.json"

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,
            text=True
        )

        if process.stdout is None:
            print("Error: process.stdout is None")
            return

        for line in process.stdout:
            line = line.strip()
            if not line:
                continue

            vals = line.split("\t")

            if len(vals) < len(FIELD_MAP):
                vals += [""] * (len(FIELD_MAP) - len(vals))

            row = dict(zip(FIELD_MAP, vals))

            try:
                processed = {
                    "timestamp": float(row["timestamp"]) if row["timestamp"] else 0.0,
                    "protocols": row["protocols"],
                    "src_ip": (row["src_ip_v4"] or row["src_ip_v6"] or "").split(",")[0],
                    "dst_ip": (row["dst_ip_v4"] or row["dst_ip_v6"] or "").split(",")[0],
                    "src_port": str(int((row["src_port_tcp"] or row["src_port_udp"] or "0").split(",")[0] or "0")),
                    "dst_port": str(int((row["dst_port_tcp"] or row["dst_port_udp"] or "0").split(",")[0] or "0")),
                    "packet_size": row["packet_size"],
                    "payload_len": row["payload_len_tcp"] or row["payload_len_udp"] or "0",
                    "raw_payload_hex": row["payload_hex_tcp"] or row["payload_hex_udp"] or row["payload_hex_data"] or "",
                    "info": row["info"],
                    "tcp_seq": row["tcp_seq"] or "0",
                    "tcp_flags_syn": row["tcp_flags_syn"],
                    "tcp_flags_ack": row["tcp_flags_ack"],
                    "tcp_flags_fin": row["tcp_flags_fin"],
                    "tcp_flags_rst": row["tcp_flags_rst"],
                    "tcp_flags_psh": row["tcp_flags_psh"],
                    "tcp_flags_urg": row["tcp_flags_urg"],
                    "tcp_retransmission": row["tcp_retransmission"],
                    "tcp_window_size": row["tcp_window_size"] or "0",
                    "ttl_hop_limit": row["ttl_hop_limit_v4"] or row["ttl_hop_limit_v6"],
                    "fragmentation": "Yes" if (
                        row["ip_flags_mf"] == "1" or row["ipv6_fragment"]
                    ) else "No"
                }

                # Dynamically update active targets config at most once per second
                current_time = time.time()
                if current_time - last_targets_check > 1.0:
                    last_targets_check = current_time
                    if os.path.exists(TARGETS_FILE):
                        try:
                            mtime = os.path.getmtime(TARGETS_FILE)
                            if mtime > last_targets_mtime:
                                with open(TARGETS_FILE, "r") as f:
                                    # Expected format: ["192.168.1.10", "192.168.1.15"]
                                    active_targets = json.load(f)
                                last_targets_mtime = mtime
                        except Exception:
                            pass

                # If targets exist, filter. Otherwise let everything through 
                # (Method 1 implies all traffic routing through this interface should be processed)
                if active_targets:
                    # check if the packet has src or dst in targets
                    target_ips = [t['ip'] for t in active_targets] if isinstance(active_targets[0], dict) else active_targets
                    if processed["src_ip"] not in target_ips and processed["dst_ip"] not in target_ips:
                        # Dropped by active targets filtering
                        print(f"Dropped: {processed['src_ip']} -> {processed['dst_ip']}", flush=True)
                        continue 

                print(processed, flush=True)
                try:
                    packet_queue.put_nowait(processed)
                except queue.Full:
                    # print("Queue full!", file=sys.stderr)
                    pass

            except Exception as e:
                print(f"Exception parsing row: {e}", file=sys.stderr)
                continue

        print("tshark process standard output closed.")
        process.wait()
        if process.returncode != 0:
            print(f"tshark exited with code {process.returncode}", file=sys.stderr)

    except KeyboardInterrupt:
        print("\nStopping Live Capture.")
        process.terminate()
        packet_queue.put(None) 
        writer.join(timeout=1.0)
            
    except Exception as e:
        print(f"Capture error: {e}")
        process.terminate()


if __name__ == "__main__":
    main()
