import subprocess
import time
import os
import signal
import sys
import shutil

def start():
    root = os.path.dirname(os.path.abspath(__file__))
    venv_python = f"{root}/.venv/bin/python"
    daphne = f"{root}/.venv/bin/daphne"

    try:
        subprocess.run(
            [venv_python, "-c", "import sys; print(sys.executable)"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.CalledProcessError):
        print("\n[CRITICAL] Sentinel virtualenv is not healthy.")
        print(f"Expected working interpreter: {venv_python}")
        print("Rebuild the environment with: uv venv --python /usr/bin/python3.13 .venv && uv sync --python /usr/bin/python3.13")
        sys.exit(1)
    
    # 1. Cleanup
    print("--- Sentinel Orchestrator ---")
    print("Stopping existing services...")
    subprocess.run("lsof -ti:5173,8000,8011 | xargs kill -9", shell=True, stderr=subprocess.DEVNULL)
    subprocess.run("pkill -f live_capture.py", shell=True, stderr=subprocess.DEVNULL)
    subprocess.run("pkill -f tshark", shell=True, stderr=subprocess.DEVNULL)
    subprocess.run("sudo pkill -f arpspoof", shell=True, stderr=subprocess.DEVNULL)
    
    # Reset live data to avoid processing old packets
    live_data = f"{root}/docs/live_packets.json"
    if os.path.exists(live_data):
        print("Clearing old capture data...")
        os.remove(live_data)
    os.makedirs(f"{root}/docs", exist_ok=True)
    open(live_data, 'a').close()

    time.sleep(2)

    # 2. Start Django
    print("Launching Django Backend (Port 8000)...")
    django_proc = subprocess.Popen(
        [daphne, "-b", "0.0.0.0", "-p", "8000", "backend.asgi:application"],
        cwd=f"{root}/dashboard/backend",
        stdout=open(f"{root}/django.log", "w"),
        stderr=subprocess.STDOUT
    )

    # 3. Start Live Capture
    tshark_path = shutil.which("tshark")
    if not tshark_path and os.path.exists("/usr/bin/tshark"):
        tshark_path = "/usr/bin/tshark"
        
    if tshark_path:
        print("Launching Live Capture (tshark)...")
        capture_proc = subprocess.Popen(
            [venv_python, f"{root}/live_capture.py"],
            stdout=open(f"{root}/capture.log", "w"),
            stderr=subprocess.STDOUT
        )
    else:
        print("Warning: tshark not found. Skipping Live Capture.")
        capture_proc = None

    # 4. Start Pathway Engine
    print("Launching Pathway Engine (Port 8011)...")
    time.sleep(5) 
    # Use the original user's huggingface cache to avoid re-downloading
    engine_env = {
        **os.environ, 
        "RUST_BACKTRACE": "1",
        "HF_HOME": "/home/vinay/.cache/huggingface"
    }
    pathway_proc = subprocess.Popen(
        [venv_python, f"{root}/main.py"],
        stdout=open(f"{root}/pathway.log", "w"),
        stderr=subprocess.STDOUT,
        env=engine_env
    )

    # 5. Start Frontend
    npm_path = shutil.which("npm")
    if not npm_path:
        print("\n[CRITICAL] npm is not installed or not available on PATH.")
        print("Install Node.js/npm, then rerun start_sentinel.py.")
        for proc in (django_proc, pathway_proc, capture_proc, monitor_proc if 'monitor_proc' in locals() else None):
            if proc:
                proc.terminate()
        sys.exit(1)

    print("Launching React Dashboard (Port 5173)...")
    vite_proc = subprocess.Popen(
        [npm_path, "run", "dev", "--", "--host", "0.0.0.0"],
        cwd=f"{root}/dashboard/frontend",
        stdout=open(f"{root}/vite.log", "w"),
        stderr=subprocess.STDOUT
    )

    print("\n[SUCCESS] Sentinel is fully operational!")
    print(f"URL: http://localhost:5173")
    print(f"Logs: tail -f {root}/*.log")
    print("Press Ctrl+C to stop all services.")
    
    procs = {
        "Django": django_proc,
        "Pathway": pathway_proc,
        "Vite": vite_proc
    }

    # 6. Start System Monitor
    print("Launching System Monitor...")
    monitor_proc = subprocess.Popen(
        [venv_python, f"{root}/system_monitor.py"],
        stdout=open(f"{root}/monitor.log", "w"),
        stderr=subprocess.STDOUT
    )
    procs["SystemMonitor"] = monitor_proc

    if capture_proc:
        procs["Capture"] = capture_proc

    try:
        while True:
            time.sleep(2)
            for name, p in procs.items():
                if p.poll() is not None:
                    print(f"\n[CRITICAL] {name} service stopped unexpectedly!")
                    sys.exit(1)
    except KeyboardInterrupt:
        print("\nShutting down Sentinel...")
        for name, p in procs.items():
            print(f"Stopping {name}...")
            p.terminate()
        print("All services stopped.")

if __name__ == "__main__":
    start()
