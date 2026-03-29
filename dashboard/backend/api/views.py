from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
import requests
import json
import subprocess
import os
import re
import time
from pathlib import Path

from .autoencoder_manager import (
    disable_detection,
    enable_detection,
    get_status as get_autoencoder_status,
    start_training,
    stop_training,
)


FLOW_CACHE = {}
AUTOENCODER_CACHE = {}
CACHE_TTL_SECONDS = 60


def _cleanup_caches():
    now = time.time()
    for cache in (FLOW_CACHE, AUTOENCODER_CACHE):
        stale_keys = [
            key for key, value in cache.items()
            if now - float(value.get("_cache_updated_at", 0)) > CACHE_TTL_SECONDS
        ]
        for key in stale_keys:
            cache.pop(key, None)


def _base_flow_status(flow: dict) -> dict:
    anomaly_score = float(flow.get("anomaly_score") or 0)
    last_info = str(flow.get("last_packet_info") or "").strip()
    is_anomaly = anomaly_score > 0 and bool(last_info)
    normalized = dict(flow)
    normalized["type"] = "flow_update"
    normalized["detector"] = normalized.get("detector") or "heuristic"
    normalized["status"] = "anomaly" if is_anomaly else "ok"
    normalized["_cache_updated_at"] = time.time()
    return normalized


def _overlay_score(score: dict) -> dict:
    normalized = dict(score)
    normalized["type"] = "autoencoder_score"
    normalized["detector"] = "autoencoder"
    normalized["_cache_updated_at"] = time.time()
    return normalized


def _merge_flow_payload(flow_key: str) -> dict | None:
    base = FLOW_CACHE.get(flow_key)
    overlay = AUTOENCODER_CACHE.get(flow_key)
    if base is None:
        return None

    engine = get_autoencoder_status().get("engine", "heuristic")
    merged = dict(base)
    if overlay:
        merged["autoencoder_error"] = overlay.get("autoencoder_error")
        merged["autoencoder_mean_error"] = overlay.get("autoencoder_mean_error")
        merged["anomalous_packet_count"] = overlay.get("anomalous_packet_count", 0)
    if engine == "autoencoder" and overlay:
        merged["anomaly_score"] = overlay.get("anomaly_score", 0)
        merged["last_packet_info"] = overlay.get("last_packet_info", merged.get("last_packet_info"))
        merged["detector"] = "autoencoder"
        merged["status"] = overlay.get("status", "ok")
        merged["packet_count"] = max(
            int(merged.get("packet_count") or 0),
            int(overlay.get("packet_count") or 0),
        )
        merged["last_packet_time"] = overlay.get("last_packet_time", merged.get("last_packet_time"))
    elif engine == "autoencoder":
        merged["anomaly_score"] = 0
        merged["last_packet_info"] = "Awaiting autoencoder score"
        merged["detector"] = "autoencoder"
        merged["status"] = "ok"
    else:
        merged["detector"] = merged.get("detector") or "heuristic"
        merged["status"] = merged.get("status") or "ok"
    merged["type"] = "flow_update"
    merged.pop("_cache_updated_at", None)
    return merged


def _broadcast_update(update: dict):
    channel_layer = get_channel_layer()
    async_to_sync(channel_layer.group_send)(
        "packets",
        {
            "type": "send_packet_update",
            "data": update,
        },
    )

class NetworkInterfacesView(APIView):
    """Returns available network interfaces from the OS."""
    def get(self, request):
        try:
            result = subprocess.run(
                ["ip", "-j", "link", "show"],
                capture_output=True, text=True, timeout=5
            )
            raw = json.loads(result.stdout or "[]")
            ifaces = []
            for iface in raw:
                name = iface.get("ifname", "")
                if not name or name == "lo":
                    continue
                link_type = iface.get("link_type", "ether")
                flags = iface.get("flags", [])
                state = iface.get("operstate", "UNKNOWN")
                ifaces.append({
                    "name": name,
                    "type": link_type,
                    "state": state,
                    "up": "UP" in flags,
                })
            ifaces.insert(0, {"name": "lo", "type": "loopback", "state": "UNKNOWN", "up": True})
            ifaces.insert(0, {"name": "any", "type": "pseudo", "state": "UP", "up": True})
            return Response(ifaces, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class PacketUpdateView(APIView):
    def post(self, request):
        data = request.data
        updates = data if isinstance(data, list) else [data]
        _cleanup_caches()

        for update in updates:
            update_type = update.get("type")
            if update_type in {"graph_edge", "port_alert", "system_stats"}:
                _broadcast_update(update)
                continue

            if update_type == "autoencoder_score":
                flow_key = update.get("flow")
                if not flow_key:
                    continue
                AUTOENCODER_CACHE[flow_key] = _overlay_score(update)
                merged = _merge_flow_payload(flow_key)
                if merged:
                    _broadcast_update(merged)
                continue

            flow_key = update.get("flow")
            if not flow_key:
                _broadcast_update(update)
                continue
            FLOW_CACHE[flow_key] = _base_flow_status(update)
            merged = _merge_flow_payload(flow_key)
            if merged:
                _broadcast_update(merged)
        return Response({"status": f"broadcasted {len(updates)} updates"}, status=status.HTTP_200_OK)

class ChatProxyView(APIView):
    def post(self, request):
        query = request.data.get("messages")
        model = request.data.get("model")
        
        if not query:
            return Response({"error": "No query provided"}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            response = requests.post(
                "http://localhost:8011",
                json={
                    "messages": query, 
                    "model": model,
                    "selected_row": request.data.get("selected_row")
                },
                timeout=30
            )
            return Response(response.json(), status=response.status_code)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

SPOOF_PROCESSES = []


def _project_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent.parent


def _active_targets_path() -> Path:
    return _project_root() / "active_targets.json"


def _whitelist_path() -> Path:
    return _project_root() / "whitelist.json"


def _resolve_capture_interface(requested: str | None) -> str:
    if requested:
        return requested
    path = _whitelist_path()
    if path.exists():
        try:
            with open(path, "r") as f:
                whitelist = json.load(f)
            interface = whitelist.get("capture_interface")
            if interface:
                return interface
        except Exception:
            pass
    return "any"


def _default_route_interface() -> str | None:
    try:
        result = subprocess.run(
            ["ip", "-j", "route", "show", "default"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        routes = json.loads(result.stdout or "[]")
        for route in routes:
            dev = route.get("dev")
            if dev:
                return dev
    except Exception:
        pass
    return None


def _resolve_spoof_interface(requested: str | None) -> str:
    interface = _resolve_capture_interface(requested)
    if interface not in {"any", "lo"}:
        return interface

    route_iface = _default_route_interface()
    if route_iface:
        return route_iface

    try:
        result = subprocess.run(
            ["ip", "-j", "link", "show"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        links = json.loads(result.stdout or "[]")
        for link in links:
            name = link.get("ifname")
            flags = set(link.get("flags", []))
            if name and name != "lo" and "UP" in flags:
                return name
    except Exception:
        pass

    return interface

class NetworkDevicesView(APIView):
    def get(self, request):
        try:
            # Get host IP first
            host_ip = None
            try:
                ip_res = subprocess.run(['ip', '-4', 'addr', 'show'], capture_output=True, text=True, timeout=2)
                match = re.search(r'inet (192\.168\.[\d\.]+)', ip_res.stdout)
                if match: host_ip = match.group(1)
            except Exception: pass

            result = subprocess.run(['sudo', '-n', 'arp-scan', '--localnet'], capture_output=True, text=True, timeout=10)
            output = result.stdout
            devices = []
            
            if host_ip:
                devices.append({'ip': host_ip, 'mac': '(This Device)'})

            for line in output.split('\n'):
                if not line.strip(): continue
                # arp-scan format: <IP>\t<MAC>\t<Manufacturer>
                match = re.search(r'^((?:[0-9]{1,3}\.){3}[0-9]{1,3})\s+([0-9a-fA-F:]+)', line)
                if match:
                    ip = match.group(1)
                    if ip != host_ip: 
                        devices.append({'ip': ip, 'mac': match.group(2)})
            
            unique_devices = []
            seen = set()
            for d in devices:
                if d['ip'] not in seen:
                    unique_devices.append(d)
                    seen.add(d['ip'])
            
            return Response(unique_devices, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class SpoofStartView(APIView):
    def post(self, request):
        targets = request.data.get('targets', [])
        gateway = request.data.get('gateway', '192.168.1.1')
        interface = _resolve_spoof_interface(request.data.get('interface'))
        
        if not targets:
            return Response({"error": "No targets provided"}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            iface_check = subprocess.run(
                ['ip', 'link', 'show', 'dev', interface],
                capture_output=True,
                text=True,
                timeout=3,
            )
            if iface_check.returncode != 0:
                return Response({"error": f"Capture interface '{interface}' not found on this host."}, status=status.HTTP_400_BAD_REQUEST)

            # Get host IP to skip spoofing itself
            host_ip = None
            try:
                ip_res = subprocess.run(['ip', '-4', 'addr', 'show'], capture_output=True, text=True, timeout=2)
                match = re.search(r'inet (192\.168\.[\d\.]+)', ip_res.stdout)
                if match: host_ip = match.group(1)
            except Exception: pass

            cleaned_targets = [
                target for target in targets
                if target and target not in {host_ip, gateway}
            ]
            if not cleaned_targets:
                return Response(
                    {"error": "No valid targets remained after excluding the host device and gateway."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Enable IP forwarding
            subprocess.run(['sudo', '-n', 'sysctl', '-w', 'net.ipv4.ip_forward=1'], check=True)
            
            global SPOOF_PROCESSES
            started_processes = []
            
            for target in cleaned_targets:
                p1 = subprocess.Popen(
                    ['sudo', '-n', 'arpspoof', '-i', interface, '-t', target, gateway],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                p2 = subprocess.Popen(
                    ['sudo', '-n', 'arpspoof', '-i', interface, '-t', gateway, target],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                started_processes.extend([p1, p2])

            if not started_processes:
                return Response({"error": "No valid targets remained after filtering host and gateway."}, status=status.HTTP_400_BAD_REQUEST)

            time.sleep(0.5)
            failed = [p for p in started_processes if p.poll() is not None]
            if failed:
                for proc in started_processes:
                    if proc.poll() is None:
                        proc.terminate()
                subprocess.run(['sudo', '-n', 'sysctl', '-w', 'net.ipv4.ip_forward=0'], check=False)
                with open(_active_targets_path(), 'w') as f:
                    json.dump([], f)
                return Response(
                    {"error": f"ARP spoofing failed to start on interface '{interface}'. Check sudo/arpspoof permissions and interface selection."},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )

            with open(_active_targets_path(), 'w') as f:
                json.dump(cleaned_targets, f)
            SPOOF_PROCESSES.extend(started_processes)
                
            return Response({"status": f"ARP spoofing started for {len(cleaned_targets)} targets", "interface": interface}, status=status.HTTP_200_OK)
        except Exception as e:
            with open(_active_targets_path(), 'w') as f:
                json.dump([], f)
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class SpoofStopView(APIView):
    def post(self, request):
        try:
            # Clear active targets
            with open(_active_targets_path(), 'w') as f:
                json.dump([], f)

            # Disable IP forwarding
            subprocess.run(['sudo', '-n', 'sysctl', '-w', 'net.ipv4.ip_forward=0'], check=False)
            # Kill arpspoof
            subprocess.run(['sudo', '-n', 'pkill', '-f', 'arpspoof'], check=False)
            
            global SPOOF_PROCESSES
            SPOOF_PROCESSES = []
            
            return Response({"status": "ARP spoofing stopped"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class WhitelistSettingsView(APIView):
    def get_whitelist_path(self):
        return _whitelist_path()

    def get(self, request):
        path = self.get_whitelist_path()
        if path.exists():
            with open(path, 'r') as f:
                return Response(json.load(f))
        return Response({"error": "whitelist.json not found"}, status=status.HTTP_404_NOT_FOUND)
        
    def post(self, request):
        path = self.get_whitelist_path()
        try:
            with open(path, 'w') as f:
                json.dump(request.data, f)
            return Response({"status": "Whitelist updated successfully"})
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class AutoencoderStatusView(APIView):
    def get(self, request):
        return Response(get_autoencoder_status(), status=status.HTTP_200_OK)


class AutoencoderTrainStartView(APIView):
    def post(self, request):
        replace_existing = bool(request.data.get("replace_existing", True))
        try:
            status_payload = start_training(replace_existing=replace_existing)
            return Response(status_payload, status=status.HTTP_200_OK)
        except RuntimeError as exc:
            return Response({"error": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as exc:
            return Response({"error": str(exc)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class AutoencoderTrainStopView(APIView):
    def post(self, request):
        try:
            status_payload = stop_training()
            return Response(status_payload, status=status.HTTP_200_OK)
        except Exception as exc:
            return Response({"error": str(exc)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class AutoencoderDetectionEnableView(APIView):
    def post(self, request):
        try:
            status_payload = enable_detection()
            return Response(status_payload, status=status.HTTP_200_OK)
        except RuntimeError as exc:
            return Response({"error": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as exc:
            return Response({"error": str(exc)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class AutoencoderDetectionDisableView(APIView):
    def post(self, request):
        try:
            status_payload = disable_detection()
            return Response(status_payload, status=status.HTTP_200_OK)
        except Exception as exc:
            return Response({"error": str(exc)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
