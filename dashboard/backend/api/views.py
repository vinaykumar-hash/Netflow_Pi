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
        channel_layer = get_channel_layer()
        data = request.data
        
        updates = data if isinstance(data, list) else [data]
        
        for update in updates:
            async_to_sync(channel_layer.group_send)(
                "packets",
                {
                    "type": "send_packet_update",
                    "data": update
                }
            )
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
