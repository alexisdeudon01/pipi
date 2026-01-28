import os
import time
import json
import subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

PORT = int(os.environ.get("AGENT_PORT", "8787"))
AP_IFACE_HINT = os.environ.get("AP_IFACE_HINT", "wlan0")
UP_IFACE_HINT = os.environ.get("UP_IFACE_HINT", "eth0")

def sh(cmd):
    """Run shell command and return stdout (safe)."""
    p = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return p.stdout.strip()

def iface_bytes(iface):
    try:
        rx = int(sh(f"cat /sys/class/net/{iface}/statistics/rx_bytes 2>/dev/null || echo 0"))
        tx = int(sh(f"cat /sys/class/net/{iface}/statistics/tx_bytes 2>/dev/null || echo 0"))
        return rx, tx
    except Exception:
        return 0, 0

def detect_ifaces():
    # Try to detect wlan/eth quickly
    links = sh("ip -br link").splitlines()
    names = [ln.split()[0] for ln in links if ln.strip()]
    ap = AP_IFACE_HINT if AP_IFACE_HINT in names else next((n for n in names if n.startswith("wl")), AP_IFACE_HINT)
    up = UP_IFACE_HINT if UP_IFACE_HINT in names else next((n for n in names if n.startswith("en") or n.startswith("eth")), UP_IFACE_HINT)
    return ap, up

def top_talkers(limit=10):
    # Very lightweight: count established connections by remote IP using ss (no payload)
    out = sh("ss -Hntu state established 2>/dev/null || true")
    counts = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        # local:port and peer:port usually at end
        peer = parts[-1]
        ip = peer.rsplit(":", 1)[0].strip("[]")
        counts[ip] = counts.get(ip, 0) + 1
    top = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:limit]
    return top

def leases():
    txt = sh("cat /var/lib/misc/dnsmasq.leases 2>/dev/null || true")
    items = []
    for line in txt.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            expiry, mac, ip, hostname = parts[:4]
            items.append({"hostname": hostname, "ip": ip, "mac": mac, "expiry": expiry})
    return items

def health():
    return {
        "time": int(time.time()),
        "hostname": sh("hostname"),
        "kernel": sh("uname -a"),
    }

class Handler(BaseHTTPRequestHandler):
    def _send_json(self, obj, code=200):
        data = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/health":
            return self._send_json(health())
        if u.path == "/snapshot":
            ap, up = detect_ifaces()
            rx1, tx1 = iface_bytes(ap)
            rx2, tx2 = iface_bytes(up)
            return self._send_json({
                "time": int(time.time()),
                "ifaces": {"ap": ap, "upstream": up},
                "bytes": {ap: {"rx": rx1, "tx": tx1}, up: {"rx": rx2, "tx": tx2}},
                "leases": leases(),
                "top_established_peers": top_talkers(12),
            })
        if u.path == "/stream":
            # Server-Sent Events
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()

            ap, up = detect_ifaces()
            last_ap = iface_bytes(ap)
            last_up = iface_bytes(up)
            last_t = time.time()

            try:
                while True:
                    time.sleep(1.0)
                    now = time.time()
                    rx_ap, tx_ap = iface_bytes(ap)
                    rx_up, tx_up = iface_bytes(up)
                    dt = max(0.5, now - last_t)

                    payload = {
                        "time": int(now),
                        "ifaces": {"ap": ap, "upstream": up},
                        "rates_bps": {
                            ap: {"rx": (rx_ap - last_ap[0]) / dt, "tx": (tx_ap - last_ap[1]) / dt},
                            up: {"rx": (rx_up - last_up[0]) / dt, "tx": (tx_up - last_up[1]) / dt},
                        },
                        "leases_count": len(leases()),
                        "top_established_peers": top_talkers(8),
                    }
                    data = json.dumps(payload)
                    self.wfile.write(f"event: tick\ndata: {data}\n\n".encode("utf-8"))
                    self.wfile.flush()

                    last_ap = (rx_ap, tx_ap)
                    last_up = (rx_up, tx_up)
                    last_t = now
            except BrokenPipeError:
                return
            except Exception:
                return

        self._send_json({"error":"not found"}, code=404)

def main():
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"pi-agent listening on 0.0.0.0:{PORT}")
    server.serve_forever()

if __name__ == "__main__":
    main()
