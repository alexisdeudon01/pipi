import json
import threading
import time
import queue
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import paramiko
import requests

APP_TITLE = "Pi Admin Pro (Safe) — GUI Ubuntu"
UI_POLL_MS = 120
MAX_TEXT_CHARS = 250_000

ui_q = queue.Queue()

def sh_quote(s: str) -> str:
    return "'" + s.replace("'", "'\"'\"'") + "'"

def ssh_run(host, user, pwd, cmd: str, sudo=False, timeout=8):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, username=user, password=pwd, timeout=timeout)
    if sudo:
        full = f"sudo -S bash -lc {sh_quote(cmd)}"
        stdin, stdout, stderr = client.exec_command(full, get_pty=True)
        stdin.write(pwd + "\n"); stdin.flush()
    else:
        stdin, stdout, stderr = client.exec_command(f"bash -lc {sh_quote(cmd)}", get_pty=True)
    out = stdout.read().decode(errors="replace")
    err = stderr.read().decode(errors="replace")
    rc = stdout.channel.recv_exit_status()
    client.close()
    return out.strip(), err.strip(), rc

def post(kind, payload):
    ui_q.put((kind, payload))

def load_cfg():
    with open("config.json","r",encoding="utf-8") as f:
        return json.load(f)

def parse_leases(leases_text: str):
    items = []
    for line in leases_text.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            expiry, mac, ip, hostname = parts[:4]
            items.append((hostname, ip, mac, expiry))
    return items

def parse_arp(neigh_text: str):
    mapping = {}
    for line in neigh_text.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[0].count(".") == 3:
            ip = parts[0]
            if "lladdr" in parts:
                idx = parts.index("lladdr")
                if idx + 1 < len(parts):
                    mapping[ip] = parts[idx+1]
    return mapping

class App:
    def __init__(self, root):
        self.root = root
        root.title(APP_TITLE)
        root.configure(bg="#111111")
        style = ttk.Style()
        try: style.theme_use("clam")
        except: pass
        style.configure(".", background="#111111", foreground="#eaeaea", fieldbackground="#1a1a1a")
        style.configure("TFrame", background="#111111")
        style.configure("TLabel", background="#111111", foreground="#eaeaea")
        style.configure("TEntry", fieldbackground="#1a1a1a", foreground="#eaeaea")
        style.configure("TProgressbar", troughcolor="#1a1a1a", background="#3a7afe")
        style.configure("TNotebook.Tab", padding=(10,6))

        self.cfg = load_cfg()
        self.host = tk.StringVar(value=self.cfg["pi_host"])
        self.user = tk.StringVar(value=self.cfg["pi_user"])
        self.pwd  = tk.StringVar(value=self.cfg["pi_pass"])
        self.agent_port = tk.IntVar(value=self.cfg.get("agent_port",8787))

        self.progress = ttk.Progressbar(root, mode="indeterminate")
        self.progress.pack(fill="x", padx=10, pady=6)

        nb = ttk.Notebook(root)
        nb.pack(fill="both", expand=True, padx=10, pady=6)

        self.tab_ctrl = ttk.Frame(nb, padding=10)
        self.tab_clients = ttk.Frame(nb, padding=10)
        self.tab_logs = ttk.Frame(nb, padding=10)
        self.tab_live = ttk.Frame(nb, padding=10)

        nb.add(self.tab_ctrl, text="Contrôle")
        nb.add(self.tab_clients, text="Appareils")
        nb.add(self.tab_live, text="Live")
        nb.add(self.tab_logs, text="Logs")

        self._build_ctrl()
        self._build_clients()
        self._build_live()
        self._build_logs()

        self.status = tk.StringVar(value="Prêt")
        ttk.Label(root, textvariable=self.status).pack(anchor="w", padx=12, pady=4)

        self.sse_thread = None
        self.sse_stop = threading.Event()
        self.rates = []

        self.root.after(UI_POLL_MS, self._pump)

    def _build_ctrl(self):
        frm = self.tab_ctrl

        row = ttk.Frame(frm); row.pack(fill="x", pady=4)
        ttk.Label(row, text="Pi IP").pack(side="left")
        ttk.Entry(row, textvariable=self.host, width=16).pack(side="left", padx=6)
        ttk.Label(row, text="User").pack(side="left")
        ttk.Entry(row, textvariable=self.user, width=10).pack(side="left", padx=6)
        ttk.Label(row, text="Pass").pack(side="left")
        ttk.Entry(row, textvariable=self.pwd, width=16, show="*").pack(side="left", padx=6)
        ttk.Label(row, text="Agent port").pack(side="left")
        ttk.Entry(row, textvariable=self.agent_port, width=6).pack(side="left", padx=6)

        btns = ttk.Frame(frm); btns.pack(fill="x", pady=6)
        ttk.Button(btns, text="🔍 Vérifier tout", command=lambda: self._thread(self.verify_all)).pack(side="left", padx=4)
        ttk.Button(btns, text="🧾 Export logs", command=lambda: self._thread(self.export_logs)).pack(side="left", padx=4)
        ttk.Button(btns, text="📦 Backup", command=lambda: self._thread(self.backup_all)).pack(side="left", padx=4)
        ttk.Button(btns, text="🔄 Normal", command=lambda: self._thread(self.restore_normal)).pack(side="left", padx=4)

        ttk.Separator(frm).pack(fill="x", pady=6)

        agent = ttk.Frame(frm); agent.pack(fill="x", pady=4)
        ttk.Button(agent, text="▶ Start Live (SSE)", command=lambda: self._thread(self.start_live)).pack(side="left", padx=4)
        ttk.Button(agent, text="⏹ Stop Live", command=self.stop_live).pack(side="left", padx=4)
        ttk.Button(agent, text="🩺 Agent health", command=lambda: self._thread(self.agent_health)).pack(side="left", padx=4)

    def _build_clients(self):
        frm = self.tab_clients
        top = ttk.Frame(frm); top.pack(fill="x", pady=4)
        ttk.Button(top, text="🔄 Rafraîchir", command=lambda: self._thread(self.refresh_clients)).pack(side="left", padx=4)
        ttk.Button(top, text="🚫 Bloquer sélection", command=lambda: self._thread(self.block_selected)).pack(side="left", padx=4)
        ttk.Button(top, text="✅ Débloquer sélection", command=lambda: self._thread(self.unblock_selected)).pack(side="left", padx=4)

        cols = ("hostname","ip","mac","expiry")
        self.tree = ttk.Treeview(frm, columns=cols, show="headings", height=10)
        for c, t, w in [("hostname","Nom",180),("ip","IP",120),("mac","MAC",170),("expiry","Expiry",120)]:
            self.tree.heading(c, text=t); self.tree.column(c, width=w)
        self.tree.pack(fill="both", expand=True, pady=6)

    def _build_live(self):
        frm = self.tab_live
        self.canvas = tk.Canvas(frm, height=240, bg="#0f0f0f", highlightthickness=1, highlightbackground="#2a2a2a")
        self.canvas.pack(fill="both", expand=True, pady=6)
        self.live_text = tk.Text(frm, height=8, bg="#0f0f0f", fg="#eaeaea", insertbackground="#eaeaea")
        self.live_text.pack(fill="both", expand=False)

    def _build_logs(self):
        self.log = tk.Text(self.tab_logs, bg="#0f0f0f", fg="#eaeaea", insertbackground="#eaeaea")
        self.log.pack(fill="both", expand=True)

    def _thread(self, fn):
        threading.Thread(target=fn, daemon=True).start()

    def _log(self, msg):
        post("log", msg)

    def _set_status(self, msg):
        post("status", msg)

    def verify_all(self):
        self.progress.start()
        self._log("🔍 Vérification complète…")
        try:
            host, user, pwd = self.host.get().strip(), self.user.get().strip(), self.pwd.get().strip()
            checks = [
                ("Interfaces", "ip -br a", True),
                ("Routes", "ip route", True),
                ("IP forward", "sysctl net.ipv4.ip_forward", True),
                ("NAT", "iptables -t nat -S | grep MASQUERADE || echo 'NO NAT'", True),
                ("hostapd", "systemctl is-active hostapd || true", True),
                ("dnsmasq", "systemctl is-active dnsmasq || true", True),
                ("Leases", "cat /var/lib/misc/dnsmasq.leases 2>/dev/null || echo 'Aucun client'", True),
            ]
            for name, cmd, s in checks:
                out, err, rc = ssh_run(host, user, pwd, cmd, sudo=s)
                if err and rc != 0:
                    self._log(f"⚠️ {name}: {err}")
                else:
                    self._log(f"✅ {name}:\n{out}\n")
            self._set_status("OK")
        except Exception as e:
            self._log(f"❌ verify_all: {e}")
            self._set_status("Erreur")
        finally:
            self.progress.stop()

    def refresh_clients(self):
        self.progress.start()
        self._log("📶 Refresh clients…")
        try:
            host, user, pwd = self.host.get().strip(), self.user.get().strip(), self.pwd.get().strip()
            leases, _, _ = ssh_run(host, user, pwd, "cat /var/lib/misc/dnsmasq.leases 2>/dev/null || true", sudo=True)
            neigh, _, _  = ssh_run(host, user, pwd, "ip neigh show", sudo=True)
            items = parse_leases(leases)
            arp = parse_arp(neigh)

            self.tree.delete(*self.tree.get_children())
            for hostname, ip, mac, expiry in items:
                if not mac:
                    mac = arp.get(ip,"")
                self.tree.insert("", "end", values=(hostname, ip, mac, expiry))
            self._set_status(f"Clients: {len(items)}")
        except Exception as e:
            self._log(f"❌ refresh_clients: {e}")
            self._set_status("Erreur")
        finally:
            self.progress.stop()

    def _selected(self):
        sel = self.tree.selection()
        if not sel: return None
        return self.tree.item(sel[0], "values")

    def block_selected(self):
        c = self._selected()
        if not c:
            messagebox.showinfo("Info","Sélectionne un appareil.")
            return
        hostname, ip, mac, expiry = c
        if not mac:
            messagebox.showerror("Erreur","MAC vide.")
            return
        self.progress.start()
        try:
            host, user, pwd = self.host.get().strip(), self.user.get().strip(), self.pwd.get().strip()
            ssh_run(host, user, pwd, f"iptables -I FORWARD -m mac --mac-source {mac} -j DROP", sudo=True)
            self._log(f"🚫 Bloqué: {hostname} {ip} {mac}")
            self._set_status("Bloqué")
        except Exception as e:
            self._log(f"❌ block: {e}")
            self._set_status("Erreur")
        finally:
            self.progress.stop()

    def unblock_selected(self):
        c = self._selected()
        if not c:
            messagebox.showinfo("Info","Sélectionne un appareil.")
            return
        hostname, ip, mac, expiry = c
        if not mac:
            messagebox.showerror("Erreur","MAC vide.")
            return
        self.progress.start()
        try:
            host, user, pwd = self.host.get().strip(), self.user.get().strip(), self.pwd.get().strip()
            ssh_run(host, user, pwd, f"iptables -D FORWARD -m mac --mac-source {mac} -j DROP", sudo=True)
            self._log(f"✅ Débloqué: {hostname} {ip} {mac} (si règle existait)")
            self._set_status("Débloqué")
        except Exception as e:
            self._log(f"❌ unblock: {e}")
            self._set_status("Erreur")
        finally:
            self.progress.stop()

    def export_logs(self):
        self.progress.start()
        self._log("🧾 Collect logs…")
        try:
            host, user, pwd = self.host.get().strip(), self.user.get().strip(), self.pwd.get().strip()
            cmd = r"""
echo "===== DATE ====="; date
echo "===== IP -BR A ====="; ip -br a
echo "===== IP ROUTE ====="; ip route
echo "===== SYSCTL ====="; sysctl net.ipv4.ip_forward
echo "===== HOSTAPD STATUS ====="; systemctl status hostapd --no-pager || true
echo "===== DNSMASQ STATUS ====="; systemctl status dnsmasq --no-pager || true
echo "===== JOURNAL hostapd (120) ====="; journalctl -u hostapd -n 120 --no-pager || true
echo "===== JOURNAL dnsmasq (120) ====="; journalctl -u dnsmasq -n 120 --no-pager || true
echo "===== IPTABLES-SAVE ====="; iptables-save || true
echo "===== LEASES ====="; cat /var/lib/misc/dnsmasq.leases 2>/dev/null || true
"""
            out, _, _ = ssh_run(host, user, pwd, cmd, sudo=True)
            path = filedialog.asksaveasfilename(title="Enregistrer logs", defaultextension=".txt",
                                                filetypes=[("Text","*.txt")])
            if path:
                with open(path,"w",encoding="utf-8") as f: f.write(out)
                self._log(f"✅ Logs: {path}")
                self._set_status("Logs OK")
        except Exception as e:
            self._log(f"❌ export_logs: {e}")
            self._set_status("Erreur")
        finally:
            self.progress.stop()

    def backup_all(self):
        self.progress.start()
        self._log("📦 Backup…")
        try:
            host, user, pwd = self.host.get().strip(), self.user.get().strip(), self.pwd.get().strip()
            remote = f"/home/{user}/net_backup_{int(time.time())}.tar.gz"
            cmd = f"""
tar czf {remote} /etc/hostapd /etc/dnsmasq* /etc/dhcpcd.conf /etc/sysctl.conf /etc/default/hostapd 2>/dev/null || true
iptables-save > /home/{user}/iptables.backup.txt || true
echo "{remote}"
"""
            out, _, _ = ssh_run(host, user, pwd, cmd, sudo=True)
            self._log(f"✅ Backup Pi: {out}")
            self._set_status("Backup OK")
        except Exception as e:
            self._log(f"❌ backup_all: {e}")
            self._set_status("Erreur")
        finally:
            self.progress.stop()

    def restore_normal(self):
        if not messagebox.askyesno("Confirm","Revenir réseau NORMAL (AP OFF, NAT OFF) ?"):
            return
        self.progress.start()
        self._log("🔄 Restore normal…")
        try:
            host, user, pwd = self.host.get().strip(), self.user.get().strip(), self.pwd.get().strip()
            cmd = """
systemctl stop hostapd dnsmasq || true
iptables -F || true
iptables -t nat -F || true
sysctl -w net.ipv4.ip_forward=0 >/dev/null || true
dhclient -r eth0 || true
dhclient eth0 || true
"""
            ssh_run(host, user, pwd, cmd, sudo=True)
            self._log("✅ Normal.")
            self._set_status("Normal")
        except Exception as e:
            self._log(f"❌ restore_normal: {e}")
            self._set_status("Erreur")
        finally:
            self.progress.stop()

    # ===== Live agent =====
    def agent_url(self, path):
        return f"http://{self.host.get().strip()}:{self.agent_port.get()}{path}"

    def agent_health(self):
        self.progress.start()
        try:
            r = requests.get(self.agent_url("/health"), timeout=3)
            self._log(f"🩺 Agent health: {r.status_code} {r.text}")
            self._set_status("Agent OK" if r.ok else "Agent NOK")
        except Exception as e:
            self._log(f"❌ Agent health: {e}")
            self._set_status("Agent NOK")
        finally:
            self.progress.stop()

    def start_live(self):
        if self.sse_thread and self.sse_thread.is_alive():
            self._log("ℹ️ Live déjà lancé.")
            return
        self._log("▶ Live start…")
        self.sse_stop.clear()
        self.sse_thread = threading.Thread(target=self._sse_loop, daemon=True)
        self.sse_thread.start()

    def stop_live(self):
        self.sse_stop.set()
        self._log("⏹ Live stop demandé.")

    def _sse_loop(self):
        url = self.agent_url("/stream")
        try:
            with requests.get(url, stream=True, timeout=5) as r:
                r.raise_for_status()
                event = None
                data = ""
                for raw in r.iter_lines(decode_unicode=True):
                    if self.sse_stop.is_set():
                        break
                    if raw is None: 
                        continue
                    line = raw.strip()
                    if line.startswith("event:"):
                        event = line.split(":",1)[1].strip()
                    elif line.startswith("data:"):
                        data = line.split(":",1)[1].strip()
                    elif line == "":
                        # dispatch
                        if event == "tick" and data:
                            post("live", data)
                        event = None; data = ""
        except Exception as e:
            post("log", f"❌ Live SSE: {e}")
            post("status", "Live OFF")

    def _draw_rates(self, rates):
        # rates is dict: iface->rx/tx
        c = self.canvas
        w = c.winfo_width(); h = c.winfo_height()
        c.delete("all")
        c.create_rectangle(0,0,w,h, fill="#0f0f0f", outline="#2a2a2a")
        # keep last 60 points of upstream rx
        # data structure self.rates: list of (ts, rx_up, tx_up)
        if len(self.rates) < 2:
            c.create_text(w//2, h//2, text="En attente de données…", fill="#eaeaea")
            return
        maxv = max(max(rx,tx) for _, rx, tx in self.rates)
        maxv = max(1.0, maxv)
        n = len(self.rates)
        step = max(1, (w-20)//max(1,n-1))
        def y(v): return h - int((v/maxv)*(h-30)) - 10
        x = 10
        pts_rx = []
        pts_tx = []
        for _, rx, tx in self.rates:
            pts_rx.append((x, y(rx)))
            pts_tx.append((x, y(tx)))
            x += step
        c.create_text(10,10, anchor="nw", text=f"Max ~ {maxv/1024:.1f} KB/s", fill="#eaeaea")
        # draw lines (blue/orange)
        for i in range(1,len(pts_rx)):
            c.create_line(*pts_rx[i-1], *pts_rx[i], fill="#3a7afe", width=2)
            c.create_line(*pts_tx[i-1], *pts_tx[i], fill="#f4a261", width=2)

    def _pump(self):
        try:
            while True:
                kind, payload = ui_q.get_nowait()
                if kind == "log":
                    self.log.insert(tk.END, payload+"\n")
                    self.log.see(tk.END)
                    if len(self.log.get("1.0", tk.END)) > MAX_TEXT_CHARS:
                        self.log.delete("1.0","1.0+50000c")
                        self.log.insert(tk.END,"\n[INFO] Log tronqué (limite mémoire UI)\n")
                elif kind == "status":
                    self.status.set(payload)
                elif kind == "live":
                    # parse json
                    import json
                    obj = json.loads(payload)
                    # pick upstream iface and show rx/tx
                    up = obj["ifaces"]["upstream"]
                    rx = obj["rates_bps"][up]["rx"]
                    tx = obj["rates_bps"][up]["tx"]
                    self.rates.append((obj["time"], rx, tx))
                    if len(self.rates) > 60:
                        self.rates = self.rates[-60:]
                    self._draw_rates(obj["rates_bps"])
                    self.live_text.delete("1.0", tk.END)
                    self.live_text.insert(tk.END, json.dumps(obj, indent=2))
                    self.status.set("Live ON")
        except queue.Empty:
            pass
        self.root.after(UI_POLL_MS, self._pump)

def main():
    root = tk.Tk()
    app = App(root)
    root.mainloop()

if __name__ == "__main__":
    main()
