# Pi Admin Pro (Safe) — Ubuntu GUI + Pi Agent Docker

Ce projet fournit une **interface graphique (Ubuntu)** pour administrer et monitorer **ton Raspberry Pi AP** (hostapd/dnsmasq/NAT),
et un **agent côté Pi** (dans un conteneur Docker) qui remonte des **logs / métriques réseau** (sans déchiffrer le contenu HTTPS).

## Ce que ça fait (safe / admin réseau)
- Vérifie l'état: interfaces, routes, ip_forward, NAT, services hostapd/dnsmasq
- Liste clients (Nom/IP/MAC) via dnsmasq leases + ip neigh
- Bloquer / débloquer un client (MAC) via règles iptables (FORWARD)
- Remonte des métriques (débit, connexions, top IP) via l'agent Pi
- Export logs (journalctl hostapd/dnsmasq, iptables-save, leases)

## Ce que ça ne fait pas
- Pas de déchiffrement / MITM
- Pas de "lecture de communications" chiffrées (HTTPS, etc.)
  Tu verras **métadonnées** (IP, ports, volumes, états de connexions), pas le contenu.

## Architecture recommandée (simple et robuste)
- Sur le Pi: un conteneur `pi-agent` qui expose un flux SSE HTTP (port 8787) et collecte des infos système/réseau.
- Sur Ubuntu: app GUI Python (native, **pas dans Docker**) qui:
  - se connecte au Pi en SSH pour les actions admin (iptables, services)
  - lit le flux SSE de l'agent pour afficher les métriques en live

> Note: Exécuter une GUI Tkinter *dans Docker* est possible via X11, mais c'est plus fragile (Wayland/Xorg).
> La voie la plus fiable: GUI native + agent Docker sur le Pi.

---

## Pré-requis
### Ubuntu
- Python 3.10+ (ou 3.12 ok)
- `python3-venv`, `python3-tk`
- Optionnel: Docker (uniquement si tu veux builder l'image de l'agent depuis Ubuntu)

### Raspberry Pi
- Docker installé (ou installation via `scripts/install_docker_pi.sh`)
- Pi en mode AP (hostapd/dnsmasq/NAT) déjà configuré

---

## Démarrage rapide (Ubuntu)
```bash
cd pi-admin-pro-safe
./scripts/bootstrap_ubuntu.sh
./scripts/run_gui.sh
```

## Déployer l'agent sur le Pi (Ubuntu -> Pi)
1) Mets tes identifiants dans `config.json`
2) Lance:
```bash
./scripts/deploy_pi_agent.sh
```

L'agent écoutera sur: `http://<PI_IP>:8787/stream` (SSE)

---

## Configuration
Édite `config.json`:
- `pi_host`, `pi_user`, `pi_pass`
- `agent_port` (8787 par défaut)
- interfaces (auto-detect la plupart du temps)

---

## Dépannage
- Si l'agent ne démarre pas: `docker logs -f pi-agent`
- Si le flux SSE ne répond pas: `curl http://PI:8787/health`
- Si la GUI n'affiche rien: vérifie `config.json` + connectivité SSH

