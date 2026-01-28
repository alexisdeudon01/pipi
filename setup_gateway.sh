#!/bin/bash

# Couleurs pour les logs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Fonctions de logging
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCÈS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[ATTENTION]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERREUR]${NC} $1"
    exit 1 # Arrête le script en cas d'erreur critique
}

# Configuration
PI_IP="192.168.178.67"
PI_USER="pi"
SSH_CMD="ssh ${PI_USER}@${PI_IP}"

log_info "-------------------------------------------------------"
log_info "Raspberry Pi 5 Gateway Setup Script"
log_info "Target: ${PI_IP}"
log_info "-------------------------------------------------------"

# 0. Persistence & IP Forwarding
setup_persistence() {
    log_info "Démarrage de la configuration de la persistance..."
    ssh ${PI_USER}@${PI_IP} "sudo /usr/bin/sed -i 's/^#\\?net.ipv4.ip_forward=.*/net.ipv4.ip_forward=1/' /etc/sysctl.conf" || log_error "Échec de la modification de /etc/sysctl.conf"
    ssh ${PI_USER}@${PI_IP} "sudo /usr/bin/grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf || echo 'net.ipv4.ip_forward=1' | sudo /usr/bin/tee -a /etc/sysctl.conf >/dev/null" || log_error "Échec de l'ajout de net.ipv4.ip_forward=1"
    ssh ${PI_USER}@${PI_IP} "sudo /sbin/sysctl -p" || log_error "Échec de l'application des paramètres sysctl" # Utilisation du chemin absolu pour sysctl
    log_success "IP Forwarding est $( ssh ${PI_USER}@${PI_IP} '/sbin/sysctl net.ipv4.ip_forward' )"
}

# 1. Routed AP (Evil Twin Style)
setup_routed_ap() {
    local MANUAL_SSID="$1"
    log_info "Démarrage de la configuration du point d'accès routé (Evil Twin)..."

    # Assurer que NetworkManager est en cours d'exécution
    log_info "Vérification et démarrage de NetworkManager..."
    ssh ${PI_USER}@${PI_IP} "sudo /usr/bin/systemctl is-active --quiet NetworkManager || sudo /usr/bin/systemctl start NetworkManager" || log_error "Échec du démarrage de NetworkManager"
    ssh ${PI_USER}@${PI_IP} "sudo /usr/bin/systemctl enable NetworkManager" || log_error "Échec de l'activation de NetworkManager"
    log_success "NetworkManager est $( ssh ${PI_USER}@${PI_IP} '/usr/bin/systemctl is-active NetworkManager' )"

    # Assurer que wlan0 est géré par NetworkManager
    log_info "Assurer que wlan0 est géré par NetworkManager..."
    ssh ${PI_USER}@${PI_IP} "sudo /usr/bin/nmcli device set wlan0 managed yes" || log_error "Échec de la gestion de wlan0 par NetworkManager"
    ssh ${PI_USER}@${PI_IP} "sudo /usr/bin/nmcli device reapply wlan0" # Tente de réappliquer la configuration par défaut si nécessaire
    log_success "wlan0 est $( ssh ${PI_USER}@${PI_IP} '/usr/bin/nmcli device show wlan0 | grep GENERAL.STATE' )"
    
    TARGET_SSID=""
    if [ -n "$MANUAL_SSID" ]; then
        TARGET_SSID="$MANUAL_SSID"
        log_info "SSID cible défini manuellement : $TARGET_SSID"
    else
        # Detect current SSID
        CURRENT_SSID=$(ssh ${PI_USER}@${PI_IP} "/usr/bin/nmcli -t -f active,ssid dev wifi | grep '^yes' | cut -d: -f2")
        
        if [ -z "$CURRENT_SSID" ]; then
            log_error "wlan0 n'est pas connecté à un réseau Wi-Fi et aucun SSID n'a été spécifié manuellement. Veuillez connecter wlan0 à un réseau avant d'exécuter ce script pour le mode Evil Twin, ou spécifiez le SSID manuellement. Utilisation : ./setup_gateway.sh ap [SSID_cible]"
        fi
        TARGET_SSID="$CURRENT_SSID"
        log_info "SSID cible détecté : $TARGET_SSID"
    fi

    # Demander le mot de passe du hotspot
    read -s -p "Entrez le mot de passe pour le hotspot '$TARGET_SSID': " HOTSPOT_PASS
    echo

    # Vérifier si la connexion EvilTwin existe déjà et la supprimer si c'est le cas
    if ssh ${PI_USER}@${PI_IP} "/usr/bin/nmcli con show EvilTwin &>/dev/null"; then
        log_warning "Connexion 'EvilTwin' existante détectée. Suppression et recréation."
        ssh ${PI_USER}@${PI_IP} "sudo /usr/bin/nmcli con delete EvilTwin" || log_error "Échec de la suppression de la connexion EvilTwin existante"
    fi

    # Configure Hotspot
    NMCLI_ADD_CMD="sudo /usr/bin/nmcli con add type wifi ifname wlan0 mode ap con-name EvilTwin ssid \"${TARGET_SSID}\" wifi-sec.key-mgmt wpa-psk wifi-sec.psk \"${HOTSPOT_PASS}\" autoconnect yes"
    ssh ${PI_USER}@${PI_IP} "${NMCLI_ADD_CMD}" || log_error "Échec de la création du hotspot EvilTwin"
    ssh ${PI_USER}@${PI_IP} "sudo /usr/bin/nmcli con modify EvilTwin 802-11-wireless.band bg ipv4.method shared" || log_error "Échec de la modification de la connexion EvilTwin"
    ssh ${PI_USER}@${PI_IP} "sudo /usr/bin/nmcli con up EvilTwin" || log_error "Échec de l'activation de la connexion EvilTwin"
    log_success "Hotspot EvilTwin '${TARGET_SSID}' configuré et activé."

    # NAT Configuration
    log_info "Configuration du NAT iptables..."
    ssh ${PI_USER}@${PI_IP} "sudo /usr/sbin/iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE" || log_error "Échec de l'ajout de la règle MASQUERADE"
    ssh ${PI_USER}@${PI_IP} "sudo /usr/sbin/iptables -A FORWARD -i wlan0 -o eth0 -j ACCEPT" || log_error "Échec de l'ajout de la règle FORWARD wlan0->eth0"
    ssh ${PI_USER}@${PI_IP} "sudo /usr/sbin/iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT" || log_error "Échec de l'ajout de la règle FORWARD RELATED,ESTABLISHED"
    log_success "Règles NAT iptables configurées."

    # Log
    log_info "--- État du point d'accès ---"
    ssh ${PI_USER}@${PI_IP} "/usr/bin/nmcli device status | grep wlan0"
    log_info "--- Règles NAT actives ---"
    ssh ${PI_USER}@${PI_IP} "sudo /usr/sbin/iptables -t nat -L POSTROUTING -v -n"

    # Test
    log_info "Exécution du test : Vérification du transfert de paquets..."
    ssh ${PI_USER}@${PI_IP} "sudo /usr/sbin/timeout 5 /usr/sbin/tcpdump -i eth0 -n icmp and src net 10.42.0.0/24 &"
    log_info "Commande de test initiée. Si des clients se connectent à '$TARGET_SSID', vous devriez voir du trafic sur eth0."
}

restore_routed_ap() {
    log_info "Restauration du client réseau standard (AP routé)..."
    ssh ${PI_USER}@${PI_IP} "sudo /usr/bin/nmcli con down EvilTwin && sudo /usr/bin/nmcli con delete EvilTwin" || log_warning "Échec de la suppression de la connexion EvilTwin (peut-être déjà supprimée)"
    ssh ${PI_USER}@${PI_IP} "while sudo /usr/sbin/iptables -t nat -C POSTROUTING -o eth0 -j MASQUERADE 2>/dev/null; do sudo /usr/sbin/iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE; done; while sudo /usr/sbin/iptables -C FORWARD -i wlan0 -o eth0 -j ACCEPT 2>/dev/null; do sudo /usr/sbin/iptables -D FORWARD -i wlan0 -o eth0 -j ACCEPT; done; while sudo /usr/sbin/iptables -C FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; do sudo /usr/sbin/iptables -D FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT; done" || log_warning "Échec de la suppression des règles iptables (peut-être déjà supprimées)"
    log_success "Connexion EvilTwin supprimée et règles iptables retirées."
}

# 2. Transparent Bridge (Layer 2)
setup_bridge() {
    log_info "Démarrage de la configuration du pont transparent (Layer 2)..."
    
    # Stop NetworkManager for wlan0/eth0 to avoid conflicts
    log_info "Arrêt de NetworkManager pour éviter les conflits sur wlan0/eth0..."
    ssh ${PI_USER}@${PI_IP} "sudo /usr/bin/systemctl stop NetworkManager" || log_warning "Échec de l'arrêt de NetworkManager (peut-être déjà arrêté)"

    # Create systemd-networkd config
    log_info "Création des fichiers de configuration systemd-networkd pour le pont br0..."
    ssh ${PI_USER}@${PI_IP} "sudo /usr/bin/tee /etc/systemd/network/25-br0.netdev <<EOF
[NetDev]
Name=br0
Kind=bridge
EOF" || log_error "Échec de la création de 25-br0.netdev"

    ssh ${PI_USER}@${PI_IP} "sudo /usr/bin/tee /etc/systemd/network/25-br0.network <<EOF
[Match]
Name=br0
[Network]
DHCP=yes
EOF" || log_error "Échec de la création de 25-br0.network"

    ssh ${PI_USER}@${PI_IP} "sudo /usr/bin/tee /etc/systemd/network/25-eth0.network <<EOF
[Match]
Name=eth0
[Network]
Bridge=br0
EOF" || log_error "Échec de la création de 25-eth0.network"

    ssh ${PI_USER}@${PI_IP} "sudo /usr/bin/tee /etc/systemd/network/25-wlan0.network <<EOF
[Match]
Name=wlan0
[Network]
Bridge=br0
EOF" || log_error "Échec de la création de 25-wlan0.network"

    log_info "Activation et démarrage de systemd-networkd..."
    ssh ${PI_USER}@${PI_IP} "sudo /usr/bin/systemctl enable --now systemd-networkd" || log_error "Échec de l'activation/démarrage de systemd-networkd"
    log_success "Pont transparent br0 configuré et activé."
    
    # Log
    log_info "--- Table du pont ---"
    ssh ${PI_USER}@${PI_IP} "/usr/sbin/brctl show br0 || /usr/sbin/bridge link"
    log_info "--- États des interfaces ---"
    ssh ${PI_USER}@${PI_IP} "/usr/bin/networkctl status br0"

    # Test
    log_info "Exécution du test : Vérification de l'invisibilité du pont..."
    ssh ${PI_USER}@${PI_IP} "/usr/sbin/ip addr show br0"
    log_info "Si br0 n'a pas d'IP ou la même IP que eth0 précédemment, le pont est transparent."
}

restore_bridge() {
    log_info "Restauration depuis le pont transparent..."
    ssh ${PI_USER}@${PI_IP} "sudo /usr/bin/systemctl disable --now systemd-networkd" || log_warning "Échec de la désactivation de systemd-networkd (peut-être déjà désactivé)"
    ssh ${PI_USER}@${PI_IP} "sudo /usr/bin/rm -f /etc/systemd/network/25-br0.* /etc/systemd/network/25-eth0.network /etc/systemd/network/25-wlan0.network" || log_error "Échec de la suppression des fichiers de configuration du pont"
    ssh ${PI_USER}@${PI_IP} "sudo /usr/bin/systemctl start NetworkManager" || log_error "Échec du redémarrage de NetworkManager"
    log_success "systemd-networkd désactivé et NetworkManager redémarré. Pont transparent restauré."
}

# 3. DNS Interceptor (The Sinkhole)
setup_dns_interceptor() {
    log_info "Démarrage de la configuration de l'intercepteur DNS (The Sinkhole)..."
    
    # Redirect port 53 to local Pi-hole (assuming it's on 127.0.0.1 or Pi's IP)
    log_info "Redirection du trafic DNS (port 53) vers l'instance locale (127.0.0.1:53)..."
    ssh ${PI_USER}@${PI_IP} "sudo /usr/sbin/iptables -t nat -A PREROUTING -i wlan0 -p udp --dport 53 -j DNAT --to-destination 127.0.0.1:53" || log_error "Échec de la redirection UDP DNS"
    ssh ${PI_USER}@${PI_IP} "sudo /usr/sbin/iptables -t nat -A PREROUTING -i wlan0 -p tcp --dport 53 -j DNAT --to-destination 127.0.0.1:53" || log_error "Échec de la redirection TCP DNS"
    log_success "Règles de redirection DNS configurées."
    
    # Log
    log_info "--- Suivi des logs DNS (3 secondes) ---"
    ssh ${PI_USER}@${PI_IP} "sudo /usr/bin/timeout 3 /usr/bin/tail -f /var/log/pihole.log || sudo /usr/bin/timeout 3 /usr/bin/tail -f /var/log/syslog | grep dnsmasq"

    # Test
    log_info "Exécution du test : Vérification de la redirection DNS..."
    ssh ${PI_USER}@${PI_IP} "/usr/bin/dig @127.0.0.1 doubleclick.net +short"
    log_info "Si le résultat est 0.0.0.0 ou bloqué, le sinkhole est actif."
}

restore_dns_interceptor() {
    log_info "Restauration des paramètres DNS..."
    ssh ${PI_USER}@${PI_IP} "sudo /usr/sbin/iptables -t nat -D PREROUTING -i wlan0 -p udp --dport 53 -j DNAT --to-destination 127.0.0.1:53" || log_warning "Échec de la suppression de la règle UDP DNS (peut-être déjà supprimée)"
    ssh ${PI_USER}@${PI_IP} "sudo /usr/sbin/iptables -t nat -D PREROUTING -i wlan0 -p tcp --dport 53 -j DNAT --to-destination 127.0.0.1:53" || log_warning "Échec de la suppression de la règle TCP DNS (peut-être déjà supprimée)"
    log_success "Règles de redirection DNS supprimées."
}

# Menu
case "$1" in
    "ap")
        setup_persistence
        setup_routed_ap "$2"
        log_success "Configuration du point d'accès routé terminée."
        ;;
    "bridge")
        setup_persistence
        setup_bridge
        log_success "Configuration du pont transparent terminée."
        ;;
    "dns")
        setup_dns_interceptor
        log_success "Configuration de l'intercepteur DNS terminée."
        ;;
    "restore-ap")
        restore_routed_ap
        log_success "Restauration du point d'accès routé terminée."
        ;;
    "restore-bridge")
        restore_bridge
        log_success "Restauration du pont transparent terminée."
        ;;
    "restore-dns")
        restore_dns_interceptor
        log_success "Restauration de l'intercepteur DNS terminée."
        ;;
    *)
        log_error "Utilisation: $0 {ap|bridge|dns|restore-ap|restore-bridge|restore-dns} [SSID_pour_AP_optionnel]"
        ;;
esac
