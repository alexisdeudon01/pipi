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
    # Pas d'exit 1 ici car c'est un script de vérification, on veut voir tous les résultats.
}

# Configuration
PI_IP="192.168.178.67"
PI_USER="pi"
# SSH_CMD est supprimé car nous utiliserons ssh directement avec les chemins absolus

log_info "-------------------------------------------------------"
log_info "Raspberry Pi 5 Gateway Verification Script"
log_info "Target: ${PI_IP}"
log_info "-------------------------------------------------------"

# Verify IP Forwarding
verify_ip_forwarding() {
    log_info "Vérification du forwarding IP..."
    local FORWARD_STATUS=$(ssh ${PI_USER}@${PI_IP} "sudo /sbin/sysctl net.ipv4.ip_forward" 2>/dev/null)
    if [[ "$FORWARD_STATUS" == *"net.ipv4.ip_forward = 1"* ]]; then
        log_success "IP Forwarding est activé: ${FORWARD_STATUS}"
    else
        log_warning "IP Forwarding est désactivé ou non vérifiable: ${FORWARD_STATUS}"
    fi
}

# Verify Routed AP (Evil Twin Style)
verify_routed_ap() {
    log_info "Vérification du Routed AP (Evil Twin)..."
    log_info "--- État de wlan0 ---"
    local WLAN0_STATUS=$(ssh ${PI_USER}@${PI_IP} "/usr/bin/nmcli device status | grep wlan0" 2>/dev/null)
    if [ -n "$WLAN0_STATUS" ]; then
        log_info "${WLAN0_STATUS}"
    else
        log_warning "Impossible d'obtenir l'état de wlan0."
    fi

    log_info "--- Connexions NetworkManager actives ---"
    local EVILTWIN_ACTIVE=$(ssh ${PI_USER}@${PI_IP} "/usr/bin/nmcli con show --active | grep EvilTwin" 2>/dev/null)
    if [ -n "$EVILTWIN_ACTIVE" ]; then
        log_success "Connexion 'EvilTwin' active: ${EVILTWIN_ACTIVE}"
    else
        log_warning "Connexion 'EvilTwin' non active."
    fi

    log_info "--- Règles NAT iptables ---"
    local NAT_RULES=$(ssh ${PI_USER}@${PI_IP} "sudo /usr/sbin/iptables -t nat -L POSTROUTING -v -n | grep MASQUERADE" 2>/dev/null)
    local FORWARD_RULES=$(ssh ${PI_USER}@${PI_IP} "sudo /usr/sbin/iptables -L FORWARD -v -n | grep wlan0" 2>/dev/null)
    if [ -n "$NAT_RULES" ] && [ -n "$FORWARD_RULES" ]; then
        log_success "Règles NAT et FORWARD iptables présentes."
        log_info "MASQUERADE: ${NAT_RULES}"
        log_info "FORWARD wlan0: ${FORWARD_RULES}"
    else
        log_warning "Règles NAT ou FORWARD iptables manquantes."
    fi
    log_info "Résumé: Si 'EvilTwin' est actif et que les règles iptables sont présentes, le Routed AP est configuré."
}

# Verify Transparent Bridge (Layer 2)
verify_bridge() {
    log_info "Vérification du Transparent Bridge (Layer 2)..."
    log_info "--- État du service systemd-networkd ---"
    local SYSTEMD_NETWORKD_STATUS=$(ssh ${PI_USER}@${PI_IP} "sudo /usr/bin/systemctl is-active systemd-networkd" 2>/dev/null)
    if [[ "$SYSTEMD_NETWORKD_STATUS" == "active" ]]; then
        log_success "systemd-networkd est actif."
    else
        log_warning "systemd-networkd n'est pas actif ou non vérifiable: ${SYSTEMD_NETWORKD_STATUS}"
    fi

    log_info "--- Table de pontage br0 ---"
    # brctl n'est pas trouvé, on vérifie l'existence de br0 via ip link
    local BR0_STATUS=$(ssh ${PI_USER}@${PI_IP} "sudo /usr/sbin/ip link show br0" 2>/dev/null)
    if [ -n "$BR0_STATUS" ]; then
        log_success "Pont br0 existe."
        log_info "${BR0_STATUS}"
    else
        log_warning "Pont br0 non trouvé."
    fi

    log_info "--- Ports attachés au pont br0 ---"
    if [ -n "$BR0_STATUS" ]; then
        local ETH0_MASTER=$(ssh ${PI_USER}@${PI_IP} "/usr/sbin/ip -d link show eth0 | grep -o 'master [^ ]*'" 2>/dev/null)
        local WLAN0_MASTER=$(ssh ${PI_USER}@${PI_IP} "/usr/sbin/ip -d link show wlan0 | grep -o 'master [^ ]*'" 2>/dev/null)
        if [[ "$ETH0_MASTER" == "master br0" ]] && [[ "$WLAN0_MASTER" == "master br0" ]]; then
            log_success "eth0 et wlan0 sont attachés à br0."
        else
            log_warning "eth0/wlan0 ne semblent pas attachés à br0."
            [ -n "$ETH0_MASTER" ] && log_info "eth0: ${ETH0_MASTER}" || log_info "eth0: aucun master détecté"
            [ -n "$WLAN0_MASTER" ] && log_info "wlan0: ${WLAN0_MASTER}" || log_info "wlan0: aucun master détecté"
        fi
    else
        log_warning "Ports non vérifiés car br0 est absent."
    fi

    log_info "--- Adresses IP des interfaces ---"
    local BR0_IP=$(ssh ${PI_USER}@${PI_IP} "/usr/sbin/ip addr show br0 | grep 'inet '" 2>/dev/null)
    local ETH0_IP=$(ssh ${PI_USER}@${PI_IP} "/usr/sbin/ip addr show eth0 | grep 'inet '" 2>/dev/null)
    local WLAN0_IP=$(ssh ${PI_USER}@${PI_IP} "/usr/sbin/ip addr show wlan0 | grep 'inet '" 2>/dev/null)

    if [ -z "$ETH0_IP" ] && [ -z "$WLAN0_IP" ]; then # Seules eth0 et wlan0 doivent être sans IP
        if [ -n "$BR0_IP" ]; then
            log_success "br0 a une IP via DHCP (comportement attendu pour ce setup)."
            log_info "br0 IP: ${BR0_IP}"
        else
            log_warning "br0 n'a pas d'IP alors que DHCP est activé dans le setup. Vérifiez le pont/DHCP."
        fi
    else
        log_warning "Des IPs sont détectées sur eth0 ou wlan0. Vérifiez la configuration du pont."
        [ -n "$BR0_IP" ] && log_info "br0 IP: ${BR0_IP}"
        [ -n "$ETH0_IP" ] && log_info "eth0 IP: ${ETH0_IP}"
        [ -n "$WLAN0_IP" ] && log_info "wlan0 IP: ${WLAN0_IP}"
    fi
    log_info "Résumé: Si br0 existe, eth0 et wlan0 sont sans IP, et systemd-networkd est actif, le pont est configuré (br0 avec IP si DHCP)."
}

# Verify DNS Interceptor (The Sinkhole)
verify_dns_interceptor() {
    log_info "Vérification du DNS Interceptor (The Sinkhole)..."
    log_info "--- Règles iptables de redirection DNS ---"
    local DNS_REDIRECT_RULES=$(ssh ${PI_USER}@${PI_IP} "sudo /usr/sbin/iptables -t nat -L PREROUTING -v -n | grep 'dpt:53'" 2>/dev/null)
    if [ -n "$DNS_REDIRECT_RULES" ]; then
        log_success "Règles iptables de redirection DNS présentes."
        log_info "${DNS_REDIRECT_RULES}"
    else
        log_warning "Aucune règle iptables de redirection DNS trouvée."
    fi

    log_info "--- Test de résolution DNS (doubleclick.net) ---"
    local DIG_RESULT=$(ssh ${PI_USER}@${PI_IP} "/usr/bin/dig @127.0.0.1 doubleclick.net +short" 2>/dev/null)
    if echo "$DIG_RESULT" | grep -q -E '^0\.0\.0\.0$|blocked'; then
        log_success "doubleclick.net est bloqué ou redirigé (résultat: ${DIG_RESULT}). L'intercepteur DNS est actif."
    elif [ -n "$DIG_RESULT" ]; then
        log_warning "doubleclick.net n'est pas bloqué (résultat: ${DIG_RESULT}). L'intercepteur DNS pourrait ne pas être actif."
    else
        log_error "Échec du test de résolution DNS. Assurez-vous que Pi-hole/AdGuard Home est en cours d'exécution."
    fi
    log_info "Résumé: Si les règles iptables sont présentes et que 'doubleclick.net' retourne 0.0.0.0 ou est bloqué, l'intercepteur DNS est actif."
}

# Menu
case "$1" in
    "ap")
        verify_ip_forwarding
        verify_routed_ap
        log_info "Vérification du point d'accès routé terminée."
        ;;
    "bridge")
        verify_ip_forwarding
        verify_bridge
        log_info "Vérification du pont transparent terminée."
        ;;
    "dns")
        verify_dns_interceptor
        log_info "Vérification de l'intercepteur DNS terminée."
        ;;
    "all")
        verify_ip_forwarding
        verify_routed_ap
        verify_bridge
        verify_dns_interceptor
        log_info "Vérification complète terminée."
        ;;
    *)
        log_error "Utilisation: $0 {ap|bridge|dns|all}"
        ;;
esac
