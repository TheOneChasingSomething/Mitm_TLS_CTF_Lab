#!/usr/bin/env bash
set -e

# Configuration des variables
BRIDGE_NAME="br0"
TAP_NAME="tap0"
BRIDGE_IP="10.10.10.1/24"
WAN_IF="wlp148s0"
CURRENT_USER="${USER:-$LOGNAME}"

echo "[+] Début de la configuration du réseau virtuel pour QEMU..."

# 1. Charger le module noyau bridge
echo "[*] Chargement du module noyau 'bridge'..."
sudo modprobe bridge

# 2. Créer le bridge br0 s'il n'existe pas
if ! ip link show "$BRIDGE_NAME" &>/dev/null; then
    echo "[*] Création du pont $BRIDGE_NAME..."
    sudo ip link add name "$BRIDGE_NAME" type bridge
else
    echo "[!] Le pont $BRIDGE_NAME existe déjà."
fi

# 3. Activer le bridge
echo "[*] Activation de l'interface $BRIDGE_NAME..."
sudo ip link set "$BRIDGE_NAME" up

# 4. Attribuer l'IP fixe au pont (si pas déjà attribuée)
if ! ip addr show dev "$BRIDGE_NAME" | grep -q "$BRIDGE_IP"; then
    echo "[*] Attribution de l'adresse IP $BRIDGE_IP au pont $BRIDGE_NAME..."
    sudo ip addr add "$BRIDGE_IP" dev "$BRIDGE_NAME"
else
    echo "[!] L'adresse IP $BRIDGE_IP est déjà configurée sur $BRIDGE_NAME."
fi

# 5. Créer l'interface TAP pour l'utilisateur courant
if ! ip link show "$TAP_NAME" &>/dev/null; then
    echo "[*] Création de l'interface TAP $TAP_NAME pour l'utilisateur $CURRENT_USER..."
    sudo ip tuntap add dev "$TAP_NAME" mode tap user "$CURRENT_USER"
else
    echo "[!] L'interface $TAP_NAME existe déjà."
fi

# S'assurer que tap0 est bien rattachée au bridge br0
echo "[*] Configuration et rattachement de $TAP_NAME au pont $BRIDGE_NAME..."
sudo ip link set "$TAP_NAME" master "$BRIDGE_NAME" 2>/dev/null || true

# 7. Activer l'interface TAP
echo "[*] Activation de l'interface $TAP_NAME..."
sudo ip link set "$TAP_NAME" up

# 8. Activer l'IP forwarding au niveau du noyau (permanent + à chaud)
echo "[*] Activation du transfert d'IP (ip_forward)..."
if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf; then
    echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
fi
sudo sysctl -w net.ipv4.ip_forward=1 > /dev/null

# 9. Appliquer les règles NAT / IPTables
echo "[*] Application des règles iptables / NAT vers l'interface externe $WAN_IF..."
sudo iptables -t nat -C POSTROUTING -o "$WAN_IF" -j MASQUERADE &>/dev/null || \
    sudo iptables -t nat -A POSTROUTING -o "$WAN_IF" -j MASQUERADE

sudo iptables -C FORWARD -i "$BRIDGE_NAME" -o "$WAN_IF" -j ACCEPT &>/dev/null || \
    sudo iptables -A FORWARD -i "$BRIDGE_NAME" -o "$WAN_IF" -j ACCEPT

sudo iptables -C FORWARD -i "$WAN_IF" -o "$BRIDGE_NAME" -m state --state RELATED,ESTABLISHED -j ACCEPT &>/dev/null || \
    sudo iptables -A FORWARD -i "$WAN_IF" -o "$BRIDGE_NAME" -m state --state RELATED,ESTABLISHED -j ACCEPT

echo "[+] Configuration terminée avec succès !"
