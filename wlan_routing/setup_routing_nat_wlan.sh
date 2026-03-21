#!/usr/bin/env bash

set -ex

sudo -v

# sudo ip addr del 192.168.91.100/32 dev lo 2>/dev/null || true
# sudo ip addr del 192.168.91.101/32 dev lo 2>/dev/null || true

# sudo iptables -t nat -D OUTPUT -d 192.168.91.100 -j DNAT --to-destination 192.168.91.1 2>/dev/null || true
# sudo iptables -t nat -D OUTPUT -d 192.168.91.101 -j DNAT --to-destination 192.168.91.1 2>/dev/null || true

# sudo iptables -t nat -D POSTROUTING -d 192.168.91.1 -o wlan1 -j SNAT --to-source 192.168.91.124 2>/dev/null || true
# sudo iptables -t nat -D POSTROUTING -d 192.168.91.1 -o wlan2 -j SNAT --to-source 192.168.91.174 2>/dev/null || true

# sudo ip route del 192.168.91.0/24 dev wlan0 table wlan0table 2>/dev/null || true
# sudo ip route del 192.168.91.0/24 dev wlan2 table wlan1table 2>/dev/null || true
# sudo ip route del default via 192.168.91.1 dev wlan2 table wlan1table 2>/dev/null || true
# sudo ip route del 192.168.91.0/24 dev wlan2 table wlan2table 2>/dev/null || true

##############################################################################

sudo ip addr add 192.168.92.100/32 dev lo
sudo ip addr add 192.168.92.101/32 dev lo

# Route for wlan0
sudo ip route add 192.168.91.0/24 dev wlan1 table wlan1table
sudo ip route add default via 192.168.91.1 dev wlan1 table wlan1table

# Route for wlan1
sudo ip route add 192.168.91.0/24 dev wlan2 table wlan2table
sudo ip route add default via 192.168.91.1 dev wlan2 table wlan2table

sudo ip rule add from 192.168.92.100 table wlan1table
sudo ip rule add from 192.168.92.101 table wlan2table

sudo iptables -t nat -A OUTPUT -d 192.168.92.100 -j DNAT --to-destination 192.168.91.1
sudo iptables -t nat -A OUTPUT -d 192.168.92.101 -j DNAT --to-destination 192.168.91.1

sudo iptables -t nat -A POSTROUTING -s 192.168.92.100 -d 192.168.91.1 -j SNAT --to-source 192.168.91.124
sudo iptables -t nat -A POSTROUTING -s 192.168.92.101 -d 192.168.91.1 -j SNAT --to-source 192.168.91.174
