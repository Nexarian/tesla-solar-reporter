#!/usr/bin/env bash

set -ex


# Function to check if a command succeeded
check_command() {
    if [ $? -ne 0 ]; then
        echo "Error: $1"
        exit 1
    fi
}

# Function to clean up existing rules and configurations
cleanup() {
    echo "Cleaning up existing rules and configurations..."
    
    # Remove virtual IP addresses
    ip addr del 192.168.92.100/24 dev eth0 2>/dev/null || true
    ip addr del 192.168.92.101/24 dev eth0 2>/dev/null || true

    # Flush NAT table
    iptables -t nat -F
    check_command "Failed to flush NAT table"

    # Flush mangle table
    iptables -t mangle -F
    check_command "Failed to flush mangle table"

    # Remove all rules in filter table
    iptables -F
    check_command "Failed to flush filter table"

    # Remove non-default chains
    iptables -X
    check_command "Failed to delete non-default chains"

    # Remove all ip rules (except default)
    ip rule show | grep -v "from all lookup" | cut -d: -f1 | xargs -r -n1 ip rule del prio
    check_command "Failed to remove ip rules"

    # Remove routing tables
    ip route flush table 100 || true
    ip route flush table 101 || true
    check_command "Failed to flush routing tables"

    echo "Cleanup completed successfully."
}

# Main setup function
setup() {
    echo "Setting up routing and NAT rules..."

    # Enable IP forwarding
    echo 1 > /proc/sys/net/ipv4/ip_forward
    check_command "Failed to enable IP forwarding"

    # Add virtual IP addresses
    ip addr add 192.168.92.100/24 dev eth0
    check_command "Failed to add virtual IP 192.168.92.100"
    ip addr add 192.168.92.101/24 dev eth0
    check_command "Failed to add virtual IP 192.168.92.101"

    # Set up routing tables
    ip route add 192.168.91.1/32 via 192.168.1.67 dev eth0 onlink table 100
    check_command "Failed to add route to table 100"
    ip route add 192.168.91.1/32 via 192.168.1.250 dev eth0 onlink table 101
    check_command "Failed to add route to table 101"

    # Set up NAT rules
    iptables -t nat -A OUTPUT -d 192.168.92.100 -j DNAT --to-destination 192.168.91.1
    check_command "Failed to add DNAT rule for 192.168.92.100"
    iptables -t nat -A OUTPUT -d 192.168.92.101 -j DNAT --to-destination 192.168.91.1
    check_command "Failed to add DNAT rule for 192.168.92.101"

    iptables -t nat -A PREROUTING -d 192.168.92.100 -j DNAT --to-destination 192.168.91.1
    check_command "Failed to add DNAT rule for 192.168.92.100"
    iptables -t nat -A PREROUTING -d 192.168.92.101 -j DNAT --to-destination 192.168.91.1
    check_command "Failed to add DNAT rule for 192.168.92.101"

    # Set up packet marking
    iptables -t mangle -A OUTPUT -d 192.168.92.100 -j MARK --set-mark 1
    check_command "Failed to add mark for 192.168.92.100"
    iptables -t mangle -A OUTPUT -d 192.168.92.101 -j MARK --set-mark 2
    check_command "Failed to add mark for 192.168.92.101"

    # Set up ip rules
    ip rule add fwmark 1 table 100
    check_command "Failed to add ip rule for mark 1"
    ip rule add fwmark 2 table 101
    check_command "Failed to add ip rule for mark 2"

    # Set up return traffic NAT
    iptables -t nat -A POSTROUTING -s 192.168.92.100 -d 192.168.91.1 -j SNAT --to-source 192.168.1.225
    check_command "Failed to add return SNAT rule for 192.168.92.100"
    iptables -t nat -A POSTROUTING -s 192.168.92.101 -d 192.168.91.1 -j SNAT --to-source 192.168.1.225
    check_command "Failed to add return SNAT rule for 192.168.92.101"

    echo "Setup completed successfully."
}

# Main execution
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

# Cleanup first
cleanup

# Then setup
setup

echo "All operations completed successfully."
