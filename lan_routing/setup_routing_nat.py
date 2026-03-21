#!/usr/bin/env python3

#########
# Command to run
# sudo -E env PATH="$PATH" ./.venv/bin/python3 ./setup_routing_nat.py
#########
# Auto run
# sudo vim /etc/NetworkManager/dispatcher.d/99-ip-change
#########

import json
import os
import socket
import subprocess
import sys
from typing import Any, Dict, Final, List, Tuple

import iptc
import psutil
from pypowerwall import scan
from pyroute2 import IPRoute
from pyroute2.netlink.exceptions import NetlinkError

# Define constant for destination IP
DESTINATION_IP: Final[str] = "192.168.91.1"

# Generate inverter configurations dynamically
BASE_TABLE_ID: Final[int] = 200
BASE_MARK: Final[int] = 50

def check_root() -> None:
    if os.geteuid() != 0:
        print("This script must be run as root")
        sys.exit(1)

def get_network_interface() -> Tuple[str, int, Any]:
    """Find the default LAN (wired) network interface."""
    ATTRIBUTES: Final[str] = 'attrs'
    with IPRoute() as ip_route:
        return next(
            (
                (name, attr[1])
                for route in ip_route.get_routes(family=socket.AF_INET)
                    if route.get('dst_len', None) == 0
                        for attr in route[ATTRIBUTES]
                            if attr[0] == 'RTA_OIF'
                                for name in [ip_route.link('get', index=attr[1])[0][ATTRIBUTES][0][1]]
                                    if not name.startswith('wl')
            ),
            None
        )

def get_local_ip(interface: str) -> str:
    """
    Get the LAN IP address of a specific network interface.

    Args:
        interface (str): The name of the network interface (e.g., 'eth0').

    Returns:
        str: The IP address of the specified interface, or an error message if not found.
    """
    try:
        addrs = psutil.net_if_addrs().get(interface)
        if not addrs:
            return f"Interface '{interface}' not found."
        
        for addr in addrs:
            if addr.family == socket.AF_INET:
                return addr.address
        
        return f"No IPv4 address found for interface '{interface}'."
    except Exception as e:
        return f"Error retrieving IP for interface '{interface}': {e}"

def cleanup(inverters: List[Dict[str, str | int]]) -> None:
    print("Cleaning up existing rules and configurations...")
    interface = get_network_interface()
    with IPRoute() as ip_route:
        try:
            # Remove virtual IPs
            for inverter in inverters:
                try:
                    ip_route.addr('delete', index=interface[1], address=inverter['ip'], prefixlen=24)
                except NetlinkError:
                    pass

            # Flush iptables rules
            for table_name in ["nat", "mangle", "filter"]:
                table = iptc.Table(table_name)
                for chain in table.chains:
                    chain.flush()
                    for rule in chain.rules:
                        chain.delete_rule(rule)

            # Flush routes for each inverter
            for inverter in inverters:
                ip_route.flush_routes(table=inverter['table_id'])

            # Remove ip rules
            rules: List[Dict] = ip_route.get_rules()
            for rule in rules:
                for inverter in inverters:
                    if rule['table'] != inverter['table_id']:
                        continue
                    ip_route.rule('delete', **rule)

            print("Cleanup completed successfully.")

        except Exception as e:
            print(f"Error during cleanup: {e}")
            
def enable_ip_forwarding():
    try:
        subprocess.run(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"], check=True)
        print("IP forwarding enabled successfully.")
    except subprocess.CalledProcessError:
        print("Error enabling IP forwarding. Do you have sudo privileges?")

def setup(inverters: List[Dict[str, str | int]]) -> None:
    print("Setting up routing, NAT, and marking rules...")
    interface = get_network_interface()
    local_ip = get_local_ip(interface=interface[0])
    print(f"Local IP is: {local_ip}")
    with IPRoute() as ip_route:
        try:
            # Enable IP forwarding
            #enable_ip_forwarding()

            interface_index: Final[int] = interface[1]
            print(f"Interface index is: {interface_index}\n")

            # Add virtual IPs, routing tables, and marking rules
            for inverter in inverters:
                try:
                    ip = inverter['ip']
                    mark = inverter['mark']
                    table_id = inverter['table_id']
                    destination = inverter['destination']

                    print(f"Adding address: {ip}")
                    ip_route.addr('add', index=interface_index, address=ip, prefixlen=24)
                    print("Adding route")
                    ip_route.route('add', dst=f'{destination}/32', gateway=inverter['gateway'], table=table_id, flags="onlink", oif=interface[1])
                    print("Adding rule mark")
                    ip_route.rule('add', table=table_id, fwmark=mark)

                    print("Mangle table")
                    # Mangle table rules
                    mangle_table = iptc.Table(iptc.Table.MANGLE)
                    output_chain = iptc.Chain(mangle_table, "OUTPUT")
                    rule = iptc.Rule()
                    rule.dst = ip
                    target = iptc.Target(rule, "MARK")
                    target.set_mark = str(mark)
                    rule.target = target
                    output_chain.append_rule(rule)

                    # NAT rules
                    nat_table = iptc.Table(iptc.Table.NAT)
                    output_chain = iptc.Chain(nat_table, "OUTPUT")
                    prerouting_chain = iptc.Chain(nat_table, "PREROUTING")
                    postrouting_chain = iptc.Chain(nat_table, "POSTROUTING")

                    # DNAT rules
                    for chain in [output_chain, prerouting_chain]:
                        rule = iptc.Rule()
                        rule.dst = ip
                        target = iptc.Target(rule, "DNAT")
                        target.to_destination = destination
                        rule.target = target
                        chain.insert_rule(rule)

                    # SNAT rule
                    rule = iptc.Rule()
                    rule.src = ip
                    target = iptc.Target(rule, "SNAT")
                    target.to_source = local_ip
                    rule.target = target
                    postrouting_chain.insert_rule(rule)
                    
                    print(f"Address {ip} setup successfully for inverter {inverter['din']}\n")
                except (NetlinkError, iptc.IPTCError) as e:
                    print(f"Error setting up {inverter['ip']}: {e}")

            print("Setup completed successfully.")

        except Exception as e:
            print(f"Error during setup: {e}")

if __name__ == "__main__":
    check_root()
    
    #devices = scan.scan(ip="192.168.1.1", max_threads=256)
    
    #print(f"Found Inverters: {json.dumps(devices, indent=4)}")

    # inverters: List[Dict[str, str | int]] = [
    #     {
    #         "ip": f"192.168.93.{100 + i}",
    #         "table_id": BASE_TABLE_ID + i,
    #         "mark": BASE_MARK + i,
    #         "gateway": device['ip'],
    #         "din": device['din'],
    #         "destination": DESTINATION_IP
    #     }
    #     for i, device in enumerate(devices)
    # ]

    # inverters.extend([
    #     {
    #         "ip": f"192.168.93.{110 + i}",
    #         "table_id": BASE_TABLE_ID + 10 + i,
    #         "gateway": ip,
    #         "mark": BASE_MARK + i,
    #         "destination": "192.168.91.1"
    #     }
    #     for i, ip in enumerate([i['ip'] for i in devices])
    # ])
    
    inverters: List[Dict[str, str | int]] = [
        {
            "ip": "192.168.93.100",
            "table_id": BASE_TABLE_ID + 0,
            "mark": BASE_MARK + 0,
            "gateway": "10.193.123.222",
            "din": "[DIN 1 Placeholder]",
            "destination": DESTINATION_IP
        },
        {
            "ip": "192.168.93.101",
            "table_id": BASE_TABLE_ID + 1,
            "mark": BASE_MARK + 1,
            "gateway": "10.193.16.102",
            "din": "[DIN 2 Placeholder]",
            "destination": DESTINATION_IP
        }
    ]

    #cleanup(inverters)
    setup(inverters)
