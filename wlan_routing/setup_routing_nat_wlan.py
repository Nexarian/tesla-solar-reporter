#!/usr/bin/env python3

#########
# Command to run
# sudo -E env PATH="$PATH" ./.venv/bin/python3 ./setup_routing_nat.py
#########
# Auto run
# sudo vim /etc/NetworkManager/dispatcher.d/99-ip-change
#########

import ipaddress
import os
import subprocess
import sys
from ipaddress import IPv4Address
from typing import Dict, Final, List, Optional, TypedDict, cast

import iptc
from pyroute2 import IPDB, IPRoute

DESINATION_GATEWAY: Final[str] = str(IPv4Address('192.168.91.1'))
TEG_SUBNET_BASE: Final[str] = str(IPv4Address('192.168.91.0'))
TEG_SUBNET_CIDR: Final[str] = f"{TEG_SUBNET_BASE}/24"
VIRTUAL_IP_PREAMBLE: Final[str] = "192.168.92."
BASE_TABLE_ID: Final[int] = 100
BASE_IP: Final[int] = 100

KNOWN_SSIDS: Final[List[str]] = ["SSID_1", "SSID_2"]
SSID_IP_MAPPING_OVERRIDE: Final[Dict[str, IPv4Address]] = {
    ssid: IPv4Address(f"{VIRTUAL_IP_PREAMBLE}{BASE_IP + i}")
    for i, ssid in enumerate(KNOWN_SSIDS)
}


class TEG_Wifi_Interface(TypedDict):
    iface: str
    table: int
    ip: IPv4Address
    virt_ip: IPv4Address
    ssid: str


def check_root() -> None:
    if os.geteuid() == 0:
        return
    print("This script must be run as root")
    sys.exit(1)


def find_matching_wireless_interfaces() -> List[TEG_Wifi_Interface]:
    def is_wireless(ifname):
        # Check if wireless by looking for /sys/class/net/{ifname}/wireless
        return os.path.isdir(f'/sys/class/net/{ifname}/wireless')

    def in_subnet(ip_str, subnet_str=TEG_SUBNET_CIDR):
        try:
            return ipaddress.ip_address(ip_str) in ipaddress.ip_network(subnet_str)
        except ValueError:
            return False

    def get_wifi_ssid(ifname) -> Optional[str]:
        try:
            out = subprocess.check_output(["iw", "dev", ifname, "link"], stderr=subprocess.DEVNULL).decode()
            for line in out.splitlines():
                if line.strip().startswith("SSID:"):
                    return line.strip().split("SSID:")[1].strip()
        except subprocess.CalledProcessError:
            pass
        return "unknown"

    matching: List[TEG_Wifi_Interface] = []

    # Keep track of seen SSIDs
    seen_ssids = set()

    with IPDB() as ipdb:
        for iface in ipdb.interfaces.values():
            if not isinstance(iface.ifname, str):
                continue
            if iface.ifname == 'lo' or not is_wireless(iface.ifname):
                continue

            ssid = get_wifi_ssid(iface.ifname)
            if not ssid or ssid not in KNOWN_SSIDS or ssid in seen_ssids:
                continue
            seen_ssids.add(ssid)

            ssid_index = KNOWN_SSIDS.index(ssid)
            virt_ip = SSID_IP_MAPPING_OVERRIDE[ssid]
            table = BASE_TABLE_ID + ssid_index
            for ip_tuple in iface.ipaddr:
                ip_address = ip_tuple[0]  # First element is the IP string
                if not in_subnet(ip_address):
                    continue

                interface = cast(TEG_Wifi_Interface, {
                    'iface': iface.ifname,
                    'table': table,
                    'ip': str(ip_address),
                    'virt_ip': f"{virt_ip}/32",
                    'ssid': ssid
                })
                matching.append(interface)

                break # Only match one IP per iface
    return matching


def verify_routing_tables(interfaces: List[TEG_Wifi_Interface]):
    # Add custom routing tables if they don't exist already
    rt_tables_path = '/etc/iproute2/rt_tables'
    try:
        with open(rt_tables_path, 'r') as f:
            rt_content = f.read()

        rt_entries = [
            entry for idx, iface in enumerate(interfaces)
            if (entry := f"{iface['table']} wlan{idx}table") not in rt_content
        ]

        if not rt_entries:
            print("Tables already exist. All is well.")
            return

        with open(rt_tables_path, 'a') as f:
            lines = [f"{entry}\n" for entry in rt_entries]
            f.writelines(lines)
            print(f"Wrote tables to rt_tables: {lines}")
    except Exception as e:
        print(f"Warning: Unable to update routing tables file: {e}")

def format_rule(rule):
    parts = []

    # Interfaces
    if rule.in_interface:
        parts.append(f"in={rule.in_interface}")
    if rule.out_interface:
        parts.append(f"out={rule.out_interface}")

    # IPs
    if rule.src:
        parts.append(f"src={rule.src}")
    if rule.dst:
        parts.append(f"dst={rule.dst}")

    # Protocol
    if rule.protocol:
        parts.append(f"proto={rule.protocol}")

    # Matches
    for match in rule.matches:
        match_parts = [f"-m {match.name}"]
        for key, value in match.get_all_parameters().items():
            if isinstance(value, list):
                value = ",".join(str(v) for v in value)
            match_parts.append(f"--{key} {value}")
        parts.extend(match_parts)

    # Target (e.g. DNAT, SNAT, ACCEPT, DROP)
    if rule.target:
        parts.append(f"-j {rule.target.name}")

        # DNAT / SNAT specifics
        to_dst = getattr(rule.target, 'to_destination', None)
        to_src = getattr(rule.target, 'to_source', None)
        if to_dst:
            parts.append(f"--to-destination {to_dst}")
        if to_src:
            parts.append(f"--to-source {to_src}")

    return " ".join(parts)

def cleanup_interfaces(interfaces: List[TEG_Wifi_Interface]):
    def normalize_ip(ip):
        return str(ipaddress.IPv4Network(ip, strict=False)) if ip else None

    def remove_nat_rule(chain_name, dst=None, src=None, to_dst=None, to_src=None):
        dst = normalize_ip(dst)
        src = normalize_ip(src)
        to_dst = str(to_dst) if to_dst else None
        to_src = str(to_src) if to_src else None

        table = iptc.Table(iptc.Table.NAT)
        chain = iptc.Chain(table, chain_name)
        table.refresh()

        deleted = 0
        for rule in list(chain.rules):
            formatted_rule = format_rule(rule)
            print(f"\tExamining rule {formatted_rule}")

            rule_dst = normalize_ip(rule.dst)
            rule_src = normalize_ip(rule.src)

            target = rule.target.name
            target_to_dst = getattr(rule.target, 'to_destination', None)
            target_to_src = getattr(rule.target, 'to_source', None)

            reasons_skipped = []

            if dst and dst != rule_dst:
                reasons_skipped.append(f"dst mismatch: expected {dst}, got {rule_dst}")
            if src and src != rule_src:
                reasons_skipped.append(f"src mismatch: expected {src}, got {rule_src}")
            if to_dst and (target != 'DNAT' or to_dst != target_to_dst):
                reasons_skipped.append(
                    f"DNAT mismatch: expected target=DNAT and to-dest={to_dst}, "
                    f"got target={target}, to-dest={target_to_dst}"
                )
            if to_src and (target != 'SNAT' or to_src != target_to_src):
                reasons_skipped.append(
                    f"SNAT mismatch: expected target=SNAT and to-src={to_src}, "
                    f"got target={target}, to-src={target_to_src}"
                )

            if reasons_skipped:
                print(f"\t\tSkipping rule: {format_rule(rule)}")
                for reason in reasons_skipped:
                    print(f"\t\t  ↳ {reason}")
                continue

            chain.delete_rule(rule)
            deleted += 1
            print(f"\t\t  ↳ Deleted rule in {chain_name}: {formatted_rule}")
        print(f"Deleted {deleted} rules from {chain_name}")


    def clear_postrouting_snat(prefix="192.168.92."):
        """
        Remove *all* SNAT rules in the POSTROUTING chain
        whose to_source starts with the given prefix.
        """
        table = iptc.Table(iptc.Table.NAT)
        # Refresh in case rules have changed
        table.refresh()
        chain = iptc.Chain(table, "POSTROUTING")

        # Iterate over a snapshot since we're deleting as we go
        for rule in list(chain.rules):
            target = rule.target
            if target.name == 'SNAT' and getattr(target, 'to_source', '').startswith(prefix):
                chain.delete_rule(rule)


    with IPRoute() as iproute, IPDB(nl=iproute) as ipdb:
        lo = ipdb.interfaces['lo']
        for interface in interfaces:
            # Remove IP from loopback interface
            try:
                print(f"Cleanup: Removing virt ip {lo}\n{ipdb}")
                lo.del_ip(interface['virt_ip'])
            except Exception:
                print(f"Cannot delete IP address: {interface['virt_ip']}")  # IP might not be present
        ipdb.commit()

        for interface in interfaces:
            # Lookup interface index
            print("Cleanup: Link lookup")
            link = iproute.link_lookup(ifname=interface['iface'])
            interface_table = interface['table']
            interface_idx = None
            if link:
                interface_idx = link[0]
                print(f"Interface index for {interface['iface']} is {interface_idx}")
            else:
                print("Cleanup: There no interface index found.")
                continue

            #iproute.flush_routes(table=interface['table'], family=socket.AF_INET)
            route_kwargs = {}
            try:
                routes = iproute.get_routes(table=interface_table)
                for route in routes:
                    dst = route.get('dst', 'default')
                    if dst in [TEG_SUBNET_BASE, TEG_SUBNET_CIDR, 'default']:
                        # Extract only valid deletion fields
                        route_kwargs = {
                            'family': route['family'],
                            'dst_len': route['dst_len'],
                            'table': route['table'],
                            'proto': route['proto'],
                            'scope': route['scope'],
                            'type': route['type'],
                        }

                        attr_map = {
                            'RTA_DST': 'dst',
                            'RTA_GATEWAY': 'gateway',
                            'RTA_OIF': 'oif',
                        }

                        route_kwargs.update({
                            attr_map[attr_name]: attr_value
                            for attr_name, attr_value in route['attrs']
                            if attr_name in attr_map
                        })
                        if dst == 'default':
                            route_kwargs.pop('dst', None)  # default route has no 'dst'
                        iproute.route('delete', **route_kwargs)
                        print(f"\tDeleted route: {route_kwargs}")
            except Exception as e:
                print(f"Cleanup: Error deleting route: {route_kwargs}, Error: {e}")

            # Delete IP rule
            virt_ip = str(interface['virt_ip'])
            virt_ip_nocidr = virt_ip.split("/")[0]
            try:
                print(f"Cleanup: Del rule virt_ip {interface_idx}")
                # Delete *all* rules for this virtual IP, not just one table
                existing_rules = iproute.get_rules() or []
                for rule in existing_rules:
                    attrs = dict(rule.get("attrs", []))
                    rule_src = attrs.get("FRA_SRC")
                    rule_table = attrs.get("FRA_TABLE")
                    rule_prio = attrs.get("FRA_PRIORITY")

                    if rule_src != virt_ip_nocidr:
                        continue
                    print(f"\tDeleting rule: from {rule_src} table {rule_table} prio {rule_prio}")
                    try:
                        iproute.rule("delete", src=rule_src, table=rule_table, priority=rule_prio)
                    except Exception as e:
                        print(f"\tFailed to delete rule {rule_src} table {rule_table}: {e}")
            except Exception:
                pass

            # Remove iptables rules
            print(f"Cleanup: Remove OUTPUT rule")
            remove_nat_rule('OUTPUT', dst=virt_ip, to_dst=DESINATION_GATEWAY)
            print(f"Cleanup: Remove POSTROUTING rule")
            clear_postrouting_snat()
            remove_nat_rule('POSTROUTING', src=virt_ip, dst=DESINATION_GATEWAY, to_src=interface['ip'])


def setup_interfaces(interfaces: List[TEG_Wifi_Interface]):
    # Helper to add iptables rule
    def add_nat_rule(chain, dst=None, src=None, to_dst=None, to_src=None):
        rule = iptc.Rule()
        if dst:
            rule.dst = dst
        if src:
            rule.src = src

        target = iptc.Target(rule, 'DNAT' if to_dst else 'SNAT')
        if to_dst:
            target.to_destination = str(to_dst)
        if to_src:
            target.to_source = str(to_src)

        rule.target = target
        table = iptc.Table(iptc.Table.NAT)
        chain = iptc.Chain(table, chain)
        chain.insert_rule(rule)

    # IPRoute/pyroute2 setup
    with IPRoute() as iproute, IPDB(nl=iproute) as ipdb:
        lo = ipdb.interfaces['lo']
        existing_ips = [ip[0] for ip in lo.ipaddr]
        for interface in interfaces:
            # Ex: sudo ip addr add 192.168.92.100/32 dev lo
            virt_ip = interface['virt_ip']
            if virt_ip in existing_ips:
                continue
            print(f"Adding address: {virt_ip}")
            lo.add_ip(virt_ip)
        ipdb.commit()

        for interface in interfaces:
            # Lookup interface index
            print("Setup: Link lookup")
            virt_ip = interface['virt_ip']
            interface_table = interface['table']
            link = iproute.link_lookup(ifname=interface['iface'])
            interface_idx = None
            if link:
                interface_idx = link[0]
            else:
                print(f"Setup: There no interface index found for {interface['iface']}")
                continue

            # Ex: sudo ip route add 192.168.91.0/24 dev wlan1 table wlan1table
            try:
                iproute.route('add', dst=TEG_SUBNET_CIDR, oif=interface_idx, table=interface_table)
            except Exception as e:
                print(f"Error adding route: dst={TEG_SUBNET_CIDR}, oif={interface_idx}, table={interface_table}, Error: {e}")

            # Ex: sudo ip route add default via 192.168.91.1 dev wlan1 table wlan1table
            iproute.route('add', dst='default', gateway=DESINATION_GATEWAY, oif=interface_idx, table=interface_table)

            # Ex: sudo ip rule add from 192.168.92.100 table wlan1table
            iproute.rule('add', src=virt_ip, table=interface_table)

            # Ex: sudo iptables -t nat -A OUTPUT -d 192.168.92.100 -j DNAT --to-destination 192.168.91.1
            add_nat_rule('OUTPUT', dst=virt_ip, to_dst=DESINATION_GATEWAY)

            # Ex: sudo iptables -t nat -A POSTROUTING -s 192.168.92.100 -d 192.168.91.1 -j SNAT --to-source 192.168.91.124
            add_nat_rule('POSTROUTING', src=virt_ip, dst=DESINATION_GATEWAY, to_src=interface['ip'])

if __name__ == "__main__":
    check_root()
    interfaces = find_matching_wireless_interfaces()
    print("Cleaning up old routes")
    cleanup_interfaces(interfaces=interfaces)
    print("Setting up new routes")
    verify_routing_tables(interfaces=interfaces)
    setup_interfaces(interfaces=interfaces)
