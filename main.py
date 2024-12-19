import os
import sys
from typing import Any, Dict, Final, Iterable, Tuple

from pypowerwall import scan

from manual_reporter.manual_reporter import (RouteOperation,
                                             get_network_interface,
                                             manage_ip_route_pyroute,
                                             tedapi_report)

INVERTER_DATA: Final[Dict[str, Tuple[str, str]]] = {
    'INVERTER_DIN': ("INVERTER_PASSWORD", "192.168.91.1"),
}
USER_EMAIL: Final[str] = "email@email.net"


def main(devices: Iterable[Any]) -> int:
    ethernet_interface: Final[str] = get_network_interface()
    print(f"Default ethernet interface found: {ethernet_interface}")
    tedapi_subnet: Final[str] = "192.168.91.0/24"

    power: float = 0.0
    for device in devices:
        din: Final[str] = device.get('din', '')
        ip: Final[str] = device.get('ip', '')
        if not din or not ip:
            continue

        data: Final[Tuple[str, str]] = INVERTER_DATA.get(din, None)
        if not data:
            print(f"Password not found for device with DIN {din}. Skipping")
            continue

        try:
            manage_ip_route_pyroute(RouteOperation.ADD, tedapi_subnet, ip, ethernet_interface)
            power = power + tedapi_report(USER_EMAIL, data, device)
        except Exception as e:
            print(f"Error manging route or reporting for device {din}: {e}")
        finally:
            manage_ip_route_pyroute(RouteOperation.DELETE, tedapi_subnet, ip, ethernet_interface)
    print(f"Total system power is: {power}")

def is_root() -> bool:
    return os.geteuid() == 0

if __name__ == '__main__':
    if not is_root():
        # Re-run the script with sudo
        print("This script needs to run with administrative privileges. Requesting sudo...")
        try:
            os.execvp("sudo", ["sudo", "python3"] + sys.argv)
        except Exception as e:
            print(f"Failed to elevate privileges: {e}")
            sys.exit(1)

    main(scan.scan(max_threads=256))
