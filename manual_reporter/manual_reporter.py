import json
import socket
from enum import Enum, auto
from typing import Any, Dict, Final, Optional, Tuple

import pypowerwall
from pyroute2 import IPRoute, NetlinkError


def get_network_interface() -> str:
    """_summary_

    Returns:
        str: _description_
    """
    ATTRIBUTES: Final[str] = 'attrs'
    with IPRoute() as ip:
        return next(
            (
                ip.link('get', index=attr[1])[0][ATTRIBUTES][0][1]
                for route in ip.get_routes(family=socket.AF_INET) # IPv4 routes
                    if route.get('dst_len', None) == 0  # Default route
                        for attr in route[ATTRIBUTES]
                            if attr[0] == 'RTA_OIF' # Outgoing interface
            ),
            None
        )


class Tense(Enum):
    """ String/tense variation on the route operations.
    """    
    BASE = auto()
    PRESENT = auto()
    PAST = auto()


class RouteOperation(Enum):
    """Whether to add or remove a route.
    """
    ADD = {
        Tense.BASE: "add",
        Tense.PRESENT: "adding",
        Tense.PAST: "added"   
    }
    DELETE = {
        Tense.BASE: "del",
        Tense.PRESENT: "deleting",
        Tense.PAST: "deleted"
    }

    def get_action(self, tense: Tense) -> str:
        """Retrieve string representation appropriate to each RouteOperation tense.

        Args:
            tense (Tense): Tense for each operation.

        Returns:
            str: String representation of operation tense.
        """        
        return self.value.get(tense, "Tense Missing")


def manage_ip_route_pyroute(operation: RouteOperation, destination: str, gateway: str, interface: Optional[str] = None, interactive: bool = False) -> None:
    """ Manages an IP route using pyroute2's IPRoute, utilizing onlink to ensure the route works.
        For instance, if you want to map all requests that go from a CIDR range of 192.168.91.0/24 => 192.168.1.250,
        use this to add/delete such a route. This can also be configured on your router.

    Args:
        operation (RouteOperation): RouteOperation.ADD or RouteOperation.DELETE, corresponding to desired operation for network route.
        destination (str): The network or IP address in IPv4 CIDR notation (e.g., "192.168.1.0/24")
        gateway (str): The IP address of the Tesla Gateway/Powerwall (e.g., "192.168.1.250")
        interface (str, optional): The optional network interface (e.g., "eth0"). If not provided, the route is managed without specifying an interface. Defaults to None.

    Example usage:
        manage_ip_route_pyroute(RouteOperation.ADD, "192.168.1.0/24", "192.168.1.1")
        manage_ip_route_pyroute(RouteOperation.DELETE, "192.168.1.0/24", "192.168.1.1", "eth0")
    """

    route_params = {
        "family": socket.AF_INET6 if ":" in destination else socket.AF_INET,
        "dst": destination,
        "gateway": gateway
    }

    if operation == RouteOperation.ADD:
        route_params["flags"] = ["onlink"]

    with IPRoute() as ip:
        try:
            # Lookup interface index if interface is specified
            if interface:
                idxs = ip.link_lookup(ifname=interface)
                if not idxs:
                    print(f"Interface '{interface}' not found.")
                    return
                route_params["oif"] = idxs[0]
            # Perform the route operation
            ip.route(operation.get_action(Tense.BASE), **route_params)
            if interactive:
                print(f"Route {operation.get_action(Tense.PAST)}: {destination} via {gateway}" + (f" dev {interface}" if interface else "") + (f" {','.join(route_params['flags'])}" if 'flags' in route_params else ""))
        except NetlinkError as e:
            print(f"Network specific error occurred {operation.get_action(Tense.PRESENT)} route: {e}")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")


def tedapi_report(email: str, gateway_data: Tuple[str, str], device: Dict[Any, Any]) -> float:
    timezone: Final[str] = "America/New_York"
    host: Final[str] = gateway_data[1]
    password: Final[str] = ""
    pw: Final = pypowerwall.Powerwall(host,password,email,timezone,gw_pwd=gateway_data[0])

    # Some System Info
    print(f"Site Name: {pw.site_name()} - Firmware: {pw.version()} - DIN: {pw.din()}")
    print(f"System Uptime: {device['up_time'] if 'up_time' in device else pw.uptime()}\n")

    # Display String Data
    string_data = pw.strings()
    print(f"String Data: {json.dumps(string_data, indent=4)}")
    power: float = 0.0
    for value in string_data.values():
        power = power + value["Power"]
    print("String Power Total:", power)
    vitals = pw.vitals()
    for key, value in vitals.items():
        if "NEURIO" in key:
            print(f"Neurio Data: {json.dumps(value, indent=4)}")
            break

    # Display Device Vitals
    print(f"Vitals Data: {json.dumps(vitals, indent=4)}")
    return power
