#!/usr/bin/env python3
"""
Neurio Meter Control via TEDAPI over LAN with Bearer Token Auth.

Register, remove, and configure a Neurio energy meter on a Tesla
Energy Gateway (PVI / Powerwall) using BOTH:
  - TEDAPI NeurioMeterMessages API (MessageEnvelope field 9) for meter identity
  - FileStore config.json API for WiFi connection details (ip_address, TLS certs)

This enables the "Advanced WiFi Connection" method described in Tesla's
Application Note (June 2019) — but without needing the Commissioning
Wizard UI. The gateway connects to the Neurio on the home network using
the IP address and TLS certificates you configure.

Prerequisites (one-time Neurio WiFi setup):
  1. Power-cycle the Neurio to activate its hotspot (Neurio-XXXXX or PWRview-XXXXX)
  2. Connect to the Neurio hotspot WiFi
  3. Browse to https://192.168.4.1 (login: admin / OBB serial)
  4. Connect the Neurio to your home WiFi network
  5. Create a DHCP reservation on your router for the Neurio's MAC

Then use this script to register the meter with the gateway.

Requirements:
    pip install requests protobuf

Usage:
    # Add a WiFi meter (HOME WIFI method — the main use case)
    python neurio_meter_control.py --host IP --password PWD add \\
        --short-id 56206 --serial OBB3081102431 --ip 192.168.1.100 \\
        --cts site,solar,none,none

    # Add a meter WITHOUT WiFi config (direct pairing only)
    python neurio_meter_control.py --host IP --password PWD add \\
        --short-id 56206 --serial OBB3081102431

    # Write ONLY the config.json entry (if TEDAPI add already succeeded)
    python neurio_meter_control.py --host IP --password PWD write-config \\
        --short-id 56206 --serial OBB3081102431 --ip 192.168.1.100 \\
        --cts site,solar,none,none

    # Configure CTs after adding (4 CTs: site, solar, none, none)
    python neurio_meter_control.py --host IP --password PWD configure-cts \\
        --serial OBB3081102431 --cts site,solar,none,none

    # Remove a meter (TEDAPI + config.json)
    python neurio_meter_control.py --host IP --password PWD remove \\
        --serial OBB3081102431

    # Show current config (meters in config.json)
    python neurio_meter_control.py --host IP --password PWD status
    
    Working example:
        
"""
from __future__ import annotations

import argparse
import json
import sys
import tedapi_pb2

# Reuse the Bearer token API client from pvi_control_bearer.py
try:
    from pvi_control_bearer import TeslaInverterBearerAPI
except ImportError:
    print("ERROR: pvi_control_bearer.py not found (needed for TeslaInverterBearerAPI)")
    sys.exit(1)


# ============================================================
# CT Location mapping (proto int values)
# ============================================================

CT_LOCATION_MAP = {
    "invalid": 0,
    "none": 1,
    "site": 2,
    "solar": 3,
    "solar_rgm": 4,
    "battery": 5,
    "load": 6,
    "conductor": 7,
}

CT_LOCATION_NAMES = {v: k for k, v in CT_LOCATION_MAP.items()}

# Config.json uses string location names (MeterLocation enum from APK)
CONFIG_LOCATION_MAP = {
    "none": "none",
    "site": "site",
    "solar": "solar",
    "solar_rgm": "solarRGM",
    "battery": "battery",
    "load": "load",
    "conductor": "conductor",
}

NEURIO_CTS_COUNT = 4


def parse_ct_location(s: str) -> int:
    """Parse a CT location string to its int value."""
    s = s.strip().lower()
    if s in CT_LOCATION_MAP:
        return CT_LOCATION_MAP[s]
    try:
        return int(s)
    except ValueError:
        valid = ", ".join(CT_LOCATION_MAP.keys())
        raise ValueError(f"Unknown CT location '{s}'. Valid: {valid}")


# ============================================================
# Meter type detection (from APK: getNeurioMeterType)
# ============================================================

def get_meter_type(serial: str, is_wifi: bool = True) -> str:
    """
    Determine Neurio meter type from serial number.

    From APK getNeurioMeterType / getWifiNeurioMeterType:
      WiFi:  OBB/0X0 → neurio_tcp,  V-prefix → neurio_w2_tcp
      Wired: OBB/0X0 → neurio_mb,   V-prefix → neurio_w2_mb
    """
    serial_upper = serial.upper()
    if is_wifi:
        if serial_upper.startswith("V"):
            return "neurio_w2_tcp"
        return "neurio_tcp"
    else:
        if serial_upper.startswith("V"):
            return "neurio_w2_mb"
        if serial_upper.startswith("0X0") or serial_upper.startswith("OBB"):
            return "neurio_mb"
        return "neurio_tcp"


def get_neurio_ssid(short_id: str, serial: str) -> str:
    """
    Get Neurio WiFi SSID/hostname.

    From APK getNeurioSSID:
      W2/PWRview (V-serial) → PWRview-{shortId}
      Original (OBB)        → Neurio-{shortId}
    """
    if serial.upper().startswith("V"):
        return f"PWRview-{short_id}"
    return f"Neurio-{short_id}"


# ============================================================
# Config.json meter entry builder
# ============================================================

def build_wifi_meter_config(short_id: str, serial: str, ip_address: str,
                            ct_locations: list[str] | None = None,
                            meter_type: str | None = None,
                            location: str = "site",
                            mac: str | None = None,
                            scale_factor: int = 1) -> dict:
    """
    Build a config.json meter entry for a WiFi Neurio meter.

    Matches the REAL config.json format observed on production gateways:
      - "cts" is a boolean array (which CTs are active)
      - "inverted" is a boolean array
      - "connection" (not "confConnection")
      - "server_name" in https_conf is the Neurio MAC (dash-separated)
      - "location" is the meter role (site, solar, solarRGM, etc.)

    Args:
        short_id: 5-digit Neurio short ID
        serial: Meter serial (OBB or V prefix)
        ip_address: Neurio's IP on home network (or hostname)
        ct_locations: List of CT location strings to mark active (default: first CT only)
        meter_type: Override meter type (default: auto-detect from serial)
        location: Meter role — "site", "solar", "solarRGM", etc. (default: "site")
        mac: Neurio MAC address for TLS server_name (dash-separated, e.g. "04-71-4b-08-81-5b")
        scale_factor: real_power_scale_factor (default: 1)
    """
    if meter_type is None:
        meter_type = get_meter_type(serial, is_wifi=True)

    # server_name: MAC address if provided, else fall back to hostname
    if mac:
        server_name = mac
    else:
        server_name = get_neurio_ssid(short_id, serial)

    # Build CTs boolean arrays (4 entries, true = active)
    cts = [False] * NEURIO_CTS_COUNT
    inverted = [False] * NEURIO_CTS_COUNT
    if ct_locations:
        for i, loc_str in enumerate(ct_locations[:NEURIO_CTS_COUNT]):
            loc_str = loc_str.strip().lower()
            if loc_str != "none" and loc_str != "invalid":
                cts[i] = True

    # Map location string to config.json format
    config_location = CONFIG_LOCATION_MAP.get(location.strip().lower(), location)

    return {
        "location": config_location,
        "type": meter_type,
        "cts": cts,
        "inverted": inverted,
        "connection": {
            "ip_address": ip_address,
            "port": 443,
            "short_id": short_id,
            "device_serial": serial,
            "neurio_connected": True,
            "https_conf": {
                "client_cert": "/var/lib/neurio/neurio.crt",
                "client_key": "/var/lib/neurio/neurio.key",
                "server_ca_cert": "/etc/neurio-ca.crt",
                "server_name": server_name,
                "max_idle_conns_per_host": 1,
            },
        },
        "real_power_scale_factor": scale_factor,
    }


def _get_meter_serial(meter: dict) -> str:
    """Extract serial from a meter entry (could be at top level or in connection)."""
    return (meter.get("connection", {}).get("device_serial", "")
            or meter.get("serial", ""))


def write_meter_to_config(api: TeslaInverterBearerAPI, meter_entry: dict) -> bool:
    """
    Write a meter entry into config.json via FileStore API.

    Adds the meter to the 'meters' array, replacing any existing entry
    with the same device_serial.
    """
    serial = meter_entry["connection"]["device_serial"]

    def modify_config(config: dict) -> dict:
        meters = config.get("meters", [])

        # Remove any existing entry for this serial
        meters = [m for m in meters if _get_meter_serial(m) != serial]

        # Add new entry
        meters.append(meter_entry)
        config["meters"] = meters

        return config

    return api.read_and_update_config(modify_config)


def remove_meter_from_config(api: TeslaInverterBearerAPI, serial: str) -> bool:
    """Remove a meter entry from config.json by serial number."""

    def modify_config(config: dict) -> dict:
        meters = config.get("meters", [])
        original_count = len(meters)
        meters = [m for m in meters if _get_meter_serial(m) != serial]
        config["meters"] = meters

        if len(meters) == original_count:
            print(f"  Note: serial {serial} was not found in config.json meters array")

        return config

    return api.read_and_update_config(modify_config)


# ============================================================
# Neurio Meter TEDAPI operations
# ============================================================

CONNECTION_STATUS_NAMES = {
    0: "INVALID",
    1: "NO_COMMS",
    2: "PAIRING",
    3: "CONNECTED",
    4: "CONFIG_CHANGE_UNDERWAY",
}

CONNECTION_ERROR_NAMES = {
    0: "INVALID",
    1: "NONE",
    2: "UNKNOWN",
    3: "WIFI_AP",
    4: "PAIRING_COMMAND",
    5: "REBOOT_COMMAND",
}


def send_neurio_request(api: TeslaInverterBearerAPI, setup_fn) -> tedapi_pb2.Message:
    """
    Send a TEDAPI message with neuriometer payload.

    setup_fn receives the MessageEnvelope's neuriometer field and should
    populate the desired oneof (addMeterRequest, removeMeterRequest, etc.).
    Returns the full response Message.
    """
    pb = tedapi_pb2.Message()
    pb.message.deliveryChannel = tedapi_pb2.DELIVERY_CHANNEL_LOCAL_HTTPS
    pb.message.sender.local = tedapi_pb2.LOCAL_PARTICIPANT_INSTALLER
    pb.message.recipient.din = api.get_din()

    # Let caller populate the neuriometer oneof
    setup_fn(pb.message.neuriometer)

    pb.tail.value = 1

    response = api._send_message(pb)

    # Check for error response
    payload_type = response.message.WhichOneof('payload')
    if payload_type == 'common':
        msg_type = response.message.common.WhichOneof('message')
        if msg_type == 'errorResponse':
            error = response.message.common.errorResponse
            raise Exception(
                f"Gateway error (code {error.status.code}): {error.status.message}"
            )

    return response


def add_meter(api: TeslaInverterBearerAPI, short_id: str, serial: str,
              ct_locations: list[str] | None = None) -> dict:
    """
    Add a Neurio meter via TEDAPI addMeterRequest.

    This registers the meter identity (shortId + serial) with the gateway.
    For WiFi meters on the home network, you ALSO need to write the
    connection config to config.json (see write_meter_to_config).
    """
    def setup(neurio):
        req = neurio.addMeterRequest
        req.config.shortId = short_id
        req.config.serial = serial

        if ct_locations:
            for loc_str in ct_locations:
                ct = req.config.ctConfig.add()
                ct.location = parse_ct_location(loc_str)
                ct.realPowerScaleFactor = 1.0

    response = send_neurio_request(api, setup)

    payload_type = response.message.WhichOneof('payload')
    if payload_type == 'neuriometer':
        msg_type = response.message.neuriometer.WhichOneof('message')
        if msg_type == 'addMeterResponse':
            resp = response.message.neuriometer.addMeterResponse
            result = {
                "shortId": resp.config.shortId,
                "serial": resp.config.serial,
                "ctConfig": [],
            }
            for ct in resp.config.ctConfig:
                result["ctConfig"].append({
                    "location": CT_LOCATION_NAMES.get(ct.location, str(ct.location)),
                    "realPowerScaleFactor": ct.realPowerScaleFactor,
                })
            return result

    raise Exception(f"Unexpected response payload: {payload_type}")


def remove_meter(api: TeslaInverterBearerAPI, serial: str):
    """Remove a Neurio meter via TEDAPI removeMeterRequest."""
    def setup(neurio):
        neurio.removeMeterRequest.serial = serial

    response = send_neurio_request(api, setup)

    payload_type = response.message.WhichOneof('payload')
    if payload_type == 'neuriometer':
        msg_type = response.message.neuriometer.WhichOneof('message')
        if msg_type == 'removeMeterResponse':
            return True

    raise Exception(f"Unexpected response payload: {payload_type}")


def configure_cts(api: TeslaInverterBearerAPI, serial: str,
                  ct_locations: list[str],
                  scale_factors: list[float] | None = None) -> list[dict]:
    """Configure CT locations on a registered Neurio meter via TEDAPI."""
    if scale_factors is None:
        scale_factors = [1.0] * len(ct_locations)

    def setup(neurio):
        req = neurio.configureCtsRequest
        req.serial = serial
        for loc_str, scale in zip(ct_locations, scale_factors):
            ct = req.ctConfig.add()
            ct.location = parse_ct_location(loc_str)
            ct.realPowerScaleFactor = scale

    response = send_neurio_request(api, setup)

    payload_type = response.message.WhichOneof('payload')
    if payload_type == 'neuriometer':
        msg_type = response.message.neuriometer.WhichOneof('message')
        if msg_type == 'configureCtsResponse':
            resp = response.message.neuriometer.configureCtsResponse
            result = []
            for ct in resp.ctConfig:
                result.append({
                    "location": CT_LOCATION_NAMES.get(ct.location, str(ct.location)),
                    "realPowerScaleFactor": ct.realPowerScaleFactor,
                })
            return result

    raise Exception(f"Unexpected response payload: {payload_type}")


# ============================================================
# CLI Commands
# ============================================================

def make_api(args) -> TeslaInverterBearerAPI:
    """Create and login an API client from CLI args."""
    api = TeslaInverterBearerAPI(host=args.host, password=args.password)
    api.login()
    return api


def cmd_add(args):
    """Add a Neurio meter (TEDAPI + optional config.json for WiFi)."""
    api = make_api(args)
    print(f"DIN: {api.get_din()}")
    print(f"Adding meter: shortId={args.short_id} serial={args.serial}")

    ct_locations = args.cts.split(",") if args.cts else None
    if ct_locations:
        print(f"  CT locations: {ct_locations}")

    try:
        # Step 1: TEDAPI addMeter (register meter identity)
        # Note: APK does removeMeter first then addMeter (idempotent re-add)
        print("\nStep 1: TEDAPI addMeter (register meter identity)...")
        try:
            remove_meter(api, args.serial)
            print("  (Removed existing meter entry first)")
        except Exception:
            pass  # OK if not already registered

        result = add_meter(api, args.short_id, args.serial, ct_locations)
        print("  Meter registered via TEDAPI!")
        print(f"    Short ID: {result['shortId']}")
        print(f"    Serial:   {result['serial']}")
        if result['ctConfig']:
            print("    CTs:")
            for i, ct in enumerate(result['ctConfig']):
                print(f"      [{i}] {ct['location']} (scale={ct['realPowerScaleFactor']})")

        # Step 2: Write config.json WiFi connection details (if --ip provided)
        if args.ip:
            print(f"\nStep 2: Writing WiFi connection to config.json...")
            meter_type = args.meter_type or get_meter_type(args.serial, is_wifi=True)
            location = args.location or "site"
            print(f"  Meter type: {meter_type}")
            print(f"  Location:   {location}")
            print(f"  IP address: {args.ip}")
            if args.mac:
                print(f"  MAC (TLS):  {args.mac}")

            meter_entry = build_wifi_meter_config(
                short_id=args.short_id,
                serial=args.serial,
                ip_address=args.ip,
                ct_locations=ct_locations,
                meter_type=meter_type,
                location=location,
                mac=args.mac,
            )

            print(f"\n  Config entry:")
            print(f"  {json.dumps(meter_entry, indent=4)}")

            success = write_meter_to_config(api, meter_entry)
            if success:
                print("\n  Config.json updated successfully!")
            else:
                print("\n  WARNING: Config.json update may have failed")
        else:
            print("\nNo --ip provided, skipping config.json WiFi connection details.")
            print("(The gateway will only find the Neurio via direct pairing,")
            print(" NOT via your home WiFi network. Use --ip for home WiFi.)")

    except Exception as e:
        print(f"\nFailed to add meter: {e}")
    finally:
        api.logout()


def cmd_write_config(args):
    """Write ONLY the config.json meter entry (skip TEDAPI addMeter)."""
    api = make_api(args)
    print(f"DIN: {api.get_din()}")

    ct_locations = args.cts.split(",") if args.cts else None

    try:
        meter_type = args.meter_type or get_meter_type(args.serial, is_wifi=True)
        location = args.location or "site"
        print(f"Writing WiFi meter config to config.json:")
        print(f"  Short ID:   {args.short_id}")
        print(f"  Serial:     {args.serial}")
        print(f"  IP address: {args.ip}")
        print(f"  Location:   {location}")
        print(f"  Meter type: {meter_type}")
        if args.mac:
            print(f"  MAC (TLS):  {args.mac}")

        meter_entry = build_wifi_meter_config(
            short_id=args.short_id,
            serial=args.serial,
            ip_address=args.ip,
            ct_locations=ct_locations,
            meter_type=meter_type,
            location=location,
            mac=args.mac,
        )

        print(f"\n  Config entry:")
        print(f"  {json.dumps(meter_entry, indent=4)}")

        success = write_meter_to_config(api, meter_entry)
        if success:
            print("\n  Config.json updated successfully!")
        else:
            print("\n  WARNING: Config.json update may have failed")

    except Exception as e:
        print(f"Failed to write config: {e}")
    finally:
        api.logout()


def cmd_remove(args):
    """Remove a Neurio meter (TEDAPI + config.json)."""
    api = make_api(args)
    print(f"DIN: {api.get_din()}")
    print(f"Removing meter: serial={args.serial}")

    try:
        # Step 1: TEDAPI removeMeter
        print("\nStep 1: TEDAPI removeMeter...")
        try:
            remove_meter(api, args.serial)
            print("  Meter removed via TEDAPI!")
        except Exception as e:
            print(f"  TEDAPI remove failed (may not be registered): {e}")

        # Step 2: Remove from config.json
        print("\nStep 2: Removing from config.json...")
        success = remove_meter_from_config(api, args.serial)
        if success:
            print("  Config.json updated!")

    except Exception as e:
        print(f"Failed to remove meter: {e}")
    finally:
        api.logout()


def cmd_configure_cts(args):
    """Configure CTs on a meter."""
    api = make_api(args)
    print(f"DIN: {api.get_din()}")

    ct_locations = args.cts.split(",")
    print(f"Configuring CTs on serial={args.serial}: {ct_locations}")

    scale_factors = None
    if args.scales:
        scale_factors = [float(s) for s in args.scales.split(",")]

    try:
        result = configure_cts(api, args.serial, ct_locations, scale_factors)
        print("CTs configured successfully!")
        for i, ct in enumerate(result):
            print(f"  [{i}] {ct['location']} (scale={ct['realPowerScaleFactor']})")
    except Exception as e:
        print(f"Failed to configure CTs: {e}")
    finally:
        api.logout()


def cmd_status(args):
    """Show meter status from config.json."""
    api = make_api(args)
    print(f"DIN: {api.get_din()}")

    try:
        config, config_hash = api.get_config()

        # Look for meter-related config sections
        meters = config.get("meters", [])
        neurio = config.get("neurio_meters", [])

        if meters:
            print(f"\nMeters ({len(meters)}):")
            for i, meter in enumerate(meters):
                mtype = meter.get("type", "unknown")
                location = meter.get("location", "?")
                conn = meter.get("connection", meter.get("confConnection", {}))
                serial = conn.get("device_serial", meter.get("serial", "unknown"))
                short_id = conn.get("short_id", meter.get("shortId", "?"))
                ip = conn.get("ip_address", "none")
                port = conn.get("port", "?")
                connected = conn.get("neurio_connected", False)
                server_name = conn.get("https_conf", {}).get("server_name", "?")
                scale = meter.get("real_power_scale_factor", 1)

                print(f"  [{i}] {mtype}  location={location}  serial={serial}  shortId={short_id}")
                print(f"       IP: {ip}:{port}  connected: {connected}  scale: {scale}")
                print(f"       TLS server_name: {server_name}")

                cts = meter.get("cts", [])
                inverted = meter.get("inverted", [])
                if cts:
                    ct_str = ", ".join(
                        f"CT[{j}]={'ON' if c else 'off'}"
                        + (f"(inv)" if j < len(inverted) and inverted[j] else "")
                        for j, c in enumerate(cts)
                    )
                    print(f"       CTs: {ct_str}")

                if args.verbose:
                    print(f"       Full: {json.dumps(meter, indent=8)}")

        if neurio:
            print(f"\nNeurio Meters ({len(neurio)}):")
            for i, nm in enumerate(neurio):
                print(f"  [{i}] {json.dumps(nm, indent=6)}")

        # Also check for any meter references in the full config
        meter_keys = [k for k in config.keys() if "meter" in k.lower() or "neurio" in k.lower()]
        if meter_keys:
            other_keys = [k for k in meter_keys if k not in ("meters", "neurio_meters")]
            if other_keys:
                print(f"\nOther meter-related config keys:")
                for key in other_keys:
                    print(f"  {key}: {json.dumps(config[key], indent=4)}")

        if not meters and not neurio and not meter_keys:
            print("\nNo meter configuration found in config.json")
            print("(This may be expected if no meters have been added yet)")

        # Print full config for inspection if verbose
        if args.verbose:
            print(f"\nFull config.json:")
            print(json.dumps(config, indent=2))

    except Exception as e:
        print(f"Failed to get status: {e}")
    finally:
        api.logout()


def main():
    parser = argparse.ArgumentParser(
        description="Neurio Meter Control via TEDAPI (Bearer Token Auth)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Prerequisites (one-time Neurio WiFi setup):
  1. Power-cycle the Neurio to activate its hotspot (Neurio-XXXXX)
  2. Connect to the Neurio hotspot WiFi
  3. Browse to https://192.168.4.1 (login: admin / OBB serial)
  4. Connect the Neurio to your home WiFi network
  5. Create a DHCP reservation on your router for the Neurio's MAC

Then use this script to register the meter with the gateway:
  - Use 'add --ip ...' for home WiFi meters (RECOMMENDED)
  - Use 'add' without --ip for direct pairing (gateway's own WiFi)

CT Location values: none, site, solar, solar_rgm, battery, load, conductor

Meter types (auto-detected from serial, override with --meter-type):
  neurio_tcp    - Original Neurio over WiFi/TCP (OBB serial)
  neurio_w2_tcp - Neurio W2/PWRview over WiFi/TCP (V serial)
  neurio_mb     - Original Neurio wired/Modbus
  neurio_w2_mb  - Neurio W2/PWRview wired/Modbus
""",
    )
    parser.add_argument("--host", required=False, help="Gateway IP address")
    parser.add_argument("--password", required=False, help="QR code password")

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # add (TEDAPI + optional config.json)
    sub_add = subparsers.add_parser("add", help="Add a Neurio meter (TEDAPI + WiFi config)")
    sub_add.add_argument("--short-id", required=True, help="5-digit Neurio short ID (from sticker)")
    sub_add.add_argument("--serial", required=True, help="Serial number (OBB or V prefix, from sticker)")
    sub_add.add_argument("--ip", help="Neurio IP on home network (enables WiFi connection in config.json)")
    sub_add.add_argument("--mac", help="Neurio MAC address for TLS (dash-separated, e.g. 04-71-4b-08-81-5b)")
    sub_add.add_argument("--location", default="site", help="Meter role: site, solar, solarRGM, etc. (default: site)")
    sub_add.add_argument("--cts", help="Comma-separated CT locations (e.g. site,solar,none,none)")
    sub_add.add_argument("--meter-type", help="Override meter type (default: auto-detect from serial)")
    sub_add.set_defaults(func=cmd_add)

    # write-config (config.json only, no TEDAPI)
    sub_wc = subparsers.add_parser("write-config", help="Write ONLY config.json meter entry (skip TEDAPI)")
    sub_wc.add_argument("--short-id", required=True, help="5-digit Neurio short ID")
    sub_wc.add_argument("--serial", required=True, help="Serial number")
    sub_wc.add_argument("--ip", required=True, help="Neurio IP on home network")
    sub_wc.add_argument("--mac", help="Neurio MAC address for TLS (dash-separated, e.g. 04-71-4b-08-81-5b)")
    sub_wc.add_argument("--location", default="site", help="Meter role: site, solar, solarRGM, etc. (default: site)")
    sub_wc.add_argument("--cts", help="Comma-separated CT locations (e.g. site,solar,none,none)")
    sub_wc.add_argument("--meter-type", help="Override meter type (default: auto-detect from serial)")
    sub_wc.set_defaults(func=cmd_write_config)

    # remove (TEDAPI + config.json)
    sub_remove = subparsers.add_parser("remove", help="Remove a Neurio meter (TEDAPI + config.json)")
    sub_remove.add_argument("--serial", required=True, help="Serial number of meter to remove")
    sub_remove.set_defaults(func=cmd_remove)

    # configure-cts
    sub_cts = subparsers.add_parser("configure-cts", help="Configure CTs on a meter")
    sub_cts.add_argument("--serial", required=True, help="Serial number of meter")
    sub_cts.add_argument("--cts", required=True, help="Comma-separated CT locations (e.g. site,solar,none,none)")
    sub_cts.add_argument("--scales", help="Comma-separated scale factors (default: all 1.0)")
    sub_cts.set_defaults(func=cmd_configure_cts)

    # status
    sub_status = subparsers.add_parser("status", help="Show meter config from config.json")
    sub_status.add_argument("-v", "--verbose", action="store_true", help="Show full config.json")
    sub_status.set_defaults(func=cmd_status)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    if not args.host or not args.password:
        parser.error(f"--host and --password are required for '{args.command}'")

    args.func(args)


if __name__ == "__main__":
    main()
