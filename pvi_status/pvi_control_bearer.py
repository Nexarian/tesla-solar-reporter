#!/usr/bin/env python3
"""
PVI Control via TEDAPI over LAN with Bearer Token Auth.

Uses REST API login (/api/login/Basic) to get a Bearer token, then uses
that token to authenticate TEDAPI v1 protobuf requests over the LAN.

No WiFi adapters needed — works over standard LAN routing.

Confirmed working on standalone Tesla Solar Inverters (PVI):
  - REST login with QR code password → Bearer token (Provider_Engineer role)
  - Bearer token authenticates /tedapi/v1 protobuf requests
  - AuthEnvelope wrapper with EXTERNAL_AUTH_TYPE_PRESENCE is required

Requirements:
    pip install requests protobuf

Usage:
    python pvi_control_bearer.py --host IP --password PWD status
    python pvi_control_bearer.py --host IP --password PWD on
    python pvi_control_bearer.py --host IP --password PWD off
    python pvi_control_bearer.py --host IP --password PWD dc_only
    python pvi_control_bearer.py --host IP --password PWD config
    python pvi_control_bearer.py --host IP --password PWD network
    python pvi_control_bearer.py --host IP --password PWD clients
"""
from __future__ import annotations

import argparse
import json
import gzip
import struct
import socket
import sys
import time
import requests
import urllib3
from copy import deepcopy
from typing import Literal, Callable

try:
    import tedapi_pb2
except ImportError:
    print("ERROR: tedapi_pb2.py not found!")
    print("Compile with: python -m grpc_tools.protoc --python_out=. --proto_path=. tedapi_APK_VERIFIED.proto")
    sys.exit(1)

try:
    from pvi_static_rules import apply_pvi_static_rules
except ImportError:
    print("WARNING: pvi_static_rules.py not found, static rules will be skipped")
    apply_pvi_static_rules = None

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PVIStatus = Literal["on", "off", "dc_only", "unset"]


class TeslaInverterBearerAPI:
    """
    Tesla PVI TEDAPI client using Bearer token auth over LAN.

    Flow:
    1. POST /api/login/Basic with QR code password → Bearer token
    2. Use Bearer token in Authorization header for /tedapi/v1
    3. All TEDAPI messages wrapped in AuthEnvelope (PRESENCE type)
    """

    def __init__(self, host: str, password: str, name: str = "", timeout: int = 10):
        self.host = host
        self.password = password
        self.name = name or host
        self.timeout = timeout
        self.base_url = f"https://{host}"
        self.din = None
        self.token = None
        self.token_acquired_at = None

        self.session = requests.Session()
        self.session.verify = False

    def login(self) -> str:
        """Login via REST API to get Bearer token."""
        resp = self.session.post(
            f"{self.base_url}/api/login/Basic",
            json={
                "username": "installer",
                "password": self.password,
                "email": "installer@tesla.com",
                "clientInfo": {"timezone": "America/Los_Angeles"},
            },
            timeout=self.timeout,
        )
        if not resp.ok:
            raise Exception(f"Login failed: HTTP {resp.status_code} - {resp.text[:200]}")

        data = resp.json()
        self.token = data.get("token", "")
        if not self.token:
            raise Exception(f"No token in login response: {data}")

        self.token_acquired_at = time.monotonic()
        print(f"Token acquired ({len(self.token)} chars, opaque)")

        return self.token

    def logout(self):
        """Logout to end session."""
        if not self.token:
            return
        try:
            self.session.get(
                f"{self.base_url}/api/logout",
                headers={"Authorization": f"Bearer {self.token}"},
                timeout=self.timeout,
            )
        except Exception:
            pass
        finally:
            self.token = None

    def get_din(self) -> str:
        """Get device DIN using Bearer token."""
        if self.din:
            return self.din

        if not self.token:
            self.login()

        resp = self.session.get(
            f"{self.base_url}/tedapi/din",
            headers={"Authorization": f"Bearer {self.token}"},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        self.din = resp.text.strip()
        return self.din

    def _decompress_response(self, data: bytes) -> bytes:
        """Decompress gzip response if needed."""
        if len(data) >= 2 and data[0] == 0x1F and data[1] == 0x8B:
            return gzip.decompress(data)
        return data

    def _send_message(self, pb_message: tedapi_pb2.Message, _retried: bool = False) -> tedapi_pb2.Message:
        """Send TEDAPI message wrapped in AuthEnvelope, authenticated with Bearer token."""
        if not self.token:
            self.login()

        url = f"{self.base_url}/tedapi/v1"

        # Wrap in AuthEnvelope (required even with Bearer token)
        auth_env = tedapi_pb2.AuthEnvelope()
        auth_env.payload = pb_message.message.SerializeToString()
        auth_env.externalAuth.type = tedapi_pb2.EXTERNAL_AUTH_TYPE_PRESENCE
        data = auth_env.SerializeToString()

        response = self.session.post(
            url,
            data=data,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/octet-stream",
            },
            timeout=self.timeout,
        )

        # Auto-relogin on expired token
        if response.status_code in (401, 403) and not _retried:
            age = time.monotonic() - self.token_acquired_at if self.token_acquired_at else 0
            mins, secs = divmod(int(age), 60)
            hours, mins = divmod(mins, 60)
            print(f"Token expired after {hours}h {mins}m {secs}s, re-logging in...")
            self.login()
            return self._send_message(pb_message, _retried=True)

        response.raise_for_status()
        response_data = self._decompress_response(response.content)

        auth_response = tedapi_pb2.AuthEnvelope()
        auth_response.ParseFromString(response_data)

        result = tedapi_pb2.Message()
        result.message.ParseFromString(auth_response.payload)

        return result

    # =================================================================
    # FileStore API (config read/write)
    # =================================================================

    def get_config(self) -> tuple[dict, bytes]:
        """Read config.json via FileStore readFileRequest."""
        pb = tedapi_pb2.Message()
        pb.message.deliveryChannel = tedapi_pb2.DELIVERY_CHANNEL_LOCAL_HTTPS
        pb.message.sender.local = tedapi_pb2.LOCAL_PARTICIPANT_INSTALLER
        pb.message.recipient.din = self.get_din()
        pb.message.filestore.readFileRequest.domain = tedapi_pb2.FILE_STORE_API_DOMAIN_CONFIG_JSON
        pb.message.filestore.readFileRequest.name = "config.json"
        pb.tail.value = 1

        response = self._send_message(pb)

        payload_type = response.message.WhichOneof('payload')
        if payload_type == 'filestore':
            msg_type = response.message.filestore.WhichOneof('message')
            if msg_type == 'readFileResponse':
                resp = response.message.filestore.readFileResponse
                config_hash = resp.hash if resp.hash else None
                json_data = resp.file.blob.decode('utf-8')
                return json.loads(json_data), config_hash

        elif payload_type == 'common':
            if response.message.common.WhichOneof('message') == 'errorResponse':
                error = response.message.common.errorResponse
                raise Exception(f"Error reading config (code {error.status.code}): {error.status.message}")

        raise Exception(f"Unexpected payload type: {payload_type}")

    def update_config(self, config: dict, config_hash: bytes) -> bool:
        """Write config.json via FileStore updateFileRequest."""
        if not config_hash:
            raise ValueError("No config hash available")

        config_bytes = json.dumps(config).encode('utf-8')

        pb = tedapi_pb2.Message()
        pb.message.deliveryChannel = tedapi_pb2.DELIVERY_CHANNEL_LOCAL_HTTPS
        pb.message.sender.local = tedapi_pb2.LOCAL_PARTICIPANT_INSTALLER
        pb.message.recipient.din = self.get_din()
        pb.message.filestore.updateFileRequest.domain = tedapi_pb2.FILE_STORE_API_DOMAIN_CONFIG_JSON
        pb.message.filestore.updateFileRequest.file.name = "config.json"
        pb.message.filestore.updateFileRequest.file.blob = config_bytes
        pb.message.filestore.updateFileRequest.hash = config_hash
        pb.tail.value = 1

        response = self._send_message(pb)

        payload_type = response.message.WhichOneof('payload')
        if payload_type == 'filestore':
            msg_type = response.message.filestore.WhichOneof('message')
            if msg_type == 'updateFileResponse':
                return True
            return True

        elif payload_type == 'common':
            if response.message.common.WhichOneof('message') == 'errorResponse':
                error = response.message.common.errorResponse
                raise Exception(f"Config update error (code {error.status.code}): {error.status.message}")

        raise Exception(f"Unexpected response: {payload_type}")

    def read_and_update_config(self, modify_fn: Callable[[dict], dict], retries: int = 3) -> bool:
        """Read config, apply modification, write back with CAS hash."""
        try:
            config, config_hash = self.get_config()

            original_config = deepcopy(config)
            modified_config = modify_fn(deepcopy(config))

            if original_config == modified_config:
                print("  No changes needed")
                return True

            return self.update_config(modified_config, config_hash)

        except Exception as e:
            error_str = str(e)
            if retries > 0 and ("code 10" in error_str or "ABORTED" in error_str):
                print(f"  Config conflict (ABORTED), retrying... ({retries} left)")
                return self.read_and_update_config(modify_fn, retries - 1)
            raise

    # =================================================================
    # PVI Power Control
    # =================================================================

    def set_pvi_status(self, status: PVIStatus, inverter_din: str = None) -> bool:
        """Set PVI power status with static rules applied."""
        valid_statuses = ["on", "off", "dc_only", "unset"]
        if status not in valid_statuses:
            raise ValueError(f"Invalid status. Must be one of: {valid_statuses}")

        def modify_pvi_status(config: dict) -> dict:
            if "solars" not in config or not config["solars"]:
                raise ValueError("No solar inverters found in config")

            updated = False
            for solar in config["solars"]:
                if inverter_din is None or solar.get("din") == inverter_din:
                    old_status = solar.get("pvi_power_status", "unknown")
                    solar["pvi_power_status"] = status
                    updated = True
                    print(f"  {solar.get('din', 'unknown')}: {old_status} -> {status}")

            if not updated:
                raise ValueError("No matching inverters found")

            if apply_pvi_static_rules:
                config = apply_pvi_static_rules(config)

            return config

        return self.read_and_update_config(modify_pvi_status)

    def get_pvi_status(self) -> list[dict]:
        """Read current PVI status from config."""
        config, _ = self.get_config()

        if "solars" not in config or not config["solars"]:
            return []

        results = []
        for solar in config["solars"]:
            results.append({
                "din": solar.get("din", "unknown"),
                "brand": solar.get("brand", "unknown"),
                "model": solar.get("model", "unknown"),
                "pvi_power_status": solar.get("pvi_power_status", "unknown"),
                "nameplate_max_ac_power": solar.get("nameplate_max_ac_power"),
            })
        return results

    # =================================================================
    # Device Status (GraphQL query - like pypowerwall get_status)
    # =================================================================

    # GraphQL query from pypowerwall - comprehensive device status
    DEVICE_STATUS_QUERY = """ query DeviceControllerQuery {
  control {
    systemStatus {
        nominalFullPackEnergyWh
        nominalEnergyRemainingWh
    }
    islanding {
        customerIslandMode
        contactorClosed
        microGridOK
        gridOK
    }
    meterAggregates {
      location
      realPowerW
    }
    alerts {
      active
    },
    siteShutdown {
      isShutDown
      reasons
    }
    batteryBlocks {
      din
      disableReasons
    }
    pvInverters {
      din
      disableReasons
    }
  }
  system {
    time
    sitemanagerStatus {
      isRunning
    }
    updateUrgencyCheck  {
      urgency
      version {
        version
        gitHash
      }
      timestamp
    }
  }
  neurio {
    isDetectingWiredMeters
    readings {
      serial
      dataRead {
        voltageV
        realPowerW
        reactivePowerVAR
        currentA
      }
      timestamp
    }
    pairings {
      serial
      shortId
      status
      errors
      macAddress
      isWired
      modbusPort
      modbusId
      lastUpdateTimestamp
    }
  }
  pw3Can {
    firmwareUpdate {
      isUpdating
      progress {
         updating
         numSteps
         currentStep
         currentStepProgress
         progress
      }
    }
  }
  esCan {
    bus {
      PVAC {
        packagePartNumber
        packageSerialNumber
        subPackagePartNumber
        subPackageSerialNumber
        PVAC_Status {
          isMIA
          PVAC_Pout
          PVAC_State
          PVAC_Vout
          PVAC_Fout
        }
        PVAC_InfoMsg {
          PVAC_appGitHash
        }
        PVAC_Logging {
          isMIA
          PVAC_PVCurrent_A
          PVAC_PVCurrent_B
          PVAC_PVCurrent_C
          PVAC_PVCurrent_D
          PVAC_PVMeasuredVoltage_A
          PVAC_PVMeasuredVoltage_B
          PVAC_PVMeasuredVoltage_C
          PVAC_PVMeasuredVoltage_D
          PVAC_VL1Ground
          PVAC_VL2Ground
        }
        alerts {
          isComplete
          isMIA
          active
        }
      }
      PINV {
        PINV_Status {
          isMIA
          PINV_Fout
          PINV_Pout
          PINV_Vout
          PINV_State
          PINV_GridState
        }
        PINV_AcMeasurements {
          isMIA
          PINV_VSplit1
          PINV_VSplit2
        }
        PINV_PowerCapability {
          isComplete
          isMIA
          PINV_Pnom
        }
        alerts {
          isComplete
          isMIA
          active
        }
      }
      PVS {
        PVS_Status {
          isMIA
          PVS_State
          PVS_vLL
          PVS_StringA_Connected
          PVS_StringB_Connected
          PVS_StringC_Connected
          PVS_StringD_Connected
          PVS_SelfTestState
        }
        alerts {
          isComplete
          isMIA
          active
        }
      }
      THC {
        packagePartNumber
        packageSerialNumber
        THC_InfoMsg {
          isComplete
          isMIA
          THC_appGitHash
        }
        THC_Logging {
          THC_LOG_PW_2_0_EnableLineState
        }
      }
      POD {
        POD_EnergyStatus {
          isMIA
          POD_nom_energy_remaining
          POD_nom_full_pack_energy
        }
        POD_InfoMsg {
            POD_appGitHash
        }
      }
      MSA {
        packagePartNumber
        packageSerialNumber
        MSA_InfoMsg {
          isMIA
          MSA_appGitHash
          MSA_assemblyId
        }
        METER_Z_AcMeasurements {
          isMIA
          lastRxTime
          METER_Z_CTA_InstRealPower
          METER_Z_CTA_InstReactivePower
          METER_Z_CTA_I
          METER_Z_VL1G
          METER_Z_CTB_InstRealPower
          METER_Z_CTB_InstReactivePower
          METER_Z_CTB_I
          METER_Z_VL2G
        }
        MSA_Status {
          lastRxTime
        }
      }
      SYNC {
        packagePartNumber
        packageSerialNumber
        SYNC_InfoMsg {
          isMIA
          SYNC_appGitHash
        }
        METER_X_AcMeasurements {
          isMIA
          isComplete
          lastRxTime
          METER_X_CTA_InstRealPower
          METER_X_CTA_InstReactivePower
          METER_X_CTA_I
          METER_X_VL1N
          METER_X_CTB_InstRealPower
          METER_X_CTB_InstReactivePower
          METER_X_CTB_I
          METER_X_VL2N
          METER_X_CTC_InstRealPower
          METER_X_CTC_InstReactivePower
          METER_X_CTC_I
          METER_X_VL3N
        }
        METER_Y_AcMeasurements {
          isMIA
          isComplete
          lastRxTime
          METER_Y_CTA_InstRealPower
          METER_Y_CTA_InstReactivePower
          METER_Y_CTA_I
          METER_Y_VL1N
          METER_Y_CTB_InstRealPower
          METER_Y_CTB_InstReactivePower
          METER_Y_CTB_I
          METER_Y_VL2N
          METER_Y_CTC_InstRealPower
          METER_Y_CTC_InstReactivePower
          METER_Y_CTC_I
          METER_Y_VL3N
        }
        SYNC_Status {
          lastRxTime
        }
      }
      ISLANDER {
        ISLAND_GridConnection {
          ISLAND_GridConnected
          isComplete
        }
        ISLAND_AcMeasurements {
          ISLAND_VL1N_Main
          ISLAND_FreqL1_Main
          ISLAND_VL2N_Main
          ISLAND_FreqL2_Main
          ISLAND_VL3N_Main
          ISLAND_FreqL3_Main
          ISLAND_VL1N_Load
          ISLAND_FreqL1_Load
          ISLAND_VL2N_Load
          ISLAND_FreqL2_Load
          ISLAND_VL3N_Load
          ISLAND_FreqL3_Load
          ISLAND_GridState
          lastRxTime
          isComplete
          isMIA
        }
      }
    }
    enumeration {
      inProgress
      numACPW
      numPVI
    }
    firmwareUpdate {
      isUpdating
      powerwalls {
        updating
        numSteps
        currentStep
        currentStepProgress
        progress
      }
      msa {
        updating
        numSteps
        currentStep
        currentStepProgress
        progress
      }
      sync {
        updating
        numSteps
        currentStep
        currentStepProgress
        progress
      }
      pvInverters {
        updating
        numSteps
        currentStep
        currentStepProgress
        progress
      }
    }
    phaseDetection {
      inProgress
      lastUpdateTimestamp
      powerwalls {
        din
        progress
        phase
      }
    }
    inverterSelfTests {
      isRunning
      isCanceled
      pinvSelfTestsResults {
        din
        overall {
          status
          test
          summary
          setMagnitude
          setTime
          tripMagnitude
          tripTime
          accuracyMagnitude
          accuracyTime
          currentMagnitude
          timestamp
          lastError
        }
        testResults {
          status
          test
          summary
          setMagnitude
          setTime
          tripMagnitude
          tripTime
          accuracyMagnitude
          accuracyTime
          currentMagnitude
          timestamp
          lastError
        }
      }
    }
  }
}
"""

    # Query signature from pypowerwall (ECDSA sig matching the query above)
    DEVICE_STATUS_CODE = (
        b'0\201\206\002A\024\261\227\245\177\255\265\272\321r\032\250\275j'
        b'\305\030\2300\266\022B\242\264pO\262\024vd\267\316\032\f\376\322V'
        b'\001\f\177*\366\345\333g_/`\v\026\225_qc\023$\323\216y\276~\335A1'
        b'\022x\002Ap\a_\264\037]\304>\362\356\005\245V\301\177*\b\307\016'
        b'\246]\037\202\242\353I~\332\317\021\336\006\033q\317\311\264\315'
        b'\374\036\365s\272\225\215#o!\315z\353\345z\226\365\341\f\265\256r'
        b'\373\313/\027\037'
    )

    def get_status(self) -> dict:
        """
        Get comprehensive device status via GraphQL query.

        Returns a dict with: control, system, neurio, pw3Can, esCan sections.
        This is the same query used by pypowerwall's get_status().
        """
        pb = tedapi_pb2.Message()
        pb.message.deliveryChannel = tedapi_pb2.DELIVERY_CHANNEL_LOCAL_HTTPS
        pb.message.sender.local = tedapi_pb2.LOCAL_PARTICIPANT_INSTALLER
        pb.message.recipient.din = self.get_din()

        pb.message.graphql.send.num = 2
        pb.message.graphql.send.payload.value = 1
        pb.message.graphql.send.payload.text = self.DEVICE_STATUS_QUERY
        pb.message.graphql.send.code = self.DEVICE_STATUS_CODE
        pb.message.graphql.send.b.value = "{}"

        pb.tail.value = 1

        response = self._send_message(pb)

        payload_type = response.message.WhichOneof('payload')
        if payload_type == 'graphql':
            msg_type = response.message.graphql.WhichOneof('message')
            if msg_type == 'recv':
                text = response.message.graphql.recv.text
                return json.loads(text)

        elif payload_type == 'common':
            if response.message.common.WhichOneof('message') == 'errorResponse':
                error = response.message.common.errorResponse
                raise Exception(f"Error (code {error.status.code}): {error.status.message}")

        raise Exception(f"Unexpected response payload: {payload_type}")

    # =================================================================
    # Network Status
    # =================================================================

    @staticmethod
    def _fixed32_to_ip(val: int) -> str:
        if val == 0:
            return "0.0.0.0"
        return socket.inet_ntoa(struct.pack('!I', val))

    @staticmethod
    def _format_mac(mac_bytes: bytes) -> str:
        if not mac_bytes:
            return "unknown"
        return ":".join(f"{b:02x}" for b in mac_bytes)

    def get_networking_status(self):
        """Query networking status (WiFi, Ethernet, GSM)."""
        pb = tedapi_pb2.Message()
        pb.message.deliveryChannel = tedapi_pb2.DELIVERY_CHANNEL_LOCAL_HTTPS
        pb.message.sender.local = tedapi_pb2.LOCAL_PARTICIPANT_INSTALLER
        pb.message.recipient.din = self.get_din()
        pb.message.common.getNetworkingStatusRequest.CopyFrom(
            tedapi_pb2.CommonAPIGetNetworkingStatusRequest()
        )
        pb.tail.value = 1

        response = self._send_message(pb)

        payload_type = response.message.WhichOneof('payload')
        if payload_type == 'common':
            msg_type = response.message.common.WhichOneof('message')
            if msg_type == 'getNetworkingStatusResponse':
                return response.message.common.getNetworkingStatusResponse
            elif msg_type == 'errorResponse':
                error = response.message.common.errorResponse
                raise Exception(f"Error (code {error.status.code}): {error.status.message}")

        raise Exception(f"Unexpected response: {payload_type}")

    # =================================================================
    # Authorization / Client listing
    # =================================================================

    STATE_NAMES = {
        0: "INVALID", 1: "PENDING_VERIFICATION",
        2: "PENDING_VERIFICATION_TIMEOUT", 3: "VERIFIED", 4: "REMOVED",
    }
    VERIFY_NAMES = {0: "INVALID", 1: "PRESENCE_PROOF", 4: "HERMES_COMMAND"}
    KEY_TYPE_NAMES = {0: "INVALID", 1: "RSA", 2: "ECC"}
    CLIENT_TYPE_NAMES = {0: "INVALID", 1: "CUSTOMER_MOBILE_APP", 2: "VEHICLE"}

    def list_authorized_clients(self):
        """List authorized clients on this inverter."""
        pb = tedapi_pb2.Message()
        pb.message.deliveryChannel = tedapi_pb2.DELIVERY_CHANNEL_LOCAL_HTTPS
        pb.message.sender.local = tedapi_pb2.LOCAL_PARTICIPANT_INSTALLER
        pb.message.recipient.din = self.get_din()
        pb.message.authorization.listAuthorizedClientsRequest.CopyFrom(
            tedapi_pb2.AuthorizationAPIListAuthorizedClientsRequest()
        )
        pb.tail.value = 1

        response = self._send_message(pb)

        payload_type = response.message.WhichOneof('payload')
        if payload_type == 'authorization':
            msg_type = response.message.authorization.WhichOneof('message')
            if msg_type == 'listAuthorizedClientsResponse':
                return response.message.authorization.listAuthorizedClientsResponse

        elif payload_type == 'common':
            if response.message.common.WhichOneof('message') == 'errorResponse':
                error = response.message.common.errorResponse
                raise Exception(f"Error (code {error.status.code}): {error.status.message}")

        raise Exception(f"Unexpected response: {payload_type}")


# ============================================================
# CLI Commands
# ============================================================

def make_api(args) -> TeslaInverterBearerAPI:
    """Create and login an API client from CLI args."""
    api = TeslaInverterBearerAPI(host=args.host, password=args.password)
    api.login()
    return api


def print_inverter_status(inverters: list[dict]):
    for inv in inverters:
        status = inv['pvi_power_status']
        indicator = "ON" if status == "on" else "OFF" if status == "off" else status.upper()
        print(f"  [{indicator:>7}]  {inv['din']}")
        print(f"            {inv['brand']} {inv['model']}", end="")
        if inv['nameplate_max_ac_power']:
            print(f" ({inv['nameplate_max_ac_power']}W)", end="")
        print()


def cmd_status(args):
    """Show current PVI status."""
    api = make_api(args)
    print(f"DIN: {api.get_din()}")
    inverters = api.get_pvi_status()
    if not inverters:
        print("No solar inverters found in config")
    else:
        print_inverter_status(inverters)
    api.logout()


def cmd_set_power(args):
    """Set PVI power status."""
    api = make_api(args)
    print(f"DIN: {api.get_din()}")
    print(f"Setting PVI -> {args.status}")
    success = api.set_pvi_status(args.status)
    if success:
        print("Updated!")
        print_inverter_status(api.get_pvi_status())
    api.logout()


def cmd_config(args):
    """Dump full config.json."""
    api = make_api(args)
    config, config_hash = api.get_config()
    print(f"DIN:  {api.get_din()}")
    print(f"Hash: {config_hash.hex() if config_hash else 'None'}")
    print(json.dumps(config, indent=2))
    api.logout()


def cmd_network(args):
    """Show network status."""
    api = make_api(args)
    print(f"DIN: {api.get_din()}")
    resp = api.get_networking_status()

    if resp.HasField('wifi'):
        w = resp.wifi
        print(f"WiFi:")
        print(f"  MAC:     {api._format_mac(w.macAddress)}")
        print(f"  Enabled: {w.enabled}")
        print(f"  Active:  {w.activeRoute}")
        if w.HasField('ipv4Config'):
            c = w.ipv4Config
            print(f"  IP:      {api._fixed32_to_ip(c.address)}")
            print(f"  Subnet:  {api._fixed32_to_ip(c.subnetMask)}")
            print(f"  Gateway: {api._fixed32_to_ip(c.gateway)}")
        if w.HasField('connectivityStatus'):
            cs = w.connectivityStatus
            print(f"  Physical: {cs.connectedPhysical}  Internet: {cs.connectedInternet}  Tesla: {cs.connectedTesla}")

    if resp.HasField('wifiConfig'):
        print(f"WiFi SSID: {resp.wifiConfig.ssid}")

    if resp.HasField('eth'):
        e = resp.eth
        print(f"Ethernet:")
        print(f"  MAC:     {api._format_mac(e.macAddress)}")
        print(f"  Enabled: {e.enabled}")
        print(f"  Active:  {e.activeRoute}")
        if e.HasField('ipv4Config'):
            c = e.ipv4Config
            print(f"  IP:      {api._fixed32_to_ip(c.address)}")
            print(f"  Subnet:  {api._fixed32_to_ip(c.subnetMask)}")
            print(f"  Gateway: {api._fixed32_to_ip(c.gateway)}")
        if e.HasField('connectivityStatus'):
            cs = e.connectivityStatus
            print(f"  Physical: {cs.connectedPhysical}  Internet: {cs.connectedInternet}  Tesla: {cs.connectedTesla}")

    if resp.HasField('gsm'):
        print(f"GSM:")
        print(f"  Enabled: {resp.gsm.enabled}")

    api.logout()


def cmd_clients(args):
    """List authorized clients."""
    api = make_api(args)
    print(f"DIN: {api.get_din()}")
    resp = api.list_authorized_clients()

    print(f"Clients: {len(resp.clients)}")
    print(f"enableLineSwitchOff: {resp.enableLineSwitchOff}")

    for i, client in enumerate(resp.clients):
        state = api.STATE_NAMES.get(client.state, str(client.state))
        vtype = api.VERIFY_NAMES.get(client.verification, str(client.verification))
        ctype = api.CLIENT_TYPE_NAMES.get(client.type, str(client.type))
        ktype = api.KEY_TYPE_NAMES.get(client.keyType, str(client.keyType))
        roles = [str(r) for r in client.roles]

        print(f"\n[{i}] {client.description}")
        print(f"    Type: {ctype}, KeyType: {ktype}")
        print(f"    State: {state}, Verification: {vtype}")
        print(f"    Roles: {roles if roles else 'none'}")
        pk_hex = client.publicKey.hex()
        print(f"    PubKey: {pk_hex[:40]}..." if len(pk_hex) > 40 else f"    PubKey: {pk_hex}")

    api.logout()


def cmd_device_status(args):
    """Show comprehensive device status via GraphQL query."""
    api = make_api(args)
    print(f"DIN: {api.get_din()}")

    try:
        data = api.get_status()
    except Exception as e:
        print(f"Error: {e}")
        api.logout()
        return

    section = getattr(args, 'section', None)

    if section:
        # Show specific section
        if section in data:
            print(f"\n{section}:")
            print(json.dumps(data[section], indent=2))
        else:
            print(f"Section '{section}' not found. Available: {list(data.keys())}")
    else:
        # Summary view
        control = data.get("control", {})
        system = data.get("system", {})
        neurio = data.get("neurio", {})

        # System info
        print(f"\nSystem time: {system.get('time', '?')}")
        sm = system.get("sitemanagerStatus", {})
        print(f"Sitemanager running: {sm.get('isRunning', '?')}")
        update = system.get("updateUrgencyCheck", {})
        if update:
            ver = update.get("version", {})
            print(f"Firmware: {ver.get('version', '?')} ({ver.get('gitHash', '?')[:8]})")
            print(f"Update urgency: {update.get('urgency', '?')}")

        # Grid / Islanding
        islanding = control.get("islanding", {})
        if islanding:
            print(f"\nGrid: {'OK' if islanding.get('gridOK') else 'DOWN'}"
                  f"  Contactor: {'CLOSED' if islanding.get('contactorClosed') else 'OPEN'}"
                  f"  MicroGrid: {'OK' if islanding.get('microGridOK') else 'DOWN'}")
            print(f"Island mode: {islanding.get('customerIslandMode', '?')}")

        # Meter aggregates
        meters = control.get("meterAggregates", [])
        if meters:
            print(f"\nMeter Aggregates:")
            for m in meters:
                loc = m.get("location", "?")
                power = m.get("realPowerW", 0)
                print(f"  {loc:>10}: {power:>8.1f} W")

        # Battery
        sys_status = control.get("systemStatus", {})
        if sys_status.get("nominalFullPackEnergyWh"):
            full = sys_status["nominalFullPackEnergyWh"]
            remaining = sys_status.get("nominalEnergyRemainingWh", 0)
            pct = (remaining / full * 100) if full else 0
            print(f"\nBattery: {remaining:.0f} / {full:.0f} Wh ({pct:.1f}%)")

        # Battery blocks
        blocks = control.get("batteryBlocks", [])
        if blocks:
            print(f"Battery blocks: {len(blocks)}")
            for b in blocks:
                reasons = b.get("disableReasons", [])
                status = "DISABLED" if reasons else "OK"
                print(f"  {b.get('din', '?')}: {status}" +
                      (f" ({', '.join(reasons)})" if reasons else ""))

        # PV Inverters
        pvs = control.get("pvInverters", [])
        if pvs:
            print(f"\nPV Inverters: {len(pvs)}")
            for pv in pvs:
                reasons = pv.get("disableReasons", [])
                status = "DISABLED" if reasons else "OK"
                print(f"  {pv.get('din', '?')}: {status}" +
                      (f" ({', '.join(reasons)})" if reasons else ""))

        # Neurio
        if neurio:
            readings = neurio.get("readings", [])
            pairings = neurio.get("pairings", [])
            detecting = neurio.get("isDetectingWiredMeters", False)

            if pairings:
                print(f"\nNeurio Pairings ({len(pairings)}):")
                for p in pairings:
                    wired = "wired" if p.get("isWired") else "WiFi"
                    print(f"  {p.get('serial', '?')} (shortId={p.get('shortId', '?')}) "
                          f"{wired} status={p.get('status', '?')}"
                          f" mac={p.get('macAddress', '?')}")
                    if p.get("errors"):
                        print(f"    errors: {p['errors']}")

            if readings:
                print(f"\nNeurio Readings ({len(readings)}):")
                for r in readings:
                    print(f"  {r.get('serial', '?')}:")
                    for dr in r.get("dataRead", []):
                        print(f"    {dr.get('realPowerW', 0):>8.1f} W  "
                              f"{dr.get('voltageV', 0):>6.1f} V  "
                              f"{dr.get('currentA', 0):>6.2f} A")

            if detecting:
                print(f"  (detecting wired meters...)")

        # Alerts
        alerts = control.get("alerts", {}).get("active", [])
        if alerts:
            print(f"\nActive Alerts ({len(alerts)}):")
            for a in alerts:
                print(f"  - {a}")

        # Site shutdown
        shutdown = control.get("siteShutdown", {})
        if shutdown.get("isShutDown"):
            print(f"\nSITE IS SHUT DOWN! Reasons: {shutdown.get('reasons', [])}")

        if args.verbose:
            print(f"\nFull response:")
            print(json.dumps(data, indent=2))

    api.logout()


def main():
    parser = argparse.ArgumentParser(
        description="Tesla PVI Control via TEDAPI over LAN (Bearer Token Auth)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--host", required=False, help="Inverter IP address")
    parser.add_argument("--password", required=False, help="QR code password")

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # status
    subparsers.add_parser("status", help="Show current PVI status").set_defaults(func=cmd_status)

    # on/off/dc_only/unset
    for pvi_cmd in ["on", "off", "dc_only", "unset"]:
        sub = subparsers.add_parser(pvi_cmd, help=f"Set PVI power to {pvi_cmd}")
        sub.set_defaults(func=cmd_set_power, status=pvi_cmd)

    # device-status (GraphQL query)
    sub_ds = subparsers.add_parser("device-status", help="Comprehensive device status (GraphQL)")
    sub_ds.add_argument("section", nargs="?", help="Show specific section (control, system, neurio, esCan, pw3Can)")
    sub_ds.add_argument("-v", "--verbose", action="store_true", help="Show full JSON response")
    sub_ds.set_defaults(func=cmd_device_status)

    # config
    subparsers.add_parser("config", help="Dump full config.json").set_defaults(func=cmd_config)

    # network
    subparsers.add_parser("network", help="Show network status").set_defaults(func=cmd_network)

    # clients
    subparsers.add_parser("clients", help="List authorized clients").set_defaults(func=cmd_clients)


    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    args.func(args)


if __name__ == "__main__":
    main()
