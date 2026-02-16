#!/usr/bin/env python3
"""
Tesla TEDAPI LAN Client — RSA key pairing + signed routable messages.

Enables TEDAPI access over LAN (not just gateway WiFi) on firmware 25.10+
by using RSA-signed RoutableMessages sent to /tedapi/v1r.

Setup flow:
    1. Authenticate with Tesla (get OAuth token)
    2. Find your energy_site_id
    3. Register RSA key via cloud OR locally
    4. Toggle inverter breaker to verify (PENDING → VERIFIED)
    5. Send signed commands to /tedapi/v1r from any network

Usage:
    # Step 1: Get OAuth token
    python register_local_client.py auth

    # Step 2: Find your site ID
    python register_local_client.py get-sites

    # Step 3a: Register via Tesla cloud (preferred — sends via Hermes)
    python register_local_client.py register-cloud --site-id YOUR_SITE_ID

    # Step 3b: Register locally (must be on gateway WiFi)
    python register_local_client.py --host 192.168.91.1 --password GW_PWD register

    # Step 4: Check verification status
    python register_local_client.py --host 192.168.91.1 --password GW_PWD list
    python register_local_client.py cloud-list --site-id YOUR_SITE_ID

    # Step 5: Test signed message over LAN
    python register_local_client.py --host 192.168.91.1 --din DEVICE_DIN test-signed

    # Remove a registered key
    python register_local_client.py --host 192.168.91.1 --password GW_PWD remove
"""
from __future__ import annotations

import argparse
import base64
import gzip
import json
import math
import sys
import time
import uuid
from pathlib import Path

import requests
import urllib3
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# TEDAPI protos (existing)
import tedapi_pb2

# Vehicle command protos (for RoutableMessage + signing)
import vehicle_command_pb2 as vc

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_KEY_DIR = Path.home() / ".tesla_local_key"
PRIVATE_KEY_FILE = "client_rsa_private.pem"
PUBLIC_KEY_FILE = "client_rsa_public.der"
DESCRIPTION = "Home LAN Client"

STATE_NAMES = {
    0: "INVALID", 1: "PENDING_VERIFICATION",
    2: "PENDING_VERIFICATION_TIMEOUT", 3: "VERIFIED", 4: "REMOVED",
}

# ============================================================
# Key management
# ============================================================

def get_key_dir(key_dir: str | None) -> Path:
    d = Path(key_dir) if key_dir else DEFAULT_KEY_DIR
    d.mkdir(parents=True, exist_ok=True)
    return d


def generate_rsa_key_pair(key_dir: Path, force: bool = False):
    """Generate RSA 4096-bit key pair (DER PKCS1 public key format)."""
    priv_path = key_dir / PRIVATE_KEY_FILE
    pub_path = key_dir / PUBLIC_KEY_FILE

    if priv_path.exists() and not force:
        print(f"Key pair already exists at {key_dir}")
        print("  Use --force-new-key to regenerate")
        return load_rsa_key_pair(key_dir)

    print("Generating RSA 4096-bit key pair...")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

    # Save private key as PEM
    priv_path.write_bytes(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    print(f"  Private key saved: {priv_path}")

    # Save public key as DER PKCS1 (RSAPublicKey format — what Tesla expects)
    pub_der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.PKCS1,
    )
    pub_path.write_bytes(pub_der)
    print(f"  Public key saved:  {pub_path} ({len(pub_der)} bytes)")

    return private_key, pub_der


def load_rsa_key_pair(key_dir: Path):
    """Load existing RSA key pair from disk."""
    priv_path = key_dir / PRIVATE_KEY_FILE
    if not priv_path.exists():
        raise FileNotFoundError(f"No private key at {priv_path}")

    print(f"Loading RSA key pair from {key_dir}...")
    private_key = serialization.load_pem_private_key(
        priv_path.read_bytes(), password=None,
    )

    pub_der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.PKCS1,
    )

    pub_path = key_dir / PUBLIC_KEY_FILE
    if not pub_path.exists():
        pub_path.write_bytes(pub_der)

    print(f"  Public key: {len(pub_der)} bytes")
    return private_key, pub_der


# ============================================================
# Local registration (via WiFi, using existing TEDAPI auth)
# ============================================================

def _make_local_session(host: str, password: str) -> tuple[requests.Session, str, str]:
    """Create an authenticated session and get the DIN."""
    session = requests.Session()
    session.auth = ('Tesla_Energy_Device', password)
    session.verify = False
    session.headers.update({'Content-Type': 'application/octet-stream'})
    base = f"https://{host}"

    resp = session.get(f"{base}/tedapi/din", timeout=10)
    resp.raise_for_status()
    din = resp.text.strip()
    return session, din, base


def _send_local_message(session, base_url, pb_message):
    """Send a TEDAPI message wrapped in AuthEnvelope."""
    auth_env = tedapi_pb2.AuthEnvelope()
    auth_env.payload = pb_message.message.SerializeToString()
    auth_env.externalAuth.type = tedapi_pb2.EXTERNAL_AUTH_TYPE_PRESENCE
    data = auth_env.SerializeToString()

    resp = session.post(f"{base_url}/tedapi/v1", data=data, timeout=10)
    resp.raise_for_status()
    resp_data = resp.content
    if len(resp_data) >= 2 and resp_data[0] == 0x1f and resp_data[1] == 0x8b:
        resp_data = gzip.decompress(resp_data)

    auth_response = tedapi_pb2.AuthEnvelope()
    auth_response.ParseFromString(resp_data)
    result = tedapi_pb2.Message()
    result.message.ParseFromString(auth_response.payload)
    return result


def cmd_register(args):
    """Register RSA key with gateway locally (must be on WiFi)."""
    key_dir = get_key_dir(args.key_dir)
    private_key, pub_der = generate_rsa_key_pair(key_dir, force=args.force_new_key)

    session, din, base = _make_local_session(args.host, args.password)
    print(f"Gateway DIN: {din}\n")

    # Check if already registered
    pb = tedapi_pb2.Message()
    pb.message.deliveryChannel = tedapi_pb2.DELIVERY_CHANNEL_LOCAL_HTTPS
    pb.message.sender.local = tedapi_pb2.LOCAL_PARTICIPANT_INSTALLER
    pb.message.recipient.din = din
    pb.message.authorization.listAuthorizedClientsRequest.CopyFrom(
        tedapi_pb2.AuthorizationAPIListAuthorizedClientsRequest()
    )
    pb.tail.value = 1
    response = _send_local_message(session, base, pb)

    if response.message.WhichOneof('payload') == 'authorization':
        msg_type = response.message.authorization.WhichOneof('message')
        if msg_type == 'listAuthorizedClientsResponse':
            for client in response.message.authorization.listAuthorizedClientsResponse.clients:
                if client.publicKey == pub_der:
                    state = STATE_NAMES.get(client.state, str(client.state))
                    print(f"Key already registered (state: {state})")
                    if client.state == 3:
                        print("VERIFIED! Ready to use signed messages.")
                    return

    # Register
    pb2 = tedapi_pb2.Message()
    pb2.message.deliveryChannel = tedapi_pb2.DELIVERY_CHANNEL_LOCAL_HTTPS
    pb2.message.sender.local = tedapi_pb2.LOCAL_PARTICIPANT_INSTALLER
    pb2.message.recipient.din = din
    req = pb2.message.authorization.addAuthorizedClientRequest
    req.type = tedapi_pb2.AUTHORIZED_CLIENT_TYPE_CUSTOMER_MOBILE_APP
    req.description = args.description
    req.keyType = tedapi_pb2.AUTHORIZED_KEY_TYPE_RSA
    req.publicKey = pub_der
    pb2.tail.value = 1

    print(f"Registering RSA key ({len(pub_der)} bytes) as '{args.description}'...")
    response = _send_local_message(session, base, pb2)

    payload_type = response.message.WhichOneof('payload')
    if payload_type == 'authorization':
        msg_type = response.message.authorization.WhichOneof('message')
        if msg_type == 'addAuthorizedClientResponse':
            resp = response.message.authorization.addAuthorizedClientResponse
            if resp.HasField('client'):
                state = STATE_NAMES.get(resp.client.state, str(resp.client.state))
                VERIFY_TYPES = {0: "INVALID", 1: "PRESENCE_PROOF", 4: "HERMES_COMMAND"}
                vtype = VERIFY_TYPES.get(resp.client.verification, str(resp.client.verification))
                print(f"Registered! State: {state}")
                print(f"  Verification type: {vtype}")
                if resp.client.state == 3:
                    print("\nVERIFIED! Key is ready for /tedapi/v1r!")
                elif resp.client.state == 1:
                    print("\nKey is PENDING_VERIFICATION.")
                    if resp.client.verification == 1:
                        print("** PRESENCE_PROOF — toggle breaker to verify! **")
                    else:
                        print(f"Verification type: {vtype}")
                        print("Try toggling the breaker anyway, then run 'list' to check.")
                        print("Or run: check-verify --host IP --password PWD  (polls every 5s)")
            return

    if payload_type == 'common':
        if response.message.common.WhichOneof('message') == 'errorResponse':
            error = response.message.common.errorResponse
            print(f"Error (code {error.status.code}): {error.status.message}")
            return

    print(f"Unexpected response: {payload_type}")


def _send_local_message_hermes(session, base_url, pb_message):
    """Send a TEDAPI message with HERMES_COMMAND auth type (instead of PRESENCE)."""
    auth_env = tedapi_pb2.AuthEnvelope()
    auth_env.payload = pb_message.message.SerializeToString()
    auth_env.externalAuth.type = tedapi_pb2.EXTERNAL_AUTH_TYPE_HERMES_COMMAND
    data = auth_env.SerializeToString()

    resp = session.post(f"{base_url}/tedapi/v1", data=data, timeout=10)
    resp.raise_for_status()
    resp_data = resp.content
    if len(resp_data) >= 2 and resp_data[0] == 0x1f and resp_data[1] == 0x8b:
        resp_data = gzip.decompress(resp_data)

    auth_response = tedapi_pb2.AuthEnvelope()
    auth_response.ParseFromString(resp_data)
    result = tedapi_pb2.Message()
    result.message.ParseFromString(auth_response.payload)
    return result


def cmd_register_trusted(args):
    """Register RSA key matching the Tesla app's exact message format.

    Key discovery from APK: the Tesla app uses:
    - deliveryChannel = DELIVERY_CHANNEL_INVALID (0), NOT LOCAL_HTTPS
    - No sender field (unset)
    - Only sets payload.authorization.addAuthorizedClientRequest

    This may cause the device to assign PRESENCE_PROOF verification
    instead of HERMES_COMMAND, which could be verified via breaker toggle.
    """
    key_dir = get_key_dir(args.key_dir)
    private_key, pub_der = generate_rsa_key_pair(key_dir, force=args.force_new_key)

    session, din, base = _make_local_session(args.host, args.password)
    print(f"Gateway DIN: {din}\n")

    # First remove any existing registration for this key
    if args.remove_first:
        print("Removing any existing registration for this key...")
        rm_pb = tedapi_pb2.Message()
        rm_pb.message.deliveryChannel = tedapi_pb2.DELIVERY_CHANNEL_LOCAL_HTTPS
        rm_pb.message.sender.local = tedapi_pb2.LOCAL_PARTICIPANT_INSTALLER
        rm_pb.message.recipient.din = din
        rm_pb.message.authorization.removeAuthorizedClientRequest.publicKey = pub_der
        rm_pb.tail.value = 1
        try:
            _send_local_message(session, base, rm_pb)
            print("  Existing key removed.\n")
        except Exception as e:
            print(f"  Remove failed (may not exist): {e}\n")

    VERIFY_TYPES = {0: "INVALID", 1: "PRESENCE_PROOF", 2: "BLE",
                    3: "SIGNED", 4: "HERMES_COMMAND"}

    strategies = [
        {
            "name": "Strategy 1: CUSTOMER sender (may get PRESENCE_PROOF instead of HERMES)",
            "delivery": tedapi_pb2.DELIVERY_CHANNEL_LOCAL_HTTPS,
            "sender": "customer",
            "recipient": din,
        },
        {
            "name": "Strategy 2: INSTALLER sender (original — known to get HERMES_COMMAND)",
            "delivery": tedapi_pb2.DELIVERY_CHANNEL_LOCAL_HTTPS,
            "sender": "installer",
            "recipient": din,
        },
        {
            "name": "Strategy 3: APP-MATCHING (INVALID delivery, no sender)",
            "delivery": tedapi_pb2.DELIVERY_CHANNEL_INVALID,
            "sender": None,
            "recipient": din,
        },
        {
            "name": "Strategy 4: LOCAL delivery + no sender",
            "delivery": tedapi_pb2.DELIVERY_CHANNEL_LOCAL_HTTPS,
            "sender": None,
            "recipient": din,
        },
    ]

    for strat in strategies:
        print(f"\n--- {strat['name']} ---")
        pb = tedapi_pb2.Message()
        pb.message.deliveryChannel = strat["delivery"]

        # Set sender only if specified
        if strat["sender"] == "installer":
            pb.message.sender.local = tedapi_pb2.LOCAL_PARTICIPANT_INSTALLER
        elif strat["sender"] == "customer":
            pb.message.sender.local = tedapi_pb2.LOCAL_PARTICIPANT_CUSTOMER

        # Set recipient only if specified
        if strat["recipient"]:
            pb.message.recipient.din = strat["recipient"]

        req = pb.message.authorization.addAuthorizedClientRequest
        req.type = tedapi_pb2.AUTHORIZED_CLIENT_TYPE_CUSTOMER_MOBILE_APP
        req.description = args.description
        req.keyType = tedapi_pb2.AUTHORIZED_KEY_TYPE_RSA
        req.publicKey = pub_der
        pb.tail.value = 1

        print(f"Registering RSA key ({len(pub_der)} bytes)...")
        try:
            response = _send_local_message(session, base, pb)
        except requests.exceptions.HTTPError as e:
            print(f"  HTTP error: {e}")
            continue
        except Exception as e:
            print(f"  Error: {e}")
            continue

        payload_type = response.message.WhichOneof('payload')
        if payload_type == 'authorization':
            msg_type = response.message.authorization.WhichOneof('message')
            if msg_type == 'addAuthorizedClientResponse':
                resp = response.message.authorization.addAuthorizedClientResponse
                if resp.HasField('client'):
                    state = STATE_NAMES.get(resp.client.state, str(resp.client.state))
                    vtype = VERIFY_TYPES.get(resp.client.verification, str(resp.client.verification))
                    print(f"  Registered! State: {state}")
                    print(f"  Verification: {vtype}")
                    if resp.client.state == 3:
                        print("\n  VERIFIED! Key is ready for /tedapi/v1r!")
                        return
                    elif resp.client.state == 1:
                        print(f"  PENDING — verification type: {vtype}")
                        if vtype == "PRESENCE_PROOF":
                            print("\n  ** PRESENCE_PROOF! Toggle breaker to verify! **")
                            print("  Leave key registered and toggle the inverter breaker.")
                            return
                        # Remove for next strategy only if HERMES
                        if strat != strategies[-1]:
                            print("  Removing key to try next strategy...")
                            rm_pb = tedapi_pb2.Message()
                            rm_pb.message.deliveryChannel = tedapi_pb2.DELIVERY_CHANNEL_LOCAL_HTTPS
                            rm_pb.message.sender.local = tedapi_pb2.LOCAL_PARTICIPANT_INSTALLER
                            rm_pb.message.recipient.din = din
                            rm_pb.message.authorization.removeAuthorizedClientRequest.publicKey = pub_der
                            rm_pb.tail.value = 1
                            try:
                                _send_local_message(session, base, rm_pb)
                            except Exception:
                                pass
                continue
            print(f"  Unexpected auth message: {msg_type}")
        elif payload_type == 'common':
            if response.message.common.WhichOneof('message') == 'errorResponse':
                error = response.message.common.errorResponse
                print(f"  Error (code {error.status.code}): {error.status.message}")
        else:
            print(f"  Unexpected response: {payload_type}")

    print("\n--- All strategies exhausted ---")
    print("None achieved VERIFIED or PRESENCE_PROOF verification.")
    print("Run 'list' to check current state.")


def cmd_configure_remote(args):
    """Send configureRemoteServiceRequest to enable remote service access.

    This may trigger the device to contact Tesla cloud, potentially
    allowing HERMES_COMMAND verification of pending keys.
    """
    session, din, base = _make_local_session(args.host, args.password)
    print(f"Gateway DIN: {din}\n")

    pb = tedapi_pb2.Message()
    pb.message.deliveryChannel = tedapi_pb2.DELIVERY_CHANNEL_LOCAL_HTTPS
    pb.message.sender.local = tedapi_pb2.LOCAL_PARTICIPANT_INSTALLER
    pb.message.recipient.din = din
    req = pb.message.authorization.configureRemoteServiceRequest
    req.durationSeconds = args.duration
    req.sessionId = str(uuid.uuid4())
    req.requesterEmail = args.email
    pb.tail.value = 1

    print(f"Configuring remote service access...")
    print(f"  Duration: {args.duration} seconds ({args.duration // 3600} hours)")
    print(f"  Session ID: {req.sessionId}")
    print(f"  Email: {args.email}\n")

    response = _send_local_message(session, base, pb)

    payload_type = response.message.WhichOneof('payload')
    if payload_type == 'authorization':
        msg_type = response.message.authorization.WhichOneof('message')
        if msg_type == 'configureRemoteServiceResponse':
            print("Remote service configured successfully!")
            print("The device may now contact Tesla cloud for key verification.")
            print("\nNext: run 'list' after a few minutes to check key states.")
            return
        print(f"Unexpected auth message: {msg_type}")
    elif payload_type == 'common':
        if response.message.common.WhichOneof('message') == 'errorResponse':
            error = response.message.common.errorResponse
            print(f"Error (code {error.status.code}): {error.status.message}")
            return
    else:
        print(f"Unexpected response: {payload_type}")


def cmd_get_device_key(args):
    """Get the device's signed commands public key (ECC)."""
    session, din, base = _make_local_session(args.host, args.password)
    print(f"Gateway DIN: {din}\n")

    pb = tedapi_pb2.Message()
    pb.message.deliveryChannel = tedapi_pb2.DELIVERY_CHANNEL_LOCAL_HTTPS
    pb.message.sender.local = tedapi_pb2.LOCAL_PARTICIPANT_INSTALLER
    pb.message.recipient.din = din
    pb.message.authorization.getSignedCommandsPublicKeyRequest.CopyFrom(
        tedapi_pb2.AuthorizationAPIGetSignedCommandsPublicKeyRequest()
    )
    pb.tail.value = 1

    print("Requesting device's signed commands public key...")
    response = _send_local_message(session, base, pb)

    payload_type = response.message.WhichOneof('payload')
    if payload_type == 'authorization':
        msg_type = response.message.authorization.WhichOneof('message')
        if msg_type == 'getSignedCommandsPublicKeyResponse':
            resp = response.message.authorization.getSignedCommandsPublicKeyResponse
            print(f"Device ECC public key: {resp.pubKeyEcc.hex()}")
            print(f"  Length: {len(resp.pubKeyEcc)} bytes")
            return
        print(f"Unexpected auth message: {msg_type}")
    elif payload_type == 'common':
        if response.message.common.WhichOneof('message') == 'errorResponse':
            error = response.message.common.errorResponse
            print(f"Error (code {error.status.code}): {error.status.message}")
            return
    else:
        print(f"Unexpected response: {payload_type}")


def _cloud_headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }

OWNER_API = "https://owner-api.teslamotors.com"
FLEET_API = "https://fleet-api.prd.na.vn.cloud.tesla.com"


def cmd_auth(args):
    """Get a Tesla OAuth token via PKCE flow."""
    import hashlib
    import secrets
    import webbrowser
    from urllib.parse import parse_qs, urlparse

    # Generate PKCE verifier + challenge
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b'=').decode()

    state = secrets.token_urlsafe(16)

    auth_url = (
        "https://auth.tesla.com/oauth2/v3/authorize?"
        f"response_type=code&client_id=ownerapi&"
        f"redirect_uri=https://auth.tesla.com/void/callback&"
        f"scope=openid+email+offline_access+phone&"
        f"state={state}&code_challenge={challenge}&"
        f"code_challenge_method=S256"
    )

    print("Login URL (open in ANY browser — phone, laptop, etc.):")
    print(f"\n{auth_url}\n")

    # Try to open browser, suppress stderr noise from Chromium on Pi
    import subprocess
    try:
        subprocess.Popen(
            ["xdg-open", auth_url],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except Exception:
        try:
            webbrowser.open(auth_url)
        except Exception:
            pass

    print("After logging in, you'll be redirected to a URL like:")
    print("  https://auth.tesla.com/void/callback?code=...&state=...")
    redirect_url = input("\nPaste the full redirect URL here: ").strip()

    parsed = urlparse(redirect_url)
    qs = parse_qs(parsed.query)
    code = qs.get('code', [None])[0]
    if not code:
        print("ERROR: Could not extract authorization code from URL")
        return

    print("\nExchanging code for token...")
    resp = requests.post("https://auth.tesla.com/oauth2/v3/token", json={
        "grant_type": "authorization_code",
        "client_id": "ownerapi",
        "code": code,
        "code_verifier": verifier,
        "redirect_uri": "https://auth.tesla.com/void/callback",
    }, timeout=30)

    if not resp.ok:
        print(f"Token exchange failed: {resp.status_code}")
        print(resp.text)
        return

    tokens = resp.json()
    access_token = tokens.get("access_token", "")
    refresh_token = tokens.get("refresh_token", "")

    # Save tokens
    key_dir = get_key_dir(args.key_dir)
    token_file = key_dir / "tesla_tokens.json"
    token_file.write_text(json.dumps({
        "access_token": access_token,
        "refresh_token": refresh_token,
    }, indent=2))

    print(f"\nTokens saved to {token_file}")
    print(f"Access token: {access_token[:20]}...{access_token[-10:]}")
    print(f"\nUse with: --token {access_token[:20]}...")
    print("Or omit --token and it will be loaded from the saved file.")


def _get_token(args) -> str:
    """Get token from --token arg or saved file."""
    if hasattr(args, 'token') and args.token:
        return args.token
    key_dir = get_key_dir(args.key_dir)
    token_file = key_dir / "tesla_tokens.json"
    if token_file.exists():
        tokens = json.loads(token_file.read_text())
        return tokens.get("access_token", "")
    print("ERROR: No --token provided and no saved token found.")
    print("Run: python register_local_client.py auth")
    sys.exit(1)


def cmd_get_sites(args):
    """List Tesla energy sites to find your site_id."""
    token = _get_token(args)
    api_base = FLEET_API if args.use_fleet_api else OWNER_API

    print(f"Fetching products from {api_base}...")
    session = requests.Session()
    session.headers.update(_cloud_headers(token))
    session.headers['User-Agent'] = urllib3.util.SKIP_HEADER
    resp = session.get(f"{api_base}/api/1/products", timeout=30)
    print(f"  Status: {resp.status_code}")

    if not resp.ok:
        print(f"  Error: {resp.text}")
        return

    data = resp.json()
    products = data.get("response", [])
    print(f"\nFound {len(products)} product(s):\n")

    for p in products:
        site_id = p.get("energy_site_id")
        gw_id = p.get("gateway_id", "")
        site_name = p.get("site_name", "unknown")
        resource_type = p.get("resource_type", "unknown")
        print(f"  Site Name:     {site_name}")
        print(f"  Resource Type: {resource_type}")
        print(f"  energy_site_id: {site_id}")
        print(f"  gateway_id:     {gw_id}")
        # Additional useful fields
        for key in ("battery_type", "components", "energy_left"):
            if key in p:
                print(f"  {key}: {p[key]}")
        print()


def cmd_register_cloud(args):
    """Register RSA key via Tesla cloud API — tries multiple payload formats."""
    key_dir = get_key_dir(args.key_dir)
    private_key, pub_der = generate_rsa_key_pair(key_dir, force=args.force_new_key)

    pub_b64 = base64.b64encode(pub_der).decode()
    print(f"Public key (base64, {len(pub_der)} bytes):")
    print(f"  {pub_b64[:60]}...")

    token = _get_token(args)

    # Build list of (description, api_base, url_suffix, payload) to try
    attempts = []

    # Base URLs to try
    api_bases = [
        ("Owner API", OWNER_API),
        ("Fleet API", FLEET_API),
    ]

    # Payload variants
    payloads = [
        ("trusted_signature (snake_case)", {
            "command_properties": {
                "message": {
                    "authorization": {
                        "add_authorized_client_by_trusted_signature_request": {
                            "type": 1,
                            "description": args.description,
                            "key_type": 1,
                            "public_key": pub_b64,
                            "roles": [1],
                            "identifier": "local-lan-client",
                        }
                    }
                },
                "identifier_type": 1,
            },
            "command_type": "grpc_command",
        }),
        ("regular add_client (snake_case)", {
            "command_properties": {
                "message": {
                    "authorization": {
                        "add_authorized_client_request": {
                            "key_type": 1,
                            "public_key": pub_b64,
                            "authorized_client_type": 1,
                            "description": args.description,
                        }
                    }
                },
                "identifier_type": 1,
            },
            "command_type": "grpc_command",
        }),
        ("trusted_signature (camelCase)", {
            "command_properties": {
                "message": {
                    "authorization": {
                        "addAuthorizedClientByTrustedSignatureRequest": {
                            "type": 1,
                            "description": args.description,
                            "keyType": 1,
                            "publicKey": pub_b64,
                            "roles": [1],
                            "identifier": "local-lan-client",
                        }
                    }
                },
                "identifierType": 1,
            },
            "commandType": "grpc_command",
        }),
    ]

    # URL suffixes to try
    url_suffixes = [
        "/command?language=en_GB",
        "/command",
    ]

    for api_name, api_base in api_bases:
        for url_suffix in url_suffixes:
            for payload_name, payload in payloads:
                attempts.append((
                    f"{api_name} | {url_suffix} | {payload_name}",
                    f"{api_base}/api/1/energy_sites/{args.site_id}{url_suffix}",
                    payload,
                ))

    session = requests.Session()
    session.headers.update(_cloud_headers(token))
    session.headers['User-Agent'] = urllib3.util.SKIP_HEADER

    for desc, url, payload in attempts:
        print(f"\n--- {desc} ---")
        print(f"  URL: {url}")
        try:
            resp = session.post(url, json=payload, timeout=30)
            print(f"  Status: {resp.status_code}")
            body = resp.text[:500]
            print(f"  Response: {body}")
            if resp.ok:
                print(f"\n  SUCCESS! Cloud registration may have been sent.")
                print("  Check with: list --host IP --password PWD")
                return
        except Exception as e:
            print(f"  Error: {e}")

    print("\n--- All cloud attempts failed ---")
    print("Solar-only sites may not support cloud command routing.")
    print("\nAlternative: Register locally, then check if Tesla app can verify.")


def cmd_cloud_list(args):
    """List authorized clients via Tesla cloud API."""
    token = _get_token(args)
    api_base = FLEET_API if args.use_fleet_api else OWNER_API
    url = f"{api_base}/api/1/energy_sites/{args.site_id}/command?language=en_GB"

    payload = {
        "command_properties": {
            "message": {
                "authorization": {
                    "list_authorized_clients_request": {}
                }
            },
            "identifier_type": 1,
        },
        "command_type": "grpc_command",
    }

    print(f"Querying authorized clients via cloud ({api_base})...")
    session = requests.Session()
    session.headers.update(_cloud_headers(token))
    session.headers['User-Agent'] = urllib3.util.SKIP_HEADER
    resp = session.post(url, json=payload, timeout=30)
    print(f"  Status: {resp.status_code}")

    if not resp.ok:
        print(f"  Error: {resp.text}")
        return

    result = resp.json()
    print(f"  Response: {json.dumps(result, indent=2)}")


def cmd_list(args):
    """List authorized clients."""
    session, din, base = _make_local_session(args.host, args.password)
    print(f"Gateway DIN: {din}\n")

    pb = tedapi_pb2.Message()
    pb.message.deliveryChannel = tedapi_pb2.DELIVERY_CHANNEL_LOCAL_HTTPS
    pb.message.sender.local = tedapi_pb2.LOCAL_PARTICIPANT_INSTALLER
    pb.message.recipient.din = din
    pb.message.authorization.listAuthorizedClientsRequest.CopyFrom(
        tedapi_pb2.AuthorizationAPIListAuthorizedClientsRequest()
    )
    pb.tail.value = 1
    response = _send_local_message(session, base, pb)

    if response.message.WhichOneof('payload') == 'authorization':
        msg_type = response.message.authorization.WhichOneof('message')
        if msg_type == 'listAuthorizedClientsResponse':
            resp = response.message.authorization.listAuthorizedClientsResponse
            print(f"Authorized Clients ({len(resp.clients)} total):")
            print(f"  enableLineSwitchOff: {resp.enableLineSwitchOff}\n")
            KEY_TYPES = {0: "INVALID", 1: "RSA", 2: "ECC"}
            CLIENT_TYPES = {0: "INVALID", 1: "CUSTOMER_MOBILE_APP", 2: "VEHICLE"}
            VERIFY_TYPES = {0: "INVALID", 1: "PRESENCE_PROOF", 4: "HERMES_COMMAND"}
            for i, c in enumerate(resp.clients):
                pub_hex = c.publicKey.hex()
                pub_preview = f"{pub_hex[:40]}..." if len(pub_hex) > 40 else pub_hex
                print(f"  [{i}] Type:     {CLIENT_TYPES.get(c.type, c.type)}")
                print(f"      Desc:     {c.description}")
                print(f"      KeyType:  {KEY_TYPES.get(c.keyType, c.keyType)}")
                print(f"      PubKey:   {pub_preview}")
                print(f"      State:    {STATE_NAMES.get(c.state, c.state)}")
                print(f"      Verify:   {VERIFY_TYPES.get(c.verification, c.verification)}")
                print()


def cmd_remove(args):
    """Remove a registered key."""
    key_dir = get_key_dir(args.key_dir)
    _, pub_der = load_rsa_key_pair(key_dir)

    session, din, base = _make_local_session(args.host, args.password)
    print(f"Gateway DIN: {din}\n")

    pb = tedapi_pb2.Message()
    pb.message.deliveryChannel = tedapi_pb2.DELIVERY_CHANNEL_LOCAL_HTTPS
    pb.message.sender.local = tedapi_pb2.LOCAL_PARTICIPANT_INSTALLER
    pb.message.recipient.din = din
    pb.message.authorization.removeAuthorizedClientRequest.publicKey = pub_der
    pb.tail.value = 1

    print(f"Removing key...")
    response = _send_local_message(session, base, pb)

    payload_type = response.message.WhichOneof('payload')
    if payload_type == 'authorization':
        msg_type = response.message.authorization.WhichOneof('message')
        if msg_type == 'removeAuthorizedClientResponse':
            print("Removed!")
            return
    if payload_type == 'common':
        if response.message.common.WhichOneof('message') == 'errorResponse':
            error = response.message.common.errorResponse
            print(f"Error (code {error.status.code}): {error.status.message}")
            return
    print(f"Unexpected: {payload_type}")


# ============================================================
# Signed routable messages (for /tedapi/v1r — works over LAN)
# ============================================================

def to_tlv(tag: int, value_bytes: bytes) -> bytes:
    """Encode a tag-length-value triplet."""
    return tag.to_bytes(1, 'big') + len(value_bytes).to_bytes(1, 'big') + value_bytes


def build_signed_routable_message(
    private_key,
    public_key_bytes: bytes,
    din: str,
    message_envelope_bytes: bytes,
) -> bytes:
    """Build a signed RoutableMessage for /tedapi/v1r.

    Args:
        private_key: RSA private key
        public_key_bytes: DER PKCS1 public key bytes
        din: Target device DIN
        message_envelope_bytes: Serialized MessageEnvelope proto
    Returns:
        Serialized RoutableMessage bytes
    """
    # Build unsigned RoutableMessage first (need protobuf_message_as_bytes for signing)
    routable = vc.RoutableMessage()
    routable.to_destination.domain = vc.DOMAIN_ENERGY_DEVICE
    routable.protobuf_message_as_bytes = message_envelope_bytes
    routable.uuid = str(uuid.uuid4()).encode()

    # Expiration: ceil(now) + 12 seconds
    expires_at = math.ceil(time.time()) + 12

    # Build TLV payload to sign
    tlv_payload = b''.join([
        to_tlv(vc.TAG_SIGNATURE_TYPE, vc.SIGNATURE_TYPE_RSA.to_bytes(1, 'big')),
        to_tlv(vc.TAG_DOMAIN, vc.DOMAIN_ENERGY_DEVICE.to_bytes(1, 'big')),
        to_tlv(vc.TAG_PERSONALIZATION, din.encode()),
        to_tlv(vc.TAG_EXPIRES_AT, expires_at.to_bytes(4, 'big')),
        vc.TAG_END.to_bytes(1, 'big'),
        message_envelope_bytes,
    ])

    # RSA sign with SHA-512 PKCS1v15 (confirmed from Matthew1471's working implementation)
    signature = private_key.sign(
        data=tlv_payload,
        padding=padding.PKCS1v15(),
        algorithm=hashes.SHA512(),
    )

    # Attach signature
    routable.signature_data.signer_identity.public_key = public_key_bytes
    routable.signature_data.rsa_data.expires_at = expires_at
    routable.signature_data.rsa_data.signature = signature

    return routable.SerializeToString()


def build_message_envelope(din: str, payload_setter) -> bytes:
    """Build a MessageEnvelope with HERMES_COMMAND delivery channel.

    Args:
        din: Target device DIN
        payload_setter: Callable that sets the payload on the MessageEnvelope
    Returns:
        Serialized MessageEnvelope bytes
    """
    env = tedapi_pb2.MessageEnvelope()
    env.deliveryChannel = tedapi_pb2.DELIVERY_CHANNEL_HERMES_COMMAND
    env.sender.authorizedClient = tedapi_pb2.AUTHORIZED_CLIENT_TYPE_CUSTOMER_MOBILE_APP
    env.recipient.din = din
    payload_setter(env)
    return env.SerializeToString()


def send_signed_request(host: str, routable_bytes: bytes) -> bytes:
    """POST signed RoutableMessage to /tedapi/v1r and return raw response."""
    session = requests.Session()
    session.verify = False

    resp = session.post(
        f"https://{host}/tedapi/v1r",
        data=routable_bytes,
        headers={'Content-Type': 'application/octet-stream'},
        timeout=15,
    )
    print(f"  HTTP {resp.status_code} ({len(resp.content)} bytes)")
    resp.raise_for_status()
    return resp.content


def parse_routable_response(raw: bytes):
    """Parse a RoutableMessage response into a MessageEnvelope."""
    # Decompress if gzipped
    if len(raw) >= 2 and raw[0] == 0x1f and raw[1] == 0x8b:
        raw = gzip.decompress(raw)

    routable = vc.RoutableMessage()
    routable.ParseFromString(raw)

    if routable.signed_message_status.operation_status == vc.OPERATIONSTATUS_ERROR:
        fault = vc.MessageFault_E.Name(routable.signed_message_status.signed_message_fault)
        raise Exception(f"Signed message error: {fault}")

    if routable.protobuf_message_as_bytes:
        env = tedapi_pb2.MessageEnvelope()
        env.ParseFromString(routable.protobuf_message_as_bytes)
        return env

    return routable


def cmd_test_signed(args):
    """Test signed message: query networking status over LAN."""
    key_dir = get_key_dir(args.key_dir)
    private_key, pub_der = load_rsa_key_pair(key_dir)

    din = args.din
    if not din:
        if not args.password:
            print("ERROR: --din or --password required for test-signed")
            return
        _, din, _ = _make_local_session(args.host, args.password)
    print(f"Target DIN: {din}")

    # Build a networking status request
    def set_networking_status(env):
        env.common.getNetworkingStatusRequest.CopyFrom(
            tedapi_pb2.CommonAPIGetNetworkingStatusRequest()
        )

    print("\nBuilding signed networking status request...")
    envelope_bytes = build_message_envelope(din, set_networking_status)
    routable_bytes = build_signed_routable_message(
        private_key, pub_der, din, envelope_bytes,
    )
    print(f"  RoutableMessage: {len(routable_bytes)} bytes")

    print(f"\nSending to https://{args.host}/tedapi/v1r ...")
    try:
        raw_response = send_signed_request(args.host, routable_bytes)
        env = parse_routable_response(raw_response)
        if hasattr(env, 'common'):
            msg_type = env.common.WhichOneof('message')
            if msg_type == 'getNetworkingStatusResponse':
                resp = env.common.getNetworkingStatusResponse
                print("\nNetworking status received!")
                if resp.HasField('wifi'):
                    print(f"  WiFi enabled: {resp.wifi.enabled}")
                if resp.HasField('eth'):
                    print(f"  Eth enabled:  {resp.eth.enabled}")
                if resp.HasField('gsm'):
                    print(f"  GSM enabled:  {resp.gsm.enabled}")
                return
            elif msg_type == 'errorResponse':
                error = env.common.errorResponse
                print(f"\nGateway error (code {error.status.code}): {error.status.message}")
                return
        print(f"\nResponse envelope: {env}")
    except requests.exceptions.HTTPError as e:
        print(f"\nHTTP error: {e}")
        print("The /tedapi/v1r endpoint may not exist on this device,")
        print("or the key may not be VERIFIED yet.")
    except Exception as e:
        print(f"\nError: {e}")


def cmd_test_signed_config(args):
    """Test signed message: read config.json over LAN."""
    key_dir = get_key_dir(args.key_dir)
    private_key, pub_der = load_rsa_key_pair(key_dir)

    din = args.din
    if not din:
        if not args.password:
            print("ERROR: --din or --password required")
            return
        _, din, _ = _make_local_session(args.host, args.password)
    print(f"Target DIN: {din}")

    # Build a FileStore readFile request
    def set_read_config(env):
        env.filestore.readFileRequest.domain = tedapi_pb2.FILE_STORE_API_DOMAIN_CONFIG_JSON
        env.filestore.readFileRequest.name = "config.json"

    print("\nBuilding signed config read request...")
    envelope_bytes = build_message_envelope(din, set_read_config)
    routable_bytes = build_signed_routable_message(
        private_key, pub_der, din, envelope_bytes,
    )
    print(f"  RoutableMessage: {len(routable_bytes)} bytes")

    print(f"\nSending to https://{args.host}/tedapi/v1r ...")
    try:
        raw_response = send_signed_request(args.host, routable_bytes)
        env = parse_routable_response(raw_response)
        if hasattr(env, 'filestore'):
            msg_type = env.filestore.WhichOneof('message')
            if msg_type == 'readFileResponse':
                resp = env.filestore.readFileResponse
                config = json.loads(resp.file.blob.decode('utf-8'))
                print("\nConfig received!")
                print(json.dumps(config, indent=2)[:2000])
                return
        if hasattr(env, 'common'):
            if env.common.WhichOneof('message') == 'errorResponse':
                error = env.common.errorResponse
                print(f"\nGateway error (code {error.status.code}): {error.status.message}")
                return
        print(f"\nResponse: {env}")
    except requests.exceptions.HTTPError as e:
        print(f"\nHTTP error: {e}")
    except Exception as e:
        print(f"\nError: {e}")


# ============================================================
# REST API login test (does the PVI have /api/login/Basic?)
# ============================================================

def cmd_rest_login(args):
    """Test REST API /api/login/Basic on the device.

    The Tesla One app uses this for installer login on Powerwalls.
    Standalone PVIs may or may not support it.
    """
    host = args.host
    password = args.rest_password or args.password
    if not password:
        print("ERROR: --rest-password or --password required")
        return

    session = requests.Session()
    session.verify = False

    # Try /api/login/Basic
    url = f"https://{host}/api/login/Basic"
    payload = {
        "username": "installer",
        "password": password,
        "email": "installer@tesla.com",
        "clientInfo": {"timezone": "America/Los_Angeles"},
    }

    print(f"Testing REST API login at {url}...")
    print(f"  Username: installer")
    print(f"  Password: {password[:3]}...{password[-2:]}\n")

    try:
        resp = session.post(url, json=payload, timeout=10)
        print(f"  HTTP {resp.status_code}")
        print(f"  Response: {resp.text[:500]}")

        if resp.ok:
            data = resp.json()
            token = data.get("token", "")
            if token:
                print(f"\n  LOGIN SUCCESS! Token: {token[:30]}...")
                print("\n  Testing /api/config ...")
                config_resp = session.get(
                    f"https://{host}/api/config",
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=10,
                )
                print(f"  HTTP {config_resp.status_code}")
                if config_resp.ok:
                    config = config_resp.json()
                    print(f"  Config keys: {list(config.keys())[:10]}")
                    if "solars" in config:
                        for s in config["solars"]:
                            print(f"  Inverter: {s.get('din')} status={s.get('pvi_power_status')}")
                else:
                    print(f"  Config response: {config_resp.text[:300]}")
            else:
                print(f"\n  Response has no token: {data}")
        else:
            print(f"\n  Login failed. PVI may not support REST API.")
    except requests.exceptions.ConnectionError as e:
        print(f"\n  Connection failed: {e}")
        print("  The PVI likely does not have a REST API server.")
    except Exception as e:
        print(f"\n  Error: {e}")


def cmd_rest_explore(args):
    """Explore REST API endpoints on the device.

    After a successful login, tries many known Tesla REST endpoints
    to discover what's available on a standalone PVI.
    """
    host = args.host
    password = args.rest_password or args.password
    if not password:
        print("ERROR: --rest-password or --password required")
        return

    session = requests.Session()
    session.verify = False

    # Login first
    url = f"https://{host}/api/login/Basic"
    payload = {
        "username": "installer",
        "password": password,
        "email": "installer@tesla.com",
        "clientInfo": {"timezone": "America/Los_Angeles"},
    }
    resp = session.post(url, json=payload, timeout=10)
    if not resp.ok:
        print(f"Login failed: {resp.status_code} {resp.text}")
        return
    token = resp.json().get("token", "")
    if not token:
        print("No token in login response")
        return
    print(f"Logged in, token: {token[:20]}...\n")

    headers = {"Authorization": f"Bearer {token}"}

    # List of endpoints to probe (GET unless noted)
    endpoints = [
        ("GET",  "/api/config"),
        ("GET",  "/api/site_info"),
        ("GET",  "/api/site_info/site_name"),
        ("GET",  "/api/status"),
        ("GET",  "/api/system_status"),
        ("GET",  "/api/system_status/grid_status"),
        ("GET",  "/api/system_status/soe"),
        ("GET",  "/api/devices"),
        ("GET",  "/api/devices/vitals"),
        ("GET",  "/api/meters"),
        ("GET",  "/api/meters/aggregates"),
        ("GET",  "/api/operation"),
        ("GET",  "/api/powerwalls"),
        ("GET",  "/api/powerwalls/status"),
        ("GET",  "/api/solars"),
        ("GET",  "/api/solars/brands"),
        ("GET",  "/api/networks"),
        ("GET",  "/api/networks/wifi_scan"),
        ("GET",  "/api/system/networks"),
        ("GET",  "/api/system/update/status"),
        ("GET",  "/api/installer"),
        ("GET",  "/api/installer/info"),
        ("GET",  "/api/customer"),
        ("GET",  "/api/customer/registration"),
        ("GET",  "/api/auth/toggle/supported"),
        ("GET",  "/api/authorization"),
        ("GET",  "/api/authorization/clients"),
        ("GET",  "/api/sitemaster"),
        ("GET",  "/api/sitemaster/run"),
        ("GET",  "/api/troubleshooting/problems"),
        ("GET",  "/tedapi/din"),
        ("GET",  "/tedapi/v1"),
    ]

    print(f"Probing {len(endpoints)} endpoints...\n")
    found = []
    for method, path in endpoints:
        full_url = f"https://{host}{path}"
        try:
            if method == "GET":
                r = session.get(full_url, headers=headers, timeout=5)
            else:
                r = session.post(full_url, headers=headers, timeout=5)

            status = r.status_code
            body = r.text[:200].replace("\n", " ")
            marker = "+" if status == 200 else " "
            print(f"  {marker} {status} {method:4s} {path}")
            if status == 200:
                print(f"         {body}")
                found.append((path, body))
        except Exception as e:
            print(f"    ERR  {method:4s} {path}  ({e})")

    print(f"\n{'='*60}")
    print(f"Found {len(found)} working endpoints:")
    for path, body in found:
        print(f"  {path}")
        print(f"    {body[:150]}")


# ============================================================
# TEDAPI via Bearer token (REST login token for protobuf auth)
# ============================================================

def cmd_tedapi_bearer(args):
    """Test TEDAPI v1 using Bearer token from REST API login.

    Instead of HTTP Basic Auth (Tesla_Energy_Device/password),
    use the Bearer token from /api/login/Basic to authenticate
    TEDAPI protobuf requests. If this works, no WiFi adapter needed.
    """
    host = args.host
    password = args.password
    if not password:
        print("ERROR: --password required")
        return

    session = requests.Session()
    session.verify = False

    # Step 1: REST API login to get Bearer token
    print("Step 1: REST API login...")
    resp = session.post(
        f"https://{host}/api/login/Basic",
        json={
            "username": "installer",
            "password": password,
            "email": "installer@tesla.com",
            "clientInfo": {"timezone": "America/Los_Angeles"},
        },
        timeout=10,
    )
    if not resp.ok:
        print(f"  Login failed: {resp.status_code} {resp.text}")
        return
    token = resp.json().get("token", "")
    if not token:
        print("  No token returned")
        return
    print(f"  Token: {token[:30]}...\n")

    # Step 2: Get DIN (try both auth methods)
    print("Step 2: Get DIN...")
    din = None
    # Try Bearer token for DIN
    r = session.get(
        f"https://{host}/tedapi/din",
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    if r.ok:
        din = r.text.strip()
        print(f"  DIN (via Bearer): {din}")
    else:
        # Fallback to Basic auth
        r2 = session.get(
            f"https://{host}/tedapi/din",
            auth=('Tesla_Energy_Device', password),
            timeout=10,
        )
        if r2.ok:
            din = r2.text.strip()
            print(f"  DIN (via Basic auth): {din}")
    if not din:
        print("  Could not get DIN")
        return

    # Build a simple TEDAPI request (networking status)
    pb = tedapi_pb2.Message()
    pb.message.deliveryChannel = tedapi_pb2.DELIVERY_CHANNEL_LOCAL_HTTPS
    pb.message.sender.local = tedapi_pb2.LOCAL_PARTICIPANT_INSTALLER
    pb.message.recipient.din = din
    pb.message.common.getNetworkingStatusRequest.CopyFrom(
        tedapi_pb2.CommonAPIGetNetworkingStatusRequest()
    )
    pb.tail.value = 1

    # Build AuthEnvelope
    auth_env = tedapi_pb2.AuthEnvelope()
    auth_env.payload = pb.message.SerializeToString()
    auth_env.externalAuth.type = tedapi_pb2.EXTERNAL_AUTH_TYPE_PRESENCE
    data = auth_env.SerializeToString()

    # Step 3: Try multiple auth strategies for TEDAPI v1
    print("\nStep 3: Sending TEDAPI request with different auth strategies...\n")

    strategies = [
        {
            "name": "Bearer token only",
            "headers": {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/octet-stream",
            },
            "auth": None,
        },
        {
            "name": "Bearer token + Basic auth",
            "headers": {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/octet-stream",
            },
            "auth": ('Tesla_Energy_Device', password),
        },
        {
            "name": "Basic auth only (control)",
            "headers": {
                "Content-Type": "application/octet-stream",
            },
            "auth": ('Tesla_Energy_Device', password),
        },
    ]

    for strat in strategies:
        print(f"  --- {strat['name']} ---")
        try:
            r = session.post(
                f"https://{host}/tedapi/v1",
                data=data,
                headers=strat["headers"],
                auth=strat["auth"],
                timeout=10,
            )
            print(f"    HTTP {r.status_code} ({len(r.content)} bytes)")

            if r.ok:
                resp_data = r.content
                if len(resp_data) >= 2 and resp_data[0] == 0x1f and resp_data[1] == 0x8b:
                    resp_data = gzip.decompress(resp_data)

                auth_response = tedapi_pb2.AuthEnvelope()
                auth_response.ParseFromString(resp_data)
                result = tedapi_pb2.Message()
                result.message.ParseFromString(auth_response.payload)

                payload_type = result.message.WhichOneof('payload')
                if payload_type == 'common':
                    msg_type = result.message.common.WhichOneof('message')
                    if msg_type == 'getNetworkingStatusResponse':
                        resp = result.message.common.getNetworkingStatusResponse
                        print(f"    SUCCESS! Got networking status:")
                        if resp.HasField('wifiConfig'):
                            print(f"      WiFi SSID: {resp.wifiConfig.ssid}")
                        if resp.HasField('wifi'):
                            print(f"      WiFi enabled: {resp.wifi.enabled}")
                        if resp.HasField('eth'):
                            print(f"      Eth enabled: {resp.eth.enabled}")
                    elif msg_type == 'errorResponse':
                        error = result.message.common.errorResponse
                        print(f"    Error: code {error.status.code}: {error.status.message}")
                    else:
                        print(f"    Response type: {msg_type}")
                else:
                    print(f"    Payload type: {payload_type}")
            else:
                print(f"    Response: {r.text[:200]}")
        except Exception as e:
            print(f"    Error: {e}")

    # Step 4: Also try without AuthEnvelope (raw MessageEnvelope)
    print(f"\n  --- Bearer token + raw MessageEnvelope (no AuthEnvelope) ---")
    try:
        raw_env = pb.message.SerializeToString()
        r = session.post(
            f"https://{host}/tedapi/v1",
            data=raw_env,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/octet-stream",
            },
            timeout=10,
        )
        print(f"    HTTP {r.status_code} ({len(r.content)} bytes)")
        if r.ok:
            print(f"    Response: {r.content[:200]}")
        else:
            print(f"    Response: {r.text[:200]}")
    except Exception as e:
        print(f"    Error: {e}")


# ============================================================
# REST API PVI control (read/write solar status)
# ============================================================

def cmd_rest_solar(args):
    """Read or write PVI solar status via REST API.

    Uses /api/solars to read status, and attempts POST to change it.
    This bypasses TEDAPI protobuf entirely — works with QR code password.
    """
    host = args.host
    password = args.rest_password or args.password
    if not password:
        print("ERROR: --rest-password or --password required")
        return

    session = requests.Session()
    session.verify = False

    # Login
    url = f"https://{host}/api/login/Basic"
    payload = {
        "username": "installer",
        "password": password,
        "email": "installer@tesla.com",
        "clientInfo": {"timezone": "America/Los_Angeles"},
    }
    resp = session.post(url, json=payload, timeout=10)
    if not resp.ok:
        print(f"Login failed: {resp.status_code} {resp.text}")
        return
    token = resp.json().get("token", "")
    headers = {"Authorization": f"Bearer {token}"}
    print(f"Logged in.\n")

    # Read current solars
    print("Reading /api/solars ...")
    resp = session.get(f"https://{host}/api/solars", headers=headers, timeout=10)
    if not resp.ok:
        print(f"  Failed: {resp.status_code} {resp.text}")
        return

    solars = resp.json()
    print(f"  Found {len(solars)} inverter(s):")
    for s in solars:
        print(f"    DIN: {s.get('din', 'unknown')}")
        print(f"    Brand: {s.get('brand')}, Model: {s.get('model')}")
        print(f"    Status: {s.get('pvi_power_status')}")
        print(f"    Serial: {s.get('serial_number')}")
        print()

    if not args.set_status:
        return

    # Try to write new status
    new_status = args.set_status
    valid = ["on", "off", "dc_only", "unset"]
    if new_status not in valid:
        print(f"ERROR: --set-status must be one of: {valid}")
        return

    print(f"Attempting to set pvi_power_status = '{new_status}'...\n")

    # Strategy 1: POST full solars array with modified status
    modified = json.loads(json.dumps(solars))  # deep copy
    for s in modified:
        s["pvi_power_status"] = new_status

    strategies = [
        ("POST /api/solars (full array)", "POST",
         f"https://{host}/api/solars", modified),
        ("PUT /api/solars (full array)", "PUT",
         f"https://{host}/api/solars", modified),
        ("POST /api/solars (single object)", "POST",
         f"https://{host}/api/solars", modified[0] if modified else {}),
        ("PUT /api/solars (single object)", "PUT",
         f"https://{host}/api/solars", modified[0] if modified else {}),
        ("POST /api/config with solars", "POST",
         f"https://{host}/api/config", {"solars": modified}),
        ("PUT /api/config with solars", "PUT",
         f"https://{host}/api/config", {"solars": modified}),
        ("POST /api/operation", "POST",
         f"https://{host}/api/operation",
         {"real_mode": "self_consumption", "pvi_power_status": new_status}),
    ]

    for desc, method, url, data in strategies:
        print(f"  --- {desc} ---")
        try:
            if method == "POST":
                r = session.post(url, json=data, headers=headers, timeout=10)
            else:
                r = session.put(url, json=data, headers=headers, timeout=10)
            print(f"    {r.status_code}: {r.text[:200]}")
            if r.ok:
                print(f"\n  SUCCESS with {desc}!")
                # Verify
                print("\n  Verifying...")
                v = session.get(f"https://{host}/api/solars",
                                headers=headers, timeout=10)
                if v.ok:
                    for s in v.json():
                        print(f"    {s.get('din')}: {s.get('pvi_power_status')}")
                return
        except Exception as e:
            print(f"    Error: {e}")

    print("\n  All write strategies failed.")
    print("  PVI control via REST may require TEDAPI FileStore instead.")


# ============================================================
# Check/poll key verification status (for after breaker toggle)
# ============================================================

def cmd_check_verify(args):
    """Poll key verification status repeatedly (for breaker toggle testing).

    Usage: Toggle the breaker, then run this to watch state changes.
    """
    key_dir = get_key_dir(args.key_dir)
    _, pub_der = load_rsa_key_pair(key_dir)

    session, din, base = _make_local_session(args.host, args.password)
    print(f"Gateway DIN: {din}")
    print(f"Polling every {args.interval}s... (Ctrl+C to stop)\n")

    VERIFY_TYPES = {0: "INVALID", 1: "PRESENCE_PROOF", 4: "HERMES_COMMAND"}
    poll_count = 0

    try:
        while True:
            poll_count += 1
            pb = tedapi_pb2.Message()
            pb.message.deliveryChannel = tedapi_pb2.DELIVERY_CHANNEL_LOCAL_HTTPS
            pb.message.sender.local = tedapi_pb2.LOCAL_PARTICIPANT_INSTALLER
            pb.message.recipient.din = din
            pb.message.authorization.listAuthorizedClientsRequest.CopyFrom(
                tedapi_pb2.AuthorizationAPIListAuthorizedClientsRequest()
            )
            pb.tail.value = 1

            try:
                response = _send_local_message(session, base, pb)
            except Exception as e:
                print(f"  [{poll_count}] Error: {e}")
                time.sleep(args.interval)
                continue

            if response.message.WhichOneof('payload') == 'authorization':
                msg_type = response.message.authorization.WhichOneof('message')
                if msg_type == 'listAuthorizedClientsResponse':
                    resp = response.message.authorization.listAuthorizedClientsResponse
                    found = False
                    for c in resp.clients:
                        if c.publicKey == pub_der:
                            found = True
                            state = STATE_NAMES.get(c.state, str(c.state))
                            vtype = VERIFY_TYPES.get(c.verification, str(c.verification))
                            ts = time.strftime("%H:%M:%S")
                            print(f"  [{poll_count}] {ts}  State: {state}  Verify: {vtype}")
                            if c.state == 3:
                                print("\n  ** VERIFIED! Key is authorized for /tedapi/v1r! **")
                                print("  You can now send signed messages over LAN.")
                                return
                            break
                    if not found:
                        print(f"  [{poll_count}] Key not found in authorized clients list!")
                        return

            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n\nStopped polling.")


# ============================================================
# Main CLI
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="Tesla TEDAPI LAN Client — RSA signed routable messages"
    )
    parser.add_argument("--host", default="192.168.91.1",
                        help="Gateway/inverter IP")
    parser.add_argument("--password", default=None,
                        help="Gateway QR code password (for local commands)")
    parser.add_argument("--din", default=None,
                        help="Device DIN (for signed commands without WiFi)")
    parser.add_argument("--key-dir", default=None,
                        help=f"Key storage dir (default: {DEFAULT_KEY_DIR})")
    parser.add_argument("--description", default=DESCRIPTION,
                        help=f"Client description (default: {DESCRIPTION})")
    parser.add_argument("--force-new-key", action="store_true",
                        help="Regenerate key pair")

    parser.add_argument("--use-fleet-api", action="store_true",
                        help="Use Fleet API instead of Owner API for cloud commands")

    subs = parser.add_subparsers(dest="command")

    # auth (get OAuth token)
    sub_auth = subs.add_parser("auth", help="Get Tesla OAuth token (PKCE flow)")
    sub_auth.set_defaults(func=cmd_auth)

    # get-sites (list energy sites)
    sub_sites = subs.add_parser("get-sites", help="List energy sites to find site_id")
    sub_sites.add_argument("--token", default=None, help="Tesla API access token")
    sub_sites.set_defaults(func=cmd_get_sites)

    # register (local WiFi)
    sub_reg = subs.add_parser("register", help="Register RSA key locally (WiFi)")
    sub_reg.set_defaults(func=cmd_register)

    # register-trusted (local WiFi, trusted signature variant)
    sub_trusted = subs.add_parser("register-trusted",
        help="Register RSA key via trusted-signature method (local WiFi)")
    sub_trusted.add_argument("--remove-first", action="store_true",
        help="Remove existing key registration before re-registering")
    sub_trusted.set_defaults(func=cmd_register_trusted)

    # register-cloud (Tesla Owner API)
    sub_cloud = subs.add_parser("register-cloud", help="Register RSA key via Tesla cloud")
    sub_cloud.add_argument("--token", default=None, help="Tesla API access token")
    sub_cloud.add_argument("--site-id", required=True, help="Tesla energy site ID")
    sub_cloud.set_defaults(func=cmd_register_cloud)

    # cloud-list (check status via cloud)
    sub_cl = subs.add_parser("cloud-list", help="List authorized clients via cloud API")
    sub_cl.add_argument("--token", default=None, help="Tesla API access token")
    sub_cl.add_argument("--site-id", required=True, help="Tesla energy site ID")
    sub_cl.set_defaults(func=cmd_cloud_list)

    # configure-remote (enable remote service to trigger cloud verification)
    sub_remote = subs.add_parser("configure-remote",
        help="Configure remote service access (may trigger cloud key verification)")
    sub_remote.add_argument("--duration", type=int, default=86400,
        help="Duration in seconds (default: 86400 = 24 hours)")
    sub_remote.add_argument("--email", required=True,
        help="Tesla account email for the requester")
    sub_remote.set_defaults(func=cmd_configure_remote)

    # get-device-key (get device's ECC public key)
    sub_dk = subs.add_parser("get-device-key",
        help="Get device's signed commands ECC public key")
    sub_dk.set_defaults(func=cmd_get_device_key)

    # list (local)
    sub_list = subs.add_parser("list", help="List authorized clients (local)")
    sub_list.set_defaults(func=cmd_list)

    # remove
    sub_rm = subs.add_parser("remove", help="Remove registered key")
    sub_rm.set_defaults(func=cmd_remove)

    # tedapi-bearer (test TEDAPI with REST login Bearer token)
    sub_bearer = subs.add_parser("tedapi-bearer",
        help="Test TEDAPI v1 using Bearer token from REST login")
    sub_bearer.set_defaults(func=cmd_tedapi_bearer)

    # rest-login (test REST API on device)
    sub_rest = subs.add_parser("rest-login",
        help="Test REST API /api/login/Basic on the device")
    sub_rest.add_argument("--rest-password", default=None,
        help="Password for REST login (defaults to --password)")
    sub_rest.set_defaults(func=cmd_rest_login)

    # rest-explore (discover available REST endpoints)
    sub_explore = subs.add_parser("rest-explore",
        help="Explore available REST API endpoints on the device")
    sub_explore.add_argument("--rest-password", default=None,
        help="Password for REST login (defaults to --password)")
    sub_explore.set_defaults(func=cmd_rest_explore)

    # rest-solar (read/write PVI status via REST)
    sub_solar = subs.add_parser("rest-solar",
        help="Read or write PVI solar status via REST API")
    sub_solar.add_argument("--rest-password", default=None,
        help="Password for REST login (defaults to --password)")
    sub_solar.add_argument("--set-status", default=None,
        choices=["on", "off", "dc_only", "unset"],
        help="Set PVI power status (omit to just read)")
    sub_solar.set_defaults(func=cmd_rest_solar)

    # check-verify (poll key state for breaker toggle verification)
    sub_check = subs.add_parser("check-verify",
        help="Poll key verification state (use after toggling breaker)")
    sub_check.add_argument("--interval", type=int, default=5,
        help="Polling interval in seconds (default: 5)")
    sub_check.set_defaults(func=cmd_check_verify)

    # test-signed (networking status)
    sub_test = subs.add_parser("test-signed", help="Test signed msg: networking status")
    sub_test.set_defaults(func=cmd_test_signed)

    # test-signed-config (read config.json)
    sub_cfg = subs.add_parser("test-signed-config", help="Test signed msg: read config")
    sub_cfg.set_defaults(func=cmd_test_signed_config)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    LOCAL_COMMANDS = ("register", "register-trusted", "list", "remove",
                      "configure-remote", "get-device-key", "check-verify")
    REST_COMMANDS = ("rest-login", "rest-explore", "rest-solar")
    if args.command in LOCAL_COMMANDS:
        if not args.password:
            print(f"ERROR: --password required for '{args.command}' command")
            return
    if args.command in REST_COMMANDS:
        if not args.password and not getattr(args, 'rest_password', None):
            print(f"ERROR: --password or --rest-password required for '{args.command}'")
            return

    args.func(args)


if __name__ == "__main__":
    main()
