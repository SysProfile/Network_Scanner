import subprocess
import re
import json
import ipaddress
import paramiko
import traceback
import sys
import os
import threading
import time
import getpass
import requests
from datetime import datetime
from collections import defaultdict

# Optional SNMP support
try:
    from pysnmp.hlapi import (
        SnmpEngine, CommunityData, UsmUserData,
        UdpTransportTarget, ContextData,
        ObjectType, ObjectIdentity,
        getCmd, nextCmd,
        usmHMACMD5AuthProtocol, usmHMACSHAAuthProtocol,
        usmDESPrivProtocol, usmAesCfb128Protocol,
    )
    SNMP_AVAILABLE = True
except ImportError:
    SNMP_AVAILABLE = False

# ─────────────────────────────────────────────
#  PATHS
# ─────────────────────────────────────────────
SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(SCRIPT_DIR, "switches_config.json")
LOG_DIR     = "/var/log/network_scanner"

# ─────────────────────────────────────────────
#  ANSI COLORS
# ─────────────────────────────────────────────
class Color:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"
    GREY   = "\033[90m"
    ULINE  = "\033[4m"

def print_header(text): print(f"\n{Color.BOLD}{Color.CYAN}{'─'*60}\n  {text}\n{'─'*60}{Color.RESET}")
def print_ok(text):     print(f"{Color.GREEN}[✓]{Color.RESET} {text}")
def print_info(text):   print(f"{Color.CYAN}[i]{Color.RESET} {text}")
def print_warn(text):   print(f"{Color.YELLOW}[!]{Color.RESET} {text}")
def print_err(text):    print(f"{Color.RED}[✗]{Color.RESET} {text}")

# ─────────────────────────────────────────────
#  CONFIG LOADER
# ─────────────────────────────────────────────

# Runtime state populated by load_config()
NET      = {}
SWITCHES = {}
MODELS   = {}

def load_config():
    """
    Loads switches_config.json into NET, SWITCHES and MODELS.
    If the file does not exist, creates a minimal default and loads it.
    """
    global NET, SWITCHES, MODELS

    if not os.path.isfile(CONFIG_FILE):
        print_warn(f"Config file not found. Creating default: {CONFIG_FILE}")
        _write_default_config()

    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as file_handle:
            data = json.load(file_handle)
    except json.JSONDecodeError as json_err:
        print_err(f"Invalid JSON in {CONFIG_FILE}: {json_err}")
        sys.exit(1)

    NET = data.get("network", {})

    SWITCHES = {}
    for entry in data.get("switches", []):
        sw_id = entry.get("id")
        if sw_id is not None:
            SWITCHES[sw_id] = {
                "ip":       entry.get("ip", ""),
                "model_id": entry.get("model_id", "HUAWEI_VRP"),
                "snmp":     entry.get("snmp", {}),
            }

    MODELS = {}
    for model in data.get("models", []):
        model_id = model.get("id")
        if model_id:
            MODELS[model_id] = model

    snmp_count = sum(1 for s in SWITCHES.values() if s.get("snmp", {}).get("enabled"))
    snmp_label = f", {snmp_count} SNMP-enabled" if snmp_count else ""
    print_ok(f"Config loaded — {len(SWITCHES)} switch(es){snmp_label}, {len(MODELS)} model(s) available.")

def _write_default_config():
    """Writes a minimal default switches_config.json."""
    default = {
        "network": {
            "interface":    "vmbr0",
            "network_cidr": "192.168.0.0/18",
            "dhcp_start":   "192.168.3.1",
            "dhcp_end":     "192.168.8.254"
        },
        "switches": [
            {"id": i, "ip": f"192.168.1.{i}", "model_id": "HUAWEI_VRP"}
            for i in range(1, 9)
        ],
        "models": [
            {
                "id":          "HUAWEI_VRP",
                "brand":       "Huawei",
                "description": "Huawei VRP — S310, S5700, S5720, S6720, CE series",
                "mac_format":  "huawei",
                "port_keywords":   ["GE", "ETH", "XGE"],
                "uplink_keywords": ["10GE", "XGE"],
                "error_strings":   ["Error:", "Unrecognized command", "Wrong parameter"],
                "commands": {
                    "find_mac":       "display mac-address {mac}",
                    "port_config":    "display current-configuration interface {port}",
                    "port_state":     "display interface {port} | include current state",
                    "port_vlan":      "display port vlan {port}",
                    "port_errors":    "display interface {port} | include errors",
                    "arp_lookup":     "display arp | include {mac}",
                    "lldp_neighbors": "display lldp neighbor interface {port} brief",
                    "poe_status":     "display poe power interface {port}",
                    "version":        "display version | include VRP",
                    "cpu_usage":      "display cpu-usage"
                }
            }
        ]
    }
    with open(CONFIG_FILE, "w", encoding="utf-8") as file_handle:
        json.dump(default, file_handle, indent=2)

def save_config():
    """Writes current NET, SWITCHES and MODELS back to switches_config.json."""
    switches_list = []
    for sw_id in sorted(SWITCHES.keys()):
        entry = {"id": sw_id, "ip": SWITCHES[sw_id]["ip"], "model_id": SWITCHES[sw_id]["model_id"]}
        snmp = SWITCHES[sw_id].get("snmp", {})
        if snmp.get("enabled"):
            entry["snmp"] = snmp
        switches_list.append(entry)

    models_list = []
    for model_id in sorted(MODELS.keys()):
        models_list.append(MODELS[model_id])

    data = {
        "network":  NET,
        "switches": switches_list,
        "models":   models_list,
    }
    with open(CONFIG_FILE, "w", encoding="utf-8") as file_handle:
        json.dump(data, file_handle, indent=2)
    print_ok(f"Config saved to {CONFIG_FILE}")

# ─────────────────────────────────────────────
#  MODEL HELPERS
# ─────────────────────────────────────────────
def get_model(switch_ip):
    """Returns the model dict for a given switch IP."""
    for sw_data in SWITCHES.values():
        if sw_data["ip"] == switch_ip:
            return MODELS.get(sw_data["model_id"])
    return None

def get_model_by_id(model_id):
    return MODELS.get(model_id)

def model_cmd(model, key, mac="", port=""):
    """Returns the formatted CLI command from the model definition."""
    template = model.get("commands", {}).get(key, "")
    return template.replace("{mac}", mac).replace("{port}", port)

def is_error_output(output, model):
    """Returns True if the output contains any known error strings for this model."""
    for err_str in model.get("error_strings", []):
        if err_str.lower() in output.lower():
            return True
    return False

# ─────────────────────────────────────────────
#  MAC FORMATTING PER VENDOR
# ─────────────────────────────────────────────
def format_mac_for_model(clean_mac, mac_format):
    """
    Converts a 12-char hex string to the MAC format expected by the vendor CLI.
      huawei : 5081-4037-1a2a
      cisco  : 5081.4037.1a2a
      colon  : 50:81:40:37:1a:2a   (default — Aruba, Juniper, MikroTik, D-Link, TP-Link)
    """
    clean = clean_mac.lower()
    if mac_format == "huawei":
        return f"{clean[:4]}-{clean[4:8]}-{clean[8:12]}"
    if mac_format == "cisco":
        return f"{clean[:4]}.{clean[4:8]}.{clean[8:12]}"
    return ":".join(clean[i:i+2] for i in range(0, 12, 2))

def normalize_mac(mac_str):
    """
    Returns (clean_12_hex, upper_colon_display) or (None, None) if invalid.
    clean_12 is the raw 12 hex chars used as the base for all further formatting.
    """
    clean = mac_str.replace(":", "").replace("-", "").replace(".", "").lower()
    if len(clean) != 12:
        return None, None
    upper = ":".join(clean[i:i+2].upper() for i in range(0, 12, 2))
    return clean, upper

# ─────────────────────────────────────────────
#  UTILITIES
# ─────────────────────────────────────────────
def is_in_dhcp_range(ip_str):
    try:
        ip    = ipaddress.ip_address(ip_str)
        start = ipaddress.ip_address(NET.get("dhcp_start", "0.0.0.0"))
        end   = ipaddress.ip_address(NET.get("dhcp_end",   "0.0.0.0"))
        return start <= ip <= end
    except:
        return False

def get_vendor(mac_upper):
    """Queries MAC vendor via macvendors.com public API."""
    try:
        response = requests.get(f"https://api.macvendors.com/{mac_upper}", timeout=4)
        if response.status_code == 200:
            return response.text.strip()
    except:
        pass
    return "Unknown"

def save_log(content):
    """Saves a text log to LOG_DIR."""
    os.makedirs(LOG_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path      = os.path.join(LOG_DIR, f"session_{timestamp}.log")
    with open(path, "w") as file_handle:
        file_handle.write(content)
    print_ok(f"Log saved: {path}")

def prompt_credentials():
    username = input("  SSH Username : ").strip()
    password = getpass.getpass("  SSH Password : ")
    return username, password

def prompt_snmp_credentials():
    """
    Checks which SNMP versions are needed across all switches
    and prompts for the appropriate credentials.
    Returns a dict with community (v2c) and/or v3 credentials.
    """
    creds = {}
    needs_v2c = False
    needs_v3  = False

    for sw_data in SWITCHES.values():
        snmp = sw_data.get("snmp", {})
        if snmp.get("enabled"):
            ver = str(snmp.get("version", "2c"))
            if ver == "2c":
                needs_v2c = True
            elif ver == "3":
                needs_v3 = True

    if not needs_v2c and not needs_v3:
        return creds

    print(f"\n  {Color.BOLD}SNMP Credentials{Color.RESET}")

    if needs_v2c:
        community = input("  SNMPv2c Community  : ").strip()
        if not community:
            community = "public"
        creds["community"] = community

    if needs_v3:
        print(f"  {Color.GREY}SNMPv3 credentials:{Color.RESET}")
        creds["v3_username"]      = input("    Username       : ").strip()
        creds["v3_auth_protocol"] = input("    Auth protocol  (MD5/SHA) [SHA]: ").strip().upper() or "SHA"
        creds["v3_auth_password"] = getpass.getpass("    Auth password  : ")
        creds["v3_priv_protocol"] = input("    Priv protocol  (DES/AES) [AES]: ").strip().upper() or "AES"
        creds["v3_priv_password"] = getpass.getpass("    Priv password  : ")

    return creds

def has_snmp_switches():
    """Returns True if any switch has SNMP enabled."""
    return any(s.get("snmp", {}).get("enabled") for s in SWITCHES.values())

# ─────────────────────────────────────────────
#  SSH: exec with invoke_shell fallback
#  Required for Huawei switches that reject
#  exec_command with "Unable to open channel"
# ─────────────────────────────────────────────
def ssh_exec(client, command, timeout=8):
    """
    Tries open_session first; falls back to invoke_shell
    for switches that reject direct exec_command.
    """
    try:
        transport = client.get_transport()
        if transport and transport.is_active():
            channel = transport.open_session()
            channel.settimeout(timeout)
            channel.exec_command(command)
            output   = b""
            deadline = time.time() + timeout
            while time.time() < deadline:
                if channel.recv_ready():
                    output += channel.recv(65535)
                elif channel.exit_status_ready():
                    break
                else:
                    time.sleep(0.1)
            channel.close()
            return output.decode("utf-8", errors="ignore").strip()
    except Exception:
        pass

    try:
        shell = client.invoke_shell(width=512, height=512)
        shell.settimeout(timeout)
        time.sleep(0.8)
        while shell.recv_ready():
            shell.recv(65535)
        shell.send(command + "\n")
        time.sleep(2.0)
        output   = b""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if shell.recv_ready():
                output += shell.recv(65535)
            else:
                time.sleep(0.2)
        shell.close()
        return output.decode("utf-8", errors="ignore").strip()
    except Exception:
        return ""

# ─────────────────────────────────────────────
#  SNMP FUNCTIONS
# ─────────────────────────────────────────────

# Standard OIDs
OID_QBRIDGE_FDB_PORT   = "1.3.6.1.2.1.17.7.1.2.2.1.2"   # Q-BRIDGE-MIB dot1qTpFdbPort
OID_BRIDGE_FDB_PORT    = "1.3.6.1.2.1.17.4.3.1.2"        # BRIDGE-MIB  dot1dTpFdbPort
OID_BASE_PORT_IFINDEX  = "1.3.6.1.2.1.17.1.4.1.2"        # dot1dBasePortIfIndex
OID_IF_NAME            = "1.3.6.1.2.1.31.1.1.1.1"         # IF-MIB ifName
OID_IF_DESCR           = "1.3.6.1.2.1.2.2.1.2"            # IF-MIB ifDescr
OID_SYS_DESCR          = "1.3.6.1.2.1.1.1.0"              # SNMPv2-MIB sysDescr
OID_SYS_NAME           = "1.3.6.1.2.1.1.5.0"              # SNMPv2-MIB sysName
OID_HR_CPU_LOAD        = "1.3.6.1.2.1.25.3.3.1.2"         # HOST-RESOURCES-MIB hrProcessorLoad

def _build_snmp_auth(snmp_config, snmp_creds):
    """Builds the pysnmp authentication object for a switch."""
    version = str(snmp_config.get("version", "2c"))

    if version == "2c":
        community = snmp_creds.get("community", "public")
        return CommunityData(community)

    if version == "3":
        auth_proto_map = {
            "MD5": usmHMACMD5AuthProtocol,
            "SHA": usmHMACSHAAuthProtocol,
        }
        priv_proto_map = {
            "DES": usmDESPrivProtocol,
            "AES": usmAesCfb128Protocol,
        }
        auth_proto = snmp_creds.get("v3_auth_protocol", "SHA").upper()
        priv_proto = snmp_creds.get("v3_priv_protocol", "AES").upper()
        return UsmUserData(
            snmp_creds.get("v3_username", ""),
            snmp_creds.get("v3_auth_password", ""),
            snmp_creds.get("v3_priv_password", ""),
            authProtocol=auth_proto_map.get(auth_proto, usmHMACSHAAuthProtocol),
            privProtocol=priv_proto_map.get(priv_proto, usmAesCfb128Protocol),
        )
    return None

def _mac_to_oid_suffix(clean_mac):
    """Converts a 12-char hex MAC to OID decimal suffix: '80.129.64.55.26.42'."""
    return ".".join(str(int(clean_mac[i:i+2], 16)) for i in range(0, 12, 2))

def _oid_suffix_to_mac(suffix_parts):
    """Converts OID decimal suffix parts (list of ints) to 12-char hex MAC."""
    if len(suffix_parts) != 6:
        return None
    return "".join(f"{b:02x}" for b in suffix_parts)

def snmp_get_single(switch_ip, snmp_port, auth_data, oid_str):
    """Performs a single SNMP GET and returns the value or None."""
    if not SNMP_AVAILABLE:
        return None
    try:
        iterator = getCmd(
            SnmpEngine(), auth_data,
            UdpTransportTarget((switch_ip, snmp_port), timeout=5, retries=1),
            ContextData(),
            ObjectType(ObjectIdentity(oid_str)),
        )
        error_indication, error_status, _, var_binds = next(iterator)
        if error_indication or error_status:
            return None
        for _, val in var_binds:
            result = str(val)
            if result and result.lower() not in ("", "nosuchobject", "nosuchinstance", "endofmibview"):
                return result
    except Exception:
        pass
    return None

def snmp_walk(switch_ip, snmp_port, auth_data, oid_str):
    """Walks an OID subtree and returns list of (oid_string, value) tuples."""
    if not SNMP_AVAILABLE:
        return []
    results = []
    try:
        for (error_indication, error_status, _, var_binds) in nextCmd(
            SnmpEngine(), auth_data,
            UdpTransportTarget((switch_ip, snmp_port), timeout=5, retries=1),
            ContextData(),
            ObjectType(ObjectIdentity(oid_str)),
            lexicographicMode=False,
        ):
            if error_indication or error_status:
                break
            for oid, val in var_binds:
                results.append((str(oid), str(val)))
    except Exception:
        pass
    return results

def snmp_find_mac_port(switch_ip, snmp_config, snmp_creds, clean_mac):
    """
    Searches for a MAC address via SNMP on a switch.
    Returns (port_name, bridge_port) or (None, None) if not found.

    Strategy:
      1. Try Q-BRIDGE-MIB (dot1qTpFdbPort) — VLAN-aware, most modern switches
      2. Fall back to BRIDGE-MIB (dot1dTpFdbPort) — legacy
      3. Map bridge port → ifIndex → ifName to get physical port name
    """
    auth_data = _build_snmp_auth(snmp_config, snmp_creds)
    if auth_data is None:
        return None, None

    snmp_port    = snmp_config.get("port", 161)
    mac_suffix   = _mac_to_oid_suffix(clean_mac)
    bridge_port  = None

    # 1. Try Q-BRIDGE-MIB (index: VLAN_ID.MAC_OCTETS)
    qbridge_results = snmp_walk(switch_ip, snmp_port, auth_data, OID_QBRIDGE_FDB_PORT)
    for oid_str, val in qbridge_results:
        parts = oid_str.split(".")
        if len(parts) >= 6:
            tail_mac = _oid_suffix_to_mac([int(p) for p in parts[-6:]])
            if tail_mac and tail_mac.lower() == clean_mac.lower():
                try:
                    bridge_port = int(val)
                except (ValueError, TypeError):
                    pass
                break

    # 2. Fall back to BRIDGE-MIB (index: MAC_OCTETS directly)
    if bridge_port is None:
        direct_oid = f"{OID_BRIDGE_FDB_PORT}.{mac_suffix}"
        result     = snmp_get_single(switch_ip, snmp_port, auth_data, direct_oid)
        if result is not None:
            try:
                bridge_port = int(result)
            except (ValueError, TypeError):
                pass

    if bridge_port is None:
        return None, None

    # 3. Map bridge port → ifIndex
    ifindex_oid = f"{OID_BASE_PORT_IFINDEX}.{bridge_port}"
    ifindex_val = snmp_get_single(switch_ip, snmp_port, auth_data, ifindex_oid)
    if ifindex_val is None:
        return f"bridge-port-{bridge_port}", bridge_port

    # 4. Map ifIndex → port name (try ifName first, then ifDescr)
    ifindex   = ifindex_val
    port_name = snmp_get_single(switch_ip, snmp_port, auth_data, f"{OID_IF_NAME}.{ifindex}")
    if not port_name:
        port_name = snmp_get_single(switch_ip, snmp_port, auth_data, f"{OID_IF_DESCR}.{ifindex}")
    if not port_name:
        port_name = f"ifIndex-{ifindex}"

    return port_name, bridge_port

def snmp_get_version(switch_ip, snmp_config, snmp_creds):
    """Returns sysDescr (first line, max 120 chars) via SNMP, or None."""
    auth_data = _build_snmp_auth(snmp_config, snmp_creds)
    if auth_data is None:
        return None
    result = snmp_get_single(switch_ip, snmp_config.get("port", 161), auth_data, OID_SYS_DESCR)
    if result:
        return result.splitlines()[0][:120]
    return None

def snmp_get_cpu(switch_ip, snmp_config, snmp_creds):
    """Returns average CPU load via HOST-RESOURCES-MIB, or None."""
    auth_data = _build_snmp_auth(snmp_config, snmp_creds)
    if auth_data is None:
        return None
    results = snmp_walk(switch_ip, snmp_config.get("port", 161), auth_data, OID_HR_CPU_LOAD)
    if results:
        loads = []
        for _, val in results:
            try:
                loads.append(int(val))
            except (ValueError, TypeError):
                pass
        if loads:
            avg = sum(loads) // len(loads)
            return f"CPU {avg}% (SNMP, {len(loads)} core(s))"
    return None

# ─────────────────────────────────────────────
#  PORT DETECTION  (model-aware)
# ─────────────────────────────────────────────
def detect_port_type(port_name, model):
    """
    Returns "UPLINK/TRUNK" if the port name matches an uplink keyword,
    otherwise returns "ACCESS".
    """
    for kw in model.get("uplink_keywords", []):
        if kw.upper() in port_name.upper():
            return "UPLINK/TRUNK"
    return "ACCESS"

def extract_port_from_line(line, model):
    """
    Scans a MAC table output line and returns the first token that
    matches one of the model's port_keywords.
    """
    for part in line.split():
        for kw in model.get("port_keywords", []):
            if kw.upper() in part.upper():
                return part
    return None

# ─────────────────────────────────────────────
#  PORT DETAILS  (model-aware)
# ─────────────────────────────────────────────
def get_port_details(client, port, clean_mac, model):
    """Retrieves detailed port information using model-specific commands."""
    mac_fmt = format_mac_for_model(clean_mac, model.get("mac_format", "colon"))
    lines   = ["\n" + "─"*60, f"  PORT DETAILS: {port}", "─"*60]
    checks  = [
        ("Current config",    "port_config"),
        ("Physical state",    "port_state"),
        ("Port VLAN",         "port_vlan"),
        ("Interface errors",  "port_errors"),
        ("ARP table match",   "arp_lookup"),
        ("LLDP neighbors",    "lldp_neighbors"),
        ("PoE consumption",   "poe_status"),
    ]
    for title, cmd_key in checks:
        cmd = model_cmd(model, cmd_key, mac=mac_fmt, port=port)
        if not cmd:
            continue
        try:
            output = ssh_exec(client, cmd)
            if output and not is_error_output(output, model):
                lines.append(f"\n  ▶ {title}:\n{output}")
        except:
            pass
    return "\n".join(lines)

def get_port_vlan(client, port, model):
    """Extracts the first VLAN number from the port VLAN command output."""
    cmd = model_cmd(model, "port_vlan", port=port)
    if not cmd:
        return "N/A"
    try:
        output = ssh_exec(client, cmd)
        for line in output.splitlines():
            vlan_match = re.search(r"\b(\d+)\b", line)
            if vlan_match:
                return vlan_match.group(1)
    except:
        pass
    return "N/A"

# ─────────────────────────────────────────────
#  SEARCH MAC ON A SINGLE SWITCH (thread worker)
#  Tries SSH first, falls back to SNMP if
#  the switch has SNMP enabled in its config.
# ─────────────────────────────────────────────
def search_mac_on_switch(switch_num, switch_ip, clean_mac, username, password,
                         snmp_creds, results, lock):
    sw_data  = SWITCHES.get(switch_num, {})
    model    = get_model(switch_ip)
    snmp_cfg = sw_data.get("snmp", {})

    if model is None:
        with lock:
            print_warn(f"Switch #{switch_num} ({switch_ip}) — no model defined in config, skipping.")
        return

    mac_fmt    = format_mac_for_model(clean_mac, model.get("mac_format", "colon"))
    ssh_ok     = False
    found_ssh  = False

    # ── Try SSH first ──
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            switch_ip,
            username=username,
            password=password,
            timeout=8,
            allow_agent=False,
            look_for_keys=False,
        )
        ssh_ok = True

        output = ssh_exec(client, model_cmd(model, "find_mac", mac=mac_fmt))

        if mac_fmt.lower() in output.lower():
            for line in output.splitlines():
                if mac_fmt.lower() in line.lower():
                    port = extract_port_from_line(line, model)
                    if port:
                        found_ssh = True
                        port_type = detect_port_type(port, model)
                        vlan      = get_port_vlan(client, port, model)
                        details   = (
                            get_port_details(client, port, clean_mac, model)
                            if port_type == "ACCESS" else ""
                        )
                        with lock:
                            results.append({
                                "switch_num": switch_num,
                                "switch_ip":  switch_ip,
                                "model_id":   model["id"],
                                "brand":      model.get("brand", ""),
                                "port":       port,
                                "port_type":  port_type,
                                "vlan":       vlan,
                                "details":    details,
                                "via":        "SSH",
                            })
        client.close()

    except paramiko.AuthenticationException:
        with lock:
            print_err(f"Switch #{switch_num} ({switch_ip}) — SSH authentication failed.")
    except Exception:
        with lock:
            if not snmp_cfg.get("enabled"):
                print(f"\n{Color.RED}{'!'*20} ERROR on Switch #{switch_num} ({switch_ip}) {'!'*20}{Color.RESET}")
                traceback.print_exc()

    # ── SNMP fallback ──
    if not found_ssh and snmp_cfg.get("enabled") and SNMP_AVAILABLE and snmp_creds:
        fallback_reason = "SSH found no match" if ssh_ok else "SSH connection failed"
        with lock:
            print_info(f"Switch #{switch_num} ({switch_ip}) — {fallback_reason}, trying SNMP...")

        port_name, _ = snmp_find_mac_port(switch_ip, snmp_cfg, snmp_creds, clean_mac)

        if port_name:
            port_type = detect_port_type(port_name, model)
            with lock:
                results.append({
                    "switch_num": switch_num,
                    "switch_ip":  switch_ip,
                    "model_id":   model["id"],
                    "brand":      model.get("brand", ""),
                    "port":       port_name,
                    "port_type":  port_type,
                    "vlan":       "N/A (SNMP)",
                    "details":    "",
                    "via":        "SNMP",
                })

# ─────────────────────────────────────────────
#  SEARCH MAC  (parallel across all switches)
# ─────────────────────────────────────────────
def search_mac(mac_input, username, password, snmp_creds=None, log_lines=None):
    clean_mac, mac_upper = normalize_mac(mac_input)
    if not clean_mac:
        print_err("Invalid MAC format.")
        return

    print_header(f"MAC Trace: {mac_upper}")
    vendor = get_vendor(mac_upper)
    print_info(f"Vendor        : {Color.YELLOW}{vendor}{Color.RESET}")
    print_info(f"Searching on {len(SWITCHES)} switch(es) in parallel...")

    results = []
    lock    = threading.Lock()
    threads = []

    for sw_id, sw_data in SWITCHES.items():
        thread = threading.Thread(
            target=search_mac_on_switch,
            args=(sw_id, sw_data["ip"], clean_mac, username, password,
                  snmp_creds, results, lock),
            daemon=True,
        )
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    results.sort(key=lambda x: x["switch_num"])

    if not results:
        print_warn("MAC not found on any switch.")
        return

    print()
    for entry in results:
        via_tag = entry.get("via", "SSH")
        label   = (f"Switch #{entry['switch_num']}  ({entry['switch_ip']})"
                    f"  [{entry['brand']} / {entry['model_id']}]")
        if entry["port_type"] == "ACCESS":
            print(f"{Color.GREEN}{'='*60}{Color.RESET}")
            print(f"  {Color.BOLD}MAC FOUND ON ACCESS PORT{Color.RESET}  {Color.GREY}(via {via_tag}){Color.RESET}")
            print(f"  {Color.BOLD}Switch  :{Color.RESET} {label}")
            print(f"  {Color.BOLD}Port    :{Color.RESET} {entry['port']}")
            print(f"  {Color.BOLD}VLAN    :{Color.RESET} {entry['vlan']}")
            print(f"  {Color.BOLD}Vendor  :{Color.RESET} {vendor}")
            print(f"{Color.GREEN}{'='*60}{Color.RESET}")
            if entry["details"]:
                print(entry["details"])
        else:
            print_info(
                f"MAC seen on {label} → Port {entry['port']} "
                f"({Color.YELLOW}{entry['port_type']}{Color.RESET}), "
                f"VLAN: {entry['vlan']}  {Color.GREY}[via {via_tag}]{Color.RESET}"
            )

        if log_lines is not None:
            log_lines.append(
                f"MAC {mac_upper} | Switch #{entry['switch_num']} ({entry['switch_ip']}) "
                f"[{entry['model_id']}] | Port {entry['port']} | "
                f"Type {entry['port_type']} | VLAN {entry['vlan']} | "
                f"Vendor {vendor} | via {via_tag}"
            )

# ─────────────────────────────────────────────
#  SEARCH BY IP
# ─────────────────────────────────────────────
def search_by_ip(username, password, snmp_creds=None):
    target_ip = input("Enter IP to locate: ").strip()
    print_header(f"Search by IP: {target_ip}")

    found_mac = None

    try:
        proc = subprocess.run(["arp", "-n", target_ip], capture_output=True, text=True)
        for line in proc.stdout.splitlines():
            arp_match = re.search(r"([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}", line)
            if arp_match:
                found_mac = arp_match.group()
                break
    except:
        pass

    if not found_mac:
        print_info("Not in local ARP table, trying targeted arp-scan...")
        try:
            proc = subprocess.run(
                ["arp-scan", f"--interface={NET.get('interface','eth0')}", target_ip, "--plain"],
                capture_output=True, text=True,
            )
            for line in proc.stdout.splitlines():
                parts = line.split("\t")
                if len(parts) >= 2 and parts[0].strip() == target_ip:
                    found_mac = parts[1].strip()
                    break
        except:
            pass

    if not found_mac:
        print_err(f"Could not resolve MAC for {target_ip}.")
        return

    print_ok(f"Resolved MAC: {found_mac}")
    search_mac(found_mac, username, password, snmp_creds)

# ─────────────────────────────────────────────
#  SEARCH MULTIPLE MACs
# ─────────────────────────────────────────────
def search_multiple_macs(username, password, snmp_creds=None):
    print_header("Multiple MAC Search")
    print("Enter MACs separated by commas or one per line. Empty line to finish.\n")

    mac_list = []
    while True:
        line = input("> ").strip()
        if not line:
            break
        for item in line.split(","):
            item = item.strip()
            if item:
                mac_list.append(item)

    if not mac_list:
        print_warn("No MACs entered.")
        return

    log_lines = [f"=== Multiple MAC search {datetime.now()} ==="]
    for mac in mac_list:
        search_mac(mac, username, password, snmp_creds, log_lines)

    if input("\nSave results to log? (y/n): ").strip().lower() == "y":
        save_log("\n".join(log_lines))

# ─────────────────────────────────────────────
#  ARP SCAN
#  NOTE: Devices in the DHCP range may have
#  either static or DHCP-assigned IPs. This tool
#  uses ARP only and does NOT query the DHCP
#  server. Cross-check with your DHCP lease table.
# ─────────────────────────────────────────────
def run_arp_scan():
    interface    = NET.get("interface",    "eth0")
    network_cidr = NET.get("network_cidr", "192.168.0.0/24")

    print_header(f"ARP Scan  —  {network_cidr}  /  Interface: {interface}")
    print_info(f"DHCP range: {NET.get('dhcp_start')} → {NET.get('dhcp_end')}")
    print_info("Note: IPs in DHCP range may be static OR DHCP-assigned.")
    print_info("Cross-check with your DHCP server to confirm static assignments.")

    cmd = [
        "arp-scan",
        f"--interface={interface}",
        network_cidr,
        "--retry=2", "--timeout=600", "--plain",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except Exception as scan_error:
        print_err(f"arp-scan error: {scan_error}")
        return

    mac_to_ips = defaultdict(set)
    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            ip  = parts[0].strip()
            mac = parts[1].strip().upper()
            mac_to_ips[mac].add(ip)

    ips_in_dhcp_range = []
    for mac, ips in mac_to_ips.items():
        for ip in ips:
            if is_in_dhcp_range(ip):
                ips_in_dhcp_range.append((ip, mac))

    duplicates = [(mac, ips) for mac, ips in mac_to_ips.items() if len(ips) > 1]
    total      = len(mac_to_ips)

    if duplicates:
        print(f"\n{Color.BOLD}  MACs with multiple IPs:{Color.RESET}")
        print(f"  {'MAC ADDRESS':<20} {'#IPs':<6} {'In DHCP range':^14}  IPs")
        print("  " + "─" * 76)
        for mac, ips in sorted(duplicates, key=lambda x: -len(x[1])):
            in_range = any(is_in_dhcp_range(i) for i in ips)
            flag     = f"{Color.YELLOW}YES{Color.RESET}" if in_range else "No"
            print(f"  {mac:<20} {len(ips):<6} {flag:^14}  {', '.join(list(ips)[:5])}")

    if ips_in_dhcp_range:
        print(f"\n{Color.BOLD}{Color.YELLOW}  ⚠ IPs DETECTED IN DHCP RANGE (static or DHCP — verify with DHCP server):{Color.RESET}")
        print(f"  {'IP ADDRESS':<18} {'MAC ADDRESS'}")
        print("  " + "─" * 42)
        for ip, mac in sorted(ips_in_dhcp_range, key=lambda x: ipaddress.ip_address(x[0])):
            print(f"  {Color.YELLOW}{ip:<18}{Color.RESET} {mac}")
    else:
        print_ok("No IPs detected in the DHCP range.")

    print(f"\n  {Color.BOLD}Total MACs:{Color.RESET} {total}   "
          f"{Color.BOLD}Duplicates:{Color.RESET} {len(duplicates)}   "
          f"{Color.BOLD}In DHCP range:{Color.RESET} {len(ips_in_dhcp_range)}")

# ─────────────────────────────────────────────
#  SWITCH CONNECTIVITY CHECK  (model-aware)
#  SSH first, SNMP fallback for version/CPU.
# ─────────────────────────────────────────────
def check_switch_connectivity(username, password, snmp_creds=None):
    print_header("Switch Connectivity")
    for sw_id, sw_data in sorted(SWITCHES.items()):
        switch_ip = sw_data["ip"]
        model     = get_model_by_id(sw_data["model_id"])
        snmp_cfg  = sw_data.get("snmp", {})
        brand     = model.get("brand", sw_data["model_id"]) if model else sw_data["model_id"]
        label     = f"Switch #{sw_id} ({switch_ip}) [{brand} / {sw_data['model_id']}]"

        ping = subprocess.run(
            ["ping", "-c", "1", "-W", "1", switch_ip],
            capture_output=True
        )
        if ping.returncode != 0:
            print_warn(f"{label} — NO RESPONSE (ping)")
            continue

        if model is None:
            print_warn(f"{label} — model '{sw_data['model_id']}' not found in config.")
            continue

        ssh_ok      = False
        version_str = "N/A"
        cpu_str     = "N/A"

        # ── Try SSH ──
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                switch_ip,
                username=username,
                password=password,
                timeout=8,
                allow_agent=False,
                look_for_keys=False,
            )
            ssh_ok = True

            ver_output = ssh_exec(client, model_cmd(model, "version"))
            ver_lines  = [ln for ln in ver_output.splitlines() if ln.strip()]
            if ver_lines:
                version_str = ver_lines[0]

            cpu_output = ssh_exec(client, model_cmd(model, "cpu_usage"))
            for line in cpu_output.splitlines():
                if "cpu" in line.lower():
                    cpu_str = line.strip()
                    break

            client.close()
            print_ok(f"{label}  {Color.YELLOW}{version_str}{Color.RESET}  |  {cpu_str}")

        except paramiko.AuthenticationException:
            print_err(f"{label} — SSH authentication failed.")
        except Exception as ssh_error:
            if not snmp_cfg.get("enabled"):
                print_err(f"{label} — SSH error: {ssh_error}")

        # ── SNMP fallback ──
        if not ssh_ok and snmp_cfg.get("enabled") and SNMP_AVAILABLE and snmp_creds:
            ver = snmp_get_version(switch_ip, snmp_cfg, snmp_creds)
            cpu = snmp_get_cpu(switch_ip, snmp_cfg, snmp_creds)
            if ver:
                version_str = ver
            if cpu:
                cpu_str = cpu
            if ver or cpu:
                print_ok(f"{label}  {Color.YELLOW}{version_str}{Color.RESET}  |  {cpu_str}  {Color.GREY}[SNMP]{Color.RESET}")
            else:
                print_err(f"{label} — SSH failed, SNMP returned no data.")

# ─────────────────────────────────────────────
#  CONFIGURATION EDITOR
# ─────────────────────────────────────────────

EDITOR_MENU = """{bold}{cyan}╔════════════════════════════════════════╗
║       CONFIGURATION EDITOR             ║
╠════════════════════════════════════════╣
║  [1] Edit network settings             ║
║  [2] List switches                     ║
║  [3] Add switch                        ║
║  [4] Edit switch                       ║
║  [5] Delete switch                     ║
║  [6] List models                       ║
║  [7] Add model                         ║
║  [8] Edit model                        ║
║  [9] Delete model                      ║
║  [B] Back to main menu                 ║
╚════════════════════════════════════════╝{reset}"""

def _input_default(prompt, default):
    """Input with default value shown in brackets."""
    val = input(f"  {prompt} [{default}]: ").strip()
    return val if val else str(default)

def _input_list(prompt, current_list):
    """Input for a comma-separated list with current values shown."""
    current = ", ".join(current_list) if current_list else "(empty)"
    print(f"  {prompt}")
    val = input(f"    Current: {current}\n    New (comma-separated, Enter to keep): ").strip()
    if not val:
        return current_list
    return [item.strip() for item in val.split(",") if item.strip()]

def _validate_ip(ip_str):
    """Returns True if ip_str is a valid IPv4 address."""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def edit_network_settings():
    """Interactive editor for the network section."""
    print_header("Edit Network Settings")
    print(f"  {Color.GREY}Press Enter to keep current value.{Color.RESET}\n")

    NET["interface"]    = _input_default("Interface",    NET.get("interface", "eth0"))
    NET["network_cidr"] = _input_default("Network CIDR", NET.get("network_cidr", "192.168.0.0/24"))
    NET["dhcp_start"]   = _input_default("DHCP start",   NET.get("dhcp_start", ""))
    NET["dhcp_end"]     = _input_default("DHCP end",     NET.get("dhcp_end", ""))

    save_config()

def list_switches():
    """Displays all configured switches in a table."""
    print_header("Configured Switches")
    if not SWITCHES:
        print_warn("No switches configured.")
        return

    print(f"  {'ID':<5} {'IP ADDRESS':<18} {'MODEL':<20} {'SNMP':<20}")
    print("  " + "─" * 65)
    for sw_id in sorted(SWITCHES.keys()):
        sw   = SWITCHES[sw_id]
        snmp = sw.get("snmp", {})
        if snmp.get("enabled"):
            snmp_label = f"v{snmp.get('version','2c')} port:{snmp.get('port',161)}"
        else:
            snmp_label = "disabled"
        print(f"  {sw_id:<5} {sw['ip']:<18} {sw['model_id']:<20} {snmp_label:<20}")

def add_switch():
    """Interactive wizard to add a new switch."""
    print_header("Add Switch")

    # ID
    while True:
        try:
            new_id = int(input("  Switch ID (number): ").strip())
        except ValueError:
            print_err("ID must be a number.")
            continue
        if new_id in SWITCHES:
            print_err(f"ID {new_id} already exists.")
            continue
        break

    # IP
    while True:
        new_ip = input("  IP address: ").strip()
        if not _validate_ip(new_ip):
            print_err("Invalid IP address.")
            continue
        break

    # Model
    print(f"\n  Available models: {', '.join(sorted(MODELS.keys()))}")
    while True:
        model_id = input("  Model ID: ").strip()
        if model_id not in MODELS:
            print_err(f"Model '{model_id}' not found. Use one of the listed models.")
            continue
        break

    # SNMP
    snmp = {}
    if input("  Enable SNMP? (y/n) [n]: ").strip().lower() == "y":
        version = input("    SNMP version (2c/3) [2c]: ").strip() or "2c"
        port    = input("    SNMP port [161]: ").strip() or "161"
        snmp = {"enabled": True, "version": version, "port": int(port)}

    SWITCHES[new_id] = {"ip": new_ip, "model_id": model_id, "snmp": snmp}
    save_config()
    print_ok(f"Switch #{new_id} added.")

def edit_switch():
    """Interactive editor for an existing switch."""
    list_switches()
    if not SWITCHES:
        return

    try:
        sw_id = int(input("\n  Switch ID to edit: ").strip())
    except ValueError:
        print_err("Invalid ID.")
        return

    if sw_id not in SWITCHES:
        print_err(f"Switch #{sw_id} not found.")
        return

    sw = SWITCHES[sw_id]
    print_header(f"Edit Switch #{sw_id}")
    print(f"  {Color.GREY}Press Enter to keep current value.{Color.RESET}\n")

    new_ip = _input_default("IP address", sw["ip"])
    if _validate_ip(new_ip):
        sw["ip"] = new_ip
    else:
        print_warn("Invalid IP, keeping current value.")

    print(f"\n  Available models: {', '.join(sorted(MODELS.keys()))}")
    new_model = _input_default("Model ID", sw["model_id"])
    if new_model in MODELS:
        sw["model_id"] = new_model
    else:
        print_warn(f"Model '{new_model}' not found, keeping current.")

    # SNMP
    snmp = sw.get("snmp", {})
    snmp_enabled = snmp.get("enabled", False)
    toggle = input(f"  SNMP currently {'enabled' if snmp_enabled else 'disabled'}. Toggle? (y/n) [n]: ").strip().lower()
    if toggle == "y":
        if snmp_enabled:
            sw["snmp"] = {}
            print_info("SNMP disabled.")
        else:
            version = input("    SNMP version (2c/3) [2c]: ").strip() or "2c"
            port    = input("    SNMP port [161]: ").strip() or "161"
            sw["snmp"] = {"enabled": True, "version": version, "port": int(port)}
            print_info("SNMP enabled.")
    elif snmp_enabled:
        if input("  Edit SNMP settings? (y/n) [n]: ").strip().lower() == "y":
            snmp["version"] = _input_default("SNMP version", snmp.get("version", "2c"))
            port_val        = _input_default("SNMP port", snmp.get("port", 161))
            try:
                snmp["port"] = int(port_val)
            except ValueError:
                pass
            sw["snmp"] = snmp

    save_config()
    print_ok(f"Switch #{sw_id} updated.")

def delete_switch():
    """Deletes a switch after confirmation."""
    list_switches()
    if not SWITCHES:
        return

    try:
        sw_id = int(input("\n  Switch ID to delete: ").strip())
    except ValueError:
        print_err("Invalid ID.")
        return

    if sw_id not in SWITCHES:
        print_err(f"Switch #{sw_id} not found.")
        return

    sw = SWITCHES[sw_id]
    confirm = input(f"  Delete Switch #{sw_id} ({sw['ip']})? (yes/no): ").strip().lower()
    if confirm != "yes":
        print_info("Cancelled.")
        return

    del SWITCHES[sw_id]
    save_config()
    print_ok(f"Switch #{sw_id} deleted.")

def list_models():
    """Displays all configured models."""
    print_header("Configured Models")
    if not MODELS:
        print_warn("No models configured.")
        return

    usage = defaultdict(int)
    for sw in SWITCHES.values():
        usage[sw["model_id"]] += 1

    print(f"  {'MODEL ID':<22} {'BRAND':<16} {'MAC FMT':<10} {'USED BY':<8} DESCRIPTION")
    print("  " + "─" * 90)
    for mid in sorted(MODELS.keys()):
        m = MODELS[mid]
        count = usage.get(mid, 0)
        desc  = m.get("description", "")[:40]
        print(f"  {mid:<22} {m.get('brand',''):<16} {m.get('mac_format','colon'):<10} "
              f"{count:<8} {desc}")

def add_model():
    """Interactive wizard to create a new model definition."""
    print_header("Add Model")

    while True:
        model_id = input("  Model ID (unique, e.g. VENDOR_SERIES): ").strip()
        if not model_id:
            print_err("ID cannot be empty.")
            continue
        if model_id in MODELS:
            print_err(f"Model '{model_id}' already exists.")
            continue
        break

    brand       = input("  Brand name: ").strip()
    description = input("  Description: ").strip()

    print(f"  MAC format options: huawei, cisco, colon")
    mac_format = input("  MAC format [colon]: ").strip() or "colon"

    print(f"\n  {Color.GREY}Enter values as comma-separated lists.{Color.RESET}")
    port_kw   = [x.strip() for x in input("  Port keywords (e.g. GE,ETH,XGE): ").split(",") if x.strip()]
    uplink_kw = [x.strip() for x in input("  Uplink keywords (e.g. 10GE,XGE): ").split(",") if x.strip()]
    err_str   = [x.strip() for x in input("  Error strings (e.g. Error:,Invalid): ").split(",") if x.strip()]

    print(f"\n  {Color.BOLD}CLI Commands{Color.RESET}  {Color.GREY}(use {{mac}} and {{port}} as placeholders, Enter to skip){Color.RESET}")
    cmd_keys = [
        "find_mac", "port_config", "port_state", "port_vlan", "port_errors",
        "arp_lookup", "lldp_neighbors", "poe_status", "version", "cpu_usage"
    ]
    commands = {}
    for key in cmd_keys:
        val = input(f"    {key:18s}: ").strip()
        if val:
            commands[key] = val

    MODELS[model_id] = {
        "id":              model_id,
        "brand":           brand,
        "description":     description,
        "mac_format":      mac_format,
        "port_keywords":   port_kw,
        "uplink_keywords": uplink_kw,
        "error_strings":   err_str,
        "commands":        commands,
    }
    save_config()
    print_ok(f"Model '{model_id}' created with {len(commands)} command(s).")

def edit_model():
    """Interactive editor for an existing model."""
    list_models()
    if not MODELS:
        return

    model_id = input("\n  Model ID to edit: ").strip()
    if model_id not in MODELS:
        print_err(f"Model '{model_id}' not found.")
        return

    m = MODELS[model_id]
    print_header(f"Edit Model: {model_id}")
    print(f"  {Color.GREY}Press Enter to keep current value.{Color.RESET}\n")

    m["brand"]       = _input_default("Brand",       m.get("brand", ""))
    m["description"] = _input_default("Description", m.get("description", ""))

    print(f"  MAC format options: huawei, cisco, colon")
    m["mac_format"] = _input_default("MAC format", m.get("mac_format", "colon"))

    m["port_keywords"]   = _input_list("Port keywords",   m.get("port_keywords", []))
    m["uplink_keywords"] = _input_list("Uplink keywords", m.get("uplink_keywords", []))
    m["error_strings"]   = _input_list("Error strings",   m.get("error_strings", []))

    print(f"\n  {Color.BOLD}CLI Commands{Color.RESET}  {Color.GREY}(Enter to keep, '-' to delete){Color.RESET}")
    commands = m.get("commands", {})
    all_keys = list(commands.keys()) + [
        k for k in ["find_mac", "port_config", "port_state", "port_vlan",
                     "port_errors", "arp_lookup", "lldp_neighbors", "poe_status",
                     "version", "cpu_usage"]
        if k not in commands
    ]
    seen = set()
    unique_keys = []
    for k in all_keys:
        if k not in seen:
            seen.add(k)
            unique_keys.append(k)

    for key in unique_keys:
        current = commands.get(key, "")
        if current:
            val = input(f"    {key:18s} [{current}]: ").strip()
            if val == "-":
                commands.pop(key, None)
            elif val:
                commands[key] = val
        else:
            val = input(f"    {key:18s} [not set]: ").strip()
            if val and val != "-":
                commands[key] = val

    m["commands"] = commands
    save_config()
    print_ok(f"Model '{model_id}' updated.")

def delete_model():
    """Deletes a model after checking it's not in use."""
    list_models()
    if not MODELS:
        return

    model_id = input("\n  Model ID to delete: ").strip()
    if model_id not in MODELS:
        print_err(f"Model '{model_id}' not found.")
        return

    users = [f"#{sw_id}" for sw_id, sw in SWITCHES.items() if sw["model_id"] == model_id]
    if users:
        print_err(f"Cannot delete '{model_id}' — in use by switch(es): {', '.join(users)}")
        return

    confirm = input(f"  Delete model '{model_id}'? (yes/no): ").strip().lower()
    if confirm != "yes":
        print_info("Cancelled.")
        return

    del MODELS[model_id]
    save_config()
    print_ok(f"Model '{model_id}' deleted.")

def run_config_editor():
    """Main loop for the configuration editor sub-menu."""
    while True:
        print(EDITOR_MENU.format(bold=Color.BOLD, cyan=Color.CYAN, reset=Color.RESET))

        try:
            option = input("> Editor option: ").strip().upper()
        except EOFError:
            break

        if   option == "1": edit_network_settings()
        elif option == "2": list_switches()
        elif option == "3": add_switch()
        elif option == "4": edit_switch()
        elif option == "5": delete_switch()
        elif option == "6": list_models()
        elif option == "7": add_model()
        elif option == "8": edit_model()
        elif option == "9": delete_model()
        elif option == "B": break
        else: print_warn("Invalid option.")

    # Reload after editing
    load_config()

# ─────────────────────────────────────────────
#  NETWORK STATUS  (displayed before menu)
# ─────────────────────────────────────────────
def show_network_status():
    sw_items = []
    for sw_id, sw_data in sorted(SWITCHES.items()):
        model = get_model_by_id(sw_data["model_id"])
        brand = model.get("brand", sw_data["model_id"]) if model else sw_data["model_id"]
        snmp  = sw_data.get("snmp", {})
        snmp_tag = f" SNMP:v{snmp.get('version','2c')}" if snmp.get("enabled") else ""
        sw_items.append(f"#{sw_id} {sw_data['ip']} [{brand}]{snmp_tag}")

    summary_lines = []
    current_line  = "  "
    for item in sw_items:
        if len(current_line) + len(item) + 2 > 78:
            summary_lines.append(current_line.rstrip(", "))
            current_line = "  " + item + ", "
        else:
            current_line += item + ", "
    if current_line.strip().rstrip(","):
        summary_lines.append(current_line.rstrip(", "))

    snmp_status = ""
    if not SNMP_AVAILABLE:
        snmp_status = f"  {Color.YELLOW}SNMP     : pysnmp not installed (pip install pysnmp){Color.RESET}\n"
    elif has_snmp_switches():
        snmp_count = sum(1 for s in SWITCHES.values() if s.get("snmp", {}).get("enabled"))
        snmp_status = f"  SNMP     : {Color.GREEN}{snmp_count} switch(es) enabled{Color.RESET}\n"

    print(f"\n{Color.BOLD}{Color.ULINE}  Network Status{Color.RESET}")
    print(f"  Interface  : {Color.CYAN}{NET.get('interface','?'):<10}{Color.RESET}  "
          f"Network : {Color.CYAN}{NET.get('network_cidr','?')}{Color.RESET}")
    print(f"  DHCP range : {Color.CYAN}{NET.get('dhcp_start','?')}{Color.RESET}"
          f" → {Color.CYAN}{NET.get('dhcp_end','?')}{Color.RESET}")
    print(f"  Switches   : {Color.CYAN}{len(SWITCHES)} device(s){Color.RESET}")
    if snmp_status:
        print(snmp_status, end="")
    for line in summary_lines:
        print(f"{Color.GREY}{line}{Color.RESET}")

# ─────────────────────────────────────────────
#  MAIN MENU
# ─────────────────────────────────────────────
MENU = """{bold}{cyan}╔════════════════════════════════════════╗
║     NETWORK CONTROL PANEL  v4.0        ║
╠════════════════════════════════════════╣
║  [1] ARP Scan                          ║
║  [2] Search MAC on switches            ║
║  [3] Search by IP                      ║
║  [4] Search multiple MACs              ║
║  [5] Switch connectivity               ║
║  [E] Configuration editor              ║
║  [R] Reload config file                ║
║  [A] ALL (ARP Scan + Search MAC)       ║
║  [X] Exit                              ║
╚════════════════════════════════════════╝{reset}"""

# ─────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────
if __name__ == "__main__":
    if os.geteuid() != 0:
        print_err("This script requires ROOT privileges (needed for arp-scan).")
        sys.exit(1)

    load_config()

    current_username = None
    current_password = None
    current_snmp     = None

    while True:
        show_network_status()
        print(MENU.format(bold=Color.BOLD, cyan=Color.CYAN, reset=Color.RESET))

        try:
            option = input("> Select an option: ").strip().upper()
        except EOFError:
            break

        # Request SSH credentials once per session
        if option in ("2", "3", "4", "5", "A") and current_username is None:
            print()
            current_username, current_password = prompt_credentials()
            if has_snmp_switches() and SNMP_AVAILABLE:
                current_snmp = prompt_snmp_credentials()

        if option == "1":
            run_arp_scan()
        elif option == "2":
            mac_input = input("MAC to search (e.g. 50:81:40:37:1A:2A): ").strip()
            search_mac(mac_input, current_username, current_password, current_snmp)
        elif option == "3":
            search_by_ip(current_username, current_password, current_snmp)
        elif option == "4":
            search_multiple_macs(current_username, current_password, current_snmp)
        elif option == "5":
            check_switch_connectivity(current_username, current_password, current_snmp)
        elif option == "E":
            run_config_editor()
        elif option == "R":
            load_config()
        elif option == "A":
            run_arp_scan()
            mac_input = input("\nMAC to search: ").strip()
            search_mac(mac_input, current_username, current_password, current_snmp)
        elif option == "X":
            print_ok("Exiting network monitor.")
            break
        else:
            print_warn("Invalid option.")
