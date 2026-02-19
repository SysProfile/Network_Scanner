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
            }

    MODELS = {}
    for model in data.get("models", []):
        model_id = model.get("id")
        if model_id:
            MODELS[model_id] = model

    print_ok(f"Config loaded — {len(SWITCHES)} switch(es), {len(MODELS)} model(s) available.")

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
# ─────────────────────────────────────────────
def search_mac_on_switch(switch_num, switch_ip, clean_mac, username, password, results, lock):
    model = get_model(switch_ip)
    if model is None:
        with lock:
            print_warn(f"Switch #{switch_num} ({switch_ip}) — no model defined in config, skipping.")
        return

    mac_fmt = format_mac_for_model(clean_mac, model.get("mac_format", "colon"))

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

        output = ssh_exec(client, model_cmd(model, "find_mac", mac=mac_fmt))

        if mac_fmt.lower() in output.lower():
            for line in output.splitlines():
                if mac_fmt.lower() in line.lower():
                    port = extract_port_from_line(line, model)
                    if port:
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
                            })
        client.close()

    except paramiko.AuthenticationException:
        with lock:
            print_err(f"Switch #{switch_num} ({switch_ip}) — Authentication failed.")
    except Exception:
        with lock:
            print(f"\n{Color.RED}{'!'*20} ERROR on Switch #{switch_num} ({switch_ip}) {'!'*20}{Color.RESET}")
            traceback.print_exc()

# ─────────────────────────────────────────────
#  SEARCH MAC  (parallel across all switches)
# ─────────────────────────────────────────────
def search_mac(mac_input, username, password, log_lines=None):
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
            args=(sw_id, sw_data["ip"], clean_mac, username, password, results, lock),
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
        label = (f"Switch #{entry['switch_num']}  ({entry['switch_ip']})"
                 f"  [{entry['brand']} / {entry['model_id']}]")
        if entry["port_type"] == "ACCESS":
            print(f"{Color.GREEN}{'='*60}{Color.RESET}")
            print(f"  {Color.BOLD}MAC FOUND ON ACCESS PORT{Color.RESET}")
            print(f"  {Color.BOLD}Switch  :{Color.RESET} {label}")
            print(f"  {Color.BOLD}Port    :{Color.RESET} {entry['port']}")
            print(f"  {Color.BOLD}VLAN    :{Color.RESET} {entry['vlan']}")
            print(f"  {Color.BOLD}Vendor  :{Color.RESET} {vendor}")
            print(f"{Color.GREEN}{'='*60}{Color.RESET}")
            print(entry["details"])
        else:
            print_info(
                f"MAC seen on {label} → Port {entry['port']} "
                f"({Color.YELLOW}{entry['port_type']}{Color.RESET}), VLAN: {entry['vlan']}"
            )

        if log_lines is not None:
            log_lines.append(
                f"MAC {mac_upper} | Switch #{entry['switch_num']} ({entry['switch_ip']}) "
                f"[{entry['model_id']}] | Port {entry['port']} | "
                f"Type {entry['port_type']} | VLAN {entry['vlan']} | Vendor {vendor}"
            )

# ─────────────────────────────────────────────
#  SEARCH BY IP
# ─────────────────────────────────────────────
def search_by_ip(username, password):
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
    search_mac(found_mac, username, password)

# ─────────────────────────────────────────────
#  SEARCH MULTIPLE MACs
# ─────────────────────────────────────────────
def search_multiple_macs(username, password):
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
        search_mac(mac, username, password, log_lines)

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
    except Exception as error:
        print_err(f"arp-scan error: {error}")
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
# ─────────────────────────────────────────────
def check_switch_connectivity(username, password):
    print_header("Switch Connectivity")
    for sw_id, sw_data in sorted(SWITCHES.items()):
        switch_ip = sw_data["ip"]
        model     = get_model_by_id(sw_data["model_id"])
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

            version_str = "N/A"
            cpu_str     = "N/A"

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
            print_err(f"{label} — Authentication failed.")
        except Exception as error:
            print_err(f"{label} — SSH error: {error}")

# ─────────────────────────────────────────────
#  NETWORK STATUS  (displayed before menu)
# ─────────────────────────────────────────────
def show_network_status():
    sw_items = []
    for sw_id, sw_data in sorted(SWITCHES.items()):
        model = get_model_by_id(sw_data["model_id"])
        brand = model.get("brand", sw_data["model_id"]) if model else sw_data["model_id"]
        sw_items.append(f"#{sw_id} {sw_data['ip']} [{brand}]")

    # Wrap switch list into lines of max 72 chars
    summary_lines = []
    current_line  = "  "
    for item in sw_items:
        if len(current_line) + len(item) + 2 > 72:
            summary_lines.append(current_line.rstrip(", "))
            current_line = "  " + item + ", "
        else:
            current_line += item + ", "
    if current_line.strip().rstrip(","):
        summary_lines.append(current_line.rstrip(", "))

    print(f"\n{Color.BOLD}{Color.ULINE}  Network Status{Color.RESET}")
    print(f"  Interface  : {Color.CYAN}{NET.get('interface','?'):<10}{Color.RESET}  "
          f"Network : {Color.CYAN}{NET.get('network_cidr','?')}{Color.RESET}")
    print(f"  DHCP range : {Color.CYAN}{NET.get('dhcp_start','?')}{Color.RESET}"
          f" → {Color.CYAN}{NET.get('dhcp_end','?')}{Color.RESET}")
    print(f"  Switches   : {Color.CYAN}{len(SWITCHES)} device(s){Color.RESET}")
    for line in summary_lines:
        print(f"{Color.GREY}{line}{Color.RESET}")

# ─────────────────────────────────────────────
#  MAIN MENU
# ─────────────────────────────────────────────
MENU = """{bold}{cyan}╔════════════════════════════════════════╗
║     NETWORK CONTROL PANEL  v3.0        ║
╠════════════════════════════════════════╣
║  [1] ARP Scan                          ║
║  [2] Search MAC on switches            ║
║  [3] Search by IP                      ║
║  [4] Search multiple MACs              ║
║  [5] Switch connectivity               ║
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

        if option == "1":
            run_arp_scan()
        elif option == "2":
            mac_input = input("MAC to search (e.g. 50:81:40:37:1A:2A): ").strip()
            search_mac(mac_input, current_username, current_password)
        elif option == "3":
            search_by_ip(current_username, current_password)
        elif option == "4":
            search_multiple_macs(current_username, current_password)
        elif option == "5":
            check_switch_connectivity(current_username, current_password)
        elif option == "R":
            load_config()
        elif option == "A":
            run_arp_scan()
            mac_input = input("\nMAC to search: ").strip()
            search_mac(mac_input, current_username, current_password)
        elif option == "X":
            print_ok("Exiting network monitor.")
            break
        else:
            print_warn("Invalid option.")
