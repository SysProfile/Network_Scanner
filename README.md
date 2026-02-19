# Network Scanner

---

## The story behind this tool

My name is Sergio. Spanish is my native language, so bear with me if something reads a bit off — this README was written with that in mind.

I have been a developer for many years, working across multiple languages including .NET, PHP and others. I had never written a single line of Python before this project.

I built this tool out of a very specific and frustrating need: someone on my network kept plugging in a device that was acting as a DHCP server, conflicting with the real one and causing complete chaos for everyone on the network. I needed a way to find exactly which port on which switch that device was connected to, so I could shut it down remotely — and then wait quietly for that person to come to me complaining that their workstation had stopped working, without them realizing I already knew exactly what they had done.

It worked. The employee, who had brought in their own switch to get "better WiFi," was eventually let go.

I built this with help from **Gemini** and **Claude** (AI assistants), which made it possible for someone with no Python background to put together something actually useful.

I'm sharing it here because I think it can help others dealing with similar situations — rogue devices, unauthorized hardware, network troubleshooting, or just wanting to know what is physically plugged into what port.

**Everyone is welcome to contribute.** Whether you want to improve existing features, add support for commands from other switch brands and models, or adapt it to different environments — pull requests are open and appreciated.

---

## Important prerequisite

**SSH access must be enabled on your switches** for this tool to work. Without it, the MAC search and connectivity features will not function. Refer to your switch documentation for how to enable SSH and create a user with the appropriate permissions.

---

## Features

- **ARP Scan** — Scans a full network segment, detects all active devices, flags duplicate MACs and IPs found within the DHCP range.
- **MAC Search** — Locates a MAC across all switches in parallel via SSH, identifies the exact switch number, brand, model and access port.
- **Search by IP** — Resolves a device's MAC from the local ARP table or a targeted arp-scan, then traces it to its physical port.
- **Multiple MAC Search** — Batch search for several MACs in a single run with optional log export.
- **Switch Connectivity** — Pings each switch and connects via SSH to verify reachability, firmware version and CPU usage.
- **Multi-vendor** — All switch commands are defined in `switches_config.json`. Adding a new vendor requires only a JSON entry, no code changes.
- **Parallel SSH** — All switches are queried simultaneously using threads, reducing search time from ~64s to ~8s for 8 switches.
- **Vendor Lookup** — Queries `api.macvendors.com` to identify the hardware manufacturer of any MAC address.
- **Session credentials** — SSH username and password are asked once per session and reused across all operations. Password input is hidden.
- **Hot reload** — Option `[R]` reloads `switches_config.json` at runtime without restarting the script.
- **Session logs** — Search results can be saved to `/var/log/network_scanner/`.

---

## Requirements

### System packages
```bash
apt install arp-scan
```

### Python packages
```bash
pip install paramiko requests
```

Python 3.8 or higher is required.

---

## Usage

The script must be run as **root** because `arp-scan` requires raw socket access:

```bash
sudo python3 network_scanner.py
```

Both files must be in the same directory:
```
network_scanner.py
switches_config.json
```

If `switches_config.json` does not exist, the script creates a minimal default one automatically on first run.

---

## Configuration file: `switches_config.json`

The config file has three sections:

### `network`
Global network settings used by the ARP scan and DHCP range detection.

```json
"network": {
  "interface":    "vmbr0",
  "network_cidr": "192.168.0.0/18",
  "dhcp_start":   "192.168.3.1",
  "dhcp_end":     "192.168.8.254"
}
```

| Key | Description |
|-----|-------------|
| `interface` | Network interface passed to arp-scan |
| `network_cidr` | Network segment to scan |
| `dhcp_start` | First IP of the DHCP pool |
| `dhcp_end` | Last IP of the DHCP pool |

---

### `switches`
List of switches to query. Each entry assigns an ID, an IP and the model it uses.

```json
"switches": [
  { "id": 1, "ip": "192.168.1.1", "model_id": "HUAWEI_VRP" },
  { "id": 2, "ip": "192.168.1.2", "model_id": "HUAWEI_VRP" },
  { "id": 3, "ip": "192.168.1.3", "model_id": "CISCO_IOS"  }
]
```

| Key | Description |
|-----|-------------|
| `id` | Switch number shown in results |
| `ip` | Management IP address |
| `model_id` | Must match an `id` in the `models` array |

---

### `models`
Defines the CLI commands and behavior for each switch brand or model family.
Each model entry contains:

```json
{
  "id":          "HUAWEI_VRP",
  "brand":       "Huawei",
  "description": "Huawei VRP — S310, S5700, S5720, S6720, CE series",
  "mac_format":  "huawei",
  "port_keywords":   ["GE", "ETH", "XGE"],
  "uplink_keywords": ["10GE", "XGE"],
  "error_strings":   ["Error:", "Unrecognized command"],
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
```

| Field | Description |
|-------|-------------|
| `id` | Unique identifier referenced from `switches` entries |
| `brand` | Display name shown in results |
| `description` | Human-readable description of covered models |
| `mac_format` | MAC address format for this vendor's CLI — see below |
| `port_keywords` | Strings used to identify port names in MAC table output |
| `uplink_keywords` | If a port name contains any of these, it is treated as uplink/trunk |
| `error_strings` | Output strings that indicate a failed or unrecognized command |
| `commands` | CLI commands with `{mac}` and `{port}` as placeholders |

#### MAC address formats

Different vendors display MACs differently in their CLI:

| `mac_format` value | Example output |
|--------------------|----------------|
| `huawei` | `5081-4037-1a2a` |
| `cisco` | `5081.4037.1a2a` |
| `colon` | `50:81:40:37:1a:2a` *(default — Aruba, Juniper, MikroTik, D-Link, TP-Link)* |

---

## Supported models (included in `switches_config.json`)

| Model ID | Brand | Covers |
|----------|-------|--------|
| `HUAWEI_VRP` | Huawei | S310, S5700, S5720, S6720, S5300, CE series |
| `CISCO_IOS` | Cisco | Catalyst 2960, 3560, 3750, 3850, 9200, 9300, 9500 |
| `CISCO_NXOS` | Cisco | Nexus 5000, 7000, 9000 series |
| `ARUBA_AOS_S` | Aruba / HPE | ProCurve 2530, 2930, 3810, 5400 series |
| `ARUBA_AOS_CX` | Aruba / HPE | CX 6200, 6300, 6400, 8320, 8400 series |
| `JUNIPER_JUNOS` | Juniper | EX2300, EX3400, EX4300, EX9200 series |
| `MIKROTIK_ROS` | MikroTik | CRS, CSS and CCR series |
| `DLINK_CLI` | D-Link | DGS-1210, DGS-3000, DXS-3600 enterprise series |
| `TPLINK_JETSTREAM` | TP-Link | T1600G, T2600G, T3700G enterprise series |

---

## Adding a new switch brand or model

1. Open `switches_config.json`
2. Add a new entry to the `models` array with the correct CLI commands for that brand
3. Add your switch(es) to the `switches` array referencing the new `model_id`
4. Press `[R]` in the running script to reload without restarting

No Python code changes are required.

---

## Important notes

### ARP Scan and DHCP range detection

The ARP scan detects all devices that respond on the network. When listing IPs found within the DHCP range, **the tool cannot determine whether those IPs are statically configured or DHCP-assigned** — it only sees ARP responses. Cross-check with your DHCP server's lease table to confirm.

### Huawei SSH compatibility

Some Huawei switch firmwares reject direct `exec_command` via Paramiko with an *"Unable to open channel"* error. The `ssh_exec()` function handles this automatically by falling back to `invoke_shell` when needed. This fallback applies to all vendors.

### Logs

Session logs are saved to `/var/log/network_scanner/` when requested. The directory is created automatically if it does not exist.

---

## Tested on

- **Proxmox VE 9** (host running the script — should also work on Debian and most Linux distributions without changes)
- **Huawei S310-48T4X** switches
- Python 3.10+

---

## Contributing

Contributions are welcome. Some ideas for improvement:

- Test and refine commands for Cisco, Aruba, Juniper, MikroTik, D-Link and TP-Link models
- Add support for additional vendors (Extreme Networks, Brocade, Fortinet, etc.)
- Add SNMP as an alternative to SSH for vendors that support it better
- Export results to JSON or HTML
- Add a configuration file editor within the menu

---

## License

MIT
