"""
Parsers for nmap output.

Both the XML (`-oX`) and greppable (`-oG`) formats are normalised into the same
plain-dict structure so the rest of the app never has to care which one was
uploaded:

    {
        "args": str,                # nmap command line, if known
        "scanner_version": str,     # e.g. "7.94SVN"
        "started_at": str | None,   # ISO 8601, if known
        "source_type": "xml" | "gnmap",
        "hosts": [
            {
                "ip": str,
                "hostname": str,          # "" if none
                "state": str,             # up / down
                "os_name": str,           # "" if unknown
                "os_accuracy": int | None,
                "ports": [
                    {
                        "portid": int,
                        "protocol": str,      # tcp / udp
                        "state": str,         # open / filtered / closed ...
                        "service": str,
                        "product": str,
                        "version": str,
                        "extrainfo": str,
                        "tunnel": str,        # e.g. "ssl"
                        "scripts": [ {"id": str, "output": str}, ... ],
                    }, ...
                ],
            }, ...
        ],
    }
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone


def _epoch_to_iso(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc).isoformat()
    except (ValueError, OSError):
        return None


# ---------------------------------------------------------------------------
# XML (-oX)
# ---------------------------------------------------------------------------

def _recover_truncated_xml(data: bytes) -> "ET.Element":
    """
    Salvage a truncated nmap XML (e.g. an interrupted scan missing its closing
    </nmaprun>) by cutting at the last complete </host> and closing the document.
    Raises ValueError if nothing usable can be recovered.
    """
    end = data.rfind(b"</host>")
    if end == -1:
        raise ValueError("truncated XML with no complete <host> to recover")
    salvaged = data[: end + len(b"</host>")] + b"\n</nmaprun>\n"
    try:
        return ET.fromstring(salvaged)
    except ET.ParseError as exc:
        raise ValueError(f"could not recover truncated XML: {exc}")


def parse_xml(data: bytes | str) -> dict:
    if isinstance(data, str):
        data = data.encode("utf-8", errors="replace")
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        # Common case: an interrupted scan whose file was never closed. Try to
        # recover whatever complete <host> elements were written.
        root = _recover_truncated_xml(data)
    if root.tag != "nmaprun":
        raise ValueError("Not an nmap XML file (missing <nmaprun> root).")

    scan = {
        "args": root.get("args", ""),
        "scanner_version": root.get("version", ""),
        "started_at": _epoch_to_iso(root.get("start")),
        "source_type": "xml",
        "hosts": [],
    }

    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        state = status_el.get("state", "unknown") if status_el is not None else "unknown"

        ip = ""
        for addr in host_el.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                ip = addr.get("addr", "")
                break
        if not ip:
            # fall back to MAC or first address
            addr = host_el.find("address")
            ip = addr.get("addr", "") if addr is not None else ""

        hostname = ""
        hostnames_el = host_el.find("hostnames")
        if hostnames_el is not None:
            hn = hostnames_el.find("hostname")
            if hn is not None:
                hostname = hn.get("name", "")

        os_name, os_accuracy = "", None
        os_el = host_el.find("os")
        if os_el is not None:
            match = os_el.find("osmatch")
            if match is not None:
                os_name = match.get("name", "")
                try:
                    os_accuracy = int(match.get("accuracy")) if match.get("accuracy") else None
                except ValueError:
                    os_accuracy = None

        ports = []
        extraports = []
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for ep in ports_el.findall("extraports"):
                try:
                    cnt = int(ep.get("count", "0") or "0")
                except ValueError:
                    cnt = 0
                reasons = [er.get("reason", "") for er in ep.findall("extrareasons")]
                extraports.append({
                    "state": ep.get("state", ""),
                    "count": cnt,
                    "reason": ", ".join(r for r in reasons if r),
                })
            for port_el in ports_el.findall("port"):
                port_state_el = port_el.find("state")
                port_state = port_state_el.get("state", "") if port_state_el is not None else ""

                svc = port_el.find("service")
                service = svc.get("name", "") if svc is not None else ""
                product = svc.get("product", "") if svc is not None else ""
                version = svc.get("version", "") if svc is not None else ""
                extrainfo = svc.get("extrainfo", "") if svc is not None else ""
                tunnel = svc.get("tunnel", "") if svc is not None else ""

                scripts = []
                for script_el in port_el.findall("script"):
                    scripts.append({
                        "id": script_el.get("id", ""),
                        "output": script_el.get("output", ""),
                    })

                try:
                    portid = int(port_el.get("portid", "0"))
                except ValueError:
                    portid = 0

                ports.append({
                    "portid": portid,
                    "protocol": port_el.get("protocol", ""),
                    "state": port_state,
                    "service": service,
                    "product": product,
                    "version": version,
                    "extrainfo": extrainfo,
                    "tunnel": tunnel,
                    "scripts": scripts,
                })

        ports.sort(key=lambda p: (p["protocol"], p["portid"]))
        scan["hosts"].append({
            "ip": ip,
            "hostname": hostname,
            "state": state,
            "os_name": os_name,
            "os_accuracy": os_accuracy,
            "ports": ports,
            "extraports": extraports,
        })

    return scan


# ---------------------------------------------------------------------------
# Nessus (.nessus / NessusClientData_v2)
# ---------------------------------------------------------------------------

# Nessus severity levels -> label (kept here so the parser is the one source).
NESSUS_SEVERITY = {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}


def _nessus_text(item: "ET.Element", tag: str) -> str:
    el = item.find(tag)
    return (el.text or "").strip() if el is not None and el.text else ""


def parse_nessus(data: bytes | str) -> dict:
    """
    Parse a Nessus export (.nessus, NessusClientData_v2).

    Each <ReportHost> becomes a host in the same shape the nmap parsers produce,
    keyed by IP so it can be merged by IP alongside nmap scans. Every finding
    (<ReportItem>) is captured under host["findings"]; ports that carry findings
    are synthesised as open ports so the host table stays meaningful.
    """
    if isinstance(data, str):
        data = data.encode("utf-8", errors="replace")
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise ValueError(f"Could not parse Nessus XML: {exc}")
    if root.tag != "NessusClientData_v2":
        raise ValueError("Not a Nessus file (missing <NessusClientData_v2> root).")

    report = root.find("Report")
    scan = {
        "args": report.get("name", "") if report is not None else "",
        "scanner_version": "",
        "started_at": None,
        "source_type": "nessus",
        "hosts": [],
    }
    if report is None:
        return scan

    for rh in report.findall("ReportHost"):
        props: dict[str, str] = {}
        hp = rh.find("HostProperties")
        if hp is not None:
            for tag in hp.findall("tag"):
                props[tag.get("name", "")] = (tag.text or "").strip()

        ip = props.get("host-ip") or rh.get("name", "")
        hostname = (props.get("host-fqdn") or props.get("host-rdns")
                    or props.get("netbios-name") or "")
        if not hostname and rh.get("name") and rh.get("name") != ip:
            hostname = rh.get("name")
        os_name = props.get("operating-system", "")
        if scan["started_at"] is None and props.get("HOST_START_TIMESTAMP"):
            scan["started_at"] = _epoch_to_iso(props.get("HOST_START_TIMESTAMP"))

        findings = []
        ports_map: "dict[tuple[str, int], str]" = {}
        for ri in rh.findall("ReportItem"):
            try:
                severity = int(ri.get("severity", "0") or 0)
            except ValueError:
                severity = 0
            try:
                portid = int(ri.get("port", "0") or 0)
            except ValueError:
                portid = 0
            protocol = ri.get("protocol", "") or "tcp"
            svc = ri.get("svc_name", "") or ""

            cves = [(e.text or "").strip() for e in ri.findall("cve") if (e.text or "").strip()]
            cvss = _nessus_text(ri, "cvss3_base_score") or _nessus_text(ri, "cvss_base_score")

            findings.append({
                "plugin_id": ri.get("pluginID", ""),
                "name": ri.get("pluginName", ""),
                "family": ri.get("pluginFamily", ""),
                "severity": severity,
                "port": portid,
                "protocol": protocol,
                "service": svc,
                "risk_factor": _nessus_text(ri, "risk_factor"),
                "cvss": cvss,
                "cve": cves,
                "synopsis": _nessus_text(ri, "synopsis"),
                "description": _nessus_text(ri, "description"),
                "solution": _nessus_text(ri, "solution"),
                "output": _nessus_text(ri, "plugin_output"),
            })

            if portid > 0:
                key = (protocol, portid)
                svc_clean = svc if svc and svc not in ("general", "unknown") else ""
                if key not in ports_map or (not ports_map[key] and svc_clean):
                    ports_map[key] = svc_clean

        ports = [{
            "portid": portid,
            "protocol": proto,
            "state": "open",
            "service": svc,
            "product": "", "version": "", "extrainfo": "", "tunnel": "",
            "scripts": [],
        } for (proto, portid), svc in sorted(ports_map.items())]

        findings.sort(key=lambda f: (-f["severity"], f["name"].lower()))
        scan["hosts"].append({
            "ip": ip,
            "hostname": hostname,
            "state": "up",
            "os_name": os_name,
            "os_accuracy": None,
            "ports": ports,
            "extraports": [],
            "findings": findings,
        })

    return scan


# ---------------------------------------------------------------------------
# Greppable (-oG)
# ---------------------------------------------------------------------------

# A single port field looks like:
#   22/open/tcp//ssh//OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 (Ubuntu Linux; protocol 2.0)/
# Fields are: portid/state/proto/owner/service/rpc_info/version/
def _parse_gnmap_port(field: str) -> dict | None:
    parts = field.split("/")
    if len(parts) < 3:
        return None
    try:
        portid = int(parts[0])
    except ValueError:
        return None
    state = parts[1]
    protocol = parts[2]
    service = parts[4] if len(parts) > 4 else ""
    version = parts[6] if len(parts) > 6 else ""
    # gnmap encodes literal commas/slashes in version text; nmap escapes them,
    # but keep the raw text otherwise.
    return {
        "portid": portid,
        "protocol": protocol,
        "state": state,
        "service": service,
        "product": "",       # gnmap folds product+version together
        "version": version,
        "extrainfo": "",
        "tunnel": "",
        "scripts": [],
    }


def parse_gnmap(data: bytes | str) -> dict:
    if isinstance(data, bytes):
        data = data.decode("utf-8", errors="replace")

    scan = {
        "args": "",
        "scanner_version": "",
        "started_at": None,
        "source_type": "gnmap",
        "hosts": [],
    }

    # hosts keyed by ip so "Status" and "Ports" lines merge
    hosts: dict[str, dict] = {}

    def get_host(ip: str, hostname: str = "") -> dict:
        if ip not in hosts:
            hosts[ip] = {
                "ip": ip,
                "hostname": hostname,
                "state": "unknown",
                "os_name": "",
                "os_accuracy": None,
                "ports": [],
                "extraports": [],
            }
        elif hostname and not hosts[ip]["hostname"]:
            hosts[ip]["hostname"] = hostname
        return hosts[ip]

    host_line_re = re.compile(r"^Host:\s+(\S+)\s+\(([^)]*)\)\s*(.*)$")

    for raw in data.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#"):
            m = re.search(r"as:\s+(nmap .+?)\s*$", line)
            if m and not scan["args"]:
                scan["args"] = m.group(1)
            v = re.search(r"Nmap\s+(\S+)\s+scan initiated", line)
            if v and not scan["scanner_version"]:
                scan["scanner_version"] = v.group(1)
            continue

        m = host_line_re.match(line)
        if not m:
            continue
        ip, hostname, rest = m.group(1), m.group(2), m.group(3)
        host = get_host(ip, hostname)

        if "Status:" in rest:
            status = rest.split("Status:", 1)[1].strip().split()[0]
            host["state"] = status.lower()
        if "Ports:" in rest:
            # Ports: 22/open/tcp//ssh//..., 111/open/tcp//rpcbind//...  Ignored State: closed (995)
            ign = re.search(r"Ignored State:\s*(\w+)\s*\((\d+)\)", rest)
            if ign:
                host["extraports"] = [{"state": ign.group(1), "count": int(ign.group(2)), "reason": ""}]
            ports_part = rest.split("Ports:", 1)[1]
            ports_part = re.split(r"\bIgnored State:", ports_part)[0]
            for field in ports_part.split(","):
                field = field.strip()
                if not field:
                    continue
                parsed = _parse_gnmap_port(field)
                if parsed:
                    host["ports"].append(parsed)
            host["state"] = host["state"] if host["state"] != "unknown" else "up"

    for host in hosts.values():
        host["ports"].sort(key=lambda p: (p["protocol"], p["portid"]))
        scan["hosts"].append(host)

    return scan


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

def parse_auto(data: bytes | str, filename: str = "") -> dict:
    """Pick a parser from the filename extension, falling back to content."""
    if isinstance(data, bytes):
        head = data[:512].lstrip()
    else:
        head = data[:512].lstrip().encode()

    name = filename.lower()
    if name.endswith(".nessus") or b"NessusClientData" in head:
        return parse_nessus(data)
    if name.endswith(".xml") or head.startswith(b"<?xml") or head.startswith(b"<nmaprun"):
        return parse_xml(data)
    if name.endswith(".gnmap") or head.startswith(b"# Nmap") or head.startswith(b"Host:"):
        return parse_gnmap(data)
    # last resort: try XML then gnmap
    try:
        return parse_xml(data)
    except Exception:
        return parse_gnmap(data)
