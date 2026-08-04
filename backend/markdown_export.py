"""
Markdown export for a stored scan.

Two flavours:
  * report  -> a full, readable document (per-host sections, ports, scripts,
               notes). Good for a pentest report or handoff.
  * table   -> a single compact table (one row per open port). This is the
               format that markdown_import.py can read back in.

The table uses a fixed, documented column order so the round-trip
(export table -> import table) is lossless for the columns it carries.
"""

from __future__ import annotations

TABLE_COLUMNS = [
    "Host", "Hostname", "Port", "Proto", "State", "Service", "Product", "Version", "Notes",
]


def _esc(text: str | None) -> str:
    """Escape a cell for a markdown table (pipes and newlines)."""
    if text is None:
        return ""
    return str(text).replace("|", "\\|").replace("\n", " ").replace("\r", " ").strip()


def _version_str(port: dict) -> str:
    bits = [port.get("product", ""), port.get("version", ""), port.get("extrainfo", "")]
    return " ".join(b for b in bits if b).strip()


def to_table(scan: dict, ports_only_open: bool = True) -> str:
    """One row per port. `scan` is a db.get_scan() dict."""
    header = "| " + " | ".join(TABLE_COLUMNS) + " |"
    sep = "| " + " | ".join("---" for _ in TABLE_COLUMNS) + " |"
    lines = [header, sep]

    for host in scan.get("hosts", []):
        for port in host.get("ports", []):
            if ports_only_open and port.get("state") != "open":
                continue
            row = [
                _esc(host.get("ip")),
                _esc(host.get("hostname")),
                _esc(port.get("portid")),
                _esc(port.get("protocol")),
                _esc(port.get("state")),
                _esc(port.get("service")),
                _esc(port.get("product")),
                _esc(port.get("version")),
                _esc(host.get("notes")),
            ]
            lines.append("| " + " | ".join(row) + " |")

    # If no ports at all, still emit hosts so the table isn't empty.
    if len(lines) == 2:
        for host in scan.get("hosts", []):
            row = [
                _esc(host.get("ip")), _esc(host.get("hostname")),
                "", "", _esc(host.get("state")), "", "", "", _esc(host.get("notes")),
            ]
            lines.append("| " + " | ".join(row) + " |")

    return "\n".join(lines) + "\n"


def to_report(scan: dict, ports_only_open: bool = False) -> str:
    """A full readable markdown document for the scan."""
    out: list[str] = []
    name = scan.get("name", "nmap scan")
    out.append(f"# {name}\n")

    meta = []
    if scan.get("scanner_version"):
        meta.append(f"- **Scanner:** nmap {scan['scanner_version']}")
    if scan.get("args"):
        meta.append(f"- **Command:** `{scan['args']}`")
    if scan.get("started_at"):
        meta.append(f"- **Started:** {scan['started_at']}")
    if scan.get("imported_at"):
        meta.append(f"- **Imported:** {scan['imported_at']}")
    hosts = scan.get("hosts", [])
    up = sum(1 for h in hosts if h.get("state") == "up")
    open_ports = sum(1 for h in hosts for p in h.get("ports", []) if p.get("state") == "open")
    meta.append(f"- **Hosts:** {len(hosts)} ({up} up) &nbsp; **Open ports:** {open_ports}")
    out.append("\n".join(meta) + "\n")

    if scan.get("notes"):
        out.append("## Scan notes\n")
        out.append(scan["notes"].strip() + "\n")

    out.append("## Summary\n")
    out.append(to_table(scan, ports_only_open=True))

    out.append("## Hosts\n")
    for host in hosts:
        title = host.get("ip", "")
        if host.get("hostname"):
            title += f" ({host['hostname']})"
        out.append(f"### {title}\n")

        hmeta = [f"- **State:** {host.get('state','')}"]
        if host.get("os_name"):
            acc = f" ({host['os_accuracy']}%)" if host.get("os_accuracy") else ""
            hmeta.append(f"- **OS:** {host['os_name']}{acc}")
        out.append("\n".join(hmeta) + "\n")

        ports = [p for p in host.get("ports", [])
                 if (not ports_only_open or p.get("state") == "open")]
        if ports:
            out.append("| Port | Proto | State | Service | Version |")
            out.append("| --- | --- | --- | --- | --- |")
            for p in ports:
                out.append(
                    f"| {p.get('portid')} | {p.get('protocol')} | {p.get('state')} "
                    f"| {_esc(p.get('service'))} | {_esc(_version_str(p))} |"
                )
            out.append("")

            # Script output, if any.
            scripted = [p for p in ports if p.get("scripts")]
            if scripted:
                out.append("**Script output**\n")
                for p in scripted:
                    for s in p["scripts"]:
                        out.append(f"- `{p.get('portid')}/{p.get('protocol')}` "
                                   f"**{s.get('id','')}**")
                        body = (s.get("output") or "").strip()
                        if body:
                            out.append("  ```")
                            for bl in body.splitlines():
                                out.append("  " + bl)
                            out.append("  ```")
                out.append("")

            # Per-port notes, if any.
            noted = [p for p in ports if (p.get("notes") or "").strip()]
            if noted:
                out.append("**Port notes**\n")
                for p in noted:
                    note = p["notes"].strip().replace("\n", " ")
                    out.append(f"- `{p.get('portid')}/{p.get('protocol')}` — {_esc(note)}")
                out.append("")
        else:
            out.append("_No open ports._\n")

        if host.get("notes"):
            out.append("**Notes**\n")
            out.append("> " + host["notes"].strip().replace("\n", "\n> ") + "\n")

    return "\n".join(out).rstrip() + "\n"
