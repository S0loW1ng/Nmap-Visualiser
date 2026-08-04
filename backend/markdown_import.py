"""
Import a markdown table (as produced by markdown_export.to_table) back into the
common scan structure, so a table pasted/uploaded by a teammate can be viewed.

The parser is tolerant: it locates the header row, maps whatever of the known
columns are present (case-insensitive), and skips the `---` separator row. Extra
columns are ignored; missing columns default to empty.
"""

from __future__ import annotations

# canonical field name -> accepted header labels (lowercased)
_COLUMN_ALIASES = {
    "ip": ["host", "ip", "address"],
    "hostname": ["hostname", "host name", "name"],
    "portid": ["port", "portid"],
    "protocol": ["proto", "protocol"],
    "state": ["state", "status"],
    "service": ["service"],
    "product": ["product"],
    "version": ["version"],
    "notes": ["notes", "note"],
}


def _split_row(line: str) -> list[str]:
    line = line.strip()
    if line.startswith("|"):
        line = line[1:]
    if line.endswith("|"):
        line = line[:-1]
    # split on unescaped pipes
    cells, buf, i = [], [], 0
    while i < len(line):
        ch = line[i]
        if ch == "\\" and i + 1 < len(line) and line[i + 1] == "|":
            buf.append("|")
            i += 2
            continue
        if ch == "|":
            cells.append("".join(buf).strip())
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    cells.append("".join(buf).strip())
    return cells


def _is_separator(cells: list[str]) -> bool:
    return all(set(c) <= set("-: ") and "-" in c for c in cells if c != "") and any(cells)


def parse_markdown_table(text: str, name: str = "Imported table") -> dict:
    lines = [ln for ln in text.splitlines() if ln.strip()]
    # find the first line that looks like a table row containing a pipe
    header_idx = None
    for i, ln in enumerate(lines):
        if "|" in ln:
            header_idx = i
            break
    if header_idx is None:
        raise ValueError("No markdown table found (no '|' rows).")

    header_cells = [c.lower() for c in _split_row(lines[header_idx])]

    # map column index -> canonical field
    col_map: dict[int, str] = {}
    for idx, label in enumerate(header_cells):
        for field, aliases in _COLUMN_ALIASES.items():
            if label in aliases:
                col_map[idx] = field
                break
    if "ip" not in col_map.values():
        raise ValueError("Table needs at least a Host/IP column.")

    # gather data rows (skip separator)
    hosts: dict[str, dict] = {}
    for ln in lines[header_idx + 1:]:
        if "|" not in ln:
            continue
        cells = _split_row(ln)
        if _is_separator(cells):
            continue
        rec = {field: (cells[idx] if idx < len(cells) else "")
               for idx, field in col_map.items()}
        ip = rec.get("ip", "").strip()
        if not ip:
            continue

        if ip not in hosts:
            hosts[ip] = {
                "ip": ip,
                "hostname": rec.get("hostname", ""),
                "state": rec.get("state", "") or "up",
                "os_name": "",
                "os_accuracy": None,
                "notes": rec.get("notes", ""),
                "ports": [],
            }
        else:
            if rec.get("hostname") and not hosts[ip]["hostname"]:
                hosts[ip]["hostname"] = rec["hostname"]
            if rec.get("notes") and not hosts[ip]["notes"]:
                hosts[ip]["notes"] = rec["notes"]

        portid_raw = rec.get("portid", "").strip()
        if portid_raw:
            try:
                portid = int(portid_raw)
            except ValueError:
                continue
            hosts[ip]["ports"].append({
                "portid": portid,
                "protocol": rec.get("protocol", "") or "tcp",
                "state": rec.get("state", "") or "open",
                "service": rec.get("service", ""),
                "product": rec.get("product", ""),
                "version": rec.get("version", ""),
                "extrainfo": "",
                "tunnel": "",
                "scripts": [],
            })

    # notes column belongs to the host; strip it back out of per-port state
    host_list = []
    for h in hosts.values():
        h["ports"].sort(key=lambda p: (p["protocol"], p["portid"]))
        # host state: 'up' if any port, else whatever was given
        if h["ports"]:
            h["state"] = "up"
        host_list.append(h)

    return {
        "args": "",
        "scanner_version": "",
        "started_at": None,
        "source_type": "markdown",
        "hosts": host_list,
    }
