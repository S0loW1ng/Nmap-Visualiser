"""
Merge several stored scans into one new scan, combining hosts by IP.

Rules:
  * Hosts are grouped by IP across all selected scans.
  * Ports are grouped by (protocol, portid). Every merged port carries a
    "merge" note listing which scans it was found in (and which scans that had
    the host did NOT show it).
  * When the same port disagrees between scans (different state / service /
    version), all variants are recorded in the note and the richest "open"
    variant is used as the representative row.
  * Host-level notes summarise provenance and flag any port/OS discrepancies.

The result is returned in the same plain-dict shape the parsers produce, so it
can be handed straight to db.insert_scan().
"""

from __future__ import annotations

import json
from collections import OrderedDict

_MERGE_SCRIPT_ID = "🔀 merge"
# A recognisable, structured marker the frontend renders as a compact
# "state disagreement" panel (output is JSON: [{"state", "scans": [...]}, ...]).
_STATE_DISAGREE_ID = "port-state-disagreement"


def _sig(port: dict) -> tuple:
    return (
        port.get("state", ""),
        port.get("service", ""),
        port.get("product", ""),
        port.get("version", ""),
        port.get("extrainfo", ""),
        port.get("tunnel", ""),
    )


def _variant_desc(sig: tuple) -> str:
    state, service, product, version, extrainfo, tunnel = sig
    parts = []
    if tunnel:
        parts.append(tunnel)
    if service:
        parts.append(service)
    ver = " ".join(x for x in [product, version, extrainfo] if x).strip()
    if ver:
        parts.append(ver)
    detail = " ".join(parts)
    return f"{state or '?'}" + (f" — {detail}" if detail else "")


def _merge_port(proto: str, portid: int, occurrences: list, ip_scans: list[str]) -> dict:
    """occurrences: list of (scan_name, port_dict) for one (proto, portid)."""
    # group by signature to detect mismatches
    by_sig: "OrderedDict[tuple, list[str]]" = OrderedDict()
    for sname, port in occurrences:
        by_sig.setdefault(_sig(port), []).append(sname)
    mismatch = len(by_sig) > 1

    # representative: prefer an 'open' one, then the most detailed
    def score(item):
        _sname, p = item
        detail = len((p.get("product", "") + p.get("version", "") + p.get("extrainfo", "")))
        return (1 if p.get("state") == "open" else 0, detail)

    _rep_name, rep = max(occurrences, key=score)

    # union scripts (dedupe by id+output)
    scripts, seen = [], set()
    for _sname, p in occurrences:
        for sc in p.get("scripts", []):
            key = (sc.get("id", ""), sc.get("output", ""))
            if key not in seen:
                seen.add(key)
                scripts.append({"id": sc.get("id", ""), "output": sc.get("output", "")})

    found_in = []
    for sname, _p in occurrences:
        if sname not in found_in:
            found_in.append(sname)
    missing = [s for s in ip_scans if s not in found_in]

    # per-file STATE provenance (first state each scan reported), grouped by state
    state_by_scan: "OrderedDict[str, str]" = OrderedDict()
    for sname, port in occurrences:
        state_by_scan.setdefault(sname, (port.get("state", "") or "unknown"))
    states: "OrderedDict[str, list[str]]" = OrderedDict()
    for sname, st in state_by_scan.items():
        states.setdefault(st, []).append(sname)
    # only a disagreement when the reporting scans gave more than one distinct state
    state_disagree = len(states) > 1
    provenance = [{"state": st, "scans": names} for st, names in states.items()]
    if state_disagree and missing:
        provenance.append({"state": "not reported", "scans": missing})

    # provenance / mismatch note
    lines = [f"Found in: {', '.join(found_in)}."]
    if missing:
        lines.append(f"Not seen in: {', '.join(missing)}.")
    if mismatch:
        lines.append("Differs across scans:")
        for sig, snames in by_sig.items():
            lines.append(f"  • {', '.join(snames)}: {_variant_desc(sig)}")
    note = "\n".join(lines)

    out_scripts = scripts + [{"id": _MERGE_SCRIPT_ID, "output": note}]
    if state_disagree:
        out_scripts.append({"id": _STATE_DISAGREE_ID, "output": json.dumps(provenance)})

    return {
        "portid": portid,
        "protocol": proto,
        "state": rep.get("state", ""),
        "service": rep.get("service", ""),
        "product": rep.get("product", ""),
        "version": rep.get("version", ""),
        "extrainfo": rep.get("extrainfo", ""),
        "tunnel": rep.get("tunnel", ""),
        "scripts": out_scripts,
        "_mismatch": mismatch,
    }


def merge_scans(scans: list[dict], name: str) -> dict:
    """scans: list of db.get_scan() dicts. Returns a parsed-shape scan dict."""
    scan_names = [s.get("name", "?") for s in scans]
    hosts_by_ip: "OrderedDict[str, dict]" = OrderedDict()

    for s in scans:
        sname = s.get("name", "?")
        for h in s.get("hosts", []):
            ip = h.get("ip", "")
            if not ip:
                continue
            entry = hosts_by_ip.setdefault(ip, {
                "ip": ip,
                "hostname": "",
                "state": "down",
                "scans": [],
                "os_variants": [],       # list of (scan_name, os_name, accuracy)
                "ports": OrderedDict(),   # (proto, portid) -> [(scan_name, port), ...]
                "extra": {},              # state -> {"count": n, "reason": r} (max count wins)
                "findings": OrderedDict(),  # (plugin_id, proto, port) -> [(scan_name, finding), ...]
            })
            if sname not in entry["scans"]:
                entry["scans"].append(sname)
            if h.get("hostname") and not entry["hostname"]:
                entry["hostname"] = h["hostname"]
            if h.get("state") == "up":
                entry["state"] = "up"
            elif entry["state"] != "up" and h.get("state"):
                entry["state"] = h["state"]
            if h.get("os_name"):
                entry["os_variants"].append((sname, h["os_name"], h.get("os_accuracy")))
            for p in h.get("ports", []):
                key = (p.get("protocol", ""), int(p.get("portid", 0) or 0))
                entry["ports"].setdefault(key, []).append((sname, p))
            for ep in h.get("extraports", []):
                st = ep.get("state", "")
                cnt = int(ep.get("count", 0) or 0)
                cur = entry["extra"].get(st)
                if cur is None or cnt > cur["count"]:
                    entry["extra"][st] = {"count": cnt, "reason": ep.get("reason", "")}
            for f in h.get("findings", []):
                fkey = (f.get("plugin_id", ""), f.get("protocol", ""), int(f.get("port", 0) or 0))
                entry["findings"].setdefault(fkey, []).append((sname, f))

    merged_hosts = []
    for ip, entry in hosts_by_ip.items():
        # OS: highest-accuracy variant wins
        os_name, os_accuracy = "", None
        if entry["os_variants"]:
            best = max(entry["os_variants"], key=lambda v: (v[2] or 0))
            os_name, os_accuracy = best[1], best[2]

        ports_out = []
        for (proto, portid), occ in entry["ports"].items():
            ports_out.append(_merge_port(proto, portid, occ, entry["scans"]))
        ports_out.sort(key=lambda p: (p["protocol"], p["portid"]))

        mismatched = sum(1 for p in ports_out if p.pop("_mismatch", False))

        note_lines = [f"Merged from scans: {', '.join(entry['scans'])}."]
        if mismatched:
            note_lines.append(
                f"{mismatched} port(s) differ across scans — see the "
                f"'{_MERGE_SCRIPT_ID}' note on each port."
            )
        distinct_os = {v[1] for v in entry["os_variants"]}
        if len(distinct_os) > 1:
            os_bits = "; ".join(f"{v[0]}={v[1]}" for v in entry["os_variants"])
            note_lines.append(f"OS differs across scans: {os_bits}")

        extraports = [{"state": st, "count": v["count"], "reason": v["reason"]}
                      for st, v in entry["extra"].items() if v["count"]]

        # Findings: dedupe by (plugin, proto, port); keep the richest variant and
        # record which scans reported it.
        findings_out = []
        for _fkey, occ in entry["findings"].items():
            rep = max(occ, key=lambda it: (it[1].get("severity", 0),
                                           len(it[1].get("description", "") or "")))[1]
            srcs = []
            for sname, _f in occ:
                if sname not in srcs:
                    srcs.append(sname)
            merged_f = dict(rep)
            merged_f["sources"] = srcs
            findings_out.append(merged_f)
        findings_out.sort(key=lambda f: (-f.get("severity", 0), (f.get("name") or "").lower()))
        if findings_out:
            note_lines.append(f"{len(findings_out)} Nessus finding(s) merged.")

        merged_hosts.append({
            "ip": ip,
            "hostname": entry["hostname"],
            "state": entry["state"],
            "os_name": os_name,
            "os_accuracy": os_accuracy,
            "notes": "\n".join(note_lines),
            "ports": ports_out,
            "extraports": extraports,
            "findings": findings_out,
        })

    return {
        "source_type": "merged",
        "args": f"merged from {len(scans)} source(s)",
        "scanner_version": "",
        "started_at": None,
        # Full provenance goes in notes (collapsible) rather than the name/command.
        "notes": f"Merged {len(scans)} scan(s):\n" + ", ".join(scan_names),
        "hosts": merged_hosts,
    }
