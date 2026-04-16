#!/usr/bin/env python3
"""
MPC v1.0 — Multi-Process Coordinator
Cyberdyne Security | Author: Barry Kramer
April 15, 2026

Automates PAP Step 04 routing. Manages CHAIN-PIPE handoffs.
Tracks chain state across multi-window Claude sessions.

Deployment: Render (same platform as Protocol MCP at protocol-mcp.onrender.com)
Local dev:  python mpc_server.py  ->  http://localhost:8080/mcp/

Tools:
  mpc_init            — Initialize session from SIP Session State Header
  mpc_route           — Route a prompt (PAP Step 04 automation)
  mpc_register_output — Register Step 06 gate output in chain state table
  mpc_amend           — Process SIP-AMEND events mid-session
  mpc_close_window    — Close a window, flag dependency breaks
  mpc_status          — Return current session state
"""

import json
import os
import re
from datetime import datetime, timezone
from typing import Optional
from fastmcp import FastMCP

_sessions: dict[str, dict] = {}
mcp = FastMCP("mpc")


def _parse_sip_header(sip_header: str) -> dict:
    session = {
        "version": "1.0", "mode": "lite", "window_count": 1,
        "session_id": None, "date": None, "windows": {},
        "session_context": {}, "handoff_routes": [], "chain_records": [],
        "route_log": [], "amendments": 0,
        "created_at": datetime.now(timezone.utc).isoformat(), "status": "active"
    }
    header_match = re.search(r'\[SIP\s+[\d.]+\s*\|(.+?)\]', sip_header)
    if not header_match:
        raise ValueError("Invalid SIP header: missing [SIP ...] block.")
    for field in header_match.group(1).split('|'):
        field = field.strip()
        if ':' not in field:
            continue
        key, value = field.split(':', 1)
        key = key.strip().lower().replace('-', '_')
        value = value.strip()
        if key == 'mode': session['mode'] = value.lower()
        elif key == 'windows':
            try: session['window_count'] = int(value)
            except ValueError: pass
        elif key == 'session_id': session['session_id'] = value
        elif key == 'date': session['date'] = value
    if not session['session_id']:
        session['session_id'] = f"session-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    parts = re.split(r'---([A-Z][A-Z0-9\-]*)---', sip_header)
    current_section = None
    for i, part in enumerate(parts):
        if i % 2 == 1:
            current_section = part.strip().upper()
        else:
            if not current_section:
                continue
            if current_section == 'WINDOWS':
                for line in part.strip().split('\n'):
                    line = line.strip()
                    if not line or line.startswith('#') or ':' not in line:
                        continue
                    label, attrs_str = line.split(':', 1)
                    label = label.strip()
                    attrs = {}
                    for attr in attrs_str.split('|'):
                        attr = attr.strip()
                        if '=' in attr:
                            ak, av = attr.split('=', 1)
                            attrs[ak.strip().lower()] = av.strip()
                    tier = attrs.get('tier', 'PRODUCE').upper()
                    if tier == 'AUTO': tier = 'PRODUCE'
                    session['windows'][label] = {
                        'label': label, 'tier1': tier,
                        'role': attrs.get('role', 'general'),
                        'state': attrs.get('state', 'fresh').lower(),
                        'contamination_class': attrs.get('class', 'shared').upper(),
                        'status': 'active'
                    }
            elif current_section == 'SESSION-CONTEXT':
                for line in part.strip().split('\n'):
                    line = line.strip()
                    if not line or line.startswith('#') or ':' not in line:
                        continue
                    key, value = line.split(':', 1)
                    session['session_context'][key.strip()] = value.strip()
            elif current_section == 'HANDOFF':
                for line in part.strip().split('\n'):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    m = re.match(r'(.+?)\s*->\s*(.+?):\s*(.+)', line)
                    if m:
                        session['handoff_routes'].append({
                            'source': m.group(1).strip(),
                            'target': m.group(2).strip(),
                            'format': m.group(3).strip()
                        })
    return session


def _get_session(session_id: str) -> Optional[dict]:
    if session_id and session_id in _sessions:
        return _sessions[session_id]
    if not session_id and _sessions:
        active = {k: v for k, v in _sessions.items() if v.get('status') == 'active'}
        if active: return list(active.values())[-1]
        return list(_sessions.values())[-1]
    return None


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


@mcp.tool()
def mpc_init(sip_header: str) -> str:
    """Initialize MPC session from a SIP v1.0 Session State Header.
    Call once at session start after SIP Step S4. Returns session_id for all subsequent calls."""
    try:
        session = _parse_sip_header(sip_header)
        sid = session['session_id']
        already_exists = sid in _sessions
        _sessions[sid] = session
        routing = [f"{l} -> {w['tier1']} ({w['contamination_class']})" for l, w in session['windows'].items()]
        return json.dumps({
            "status": "initialized" if not already_exists else "re-initialized",
            "session_id": sid, "mode": session['mode'],
            "windows_registered": len(session['windows']),
            "routing_table": routing,
            "context_items": len(session['session_context']),
            "handoff_routes": len(session['handoff_routes']),
            "note": "v1.0 in-memory state. Re-run mpc_init if container restarted."
        }, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})


@mcp.tool()
def mpc_route(tier1_type: str, session_id: str = "", prompt_summary: str = "") -> str:
    """Route a prompt to the correct window. Automates PAP Step 04.
    Tier 1 types: PRODUCE | RETRIEVE | EVALUATE | TRANSFORM"""
    try:
        session = _get_session(session_id)
        if not session:
            return json.dumps({"status": "error", "message": "No active session. Run mpc_init first."})
        if session['mode'] == 'lite':
            return json.dumps({"status": "ok", "routing_decision": "N/A",
                               "reason": "SIP-LITE mode - single window session",
                               "pap_step04_log": "STEP04: N/A - SIP-LITE active"})
        t1 = tier1_type.upper().strip()
        valid = {"PRODUCE", "RETRIEVE", "EVALUATE", "TRANSFORM"}
        if t1 not in valid:
            return json.dumps({"status": "error", "message": f"Unknown Tier 1 '{t1}'. Valid: {', '.join(sorted(valid))}"})
        active = [w for w in session['windows'].values() if w['status'] == 'active']
        matches = [w for w in active if w['tier1'] == t1]
        if not matches:
            all_a = [f"{w['label']} ({w['tier1']})" for w in active]
            return json.dumps({"status": "no_match", "tier1_requested": t1, "active_windows": all_a,
                               "recommendation": f"No window assigned to {t1}. Execute SIP-AMEND with ADD_WINDOW."})
        if len(matches) == 1:
            w = matches[0]
            session['route_log'].append({"timestamp": _ts(), "action": "route", "tier1": t1,
                                         "window": w['label'], "summary": prompt_summary or ""})
            return json.dumps({"status": "ok", "routing_decision": w['label'], "tier1": t1,
                               "window_role": w['role'], "contamination_class": w['contamination_class'],
                               "pap_step04_log": f"STEP04: {t1} -> {w['label']} ({w['role']})"}, indent=2)
        return json.dumps({"status": "multiple_matches", "tier1": t1,
                           "candidates": [{"label": w['label'], "role": w['role'],
                                           "contamination_class": w['contamination_class']} for w in matches],
                           "recommendation": "Select based on contamination class or role specificity."}, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})


@mcp.tool()
def mpc_register_output(window_label: str, gate: str, output_description: str, session_id: str = "") -> str:
    """Register a PAP Step 06 Recursion Gate output in the MPC chain state table.
    Gate values: TERMINAL | CHAIN-PIPE | CHAIN-REF"""
    try:
        session = _get_session(session_id)
        if not session:
            return json.dumps({"status": "error", "message": "No active session. Run mpc_init first."})
        gate = gate.upper().strip()
        if gate not in {"TERMINAL", "CHAIN-PIPE", "CHAIN-REF"}:
            return json.dumps({"status": "error", "message": f"Unknown gate '{gate}'. Valid: TERMINAL, CHAIN-PIPE, CHAIN-REF"})
        record = {"timestamp": _ts(), "window": window_label, "gate": gate, "output": output_description}
        session['chain_records'].append(record)
        result = {"status": "registered", "gate": gate, "window": window_label, "timestamp": record["timestamp"]}
        if gate == "CHAIN-PIPE":
            routes = [r for r in session['handoff_routes'] if r['source'] == window_label]
            if routes:
                r = routes[0]
                result["handoff"] = {"target_window": r['target'], "format": r['format'],
                                     "action": f"Format as: {r['format']}. Submit to: {r['target']}."}
            else:
                result["handoff"] = {"warning": f"No handoff route for '{window_label}' in SIP header.",
                                     "action": "Define via mpc_amend(ADD_HANDOFF) or route manually."}
        elif gate == "CHAIN-REF":
            label = re.sub(r'[^a-z0-9\-]', '-', output_description[:40].lower().strip()).strip('-')
            result["reference"] = {"label": label, "note": f"Available as CHAIN-REF. Reference as: {label}"}
        elif gate == "TERMINAL":
            result["note"] = "Registered as final deliverable."
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})


@mcp.tool()
def mpc_amend(amendment_type: str, amendment_data: str, session_id: str = "") -> str:
    """Process a SIP-AMEND event - update MPC routing table mid-session.
    Types: ADD_WINDOW | UPDATE_CONTEXT | UPDATE_WINDOW | ADD_HANDOFF"""
    try:
        session = _get_session(session_id)
        if not session:
            return json.dumps({"status": "error", "message": "No active session. Run mpc_init first."})
        session['amendments'] += 1
        aid = f"AMEND{session['amendments']}"
        atype = amendment_type.upper().strip()
        if atype == "ADD_WINDOW":
            if ':' not in amendment_data:
                return json.dumps({"status": "error", "message": "Format: 'Label: TIER=X | ROLE=desc | STATE=fresh | CLASS=shared'"})
            label, attrs_str = amendment_data.split(':', 1)
            label = label.strip()
            attrs = {}
            for attr in attrs_str.split('|'):
                attr = attr.strip()
                if '=' in attr:
                    ak, av = attr.split('=', 1)
                    attrs[ak.strip().lower()] = av.strip()
            session['windows'][label] = {'label': label, 'tier1': attrs.get('tier', 'PRODUCE').upper(),
                                         'role': attrs.get('role', 'general'), 'state': attrs.get('state', 'fresh'),
                                         'contamination_class': attrs.get('class', 'shared').upper(),
                                         'status': 'active', 'added_by': aid}
            return json.dumps({"status": "ok", "amendment": aid, "action": f"Window '{label}' added",
                               "window": session['windows'][label]}, indent=2)
        elif atype == "UPDATE_CONTEXT":
            if ':' not in amendment_data:
                return json.dumps({"status": "error", "message": "Format: 'key: value'"})
            key, value = amendment_data.split(':', 1)
            session['session_context'][key.strip()] = value.strip()
            return json.dumps({"status": "ok", "amendment": aid, "action": f"Context '{key.strip()}' updated"})
        elif atype == "UPDATE_WINDOW":
            parts = amendment_data.strip().split(' ', 1)
            if len(parts) != 2 or '=' not in parts[1]:
                return json.dumps({"status": "error", "message": "Format: 'WindowLabel ATTRIBUTE=new_value'"})
            label, attr_part = parts[0].strip(), parts[1].strip()
            if label not in session['windows']:
                return json.dumps({"status": "error", "message": f"Window '{label}' not found."})
            ak, av = attr_part.split('=', 1)
            field_map = {'tier': 'tier1', 'tier1': 'tier1', 'role': 'role', 'state': 'state',
                         'class': 'contamination_class', 'contamination_class': 'contamination_class'}
            field = field_map.get(ak.strip().lower(), ak.strip().lower())
            new_val = av.strip().upper() if field in ('tier1', 'contamination_class') else av.strip()
            old_val = session['windows'][label].get(field, 'unknown')
            session['windows'][label][field] = new_val
            return json.dumps({"status": "ok", "amendment": aid, "action": f"'{label}' {field}: '{old_val}' -> '{new_val}'"})
        elif atype == "ADD_HANDOFF":
            m = re.match(r'(.+?)\s*->\s*(.+?):\s*(.+)', amendment_data)
            if not m:
                return json.dumps({"status": "error", "message": "Format: 'source -> target: format description'"})
            route = {'source': m.group(1).strip(), 'target': m.group(2).strip(),
                     'format': m.group(3).strip(), 'added_by': aid}
            session['handoff_routes'].append(route)
            return json.dumps({"status": "ok", "amendment": aid,
                               "action": f"Handoff {route['source']} -> {route['target']} added"})
        return json.dumps({"status": "error", "message": f"Unknown amendment_type '{atype}'"})
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})


@mcp.tool()
def mpc_close_window(window_label: str, final_state: str = "terminal", session_id: str = "") -> str:
    """Close a window - mark TERMINATED, remove from routing, detect DOWNSTREAM dependency breaks."""
    try:
        session = _get_session(session_id)
        if not session:
            return json.dumps({"status": "error", "message": "No active session. Run mpc_init first."})
        if window_label not in session['windows']:
            return json.dumps({"status": "error", "message": f"Window '{window_label}' not found."})
        w = session['windows'][window_label]
        w['status'] = 'terminated'
        w['final_state'] = final_state.lower()
        w['closed_at'] = _ts()
        breaks = []
        for route in session['handoff_routes']:
            if route['source'] == window_label:
                target = route['target']
                if (target in session['windows'] and session['windows'][target]['status'] == 'active'
                        and session['windows'][target]['contamination_class'] == 'DOWNSTREAM'):
                    breaks.append(f"DOWNSTREAM '{target}' was receiving CHAIN-PIPE from '{window_label}'")
        result = {"status": "ok", "window": window_label, "final_state": final_state, "closed_at": w['closed_at']}
        if breaks:
            result["dependency_breaks"] = breaks
            result["warning"] = "DOWNSTREAM windows affected. Reassign or acknowledge break."
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})


@mcp.tool()
def mpc_status(session_id: str = "") -> str:
    """Return full MPC session state - audit snapshot of windows, chain records, and routing."""
    try:
        if not _sessions:
            return json.dumps({"status": "no_sessions", "message": "No active sessions. Run mpc_init first."})
        session = _get_session(session_id)
        if not session:
            return json.dumps({"status": "error", "message": f"Session '{session_id}' not found.",
                               "known_sessions": list(_sessions.keys())})
        active = {k: {"tier1": v['tier1'], "role": v['role'], "contamination_class": v['contamination_class'],
                      "state": v['state']} for k, v in session['windows'].items() if v['status'] == 'active'}
        terminated = [k for k, v in session['windows'].items() if v['status'] == 'terminated']
        return json.dumps({
            "session_id": session['session_id'], "mode": session['mode'], "status": session['status'],
            "created_at": session['created_at'], "amendments": session['amendments'],
            "active_windows": active, "terminated_windows": terminated,
            "session_context_keys": list(session['session_context'].keys()),
            "handoff_routes": session['handoff_routes'],
            "chain_records_total": len(session['chain_records']),
            "chain_records_recent": session['chain_records'][-5:] if session['chain_records'] else [],
            "route_log_total": len(session['route_log'])
        }, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    print(f"MPC v1.0 - Cyberdyne Security")
    print(f"Starting on port {port}")
    print(f"Endpoint: http://0.0.0.0:{port}/mcp/")
    mcp.run(transport="streamable-http", host="0.0.0.0", port=port)
