from __future__ import annotations

from typing import Any, Callable

from flask import Blueprint, jsonify, request


def build_host_api_handlers(
    *,
    resolve_tenant_id: Callable[[], str],
    current_request_tenant_id: Callable[[], str],
    repo_getter: Callable[[], Any],
    get_host_registry: Callable[[str | None], Any],
    risk_available: bool,
    risk_engine: Any,
    kc_correlator: Any,
    platform_get_devices_fn: Any,
):
    def _effective_tenant_id() -> str:
        return current_request_tenant_id() or resolve_tenant_id()

    def _list_recent_events(repo: Any, tenant_id: str, limit: int) -> list[dict]:
        if hasattr(repo, "list"):
            return repo.list(tenant_id=tenant_id, limit=limit)
        if hasattr(repo, "query"):
            return repo.query(tenant_id=tenant_id, limit=limit)
        return []

    def hosts_overview():
        tid = _effective_tenant_id()
        repo = repo_getter()
        registered_map: dict = {}
        try:
            for host in get_host_registry().list_hosts(limit=300):
                host_id = str(host.get("host_id") or "").strip()
                if host_id:
                    registered_map[host_id] = dict(host)
        except Exception:
            pass

        risk_data = {}
        if risk_available:
            try:
                for host in risk_engine.get_all_hosts():
                    risk_data[host.get("host_id", host.get("hostname", ""))] = host
            except Exception:
                pass

        events_by_host: dict = {}
        mitre_by_host: dict = {}
        try:
            recent = _list_recent_events(repo, tid, 500)
            for event in recent:
                hid = event.get("host_id") or event.get("hostname") or "unknown"
                events_by_host.setdefault(hid, []).append(event)
                import json as _json
                try:
                    det = event.get("details") or {}
                    if isinstance(det, str):
                        det = _json.loads(det)
                    tech = det.get("mitre_technique") or det.get("technique")
                    tact = det.get("mitre_tactic") or det.get("tactic")
                    if tech:
                        mitre_by_host.setdefault(hid, set()).add(
                            f"{tact or '?'}/{tech}" if tact else tech
                        )
                except Exception:
                    pass
        except Exception:
            pass

        devices_map: dict = {}
        try:
            devices = platform_get_devices_fn() if callable(platform_get_devices_fn) else []
            for device in devices:
                key = device.get("hostname") or device.get("ip", "")
                if key:
                    devices_map[key] = device
        except Exception:
            pass

        incidents_by_host: dict = {}
        try:
            if kc_correlator:
                for incident in kc_correlator.get_incidents():
                    hid = incident.get("host_id") or "unknown"
                    incidents_by_host.setdefault(hid, []).append(incident)
        except Exception:
            pass

        all_host_ids = set(risk_data) | set(events_by_host) | set(devices_map) | set(registered_map)
        if not all_host_ids:
            import socket as _sock
            all_host_ids = {_sock.gethostname()}

        hosts = []
        for hid in sorted(all_host_ids):
            risk = risk_data.get(hid, {})
            device = devices_map.get(hid, {})
            events = events_by_host.get(hid, [])
            incidents = incidents_by_host.get(hid, [])
            reg = registered_map.get(hid, {})

            sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
            max_sev = max((sev_order.get(e.get("severity", "info").lower(), 0) for e in events), default=0)
            sev_map = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}
            procs = [e for e in events if "process" in (e.get("event_type", ""))][:5]
            conns = [
                e for e in events
                if "network" in (e.get("event_type", "")) or "connection" in (e.get("event_type", ""))
            ][:5]

            hosts.append({
                "host_id": hid,
                "hostname": reg.get("display_name") or device.get("hostname") or hid,
                "ip": device.get("ip") or risk.get("ip", "—"),
                "os": reg.get("platform") or device.get("os", "—"),
                "last_seen": reg.get("last_seen") or device.get("last_seen") or (events[0].get("timestamp") if events else None),
                "agent_status": reg.get("status", "unknown"),
                "agent_version": reg.get("agent_version", ""),
                "risk_score": risk.get("score", 0),
                "risk_level": risk.get("level", "unknown"),
                "event_count_24h": len(events),
                "max_severity": sev_map.get(max_sev, "info"),
                "mitre_techniques": sorted(mitre_by_host.get(hid, set())),
                "incident_count": len(incidents),
                "recent_processes": procs,
                "recent_conns": conns,
                "open_incidents": [item for item in incidents if not item.get("resolved")][:3],
            })

        hosts.sort(key=lambda host: host["risk_score"], reverse=True)
        return jsonify({"hosts": hosts, "total": len(hosts)})

    def host_timeline(host_id: str):
        tid = _effective_tenant_id()
        limit = min(int(request.args.get("limit", 200)), 500)
        repo = repo_getter()
        try:
            events = _list_recent_events(repo, tid, limit)
            host_events = [
                event for event in events
                if (event.get("host_id") or event.get("hostname") or "") == host_id
            ]
            import json as _json
            for event in host_events:
                try:
                    det = event.get("details") or {}
                    if isinstance(det, str):
                        det = _json.loads(det)
                    event["_mitre_technique"] = det.get("mitre_technique", "")
                    event["_mitre_tactic"] = det.get("mitre_tactic", "")
                    event["_process"] = det.get("process", "")
                    event["_parent_process"] = det.get("parent_process", "")
                except Exception:
                    pass
            return jsonify({"host_id": host_id, "events": host_events, "total": len(host_events)})
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

    return {
        "overview": hosts_overview,
        "timeline": host_timeline,
    }


def create_host_api_blueprint(
    *,
    auth_decorator: Callable[[Callable[..., Any]], Callable[..., Any]],
    resolve_tenant_id: Callable[[], str],
    current_request_tenant_id: Callable[[], str],
    repo_getter: Callable[[], Any],
    get_host_registry: Callable[[str | None], Any],
    risk_available: bool,
    risk_engine: Any,
    kc_correlator: Any,
    platform_get_devices_fn: Any,
):
    handlers = build_host_api_handlers(
        resolve_tenant_id=resolve_tenant_id,
        current_request_tenant_id=current_request_tenant_id,
        repo_getter=repo_getter,
        get_host_registry=get_host_registry,
        risk_available=risk_available,
        risk_engine=risk_engine,
        kc_correlator=kc_correlator,
        platform_get_devices_fn=platform_get_devices_fn,
    )
    bp = Blueprint("host_api", __name__)
    bp.add_url_rule("/api/hosts", view_func=auth_decorator(handlers["overview"]), methods=["GET"])
    bp.add_url_rule(
        "/api/hosts/<path:host_id>/timeline",
        view_func=auth_decorator(handlers["timeline"]),
        methods=["GET"],
        endpoint="host_timeline",
    )
    return bp
