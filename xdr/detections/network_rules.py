"""Network-behavior rules for the endpoint telemetry pipeline."""

from __future__ import annotations

import ipaddress

from .base import DetectionContext, DetectionRule

COMMON_EGRESS_PORTS = {22, 25, 53, 80, 110, 123, 143, 389, 443, 465, 587, 993, 995}
HIGH_RISK_PORTS = {4444, 1337, 8081, 9001}


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address((ip or "").strip()).is_private
    except ValueError:
        return True


class UnusualOutboundPortRule(DetectionRule):
    rule_id = "NG-EDR-006"
    rule_name = "Unusual outbound connection"
    alert_type = "unusual_outbound_port"
    supported_event_types = ("network_connection",)
    recommended_action = "review_egress_destination"
    base_tags = ("network", "egress", "network_anomaly")
    mitre_tactic = "command_and_control"
    mitre_technique = "T1571"

    def evaluate(self, context: DetectionContext):
        if (context.event.network_direction or "").lower() != "outbound":
            return []
        port = int(context.event.network_dst_port or 0)
        if port <= 0:
            return []
        if port in HIGH_RISK_PORTS:
            severity = "high"
            confidence = 0.81
        elif port in COMMON_EGRESS_PORTS:
            return []
        else:
            severity = "medium"
            confidence = 0.67
        return [
            self.detection(
                severity=severity,
                confidence=confidence,
                description="Connection metadata matches an uncommon outbound port pattern.",
                context=context,
                tags=["unusual_port", "external_connection"],
                details={"dst_ip": context.event.network_dst_ip, "dst_port": port},
            )
        ]


class RareOutboundDestinationRule(DetectionRule):
    rule_id = "NG-EDR-011"
    rule_name = "Rare outbound destination"
    alert_type = "rare_outbound_destination"
    supported_event_types = ("network_connection",)
    recommended_action = "investigate_new_destination"
    base_tags = ("network", "baseline", "destination_anomaly")
    mitre_tactic = "command_and_control"
    mitre_technique = "T1071"

    def evaluate(self, context: DetectionContext):
        if (context.event.network_direction or "").lower() != "outbound":
            return []
        dest_ip = context.event.network_dst_ip or ""
        if not dest_ip or _is_private(dest_ip):
            return []
        if not context.baseline_signals.get("rare_outbound_destination"):
            return []
        port = int(context.event.network_dst_port or 0)
        return [
            self.detection(
                severity="medium",
                confidence=0.7,
                description="Endpoint connected to a destination that is rare for this host baseline.",
                context=context,
                tags=["rare_destination", "external_connection"],
                details={
                    "dst_ip": dest_ip,
                    "dst_port": port,
                    "connection_count": context.profile.network_dest_counts[(dest_ip, port)],
                },
            )
        ]


class BeaconingRule(DetectionRule):
    rule_id = "NG-EDR-012"
    rule_name = "Repeated outbound beaconing pattern"
    alert_type = "beaconing_pattern_detected"
    supported_event_types = ("network_connection",)
    recommended_action = "investigate_possible_c2"
    base_tags = ("network", "beaconing", "c2_suspected")
    mitre_tactic = "command_and_control"
    mitre_technique = "T1071"

    def evaluate(self, context: DetectionContext):
        if (context.event.network_direction or "").lower() != "outbound":
            return []
        intervals = context.baseline_signals.get("beacon_intervals") or []
        if not context.baseline_signals.get("possible_beaconing") or len(intervals) < 4:
            return []
        dest_ip = context.event.network_dst_ip or ""
        port = int(context.event.network_dst_port or 0)
        return [
            self.detection(
                severity="high",
                confidence=0.78,
                description="Outbound connections show a low-variance recurring interval consistent with beaconing.",
                context=context,
                tags=["repeated_outbound", "external_connection"],
                details={"dst_ip": dest_ip, "dst_port": port, "intervals": intervals},
            )
        ]
