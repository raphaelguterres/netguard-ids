"""Response planning for NetGuard XDR."""

from __future__ import annotations

from .schema import CorrelationRecord, DetectionRecord, EndpointEvent, ResponseAction
from .severity import max_severity


class ResponseEngine:
    """Produces response plans without requiring heavy orchestration."""

    def plan(
        self,
        event: EndpointEvent,
        detections: list[DetectionRecord],
        correlations: list[CorrelationRecord],
    ) -> list[ResponseAction]:
        actions: list[ResponseAction] = []
        highest = max_severity(
            event.severity,
            *(item.severity for item in detections),
            *(item.severity for item in correlations),
        )

        if highest in {"high", "critical"}:
            actions.append(
                ResponseAction(
                    action_type="generate_incident_ticket",
                    target=event.host_id,
                    automatic=True,
                    requires_agent=False,
                    reason="Create an incident record for SOC handling.",
                )
            )
            actions.append(
                ResponseAction(
                    action_type="tag_host_risk",
                    target=event.host_id,
                    automatic=True,
                    requires_agent=False,
                    reason="Update host risk level based on current signals.",
                    parameters={"risk_level": highest},
                )
            )

        if correlations:
            actions.append(
                ResponseAction(
                    action_type="escalate_alert",
                    target=event.host_id,
                    automatic=True,
                    requires_agent=False,
                    reason="Correlation engine raised a higher-confidence incident.",
                )
            )

        if event.pid and any(self._has_any_tag(item, {"script_abuse", "process_tree", "execution_chain"}) for item in detections):
            actions.append(
                ResponseAction(
                    action_type="kill_process",
                    target=str(event.pid),
                    automatic=False,
                    requires_agent=True,
                    reason="Endpoint should terminate the suspicious process if approved.",
                    parameters={"process_name": event.process_name},
                )
            )

        if event.command_line and any(self._has_any_tag(item, {"script_abuse", "encoded_command"}) for item in detections):
            actions.append(
                ResponseAction(
                    action_type="block_execution_pattern",
                    target=event.host_id,
                    automatic=False,
                    requires_agent=True,
                    reason="Endpoint should locally block the malicious command pattern.",
                    parameters={"pattern": event.command_line[:256]},
                )
            )

        if event.auth_source_ip and any(self._has_any_tag(item, {"auth_abuse", "bruteforce", "credential_abuse"}) for item in detections):
            actions.append(
                ResponseAction(
                    action_type="block_source_ip",
                    target=event.auth_source_ip,
                    automatic=False,
                    requires_agent=True,
                    reason="Repeated auth abuse warrants source blocking if policy allows.",
                )
            )

        deduped: list[ResponseAction] = []
        seen = set()
        for action in actions:
            key = (action.action_type, action.target)
            if key not in seen:
                deduped.append(action)
                seen.add(key)
        return deduped

    @staticmethod
    def _has_any_tag(record: DetectionRecord, candidates: set[str]) -> bool:
        return any(tag in candidates for tag in (record.tags or []))
