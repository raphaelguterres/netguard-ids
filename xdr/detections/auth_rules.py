"""Authentication anomaly rules for XDR telemetry."""

from __future__ import annotations

from .base import DetectionContext, DetectionRule


class BruteForceAuthRule(DetectionRule):
    rule_id = "NG-EDR-003"
    rule_name = "Brute force authentication pattern"
    alert_type = "brute_force_auth_pattern"
    supported_event_types = ("authentication",)
    recommended_action = "investigate_source_and_user"
    base_tags = ("authentication", "auth_abuse", "bruteforce")
    mitre_tactic = "credential_access"
    mitre_technique = "T1110"

    def evaluate(self, context: DetectionContext):
        if (context.event.auth_result or "").lower() != "failure":
            return []
        key = ((context.event.username or "").lower(), context.event.auth_source_ip or "")
        failures = context.profile.recent_auth(
            key,
            within_seconds=120,
            result="failure",
            reference_ts=context.event_time.timestamp(),
        )
        if len(failures) < 5:
            return []
        return [
            self.detection(
                severity="high",
                confidence=0.84,
                description="Repeated authentication failures were observed from the same source.",
                context=context,
                tags=["excessive_failures"],
                details={
                    "username": context.event.username,
                    "source_ip": context.event.auth_source_ip,
                    "failure_count": len(failures),
                },
            )
        ]


class FailureThenSuccessRule(DetectionRule):
    rule_id = "NG-EDR-009"
    rule_name = "Repeated failures followed by success"
    alert_type = "auth_failure_then_success"
    supported_event_types = ("authentication",)
    recommended_action = "validate_account_compromise"
    base_tags = ("authentication", "auth_abuse", "credential_abuse")
    mitre_tactic = "credential_access"
    mitre_technique = "T1110"

    def evaluate(self, context: DetectionContext):
        if (context.event.auth_result or "").lower() != "success":
            return []
        key = ((context.event.username or "").lower(), context.event.auth_source_ip or "")
        failures = context.profile.recent_auth(
            key,
            within_seconds=600,
            result="failure",
            reference_ts=context.event_time.timestamp(),
        )
        if len(failures) < 3:
            return []
        related = context.recent_related(
            predicate=lambda item: item.get("event_type") == "authentication"
            and item.get("username") == context.event.username,
            limit=5,
        )
        return [
            self.detection(
                severity="high",
                confidence=0.87,
                description="Multiple authentication failures were followed by a successful login.",
                context=context,
                tags=["failure_then_success"],
                details={
                    "username": context.event.username,
                    "source_ip": context.event.auth_source_ip,
                    "previous_failures": len(failures),
                },
                related_events=related or [context.current_ref()],
            )
        ]


class LoginOutsideBaselineRule(DetectionRule):
    rule_id = "NG-EDR-010"
    rule_name = "Login outside normal time window"
    alert_type = "login_outside_baseline"
    supported_event_types = ("authentication",)
    recommended_action = "review_user_session"
    base_tags = ("authentication", "baseline", "user_anomaly")
    mitre_tactic = "initial_access"
    mitre_technique = "T1078"

    def evaluate(self, context: DetectionContext):
        if (context.event.auth_result or "").lower() != "success":
            return []
        if not context.baseline_signals.get("unusual_login_hour"):
            return []
        distribution = context.profile.login_hour_distribution(context.event.username)
        current_hour = context.event_time.hour
        dominant_hour = max(distribution, key=distribution.get) if distribution else current_hour
        return [
            self.detection(
                severity="medium",
                confidence=0.72,
                description="User login was observed outside the normal activity window for this host.",
                context=context,
                tags=["unusual_login_hour"],
                details={
                    "username": context.event.username,
                    "login_hour": current_hour,
                    "dominant_hour": dominant_hour,
                },
            )
        ]
