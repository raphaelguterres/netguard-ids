"""Process and script-abuse focused detection rules."""

from __future__ import annotations

from .base import DetectionContext, DetectionRule, canonical_command

SUSPICIOUS_POWERSHELL_TOKENS = (
    "-enc",
    "-encodedcommand",
    "downloadstring",
    "invoke-expression",
    "iex(",
    " bypass ",
    "frombase64string",
)

SUSPICIOUS_BASH_TOKENS = (
    "curl ",
    "wget ",
    "| sh",
    "| bash",
    "base64 -d",
    "chmod +x",
    "/tmp/",
)

GENERIC_ENCODED_TOKENS = (
    "-enc",
    "-encodedcommand",
    "frombase64string",
    "base64 -d",
    "certutil -decode",
)

OFFICE_PARENTS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "acrord32.exe"}
SCRIPT_CHILDREN = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "bash", "sh"}


class SuspiciousPowerShellRule(DetectionRule):
    rule_id = "NG-EDR-001"
    rule_name = "Suspicious PowerShell execution"
    alert_type = "suspicious_powershell"
    supported_event_types = ("process_execution", "script_execution")
    recommended_action = "investigate_and_review_command"
    base_tags = ("process", "script_abuse", "powershell")
    mitre_tactic = "execution"
    mitre_technique = "T1059.001"

    def evaluate(self, context: DetectionContext):
        process = (context.event.process_name or "").lower()
        command = canonical_command(context.event.command_line)
        if process not in {"powershell.exe", "pwsh.exe"}:
            return []
        matched = [token.strip() for token in SUSPICIOUS_POWERSHELL_TOKENS if token in command]
        if not matched:
            return []
        severity = "critical" if {"-enc", "downloadstring"} <= set(matched) or "invoke-expression" in matched else "high"
        return [
            self.detection(
                severity=severity,
                confidence=0.92,
                description="PowerShell command line contains encoded or execution-bypass tradecraft.",
                context=context,
                tags=["encoded_command" if "-enc" in matched else "script_execution"],
                details={"command_line": context.event.command_line, "matched_tokens": matched},
            )
        ]


class SuspiciousBashRule(DetectionRule):
    rule_id = "NG-EDR-002"
    rule_name = "Suspicious Bash execution"
    alert_type = "suspicious_bash"
    supported_event_types = ("process_execution", "script_execution")
    recommended_action = "investigate_download_execute_chain"
    base_tags = ("process", "script_abuse", "bash")
    mitre_tactic = "execution"
    mitre_technique = "T1059.004"

    def evaluate(self, context: DetectionContext):
        process = (context.event.process_name or "").lower()
        command = canonical_command(context.event.command_line)
        if process not in {"bash", "sh"}:
            return []
        matched = [token.strip() for token in SUSPICIOUS_BASH_TOKENS if token in command]
        if not matched:
            return []
        severity = "critical" if ("curl" in "".join(matched) or "wget" in "".join(matched)) and "| sh" in command else "high"
        return [
            self.detection(
                severity=severity,
                confidence=0.88,
                description="Shell command matches a download-and-execute abuse pattern.",
                context=context,
                tags=["download_execute"],
                details={"command_line": context.event.command_line, "matched_tokens": matched},
            )
        ]


class EncodedCommandRule(DetectionRule):
    rule_id = "NG-EDR-008"
    rule_name = "Encoded command execution"
    alert_type = "encoded_command_execution"
    supported_event_types = ("process_execution", "script_execution")
    recommended_action = "review_decoded_payload"
    base_tags = ("process", "script_abuse", "encoded_command")
    mitre_tactic = "defense_evasion"
    mitre_technique = "T1027"

    def evaluate(self, context: DetectionContext):
        command = canonical_command(context.event.command_line)
        if not command:
            return []
        matched = [token.strip() for token in GENERIC_ENCODED_TOKENS if token in command]
        if not matched:
            return []
        return [
            self.detection(
                severity="high",
                confidence=0.84,
                description="Interpreter command line contains encoded payload indicators.",
                context=context,
                tags=["payload_obfuscation"],
                details={"command_line": context.event.command_line, "matched_tokens": matched},
            )
        ]


class SuspiciousProcessTreeRule(DetectionRule):
    rule_id = "NG-EDR-005"
    rule_name = "Suspicious process tree"
    alert_type = "office_spawned_interpreter"
    supported_event_types = ("process_execution", "script_execution")
    recommended_action = "investigate_parent_child_chain"
    base_tags = ("process", "process_tree", "execution_chain")
    mitre_tactic = "execution"
    mitre_technique = "T1204.002"

    def evaluate(self, context: DetectionContext):
        parent = (context.event.parent_process or "").lower()
        child = (context.event.process_name or "").lower()
        if parent not in OFFICE_PARENTS or child not in SCRIPT_CHILDREN:
            return []
        return [
            self.detection(
                severity="high",
                confidence=0.91,
                description="Office or document reader spawned a scripting interpreter.",
                context=context,
                tags=["dangerous_parent_child", "office_spawned_interpreter"],
                details={
                    "parent_process": context.event.parent_process,
                    "process_name": context.event.process_name,
                    "lineage_hint": f"{context.event.parent_process} -> {context.event.process_name}",
                },
            )
        ]


class RareProcessRule(DetectionRule):
    rule_id = "NG-EDR-007"
    rule_name = "Rare process on host baseline"
    alert_type = "rare_process_execution"
    supported_event_types = ("process_execution", "script_execution")
    recommended_action = "investigate_new_process"
    base_tags = ("process", "baseline", "process_anomaly")
    mitre_tactic = "execution"
    mitre_technique = "T1204"

    def evaluate(self, context: DetectionContext):
        process = (context.event.process_name or "").lower()
        if not process or not context.baseline_signals.get("rare_process"):
            return []
        return [
            self.detection(
                severity="medium",
                confidence=0.67,
                description="Process execution deviates from the observed host baseline.",
                context=context,
                tags=["rare_process"],
                details={
                    "process_name": context.event.process_name,
                    "known_processes": len(context.profile.process_counts),
                    "execution_count": context.profile.process_counts[process],
                },
            )
        ]


class UnusualParentChildRule(DetectionRule):
    rule_id = "NG-EDR-014"
    rule_name = "Unusual parent-child relationship"
    alert_type = "unusual_parent_child"
    supported_event_types = ("process_execution", "script_execution")
    recommended_action = "review_process_lineage"
    base_tags = ("process", "baseline", "process_tree")
    mitre_tactic = "execution"
    mitre_technique = "T1204.002"

    def evaluate(self, context: DetectionContext):
        parent = (context.event.parent_process or "").lower()
        child = (context.event.process_name or "").lower()
        if not parent or not child or not context.baseline_signals.get("rare_parent_child"):
            return []
        severity = "high" if child in SCRIPT_CHILDREN else "medium"
        related = context.recent_related(
            predicate=lambda item: item.get("event_type") in {"process_execution", "script_execution"},
            limit=4,
        )
        return [
            self.detection(
                severity=severity,
                confidence=0.73,
                description="Parent-child process chain is uncommon for this host baseline.",
                context=context,
                tags=["rare_parent_child"],
                details={
                    "parent_process": context.event.parent_process,
                    "process_name": context.event.process_name,
                    "pair_count": context.profile.parent_child_counts[(parent, child)],
                },
                related_events=related or [context.current_ref()],
            )
        ]
