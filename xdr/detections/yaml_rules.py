"""YAML-backed Sigma-like rules for the XDR engine."""

from __future__ import annotations

import logging

from rules.yaml_loader import YamlRuleRegistry, load_yaml_rules

logger = logging.getLogger("netguard.yaml_rules")


class YamlRuleSet:
    """Adapter that evaluates folder-backed YAML rules within the XDR pipeline."""

    supported_event_types = ()

    def __init__(self, *, rules_dir=None):
        try:
            self._registry = load_yaml_rules(rules_dir)
        except Exception as exc:  # pragma: no cover - defensive fallback
            logger.warning("Failed to load YAML rules: %s", exc)
            self._registry = YamlRuleRegistry()

    def applies_to(self, event) -> bool:
        return True

    def evaluate(self, context):
        return self._registry.evaluate(context)
