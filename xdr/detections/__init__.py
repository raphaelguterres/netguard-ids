"""Rule registry for the NetGuard XDR detection engine."""

from .auth_rules import (
    BruteForceAuthRule,
    FailureThenSuccessRule,
    LoginOutsideBaselineRule,
)
from .base import DetectionContext, DetectionRule
from .network_rules import BeaconingRule, RareOutboundDestinationRule, UnusualOutboundPortRule
from .persistence_rules import PersistenceIndicatorRule
from .process_rules import (
    EncodedCommandRule,
    RareProcessRule,
    SuspiciousBashRule,
    SuspiciousPowerShellRule,
    SuspiciousProcessTreeRule,
    UnusualParentChildRule,
)
from .state import BehavioralBaselineAdapter, HostBehaviorProfile, HostBehaviorStore

DEFAULT_RULES = (
    SuspiciousPowerShellRule(),
    SuspiciousBashRule(),
    EncodedCommandRule(),
    SuspiciousProcessTreeRule(),
    RareProcessRule(),
    UnusualParentChildRule(),
    BruteForceAuthRule(),
    FailureThenSuccessRule(),
    LoginOutsideBaselineRule(),
    PersistenceIndicatorRule(),
    UnusualOutboundPortRule(),
    RareOutboundDestinationRule(),
    BeaconingRule(),
)

__all__ = [
    "BehavioralBaselineAdapter",
    "BruteForceAuthRule",
    "DetectionContext",
    "DetectionRule",
    "DEFAULT_RULES",
    "EncodedCommandRule",
    "FailureThenSuccessRule",
    "HostBehaviorProfile",
    "HostBehaviorStore",
    "LoginOutsideBaselineRule",
    "PersistenceIndicatorRule",
    "RareOutboundDestinationRule",
    "RareProcessRule",
    "SuspiciousBashRule",
    "SuspiciousPowerShellRule",
    "SuspiciousProcessTreeRule",
    "UnusualOutboundPortRule",
    "UnusualParentChildRule",
    "BeaconingRule",
]
