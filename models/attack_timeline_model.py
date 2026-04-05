from dataclasses import dataclass, field
from typing import List, Dict, Any


@dataclass
class TimelineStep:
    timestamp: str
    phase: str
    event_type: str
    severity: str
    message: str
    source: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackTimeline:
    attack_id: str
    host_id: str
    risk_score: int
    steps: List[TimelineStep] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attack_id": self.attack_id,
            "host_id": self.host_id,
            "risk_score": self.risk_score,
            "steps": [
                {
                    "timestamp": step.timestamp,
                    "phase": step.phase,
                    "event_type": step.event_type,
                    "severity": step.severity,
                    "message": step.message,
                    "source": step.source,
                    "metadata": step.metadata,
                }
                for step in self.steps
            ],
        }