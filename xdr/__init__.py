"""NetGuard XDR foundation package."""

from .detection import BehaviorDetectionEngine
from .pipeline import XDRPipeline
from .schema import EndpointEvent, PipelineOutcome

__all__ = ["BehaviorDetectionEngine", "EndpointEvent", "PipelineOutcome", "XDRPipeline"]
