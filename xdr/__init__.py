"""NetGuard XDR foundation package."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from .detection import BehaviorDetectionEngine
    from .pipeline import XDRPipeline
    from .schema import EndpointEvent, PipelineOutcome

__all__ = ["BehaviorDetectionEngine", "EndpointEvent", "PipelineOutcome", "XDRPipeline"]


def __getattr__(name: str):
    if name == "BehaviorDetectionEngine":
        from .detection import BehaviorDetectionEngine as _BehaviorDetectionEngine

        return _BehaviorDetectionEngine
    if name == "XDRPipeline":
        from .pipeline import XDRPipeline as _XDRPipeline

        return _XDRPipeline
    if name == "EndpointEvent":
        from .schema import EndpointEvent as _EndpointEvent

        return _EndpointEvent
    if name == "PipelineOutcome":
        from .schema import PipelineOutcome as _PipelineOutcome

        return _PipelineOutcome
    raise AttributeError(name)
