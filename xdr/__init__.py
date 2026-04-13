"""NetGuard XDR foundation package."""

from .pipeline import XDRPipeline
from .schema import EndpointEvent, PipelineOutcome

__all__ = ["EndpointEvent", "PipelineOutcome", "XDRPipeline"]
