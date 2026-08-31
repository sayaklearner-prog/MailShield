from abc import ABC, abstractmethod
from typing import List, Optional
from backend.app.schemas.intelligence import ProviderName, ThreatIntelligenceResult


class BaseIntelligenceProvider(ABC):
    """Abstract base provider interface for external threat intelligence services."""

    @property
    @abstractmethod
    def name(self) -> ProviderName:
        """Controlled provider identifier."""
        pass

    @property
    @abstractmethod
    def supported_indicator_types(self) -> List[str]:
        """List of supported IOC types (e.g. ['ip', 'domain', 'url', 'attachment_hash'])."""
        pass

    @abstractmethod
    async def enrich(
        self, indicator: str, indicator_type: str, api_key: Optional[str] = None
    ) -> ThreatIntelligenceResult:
        """Perform provider lookup, returning structured ThreatIntelligenceResult with provenance."""
        pass
