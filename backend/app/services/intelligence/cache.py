import time
from typing import Optional, Dict, Tuple
from backend.app.schemas.intelligence import ThreatIntelligenceResult
from backend.app.core.config import settings


class IntelligenceCache:
    """Thread-safe in-memory TTL cache for external threat intelligence lookups."""

    def __init__(self, ttl_seconds: int = 3600):
        self._ttl_seconds = ttl_seconds
        # Key: (provider_name, indicator_type, normalized_indicator) -> (result, expiry_timestamp)
        self._cache: Dict[Tuple[str, str, str], Tuple[ThreatIntelligenceResult, float]] = {}

    def _make_key(self, provider: str, indicator_type: str, indicator: str) -> Tuple[str, str, str]:
        return (provider.lower(), indicator_type.lower(), indicator.strip().lower())

    def get(self, provider: str, indicator_type: str, indicator: str) -> Optional[ThreatIntelligenceResult]:
        key = self._make_key(provider, indicator_type, indicator)
        entry = self._cache.get(key)
        if not entry:
            return None

        result, expiry = entry
        if time.time() > expiry:
            # Expired
            self._cache.pop(key, None)
            return None

        # Return cached copy marked as cached
        cached_result = result.model_copy()
        cached_result.is_cached = True
        return cached_result

    def set(
        self, provider: str, indicator_type: str, indicator: str, result: ThreatIntelligenceResult, ttl: Optional[int] = None
    ) -> None:
        key = self._make_key(provider, indicator_type, indicator)
        expiry = time.time() + (ttl if ttl is not None else self._ttl_seconds)
        self._cache[key] = (result, expiry)

    def clear(self) -> None:
        self._cache.clear()

    def size(self) -> int:
        # Purge expired entries on count
        now = time.time()
        expired_keys = [k for k, (_, exp) in self._cache.items() if now > exp]
        for k in expired_keys:
            self._cache.pop(k, None)
        return len(self._cache)


# Global singleton cache instance
intel_cache = IntelligenceCache(ttl_seconds=settings.INTEL_CACHE_TTL_SECONDS)
