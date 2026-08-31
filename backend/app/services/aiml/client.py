import logging
from typing import Dict, Any, List, Optional
from backend.app.services.gemini.client import GoogleGeminiClient

logger = logging.getLogger(__name__)


class AIMLClient:
    """Compatibility layer delegating all AI synthesis tasks to Google Gemini AI."""

    @classmethod
    def get_api_key(cls, override_key: Optional[str] = None) -> Optional[str]:
        return GoogleGeminiClient.get_api_key(override_key)

    @classmethod
    async def generate_completion(
        cls,
        system_prompt: str,
        user_prompt: str,
        model: Optional[str] = None,
        temperature: float = 0.1,
        api_key: Optional[str] = None,
        json_output: bool = True,
    ) -> Optional[Dict[str, Any]]:
        return await GoogleGeminiClient.generate_completion(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            model=model,
            temperature=temperature,
            api_key=api_key,
            json_output=json_output,
        )

    @classmethod
    async def synthesize_threat_intelligence(
        cls,
        indicator: str,
        indicator_type: str,
        verdict: str,
        score: Optional[int],
        provider_results: List[Dict[str, Any]],
        api_key: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        return await GoogleGeminiClient.synthesize_threat_intelligence(
            indicator=indicator,
            indicator_type=indicator_type,
            verdict=verdict,
            score=score,
            provider_results=provider_results,
            api_key=api_key,
        )

    @classmethod
    async def synthesize_network_infrastructure(
        cls,
        ip: str,
        category: str,
        is_public: bool,
        geo: Optional[Dict[str, Any]],
        asn: Optional[Dict[str, Any]],
        network_type: str,
        api_key: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        return await GoogleGeminiClient.synthesize_network_infrastructure(
            ip=ip,
            category=category,
            is_public=is_public,
            geo=geo,
            asn=asn,
            network_type=network_type,
            api_key=api_key,
        )

    @classmethod
    async def synthesize_investigation_report(
        cls,
        case_id: str,
        title: str,
        context: Dict[str, Any],
        api_key: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        return await GoogleGeminiClient.synthesize_investigation_report(
            case_id=case_id,
            title=title,
            context=context,
            api_key=api_key,
        )

    @classmethod
    async def synthesize_email_threat_summary(
        cls,
        email_data: Dict[str, Any],
        api_key: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        return await GoogleGeminiClient.synthesize_email_threat_summary(
            email_data=email_data,
            api_key=api_key,
        )

    @classmethod
    async def synthesize_email_deep_dive(
        cls,
        email_data: Dict[str, Any],
        api_key: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        return await GoogleGeminiClient.synthesize_email_deep_dive(
            email_data=email_data,
            api_key=api_key,
        )
