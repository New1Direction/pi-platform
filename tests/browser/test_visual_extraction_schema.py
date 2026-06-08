"""
tests/browser/test_visual_extraction_schema.py

Mock test for the Maxun visual extraction schema.
Verifies payload structure and failure handling.
"""

from unittest.mock import AsyncMock, patch

import pytest

# aiohttp is an optional dependency for the visual extraction integration.
# Skip the whole module cleanly when it's not installed so pytest doesn't
# error at collection time.
pytest.importorskip("aiohttp")

from src.pi_runtime.browser.visual_extraction_schema import VisualExtractionSchema  # noqa: E402


@pytest.mark.asyncio
async def test_extraction_success_returns_structured_payload():
    """Simulates a successful Maxun extraction and verifies payload shape."""
    extractor = VisualExtractionSchema(maxun_api_url="http://localhost:8080")

    with patch("aiohttp.ClientSession.post") as mock_post:
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json.return_value = {"data": {"tos_last_modified": "2026-05-20"}}
        mock_post.return_value.__aenter__.return_value = mock_response

        payload = await extractor.execute_extraction(
            scraper_id="tos_monitor", target_url="https://example.com/terms", sink_path="~/Documents/Korg/tos.md"
        )

        assert payload.scraper_id == "tos_monitor"
        assert payload.target_url == "https://example.com/terms"
        assert "tos_last_modified" in payload.extracted_data
        assert payload.sink_path is not None


@pytest.mark.asyncio
async def test_extraction_failure_returns_empty_payload():
    """Simulates a Maxun API failure and verifies empty payload fallback."""
    extractor = VisualExtractionSchema()

    with patch("aiohttp.ClientSession.post") as mock_post:
        mock_response = AsyncMock()
        mock_response.status = 500
        mock_post.return_value.__aenter__.return_value = mock_response

        payload = await extractor.execute_extraction(scraper_id="tos_monitor", target_url="https://example.com/terms")

        assert payload.extracted_data == {}
        assert payload.scraper_id == "tos_monitor"
