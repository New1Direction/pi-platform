"""
src/pi_runtime/browser/visual_extraction_schema.py

High-throughput, zero-logic visual data extraction wrapper for Maxun.
Pipes raw JSON payloads straight into operational intelligence storage.
"""

import logging
import time
from typing import Optional

import aiohttp

from .models import ExtractionSchemaPayload

logger = logging.getLogger("pi_runtime.browser.extraction")


class VisualExtractionSchema:
    """
    Triggers compiled visual scrapers and processes raw structured
    payloads directly into downstream pipeline targets.
    """

    def __init__(self, maxun_api_url: str = "http://localhost:8080"):
        self.api_url = maxun_api_url

    async def execute_extraction(
        self, scraper_id: str, target_url: str, sink_path: Optional[str] = None
    ) -> ExtractionSchemaPayload:
        """
        Triggers a predefined Maxun visual scraper layout against the target URL.
        """
        logger.info(f"[Maxun-Extractor] Invoking visual schema '{scraper_id}' against target: {target_url}")

        endpoint = f"{self.api_url}/api/v1/run/{scraper_id}"
        payload = {"url": target_url}

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(endpoint, json=payload, timeout=30) as response:
                    if response.status != 200:
                        logger.error(f"Maxun API engine returned error status: {response.status}")
                        return self._generate_empty_payload(scraper_id, target_url, sink_path)

                    raw_data = await response.json()
                    extracted_records = raw_data.get("data", {})

                    return ExtractionSchemaPayload(
                        scraper_id=scraper_id,
                        target_url=target_url,
                        extracted_data=extracted_records,
                        timestamp=time.time(),
                        sink_path=sink_path,
                    )

        except Exception as e:
            logger.error(f"Critical exception inside visual extraction pipeline: {str(e)}")
            return self._generate_empty_payload(scraper_id, target_url, sink_path)

    def _generate_empty_payload(
        self, scraper_id: str, target_url: str, sink_path: Optional[str] = None
    ) -> ExtractionSchemaPayload:
        return ExtractionSchemaPayload(
            scraper_id=scraper_id, target_url=target_url, extracted_data={}, timestamp=time.time(), sink_path=sink_path
        )
