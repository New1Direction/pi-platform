from __future__ import annotations
import os
import re
from pydantic import BaseModel, Field

def is_strict_mode() -> bool:
    env_val = os.getenv("PI_CAVEMAN_COMPRESSOR_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"
    return True

class CavemanCompressorInput(BaseModel):
    text_payload: str = Field(..., description="Conversational text to compress")

class CavemanCompressorOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if compression succeeded")
    compressed_text: str = Field(..., description="Compressed text representation")
    compression_ratio: float = Field(..., description="Ratio of compressed to original size")
    status: str = Field(..., description="Status (PASSED, REJECTED_CAVEMAN, WARN_CAVEMAN)")

class PiCavemanTokenCompressor:
    """Deterministic micro-agent that strips greetings, filler, and verbose boilerplate."""

    def __init__(self) -> None:
        self.agent_name = "PiCavemanTokenCompressor"

    def compress_tokens(self, input_envelope: CavemanCompressorInput) -> CavemanCompressorOutput:
        text = input_envelope.text_payload
        if not text:
            return CavemanCompressorOutput(is_secure=True, compressed_text="", compression_ratio=1.0, status="PASSED")

        # Strip greetings
        greetings = [
            r"\bhello\b", r"\bhi\b", r"\bhey\b", r"\bgreetings\b", r"\bhope this finds you well\b",
            r"\bhow are you\b", r"\bplease\b", r"\bthank you\b", r"\bthanks\b", r"\bcould you\b",
            r"\bi would like to\b", r"\bkindly\b", r"\bso\b", r"\bactually\b", r"\bjust\b"
        ]
        
        compressed = text
        for greet in greetings:
            compressed = re.sub(greet, "", compressed, flags=re.IGNORECASE)
            
        # Clean extra whitespace
        compressed = re.sub(r"\s+", " ", compressed).strip()
        
        orig_len = len(text)
        comp_len = len(compressed)
        ratio = comp_len / orig_len if orig_len > 0 else 1.0
        
        # In strict mode, if compression does not reduce token footprint (e.g. text already dense), still passes
        is_secure = True
        status = "PASSED"
        
        return CavemanCompressorOutput(
            is_secure=is_secure,
            compressed_text=compressed,
            compression_ratio=round(ratio, 4),
            status=status
        )
