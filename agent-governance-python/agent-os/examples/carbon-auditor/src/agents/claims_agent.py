# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Claims Agent (Agent A) - "The Reader"

Ingests Project Design Documents (PDFs) and extracts carbon credit claims.
Publishes structured Claim objects to the message bus.

Updated for atr 0.2.0:
- Public API: atr.get_tool() instead of atr._global_registry
- Tool versioning support
"""

from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

import atr

from .base import BaseAgent


class ClaimsAgent(BaseAgent):
    """
    The Claims Agent - "The Reader"
    
    Role: Ingests Project Design Documents (PDFs) and extracts:
        - Project identification
        - Geospatial polygon coordinates
        - Claimed carbon stock values
        - Claimed NDVI/vegetation values
    
    Tooling (atr 0.2.0): pdf_parser, table_extractor
    
    Publishes: Claim objects to the CLAIMS topic
    """

    def __init__(self, agent_id: str):
        super().__init__(agent_id, name="claims-agent")
        
        # NEW: Use public atr.get_tool() API (ATR-001)
        # This replaces the fragile atr._global_registry access
        pdf_tool = atr.get_tool("pdf_parser", version=">=1.0.0")
        table_tool = atr.get_tool("table_extractor", version=">=1.0.0")
        
        self._pdf_parser = atr.get_callable("pdf_parser")
        self._table_extractor = atr.get_callable("table_extractor")

    @property
    def subscribed_topics(self) -> List[str]:
        """Claims agent doesn't subscribe to any topics - it initiates the flow."""
        return ["vcm.system"]

    def process_document(
        self,
        pdf_path: str,
        correlation_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Process a Project Design Document and extract claims.
        
        Args:
            pdf_path: Path to the PDF file
            correlation_id: Optional ID for tracking the request
            
        Returns:
            The extracted claim data
        """
        self._log(f"Processing document: {pdf_path}")
        self._metrics.last_activity = datetime.now(timezone.utc)
        
        # Step 1: Parse PDF using atr tool
        parse_result = self._pdf_parser(file_path=pdf_path)
        
        if "error" in parse_result:
            self._log(f"Failed to parse PDF: {parse_result['error']}", level="ERROR")
            return {"error": parse_result["error"]}
        
        self._log(f"Parsed {parse_result.get('pages', 'unknown')} pages")
        
        # Step 2: Extract structured data using atr tool
        extract_result = self._table_extractor(text=parse_result["text"])
        
        if "error" in extract_result:
            self._log(f"Failed to extract data: {extract_result['error']}", level="ERROR")
            return {"error": extract_result["error"]}
        
        # Step 3: Build claim object
        claim = self._build_claim(extract_result)
        
        self._log(f"Extracted claim: {claim['project_id']}, NDVI={claim['claimed_ndvi']}")
        self._metrics.messages_sent += 1
        
        return claim

    def _build_claim(self, extracted_data: Dict[str, Any]) -> Dict[str, Any]:
        """Build a standardized claim object from extracted data."""
        return {
            "project_id": extracted_data.get("project_id", "UNKNOWN"),
            "polygon": extracted_data.get("polygon"),
            "year": extracted_data.get("year", 2024),
            "claimed_ndvi": extracted_data.get("claimed_ndvi", 0.0),
            "claimed_carbon_stock": extracted_data.get("carbon_stock", 0.0),
            "_provenance": extracted_data.get("_provenance"),
        }

    def get_tools(self) -> List[str]:
        """List available tools."""
        return ["pdf_parser", "table_extractor"]
