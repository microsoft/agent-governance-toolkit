# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Geo Agent (Agent B) - "The Eye"

Satellite interface that fetches imagery and calculates vegetation indices.
Listens for Claims and publishes Observations.

Updated for atr 0.2.0:
- Public API: atr.get_tool() instead of atr._global_registry
- Tool versioning support
"""

from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

import atr

from .base import BaseAgent


class GeoAgent(BaseAgent):
    """
    The Geo Agent - "The Eye"
    
    Role: Satellite interface that:
        - Listens for Claim messages with coordinates
        - Fetches satellite imagery for the specified polygon
        - Calculates NDVI (vegetation index)
        - Publishes Observation objects with actual values
    
    Tooling (atr 0.2.0): sentinel_api, ndvi_calculator
    
    Subscribes to: CLAIMS topic
    Publishes: Observation objects to the OBSERVATIONS topic
    """

    def __init__(
        self,
        agent_id: str,
        simulate_deforestation: bool = False
    ):
        """
        Initialize the Geo Agent.
        
        Args:
            agent_id: Unique identifier
            simulate_deforestation: If True, generate data showing deforestation
        """
        super().__init__(agent_id, name="geo-agent")
        
        self._simulate_deforestation = simulate_deforestation
        
        # NEW: Use public atr.get_tool() API (ATR-001)
        # This replaces the fragile atr._global_registry access
        sentinel_tool = atr.get_tool("sentinel_api", version=">=1.0.0")
        ndvi_tool = atr.get_tool("ndvi_calculator", version=">=1.0.0")
        
        self._sentinel_api = atr.get_callable("sentinel_api")
        self._ndvi_calculator = atr.get_callable("ndvi_calculator")

    @property
    def subscribed_topics(self) -> List[str]:
        """Subscribe to claims to trigger satellite lookups."""
        return ["vcm.claims"]

    def process_claim(
        self,
        claim: Dict[str, Any],
        correlation_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Process a claim by fetching satellite data and calculating NDVI.
        
        Args:
            claim: The claim data with polygon and time range
            correlation_id: Optional tracking ID
            
        Returns:
            The observation data
        """
        project_id = claim.get("project_id", "UNKNOWN")
        polygon = claim.get("polygon", "[]")
        year = claim.get("year", 2024)
        
        self._log(f"Fetching satellite data for {project_id}, year {year}")
        self._metrics.last_activity = datetime.now(timezone.utc)
        
        # Step 1: Fetch satellite imagery using atr tool
        satellite_result = self._sentinel_api(
            polygon=polygon,
            start_date=f"{year}-01-01",
            end_date=f"{year}-12-31",
        )
        
        if "error" in satellite_result:
            self._log(f"Failed to fetch satellite data: {satellite_result['error']}", level="ERROR")
            return {"error": satellite_result["error"]}
        
        cloud_cover = satellite_result.get("cloud_cover_percentage", 0) / 100.0
        
        self._log(f"Retrieved {satellite_result['product_type']} imagery, "
                  f"cloud cover: {cloud_cover:.1%}")
        
        # Step 2: Calculate NDVI using atr tool
        ndvi_result = self._ndvi_calculator(
            red_band=satellite_result["bands"]["B04_RED"],
            nir_band=satellite_result["bands"]["B08_NIR"],
            simulate_deforestation=self._simulate_deforestation,
        )
        
        if "error" in ndvi_result:
            self._log(f"Failed to calculate NDVI: {ndvi_result['error']}", level="ERROR")
            return {"error": ndvi_result["error"]}
        
        self._log(f"Calculated NDVI: mean={ndvi_result['ndvi_mean']:.3f}, "
                  f"vegetation coverage: {ndvi_result['vegetation_coverage']:.1%}")
        
        # Step 3: Build observation object
        observation = self._build_observation(
            project_id=project_id,
            ndvi_data=ndvi_result,
            cloud_cover=cloud_cover,
            satellite_provenance=satellite_result.get("_provenance"),
            ndvi_provenance=ndvi_result.get("_provenance"),
        )
        
        self._metrics.messages_sent += 1
        
        return observation

    def _build_observation(
        self,
        project_id: str,
        ndvi_data: Dict[str, Any],
        cloud_cover: float,
        satellite_provenance: Any,
        ndvi_provenance: Any,
    ) -> Dict[str, Any]:
        """Build a standardized observation object."""
        observation = {
            "project_id": project_id,
            "observed_ndvi_mean": ndvi_data["ndvi_mean"],
            "observed_ndvi_std": ndvi_data["ndvi_std"],
            "observed_ndvi_min": ndvi_data["ndvi_min"],
            "observed_ndvi_max": ndvi_data["ndvi_max"],
            "cloud_cover": cloud_cover,
            "vegetation_coverage": ndvi_data["vegetation_coverage"],
            "deforestation_indicator": ndvi_data["deforestation_indicator"],
            "pixel_count": ndvi_data["pixel_count"],
        }
        
        # Add provenance metadata (the "Cryptographic Oracle" feature)
        if satellite_provenance:
            observation["_satellite_provenance"] = satellite_provenance
        
        if ndvi_provenance:
            observation["_ndvi_provenance"] = ndvi_provenance
        
        return observation

    def get_tools(self) -> List[str]:
        """List available tools."""
        return ["sentinel_api", "ndvi_calculator"]

    def set_simulation_mode(self, simulate_deforestation: bool) -> None:
        """
        Set whether to simulate deforestation in NDVI calculations.
        
        Args:
            simulate_deforestation: If True, generate low NDVI values
        """
        self._simulate_deforestation = simulate_deforestation
        mode = "DEFORESTATION" if simulate_deforestation else "HEALTHY"
        self._log(f"Simulation mode set to: {mode}")
