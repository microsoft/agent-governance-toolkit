# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Carbon Auditor Tools

Tools registered with the Agent Tool Registry (atr) for the Carbon Auditor Swarm.
These tools provide capabilities for PDF parsing, satellite data fetching, and NDVI calculation.

Updated for atr 0.2.0:
- Public API: atr.get_tool() instead of atr._global_registry
- Tool versioning with semantic versions
- Retry policies with exponential backoff
- Rate limiting for external APIs
- Health checks for external dependencies
- Access control with permissions
"""

import atr
from atr import RetryPolicy, BackoffStrategy, HttpHealthCheck, CallableHealthCheck
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import numpy as np


# =============================================================================
# Provenance Metadata (for cryptographic verification)
# =============================================================================

@dataclass
class ProvenanceMetadata:
    """
    Cryptographic provenance for tool outputs.
    Enables verification that data hasn't been tampered with.
    """
    signature: str
    source: str
    timestamp: str
    algorithm: str = "sha256"
    
    @classmethod
    def create(cls, data: Dict[str, Any], source: str) -> "ProvenanceMetadata":
        """Create provenance metadata for data."""
        data_str = json.dumps(data, sort_keys=True, default=str)
        signature = hashlib.sha256(data_str.encode()).hexdigest()
        return cls(
            signature=f"sha256:{signature}",
            source=source,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "signature": self.signature,
            "source": self.source,
            "timestamp": self.timestamp,
            "algorithm": self.algorithm,
        }


# =============================================================================
# PDF Parser Tool (atr 0.2.0 - with versioning and retry)
# =============================================================================

@atr.register(
    name="pdf_parser",
    version="1.0.0",  # NEW: Tool versioning (ATR-002)
    description="Parse PDF or text documents and extract content",
    cost="low",
    tags=["pdf", "parsing", "document", "text_extraction"],
    side_effects=["read", "filesystem"],
    permissions=["claims-agent"],  # NEW: Access control (ATR-005)
    retry_policy=RetryPolicy(  # NEW: Retry with backoff (ATR-010)
        max_attempts=3,
        backoff=BackoffStrategy.EXPONENTIAL,
        initial_delay=0.5,
    ),
)
def parse_pdf(file_path: str) -> Dict[str, Any]:
    """
    Parse a PDF or text document and extract text content.
    
    Args:
        file_path: Path to the PDF or text file
        
    Returns:
        Dictionary with extracted text, page count, and provenance
    """
    path = Path(file_path)
    
    if not path.exists():
        # Return mock data for demo purposes
        text = _get_mock_pdf_content()
        data = {
            "text": text,
            "pages": 5,
            "filename": path.name,
        }
    elif path.suffix in ['.txt', '.md']:
        # Handle text files (for demo)
        with open(path, 'r', encoding='utf-8') as f:
            text = f.read()
        data = {
            "text": text,
            "pages": 1,
            "filename": path.name,
        }
    else:
        # Attempt real PDF parsing
        try:
            from pypdf import PdfReader
            reader = PdfReader(file_path)
            text = ""
            for page in reader.pages:
                text += page.extract_text() + "\n"
            data = {
                "text": text,
                "pages": len(reader.pages),
                "filename": path.name,
            }
        except ImportError:
            text = _get_mock_pdf_content()
            data = {
                "text": text,
                "pages": 5,
                "filename": path.name,
            }
    
    # Add provenance
    provenance = ProvenanceMetadata.create(data, f"file://{file_path}")
    data["_provenance"] = provenance.to_dict()
    
    return data


def _get_mock_pdf_content() -> str:
    """Return mock PDF content for demo."""
    return """
PROJECT DESIGN DOCUMENT
Voluntary Carbon Standard (VCS)

Project ID: VCS-2024-FOREST-001
Project Name: Amazon Rainforest Conservation Initiative

1. PROJECT DESCRIPTION
This project aims to protect 10,000 hectares of primary rainforest
in the Amazon basin from planned deforestation.

2. GEOSPATIAL BOUNDARIES
Project Polygon Coordinates (WGS84):
[-62.215, -3.465], [-62.180, -3.465], [-62.180, -3.430], [-62.215, -3.430]

3. BASELINE CARBON STOCK
Year: 2024
Forest Type: Tropical Moist Forest
Carbon Stock: 180 tonnes CO2/hectare
NDVI Baseline: 0.82

4. CLAIMED EMISSION REDUCTIONS
Annual avoided deforestation: 500 hectares
Claimed carbon credits: 90,000 tCO2e/year

5. MONITORING METHODOLOGY
Sentinel-2 satellite imagery analysis
Reference Period: 2020-2024
"""


# =============================================================================
# Table Extractor Tool (atr 0.2.0 - with versioning)
# =============================================================================

@atr.register(
    name="table_extractor",
    version="1.0.0",  # NEW: Tool versioning (ATR-002)
    description="Extract structured data from document text",
    cost="low",
    tags=["extraction", "structured_data", "parsing"],
    permissions=["claims-agent"],  # NEW: Access control (ATR-005)
)
def extract_tables(text: str) -> Dict[str, Any]:
    """
    Extract structured data (project ID, coordinates, NDVI, carbon stock) from text.
    
    Args:
        text: The document text to parse
        
    Returns:
        Dictionary with extracted structured data
    """
    data = {
        "project_id": None,
        "polygon": None,
        "year": None,
        "claimed_ndvi": None,
        "carbon_stock": None,
    }

    # Extract Project ID
    project_match = re.search(r'Project ID:\s*(VCS-[\w-]+)', text)
    if project_match:
        data["project_id"] = project_match.group(1)

    # Extract coordinates
    coord_match = re.search(
        r'Polygon Coordinates.*?:\s*(\[[-\d.,\s\[\]]+\])',
        text, re.DOTALL
    )
    if coord_match:
        data["polygon"] = coord_match.group(1)

    # Extract year
    year_match = re.search(r'Year:\s*(\d{4})', text)
    if year_match:
        data["year"] = int(year_match.group(1))

    # Extract NDVI
    ndvi_match = re.search(r'NDVI.*?:\s*([\d.]+)', text)
    if ndvi_match:
        data["claimed_ndvi"] = float(ndvi_match.group(1))

    # Extract carbon stock
    carbon_match = re.search(r'Carbon Stock:\s*([\d.]+)', text)
    if carbon_match:
        data["carbon_stock"] = float(carbon_match.group(1))

    # Add provenance
    provenance = ProvenanceMetadata.create(data, "extraction:table_extractor")
    data["_provenance"] = provenance.to_dict()

    return data


# =============================================================================
# Sentinel API Tool (atr 0.2.0 - with rate limiting and retry)
# =============================================================================

@atr.register(
    name="sentinel_api",
    version="1.0.0",  # NEW: Tool versioning (ATR-002)
    description="Fetch Sentinel-2 satellite imagery for a polygon",
    cost="medium",
    tags=["satellite", "imagery", "sentinel", "remote_sensing"],
    side_effects=["network"],
    permissions=["geo-agent"],  # NEW: Access control (ATR-005)
    rate_limit="10/minute",  # NEW: Rate limiting (ATR-006)
    retry_policy=RetryPolicy(  # NEW: Retry with backoff (ATR-010)
        max_attempts=3,
        backoff=BackoffStrategy.EXPONENTIAL,
        initial_delay=1.0,
    ),
    # Health check for Copernicus API (ATR-008)
    health_check=CallableHealthCheck(
        func=lambda: True,  # Mock - in production: ping copernicus.eu
        name="copernicus_api",
    ),
)
def fetch_sentinel_data(
    polygon: str,
    start_date: str,
    end_date: str
) -> Dict[str, Any]:
    """
    Fetch Sentinel-2 satellite imagery for a polygon and date range.
    
    Args:
        polygon: GeoJSON polygon coordinates as string
        start_date: Start date (YYYY-MM-DD)
        end_date: End date (YYYY-MM-DD)
        
    Returns:
        Dictionary with imagery metadata and band data
    """
    # Mock satellite data fetch
    # In production: connect to Copernicus, download tiles
    data = {
        "product_type": "S2MSI2A",
        "tile_id": "T20MQA",
        "acquisition_date": "2024-06-15",
        "cloud_cover_percentage": 8.5,
        "bands": {
            "B04_RED": "mock_red_band_data",
            "B08_NIR": "mock_nir_band_data",
        },
        "spatial_resolution": 10,  # meters
        "crs": "EPSG:32720",
    }

    provenance = ProvenanceMetadata.create(data, "copernicus.eu/sentinel-2")
    data["_provenance"] = provenance.to_dict()

    return data


# =============================================================================
# NDVI Calculator Tool (atr 0.2.0 - with versioning)
# =============================================================================

@atr.register(
    name="ndvi_calculator",
    version="1.0.0",  # NEW: Tool versioning (ATR-002)
    description="Calculate NDVI vegetation index from satellite bands",
    cost="low",
    tags=["vegetation", "ndvi", "remote_sensing", "analysis"],
    permissions=["geo-agent"],  # NEW: Access control (ATR-005)
)
def calculate_ndvi(
    red_band: str,
    nir_band: str,
    simulate_deforestation: bool = False
) -> Dict[str, Any]:
    """
    Calculate NDVI (Normalized Difference Vegetation Index) from satellite bands.
    
    NDVI = (NIR - RED) / (NIR + RED)
    
    Values range from -1 to 1:
    - Dense vegetation: 0.6 to 0.9
    - Sparse vegetation: 0.2 to 0.5
    - Bare soil/rock: -0.1 to 0.1
    
    Args:
        red_band: Red band data (B04) - mock identifier
        nir_band: NIR band data (B08) - mock identifier
        simulate_deforestation: If True, return low NDVI values (fraud scenario)
        
    Returns:
        Dictionary with NDVI statistics
    """
    if simulate_deforestation:
        # Simulate deforestation scenario (fraud case)
        np.random.seed(42)
        ndvi_values = np.random.uniform(0.15, 0.55, size=(100, 100))
        ndvi_values[20:60, 30:70] = np.random.uniform(0.05, 0.25, size=(40, 40))
    else:
        # Simulate healthy forest
        np.random.seed(42)
        ndvi_values = np.random.uniform(0.65, 0.88, size=(100, 100))

    data = {
        "ndvi_mean": float(np.mean(ndvi_values)),
        "ndvi_std": float(np.std(ndvi_values)),
        "ndvi_min": float(np.min(ndvi_values)),
        "ndvi_max": float(np.max(ndvi_values)),
        "pixel_count": int(ndvi_values.size),
        "vegetation_coverage": float(np.mean(ndvi_values > 0.4)),
        "deforestation_indicator": float(np.mean(ndvi_values < 0.3)),
    }

    provenance = ProvenanceMetadata.create(data, "calculation:ndvi_calculator")
    data["_provenance"] = provenance.to_dict()

    return data


# =============================================================================
# Tool Discovery Helpers
# =============================================================================

def get_claims_tools() -> list:
    """Get tools for the claims agent."""
    return ["pdf_parser", "table_extractor"]


def get_geo_tools() -> list:
    """Get tools for the geo agent."""
    return ["sentinel_api", "ndvi_calculator"]
