# Satellite Data README
#
# This directory contains satellite imagery data for carbon auditing.
# 
# IMPORTANT: Due to file size, actual satellite imagery is not included in the repo.
# The demo uses synthetic data that models real Sentinel-2 patterns.

## Data Sources for Real Deployment

### Option 1: Copernicus Data Space (Recommended)
Free registration: https://dataspace.copernicus.eu/

```python
from sentinelhub import SentinelHubRequest, DataCollection, MimeType

# Example: Fetch Sentinel-2 NDVI for a project area
request = SentinelHubRequest(
    data_collection=DataCollection.SENTINEL2_L2A,
    input_data=[{
        "dataFilter": {
            "timeRange": {"from": "2024-01-01", "to": "2024-12-31"},
            "mosaickingOrder": "leastCC"
        }
    }],
    responses=[SentinelHubRequest.output_response("ndvi", MimeType.TIFF)],
    bbox=BBox(bbox=[lon_min, lat_min, lon_max, lat_max], crs=CRS.WGS84),
    size=(512, 512)
)
```

### Option 2: Google Earth Engine
Requires Google Cloud account: https://earthengine.google.com/

```python
import ee
ee.Initialize()

# Fetch Sentinel-2 NDVI
collection = ee.ImageCollection('COPERNICUS/S2_SR') \
    .filterBounds(ee.Geometry.Point([lon, lat])) \
    .filterDate('2024-01-01', '2024-12-31')

ndvi = collection.map(lambda img: img.normalizedDifference(['B8', 'B4']))
```

### Option 3: AWS Open Data (Landsat)
No registration needed: https://registry.opendata.aws/usgs-landsat/

## Synthetic Data for Demo

The `synthetic/` subdirectory contains generated data that mimics real satellite patterns:

- NDVI values based on actual regional averages
- Seasonal variation patterns
- Deforestation signatures

This allows the demo to run without API keys while demonstrating the verification workflow.

## File Structure for Real Data

```
satellite/
├── sentinel-2/
│   └── {project_id}/
│       ├── baseline_{date}.tif     # NDVI at baseline period
│       └── current_{date}.tif      # NDVI at verification date
└── synthetic/
    └── {project_id}_ndvi.json      # Synthetic NDVI values
```
