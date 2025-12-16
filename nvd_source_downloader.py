#!/usr/bin/env python3
"""
NVD Sources Downloader
Fetches all vulnerability sources from the NVD source API v2 and organizes them by source name.
"""

import requests
import json
import logging
import time
from typing import Dict, List

logger = logging.getLogger(__name__)

def fetch_nvd_sources() -> Dict[str, List[str]]:
    """
    Fetch sources from NVD source API v2.
            
    Returns:
        Dictionary with source names as keys and sourceIdentifier lists as values
    """
    
    start_time = time.perf_counter()
    
    base_url = "https://services.nvd.nist.gov/rest/json/source/2.0"
    
    headers = {}
    
    try:
        logger.info('Starting source download through NVD Source API...')
        response = requests.get(
            url=base_url,
            headers=headers,
            timeout=60
        )
        response.raise_for_status()
        data = response.json()
        
        # Organize sources by name
        sources_dict: Dict[str, List[str]] = {}
        
        sources = data.get('sources', [])
        for source in sources:
            source_name = source.get('name', 'Unknown')
            source_identifiers = source.get('sourceIdentifiers', '')
            
            if source_identifiers:
                for source_id in source_identifiers:
                    if source_name not in sources_dict:
                        sources_dict[source_name] = []
                    sources_dict[source_name].append(source_id)
        
        logger.info (f'Finished downloading and parsing {len(sources)} sources in {time.perf_counter() - start_time:.2f}s')
        return sources_dict
    
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching sources: {e}")
        return {}

def main():
    logger = logging.getLogger(__name__)    
    sources = fetch_nvd_sources(logger)
    
    if sources:
        logger.info("NVD Sources by Name:")
        logger.info(json.dumps(sources, indent=2))     

if __name__ == "__main__":
    main()