#!/usr/bin/env python3
"""
NVD CVE Downloader Script - AI generated
Downloads all CVEs from the National Vulnerability Database (NVD) API
and saves them to a CSV file with CVE ID, description, and CVSS scores.
Uses the nvdlib package for simplified API interaction.
"""

import nvdlib
import requests
import csv
import time
from typing import Dict, Optional
import argparse
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('nvd_download.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class NVDDownloader:
    """Class to handle downloading CVE data from NVD API using direct API calls with pagination"""
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize the NVD downloader
        
        Args:
            api_key: Optional NVD API key for higher rate limits
        """
        self.api_key = api_key
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
        # Rate limiting parameters - nvdlib handles this internally but we still add delays
        self.rate_limit_delay = 6.0 if not api_key else 0.6  # seconds between requests
        self.results_per_page = 2000  # Maximum allowed by NVD API
    
    def fetch_cves_page(self, start_index: int = 0) -> Dict:
        """
        Fetch a page of CVEs directly from NVD API using resultsPerPage and startIndex
        
        Args:
            start_index: Starting index for pagination
            
        Returns:
            API response as dictionary
        """
        headers = {}
        if self.api_key:
            headers['apiKey'] = self.api_key
        
        params = {
            'resultsPerPage': self.results_per_page,
            'startIndex': start_index
        }
        
        try:
            response = requests.get(
                self.base_url,
                headers=headers,
                params=params,
                timeout=60
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"API request failed: {e}")
            raise
    
    def parse_cve_from_api(self, vuln_data: Dict) -> Dict[str, str]:
        """
        Parse CVE data from raw API response
        
        Args:
            vuln_data: Vulnerability data from API response
            
        Returns:
            Dictionary with processed CVE information
        """
        cve = vuln_data.get('cve', {})
        
        # Extract CVE ID
        cve_id = cve.get('id', '')
        
        # Extract description
        descriptions = cve.get('descriptions', [])
        description = ''
        for desc in descriptions:
            if desc.get('lang') == 'en':
                description = desc.get('value', '').replace('\n', ' ').replace('\r', ' ')
                break
        if not description and descriptions:
            description = descriptions[0].get('value', '').replace('\n', ' ').replace('\r', ' ')
        
        # Extract CVSS scores
        metrics = cve.get('metrics', {})
        cvss_v2 = ''
        cvss_v3 = ''
        cvss_v4 = ''
        
        # CVSS v2
        if 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
            try:
                cvss_v2 = str(metrics['cvssMetricV2'][0]['cvssData']['baseScore'])
            except (KeyError, IndexError):
                pass
        
        # CVSS v3.x
        if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
            try:
                cvss_v3 = str(metrics['cvssMetricV31'][0]['cvssData']['baseScore'])
            except (KeyError, IndexError):
                pass
        elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
            try:
                cvss_v3 = str(metrics['cvssMetricV30'][0]['cvssData']['baseScore'])
            except (KeyError, IndexError):
                pass
        
        # CVSS v4.0
        if 'cvssMetricV40' in metrics and metrics['cvssMetricV40']:
            try:
                cvss_v4 = str(metrics['cvssMetricV40'][0]['cvssData']['baseScore'])
            except (KeyError, IndexError):
                pass
        
        return {
            'cve': cve_id,
            'description': description,
            'cvss_v2': cvss_v2,
            'cvss_v3': cvss_v3,
            'cvss_v4': cvss_v4
        }
        
    def get_cvss_scores(self, cve) -> Dict[str, str]:
        """
        Extract CVSS scores from CVE object
        
        Args:
            cve: CVE object from nvdlib
            
        Returns:
            Dictionary with CVSS v2, v3, and v4 scores
        """
        cvss_scores = {
            'cvss_v2': '',
            'cvss_v3': '',
            'cvss_v4': ''
        }
        
        # CVSS v2
        if hasattr(cve, 'v2score') and cve.v2score:
            cvss_scores['cvss_v2'] = str(cve.v2score)
            
        # CVSS v3 (v3.0 or v3.1)
        if hasattr(cve, 'v31score') and cve.v31score:
            cvss_scores['cvss_v3'] = str(cve.v31score)
        elif hasattr(cve, 'v3score') and cve.v3score:
            cvss_scores['cvss_v3'] = str(cve.v3score)
            
        # CVSS v4 (if available)
        if hasattr(cve, 'v4score') and cve.v4score:
            cvss_scores['cvss_v4'] = str(cve.v4score)
                
        return cvss_scores
    
    def process_cve(self, cve) -> Dict[str, str]:
        """
        Process a single CVE object and extract required fields
        
        Args:
            cve: CVE object from nvdlib
            
        Returns:
            Dictionary with processed CVE information
        """
        # Extract CVE ID
        cve_id = getattr(cve, 'id', '')
        
        # Extract description - nvdlib provides this as a list of dict-like objects
        description = ''
        if hasattr(cve, 'descriptions') and cve.descriptions:
            # Find English description
            for desc in cve.descriptions:
                # desc is a dict-like object from nvdlib
                if isinstance(desc, dict) and desc.get('lang') == 'en':
                    description = desc.get('value', '').replace('\n', ' ').replace('\r', ' ')
                    break
                # Handle if it's an object with attributes
                elif hasattr(desc, 'lang') and hasattr(desc, 'value'):
                    if getattr(desc, 'lang', '') == 'en':
                        description = getattr(desc, 'value', '').replace('\n', ' ').replace('\r', ' ')
                        break
            
            # Fallback to first description
            if not description and cve.descriptions:
                first_desc = cve.descriptions[0]
                if isinstance(first_desc, dict):
                    description = first_desc.get('value', '').replace('\n', ' ').replace('\r', ' ')
                else:
                    description = str(first_desc).replace('\n', ' ').replace('\r', ' ')
        
        # Extract CVSS scores
        cvss_scores = self.get_cvss_scores(cve)
        
        return {
            'cve': cve_id,
            'description': description,
            'cvss_v2': cvss_scores['cvss_v2'],
            'cvss_v3': cvss_scores['cvss_v3'],
            'cvss_v4': cvss_scores['cvss_v4']
        }
    
    def download_all_cves(self, output_file: str = 'nvd_cves.csv') -> None:
        """
        Download all CVEs from NVD and save to CSV file
        Uses direct API calls with resultsPerPage and startIndex for proper pagination
        
        Args:
            output_file: Path to output CSV file
        """
        logger.info("Starting NVD CVE download using direct API with pagination...")
        logger.info(f"Rate limit: {self.rate_limit_delay} seconds between requests")
        logger.info(f"Results per page: {self.results_per_page}")
        
        # CSV headers
        headers = ['CVE', 'Description', 'CVSS v2', 'CVSS v3', 'CVSS v4']
        
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(headers)
            
            processed_count = 0
            start_index = 0
            total_results = None
            
            while True:
                try:
                    logger.info(f"Fetching CVEs from index {start_index}...")
                    
                    # Fetch page from API
                    response_data = self.fetch_cves_page(start_index)
                    
                    # Get total results on first request
                    if total_results is None:
                        total_results = response_data.get('totalResults', 0)
                        logger.info(f"Total CVEs in database: {total_results:,}")
                    
                    # Get vulnerabilities from response
                    vulnerabilities = response_data.get('vulnerabilities', [])
                    
                    if not vulnerabilities:
                        logger.info("No more CVEs to process")
                        break
                    
                    logger.info(f"Processing {len(vulnerabilities)} CVEs from this page...")
                    
                    # Process each CVE in this page
                    for vuln in vulnerabilities:
                        try:
                            cve_info = self.parse_cve_from_api(vuln)
                            writer.writerow([
                                cve_info['cve'],
                                cve_info['description'],
                                cve_info['cvss_v2'],
                                cve_info['cvss_v3'],
                                cve_info['cvss_v4']
                            ])
                            processed_count += 1
                            
                        except Exception as e:
                            cve_id = vuln.get('cve', {}).get('id', 'unknown')
                            logger.warning(f"Error processing CVE {cve_id}: {e}")
                            continue
                    
                    logger.info(f"Progress: {processed_count:,}/{total_results:,} CVEs ({100*processed_count/total_results:.1f}%)")
                    csvfile.flush()  # Flush to disk after each page
                    
                    # Check if we've processed all results
                    if start_index + len(vulnerabilities) >= total_results:
                        logger.info("Reached end of CVE database")
                        break
                    
                    # Move to next page
                    start_index += len(vulnerabilities)
                    
                    # Rate limiting - sleep between requests
                    logger.info(f"Rate limiting: waiting {self.rate_limit_delay} seconds...")
                    time.sleep(self.rate_limit_delay)
                    
                except KeyboardInterrupt:
                    logger.info(f"Download interrupted by user. Processed {processed_count:,} CVEs so far.")
                    raise
                except Exception as e:
                    logger.error(f"Error downloading page at index {start_index}: {e}")
                    logger.info("Retrying in 30 seconds...")
                    time.sleep(30)
                    continue
        
        logger.info(f"Download complete! Processed {processed_count:,} CVEs")
        logger.info(f"Results saved to: {output_file}")

    def download_sample_cves(self, num_cves: int = 100, output_file: str = 'sample_cves.csv') -> None:
        """
        Download a sample of CVEs for testing
        
        Args:
            num_cves: Number of CVEs to download
            output_file: Path to output CSV file
        """
        logger.info(f"Downloading sample of {num_cves} CVEs using nvdlib...")
        
        # CSV headers
        headers = ['CVE', 'Description', 'CVSS v2', 'CVSS v3', 'CVSS v4']
        
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(headers)
            
            try:
                # Use nvdlib to get sample CVEs
                if self.api_key:
                    cves = nvdlib.searchCVE(
                        limit=num_cves,
                        key=self.api_key
                    )
                else:
                    cves = nvdlib.searchCVE(
                        limit=num_cves
                    )
                
                logger.info(f"Retrieved {len(cves)} CVEs from NVD API")
                
                processed_count = 0
                for cve in cves:
                    try:
                        cve_info = self.process_cve(cve)
                        writer.writerow([
                            cve_info['cve'],
                            cve_info['description'],
                            cve_info['cvss_v2'],
                            cve_info['cvss_v3'],
                            cve_info['cvss_v4']
                        ])
                        processed_count += 1
                        
                    except Exception as e:
                        logger.warning(f"Error processing CVE {getattr(cve, 'id', 'unknown')}: {e}")
                        continue
                
                logger.info(f"Successfully downloaded {processed_count} CVEs to {output_file}")
                
            except Exception as e:
                logger.error(f"Error downloading sample CVEs: {e}")
                raise

def main():
    """Main function to run the CVE downloader"""
    parser = argparse.ArgumentParser(description='Download all CVEs from NVD API using nvdlib')
    parser.add_argument(
        '--api-key',
        help='NVD API key for higher rate limits (optional)',
        default=None
    )
    parser.add_argument(
        '--output',
        help='Output CSV file path',
        default='nvd_cves.csv'
    )
    parser.add_argument(
        '--sample',
        type=int,
        help='Download only a sample of N CVEs for testing',
        default=None
    )
    
    args = parser.parse_args()
    
    # Create downloader instance
    downloader = NVDDownloader(api_key=args.api_key)
    
    try:
        if args.sample:
            # Download sample
            downloader.download_sample_cves(num_cves=args.sample, output_file=args.output)
        else:
            # Download all CVEs
            downloader.download_all_cves(output_file=args.output)
        
    except KeyboardInterrupt:
        logger.info("Download interrupted by user")
    except Exception as e:
        logger.error(f"Download failed: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())