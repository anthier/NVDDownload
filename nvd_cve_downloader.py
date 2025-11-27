#!/usr/bin/env python3
"""
NVD CVE Downloader Script
Downloads all CVEs from the National Vulnerability Database (NVD) API
and saves them to a CSV file with CVE ID, description, CVSS v2/v3/v4 vector strings and scores, and CISA required actions.
"""

import requests
import csv
import time
from typing import Dict, Optional
import argparse
from argparse import RawTextHelpFormatter
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('nvd_cve_downloader.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# List of all columns supported by NVD API, and strings representing their exact JSON paths
# Note: JSON paths always end with the key name
supported_columns = {
    # Top level (CVE)
    'id': 'id',
    'sourceId': 'cve.sourceIdentifier',
    'vulnStatus': 'cve.vulnStatus',
    'published': 'cve.published',
    'lastModified': 'cve.lastModified',
    'evaluatorComment': 'cve.evaluatorComment',
    'evaluatorSolution': 'cve.evaluatorSolution',
    'evaluatorImpact': 'cve.evaluatorImpact',
    'cisaExploitAdd': 'cve.cisaExploitAdd',
    'cisaActionDue': 'cve.cisaActionDue',
    'cisaRequiredAction': 'cve.cisaRequiredAction',
    'cisaVulnerabilityName': 'cve.cisaVulnerabilityName',    
    'tags': 'cve.cveTags', 
    'description': 'cve.descriptions["en"]', # english description only, from "descriptions" node
    'references': 'cve.references', # puts all formatted references in one cell
    # -CVE Metrics
    # --CVSS v2
    'v2Source': 'cve.cvssMetricV2.source',
    'v2BaseSeverity': 'cve.cvssMetricV2.baseSeverity',
    'v2ExploitabilityScore': 'cve.cvssMetricV2.exploitabilityScore',
    'v2Impact': 'cve.cvssMetricV2.impactScore',
    'v2acInsufInfo': 'cve.cvssMetricV2.acInsufInfo',
    'v2ObtainAllPrivilege': 'cve.cvssMetricV2.obtainAllPrivilege',
    'v2ObtainUserPrivilege': 'cve.cvssMetricV2.obtainUserPrivilege',
    'v2ObtainOtherPrivilege': 'cve.cvssMetricV2.obtainOtherPrivilege',
    'v2UserInteractionRequired': 'cve.cvssMetricV2.userInteractionRequired',
    'v2VectorString': 'cve.cvssMetricV2.cvssData.vectorString',
    'v2AccessVector': 'cve.cvssMetricV2.cvssData.accessVector',
    'v2AccessComplexity': 'cve.cvssMetricV2.cvssData.accessComplexity',
    'v2Authentication': 'cve.cvssMetricV2.cvssData.authentication',
    'v2ConfidentialityImpact': 'cve.cvssMetricV2.cvssData.confidentialityImpact',
    'v2IntegrityImpact': 'cve.cvssMetricV2.cvssData.integrityImpact',
    'v2AvailabilityImpact': 'cve.cvssMetricV2.cvssData.availabilityImpact',
    'v2BaseScore': 'cve.cvssMetricV2.cvssData.baseScore',
    'v2Exploitability': 'cve.cvssMetricV2.cvssData.exploitability',
    'v2RemediationLevel': 'cve.cvssMetricV2.cvssData.remediationLevel',
    'v2ReportConfidence': 'cve.cvssMetricV2.cvssData.reportConfidence',
    'v2TemporalScore': 'cve.cvssMetricV2.cvssData.temporalScore',
    'v2CollateralDamagePotential': 'cve.cvssMetricV2.cvssData.collateralDamagePotential',
    'v2TargetDistribution': 'cve.cvssMetricV2.cvssData.targetDistribution',
    'v2ConfidentialityRequirement': 'cve.cvssMetricV2.cvssData.confidentialityRequirement',
    'v2IntegrityRequirement': 'cve.cvssMetricV2.cvssData.integrityRequirement',
    'v2AvailabilityRequirement': 'cve.cvssMetricV2.cvssData.availabilityRequirement',
    'v2EnvironmentalScore': 'cve.cvssMetricV2.cvssData.environmentalScore',
    # --CVSS v3.x
    'v3Source': 'cve.cvssMetricV3x.source',
    'v3ExploitabilityScore': 'cve.cvssMetricV3x.exploitabilityScore',
    'v3ImpactScore': 'cve.cvssMetricV3x.impactScore',
    'v3VectorString': 'cve.cvssMetricV3x.cvssData.vectorString',
    'v3AttackVector': 'cve.cvssMetricV3x.cvssData.attackVector',
    'v3AttackComplexity': 'cve.cvssMetricV3x.cvssData.attackComplexity',
    'v3PrivilegesRequired': 'cve.cvssMetricV3x.cvssData.privilegesRequired',
    'v3UserInteraction': 'cve.cvssMetricV3x.cvssData.userInteraction',
    'v3Scope': 'cve.cvssMetricV3x.cvssData.scope',
    'v3ConfidentialityImpact': 'cve.cvssMetricV3x.cvssData.confidentialityImpact',
    'v3IntegrityImpact': 'cve.cvssMetricV3x.cvssData.integrityImpact',
    'v3AvailabilityImpact': 'cve.cvssMetricV3x.cvssData.availabilityImpact',
    'v3BaseScore': 'cve.cvssMetricV3x.cvssData.baseScore',
    'v3BaseSeverity': 'cve.cvssMetricV3x.cvssData.baseSeverity',
    'v3ExploitCodeMaturity': 'cve.cvssMetricV3x.cvssData.exploitCodeMaturity',
    'v3RemediationLevel': 'cve.cvssMetricV3x.cvssData.remediationLevel',
    'v3ReportConfidence': 'cve.cvssMetricV3x.cvssData.reportConfidence',
    'v3TemporalScore': 'cve.cvssMetricV3x.cvssData.temporalScore',
    'v3TemporalSeverity': 'cve.cvssMetricV3x.cvssData.temporalSeverity',
    'v3ConfidentialityRequirement': 'cve.cvssMetricV3x.cvssData.confidentialityRequirement',
    'v3IntegrityRequirement': 'cve.cvssMetricV3x.cvssData.integrityRequirement',
    'v3AvailabilityRequirement': 'cve.cvssMetricV3x.cvssData.availabilityRequirement',
    'v3ModifiedAttackVector': 'cve.cvssMetricV3x.cvssData.modifiedAttackVector',
    'v3ModifiedAttackComplexity': 'cve.cvssMetricV3x.cvssData.modifiedAttackComplexity',
    'v3ModifiedPrivilegesRequired': 'cve.cvssMetricV3x.cvssData.modifiedPrivilegesRequired',
    'v3ModifiedUserInteraction': 'cve.cvssMetricV3x.cvssData.modifiedUserInteraction',
    'v3ModifiedScope': 'cve.cvssMetricV3x.cvssData.modifiedScope',
    'v3ModifiedConfidentialityImpact': 'cve.cvssMetricV3x.cvssData.modifiedConfidentialityImpact',
    'v3ModifiedIntegrityImpact': 'cve.cvssMetricV3x.cvssData.modifiedIntegrityImpact',
    'v3ModifiedAvailabilityImpact': 'cve.cvssMetricV3x.cvssData.modifiedAvailabilityImpact',
    'v3EnvironmentalScore': 'cve.cvssMetricV3x.cvssData.environmentalScore',
    'v3EnvironmentalSeverity': 'cve.cvssMetricV3x.cvssData.environmentalSeverity',
    # --CVSS v4
    'v4Source': 'cve.cvssMetricV40.source',
    'v4VectorString': 'cve.cvssMetricV40.cvssData.vectorString',
    'v4AttackVector': 'cve.cvssMetricV40.cvssData.attackVector',
    'v4AttackComplexity': 'cve.cvssMetricV40.cvssData.attackComplexity',
    'v4AttackRequirements': 'cve.cvssMetricV40.cvssData.attackRequirements',
    'v4PrivilegesRequired': 'cve.cvssMetricV40.cvssData.privilegesRequired',
    'v4UserInteraction': 'cve.cvssMetricV40.cvssData.userInteraction',
    'v4VulnConfidentialityImpact': 'cve.cvssMetricV40.cvssData.vulnConfidentialityImpact',
    'v4VulnIntegrityImpact': 'cve.cvssMetricV40.cvssData.vulnIntegrityImpact',
    'v4VulnAvailabilityImpact': 'cve.cvssMetricV40.cvssData.vulnAvailabilityImpact',
    'v4SubConfidentialityImpact': 'cve.cvssMetricV40.cvssData.subConfidentialityImpact',
    'v4SubIntegrityImpact': 'cve.cvssMetricV40.cvssData.subIntegrityImpact',
    'v4SubAvailabilityImpact': 'cve.cvssMetricV40.cvssData.subAvailabilityImpact',
    'v4ExploitMaturity': 'cve.cvssMetricV40.cvssData.exploitMaturity',
    'v4ConfidentialityRequirement': 'cve.cvssMetricV40.cvssData.confidentialityRequirement',
    'v4IntegrityRequirement': 'cve.cvssMetricV40.cvssData.integrityRequirement',
    'v4AvailabilityRequirement': 'cve.cvssMetricV40.cvssData.availabilityRequirement',
    'v4ModifiedAttackVector': 'cve.cvssMetricV40.cvssData.modifiedAttackVector',
    'v4ModifiedAttackComplexity': 'cve.cvssMetricV40.cvssData.modifiedAttackComplexity',
    'v4ModifiedAttackRequirements': 'cve.cvssMetricV40.cvssData.modifiedAttackRequirements',
    'v4ModifiedPrivilegesRequired': 'cve.cvssMetricV40.cvssData.modifiedPrivilegesRequired',
    'v4ModifiedUserInteraction': 'cve.cvssMetricV40.cvssData.modifiedUserInteraction',
    'v4ModifiedVulnConfidentialityImpact': 'cve.cvssMetricV40.cvssData.modifiedVulnConfidentialityImpact',
    'v4ModifiedVulnIntegrityImpact': 'cve.cvssMetricV40.cvssData.modifiedVulnIntegrityImpact',
    'v4ModifiedVulnAvailabilityImpact': 'cve.cvssMetricV40.cvssData.modifiedVulnAvailabilityImpact',
    'v4ModifiedSubConfidentialityImpact': 'cve.cvssMetricV40.cvssData.modifiedSubConfidentialityImpact',
    'v4ModifiedSubIntegrityImpact': 'cve.cvssMetricV40.cvssData.modifiedSubIntegrityImpact',
    'v4ModifiedSubAvailabilityImpact': 'cve.cvssMetricV40.cvssData.modifiedSubAvailabilityImpact',
    'v4Safety': 'cve.cvssMetricV40.cvssData.Safety',
    'v4Automatable': 'cve.cvssMetricV40.cvssData.Automatable',
    'v4Recovery': 'cve.cvssMetricV40.cvssData.Recovery',
    'v4ValueDensity': 'cve.cvssMetricV40.cvssData.valueDensity',
    'v4VulnResponseEffort': 'cve.cvssMetricV40.cvssData.vulnerabilityResponseEffort',
    'v4ProviderUrgency': 'cve.cvssMetricV40.cvssData.providerUrgency'
    # TODO: add CWEs and configs
}


class NVDDownloader:
    def __init__(self, api_key: Optional[str] = None, columns: list[str] = None):
        """
        Args:
            api_key: Optional NVD API key for higher rate limits
        """
        self.api_key = api_key
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
        # Rate limiting parameters (set based on NVD API docs)
        self.rate_limit_delay = 6.0 if not api_key else 1.0
        self.results_per_page = 2000  
    
    def fetch_cve_page(self, start_index: int = 0) -> Dict:
        """
        Fetch a page of CVEs from start_index, with a number of rows equal to results_per_page
        Note: Max results_per_page may be limited by NVD API.
        
        Args:
            start_index: Index of first CVE to be grabbed (in NVD's order). This is not a CVE number.
            
        Returns:
            API response as dict
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
                url=self.base_url,
                headers=headers,
                params=params,
                timeout=60
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"API request failed: {e}")
            raise
    
    def parse_cve(self, vuln_data: Dict) -> Dict[str, str]:
        """
        Parse CVE data from raw NVD API response
        
        Args:
            vuln_data: Raw data on a single vulnerability (assumes NVD API format)
            
        Returns:
            Dictionary with final CVE data as processed
        """
        cve = vuln_data.get('cve', {})

        # Get CVE ID and description
        cve_id = cve.get('id', '')
        descriptions = cve.get('descriptions', [])
        description = ''
        for desc in descriptions:
            # Always get English if available
            if desc.get('lang') == 'en':
                description = desc.get('value', '').replace('\n', ' ').replace('\r', ' ')
                break       
        # Use first description if we couldn't find English 
        if (not description) and descriptions: 
            description = descriptions[0].get('value', '').replace('\n', ' ').replace('\r', ' ')
        
        # Extract any available metrics
        metrics = cve.get('metrics', {})        
        cvss_v2 = ''
        cvss_v2_vector = ''
        cvss_v3 = ''
        cvss_v3_vector = ''
        cvss_v4 = ''
        cvss_v4_vector = ''
        cisa_required_action = ''
        
        # -- CVSS v2
        if 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
            try:
                cvss_v2 = str(metrics['cvssMetricV2'][0]['cvssData']['baseScore'])
                cvss_v2_vector = str(metrics['cvssMetricV2'][0]['cvssData']['vectorString'])
            except (KeyError, IndexError):
                pass
        
        # -- CVSS v3.1 if present, otherwise V3.0
        if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
            try:
                cvss_v3 = str(metrics['cvssMetricV31'][0]['cvssData']['baseScore'])
                cvss_v3_vector = str(metrics['cvssMetricV31'][0]['cvssData']['vectorString'])
            except (KeyError, IndexError):
                pass
        elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
            try:
                cvss_v3 = str(metrics['cvssMetricV30'][0]['cvssData']['baseScore'])
                cvss_v3_vector = str(metrics['cvssMetricV30'][0]['cvssData']['vectorString'])
            except (KeyError, IndexError):
                pass
        
        # -- CVSS v4.0
        if 'cvssMetricV40' in metrics and metrics['cvssMetricV40']:
            try:
                cvss_v4 = str(metrics['cvssMetricV40'][0]['cvssData']['baseScore'])
                cvss_v4_vector = str(metrics['cvssMetricV40'][0]['cvssData']['vectorString'])
            except (KeyError, IndexError):
                pass
        
        # Extract any available CISA required action
        try:
            cisa_required_action = str(cve.get('cisaRequiredAction', ''))
        except (KeyError, IndexError):
            pass
        
        return {
            'cve': cve_id,
            'description': description,
            'cvss_v2': cvss_v2,
            'cvss_v2_vector': cvss_v2_vector,
            'cvss_v3': cvss_v3,
            'cvss_v3_vector': cvss_v3_vector,
            'cvss_v4': cvss_v4,
            'cvss_v4_vector': cvss_v4_vector,
            'cisa_required_action': cisa_required_action
        }
    
    def download_all_cves(self, output_file: str = 'nvd_cves.csv') -> None:
        """
        Download all CVEs available in the NVD API and save to CSV file
        Uses direct API calls with resultsPerPage and startIndex for pagination
        
        Args:
            output_file: Path to output CSV file
        """
        logger.info("Starting CVE download through NVD API...")
        logger.info(f"Rate limit: {self.rate_limit_delay} seconds between requests")
        logger.info(f"Results per page: {self.results_per_page}")
        
        # CSV headers
        headers = [
            'CVE', 
            'Description', 
            'CVSS v2', 
            'CVSS v2 Vector', 
            'CVSS v3', 
            'CVSS v3 Vector', 
            'CVSS v4', 
            'CVSS v4 Vector', 
            'CISA Required Action']
        
        with open(output_file, 'w', newline='', encoding='utf-8') as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(headers)
            
            processed_count = 0
            start_index = 0
            total_cve_count = None
            
            while True:
                try:                    
                    # Fetch page from API
                    logger.info(f"Fetching CVEs from index {start_index}...")
                    response_data = self.fetch_cve_page(start_index)
                    
                    # Get total results (on first request only)
                    if total_cve_count is None:
                        total_cve_count = response_data.get('totalResults', 0)
                        logger.info(f"Total CVE count reported by NVD API: {total_cve_count:,}")
                    
                    # Get vulnerabilities from response
                    vulnerabilities = response_data.get('vulnerabilities', [])
                    
                    if not vulnerabilities:
                        logger.info("No more CVEs to process")
                        break
                    
                    logger.info(f"Processing {len(vulnerabilities)} CVEs from this page...")
                    
                    # Process each CVE in this page
                    for vuln in vulnerabilities:
                        try:
                            cve_info = self.parse_cve(vuln)
                            writer.writerow([
                                cve_info['cve'],
                                cve_info['description'],
                                cve_info['cvss_v2'],
                                cve_info['cvss_v2_vector'],
                                cve_info['cvss_v3'],
                                cve_info['cvss_v3_vector'],
                                cve_info['cvss_v4'],
                                cve_info['cvss_v4_vector'],
                                cve_info['cisa_required_action'],
                            ])
                            processed_count += 1
                            
                        except Exception as e:
                            cve_id = vuln.get('cve', {}).get('id', 'unknown')
                            logger.warning(f"Error processing CVE {cve_id}: {e}")
                            continue
                    
                    # Log progress
                    logger.info(f"Progress: {processed_count:,}/{total_cve_count:,} CVEs ({100*processed_count/total_cve_count:.1f}%)")

                    # Flush results so far to disk
                    csv_file.flush()  
                    
                    # Break if we've processed all results
                    if start_index + len(vulnerabilities) >= total_cve_count:
                        logger.info("Reached end of CVE database")
                        break
                    
                    # Set index for next page
                    start_index += len(vulnerabilities)
                    
                    # Rate limiting (sleep between requests)
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

def comma_separated_list(arg_string):
    return arg_string.split(',')

def main():
    # Configure and parse arguments    
    parser = argparse.ArgumentParser(
        description='Download all CVEs from NVD API \n\n' \
            'Notes:\n' \
            '- Only outputs English description when available\n' 
            '- Only outputs the CVSS data from primary source\n' 
            '- Only outputs one CVSS v3.x score, v3.1 if available\n'
            '- Fields not returned by NVD are left blank (many fields will be blank)',
        formatter_class=RawTextHelpFormatter
    )
    parser.add_argument(
        '--api-key',
        help='NVD API key for higher rate limits (optional)',
        default=None
    )
    parser.add_argument( 
        '--columns',
        type=comma_separated_list,
        help='List of columns to output, in output order. Select from the following: TBD', # TBD
        default=[]
    )
    parser.add_argument(
        '--output',
        help='Output file path',
        default='nvd_cves.csv'
    )      
    
    args = parser.parse_args()
    
    # Download CVEs
    downloader = NVDDownloader(api_key=args.api_key, columns=args.columns)    
    try:        
        downloader.download_all_cves(output_file=args.output)
    except KeyboardInterrupt:
        logger.info("Download interrupted by user")
    except Exception as e:
        logger.error(f"Download failed: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())