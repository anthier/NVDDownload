#!/usr/bin/env python3
"""
NVD CVE Downloader Script
    Downloads all CVEs from the National Vulnerability Database (NVD) API and saves them to a CSV file with 
    CVE ID, description, CVSS v2/v3/v4 vector strings and scores, and CISA required actions.
"""

import requests
import csv
import time
from typing import Dict
import logging
from enum import Enum
import nvd_source_downloader
import uuid

logger = logging.getLogger(__name__)

class LineParse(Enum):
    Space=1
    Preserve=2

# List of all columns supported by NVD API, and strings representing their exact JSON paths
# Note: JSON paths always end with the key name
supported_columns = {
    # Top level (CVE)
    'id': 'cve.id',
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
    'description': 'cve.descriptions.value', # english description only, from "descriptions" node
    'references': 'cve.references', # puts all formatted references in one cell
    'weaknesses': 'cve.weaknesses',
    'configurations': 'cve.configurations',
    'vendorComments': 'cve.vendorComments',
    # -CVE Metrics
    # --CVSS v2
    'v2Source': 'cve.metrics.cvssMetricV2.source',
    'v2BaseSeverity': 'cve.metrics.cvssMetricV2.baseSeverity',
    'v2ExploitabilityScore': 'cve.metrics.cvssMetricV2.exploitabilityScore',
    'v2Impact': 'cve.metrics.cvssMetricV2.impactScore',
    'v2acInsufInfo': 'cve.metrics.cvssMetricV2.acInsufInfo',
    'v2ObtainAllPrivilege': 'cve.metrics.cvssMetricV2.obtainAllPrivilege',
    'v2ObtainUserPrivilege': 'cve.metrics.cvssMetricV2.obtainUserPrivilege',
    'v2ObtainOtherPrivilege': 'cve.metrics.cvssMetricV2.obtainOtherPrivilege',
    'v2UserInteractionRequired': 'cve.metrics.cvssMetricV2.userInteractionRequired',
    'v2VectorString': 'cve.metrics.cvssMetricV2.cvssData.vectorString',
    'v2AccessVector': 'cve.metrics.cvssMetricV2.cvssData.accessVector',
    'v2AccessComplexity': 'cve.metrics.cvssMetricV2.cvssData.accessComplexity',
    'v2Authentication': 'cve.metrics.cvssMetricV2.cvssData.authentication',
    'v2ConfidentialityImpact': 'cve.metrics.cvssMetricV2.cvssData.confidentialityImpact',
    'v2IntegrityImpact': 'cve.metrics.cvssMetricV2.cvssData.integrityImpact',
    'v2AvailabilityImpact': 'cve.metrics.cvssMetricV2.cvssData.availabilityImpact',
    'v2BaseScore': 'cve.metrics.cvssMetricV2.cvssData.baseScore',       
    # --CVSS v3.x
    'v3Source': 'cve.metrics.cvssMetricV3x.source',
    'v3ExploitabilityScore': 'cve.metrics.cvssMetricV3x.exploitabilityScore',
    'v3ImpactScore': 'cve.metrics.cvssMetricV3x.impactScore',
    'v3VectorString': 'cve.metrics.cvssMetricV3x.cvssData.vectorString',
    'v3AttackVector': 'cve.metrics.cvssMetricV3x.cvssData.attackVector',
    'v3AttackComplexity': 'cve.metrics.cvssMetricV3x.cvssData.attackComplexity',
    'v3PrivilegesRequired': 'cve.metrics.cvssMetricV3x.cvssData.privilegesRequired',
    'v3UserInteraction': 'cve.metrics.cvssMetricV3x.cvssData.userInteraction',
    'v3Scope': 'cve.metrics.cvssMetricV3x.cvssData.scope',
    'v3ConfidentialityImpact': 'cve.metrics.cvssMetricV3x.cvssData.confidentialityImpact',
    'v3IntegrityImpact': 'cve.metrics.cvssMetricV3x.cvssData.integrityImpact',
    'v3AvailabilityImpact': 'cve.metrics.cvssMetricV3x.cvssData.availabilityImpact',
    'v3BaseScore': 'cve.metrics.cvssMetricV3x.cvssData.baseScore',
    'v3BaseSeverity': 'cve.metrics.cvssMetricV3x.cvssData.baseSeverity',
    # --CVSS v4
    'v4Source': 'cve.metrics.cvssMetricV40.source',
    'v4VectorString': 'cve.metrics.cvssMetricV40.cvssData.vectorString',
    'v4AttackVector': 'cve.metrics.cvssMetricV40.cvssData.attackVector',
    'v4AttackComplexity': 'cve.metrics.cvssMetricV40.cvssData.attackComplexity',
    'v4AttackRequirements': 'cve.metrics.cvssMetricV40.cvssData.attackRequirements',
    'v4PrivilegesRequired': 'cve.metrics.cvssMetricV40.cvssData.privilegesRequired',
    'v4UserInteraction': 'cve.metrics.cvssMetricV40.cvssData.userInteraction',
    'v4VulnConfidentialityImpact': 'cve.metrics.cvssMetricV40.cvssData.vulnConfidentialityImpact',
    'v4VulnIntegrityImpact': 'cve.metrics.cvssMetricV40.cvssData.vulnIntegrityImpact',
    'v4VulnAvailabilityImpact': 'cve.metrics.cvssMetricV40.cvssData.vulnAvailabilityImpact',
    'v4SubConfidentialityImpact': 'cve.metrics.cvssMetricV40.cvssData.subConfidentialityImpact',
    'v4SubIntegrityImpact': 'cve.metrics.cvssMetricV40.cvssData.subIntegrityImpact',
    'v4SubAvailabilityImpact': 'cve.metrics.cvssMetricV40.cvssData.subAvailabilityImpact',
    'v4ExploitMaturity': 'cve.metrics.cvssMetricV40.cvssData.exploitMaturity',
    'v4ConfidentialityRequirement': 'cve.metrics.cvssMetricV40.cvssData.confidentialityRequirement',
    'v4IntegrityRequirement': 'cve.metrics.cvssMetricV40.cvssData.integrityRequirement',
    'v4AvailabilityRequirement': 'cve.metrics.cvssMetricV40.cvssData.availabilityRequirement',
    'v4ModifiedAttackVector': 'cve.metrics.cvssMetricV40.cvssData.modifiedAttackVector',
    'v4ModifiedAttackComplexity': 'cve.metrics.cvssMetricV40.cvssData.modifiedAttackComplexity',
    'v4ModifiedAttackRequirements': 'cve.metrics.cvssMetricV40.cvssData.modifiedAttackRequirements',
    'v4ModifiedPrivilegesRequired': 'cve.metrics.cvssMetricV40.cvssData.modifiedPrivilegesRequired',
    'v4ModifiedUserInteraction': 'cve.metrics.cvssMetricV40.cvssData.modifiedUserInteraction',
    'v4ModifiedVulnConfidentialityImpact': 'cve.metrics.cvssMetricV40.cvssData.modifiedVulnConfidentialityImpact',
    'v4ModifiedVulnIntegrityImpact': 'cve.metrics.cvssMetricV40.cvssData.modifiedVulnIntegrityImpact',
    'v4ModifiedVulnAvailabilityImpact': 'cve.metrics.cvssMetricV40.cvssData.modifiedVulnAvailabilityImpact',
    'v4ModifiedSubConfidentialityImpact': 'cve.metrics.cvssMetricV40.cvssData.modifiedSubConfidentialityImpact',
    'v4ModifiedSubIntegrityImpact': 'cve.metrics.cvssMetricV40.cvssData.modifiedSubIntegrityImpact',
    'v4ModifiedSubAvailabilityImpact': 'cve.metrics.cvssMetricV40.cvssData.modifiedSubAvailabilityImpact',
    'v4Safety': 'cve.metrics.cvssMetricV40.cvssData.Safety',
    'v4Automatable': 'cve.metrics.cvssMetricV40.cvssData.Automatable',
    'v4Recovery': 'cve.metrics.cvssMetricV40.cvssData.Recovery',
    'v4ValueDensity': 'cve.metrics.cvssMetricV40.cvssData.valueDensity',
    'v4VulnResponseEffort': 'cve.metrics.cvssMetricV40.cvssData.vulnerabilityResponseEffort',
    'v4ProviderUrgency': 'cve.metrics.cvssMetricV40.cvssData.providerUrgency'    
}

formattable_columns = ['weaknesses', 'configurations', 'vendorComments']

class NVDDownloader:
    @property
    def sources(self):
        # Build sources list on first access
        if not self._sources:   
            logger.info('Source info requested. Sources will be downloaded.')    
            self._sources = nvd_source_downloader.fetch_nvd_sources()
            # Replace "NIST" source with "NVD" for clarity and to match NVD website
            if 'NIST' in self._sources:
                self._sources['NVD'] = self._sources.pop('NIST')   
        
        return self._sources
    
    @classmethod
    def validate_inputs(cls, columns: list[str], formatters: list[str], lf_parsing: str) -> bool:
        """
        Validate inputs to class constructor that can be validated, logging errors as appropriate.
        
        Args: see __init__.

        Returns:
            True if validation succeeded.
        """
        for column in columns:
            if not column in supported_columns:
                logger.error(f"Unsupported or invalid column found: {column}")
                return False

        for formatter in formatters:
            if not formatter in formattable_columns:
               logger.error(f"Unsupported or invalid formatter found: {formatter}")
               return False     

        if lf_parsing.lower() == 's' or lf_parsing.lower() == 'space':
            pass
        elif lf_parsing.lower() == 'p' or lf_parsing.lower() == 'preserve':
            pass
        else:
            logger.error(f"Invalid argument for lf_parsing: {lf_parsing}")
            return False
        
        return True
    
    def __init__(self, api_key: str, columns: list[str], formatters: list[str], lf_parsing: str):
        """
        Initialize inputs and internal data, without validation. For validation, first call validate_inputs.

        Args:
            api_key: Optional NVD API key for higher rate limits.
            columns: Columns to be output. Must be in supported_columns (case sensitive).
            formatters: Selected formatters for outputs. Must be in supported_formatters (case sensitive).
            lf_parsing: LF parsing setting in a string format (not case sensitive).
        """        
        self.api_key = api_key
        self.columns = columns
        self.formatters = formatters 

        if lf_parsing.lower() == 's' or lf_parsing.lower() == 'space':
            self.lf_parsing = LineParse.Space
        else:
            self.lf_parsing = LineParse.Preserve

        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self._sources = None
        
        # Rate limiting parameters (set based on NVD API docs)
        self.rate_limit_delay = 6.0 if not api_key else 0.25
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
    
    def parse_line_feeds(self, input: str) -> str:
        match self.lf_parsing:
            case LineParse.Space:
                return input.replace('\n', ' ').replace('\r', ' ')
            case LineParse.Preserve:
                return input
    
    def parse_source(self, input: str) -> str:
        # Replace emails with original names
        if '@' in input:
            for key, value in self.sources.items():
                if input in value:
                    return key
        
        # Replace UUIDs with original names
        try:
            uuid.UUID(input)
            for key, value in self.sources.items():
                if input in value:
                    return key
        except (ValueError, AttributeError, TypeError):
            pass

        return input

    def format_field(self, column_name, field) -> str:
        result = field
        
        match column_name:
            case 'weaknesses':         # TODO: remove commas from sources                       
                if isinstance(field, list):
                    result = ''
                    ignored_values = ['nvd-cwe-other', 'nvd-cwe-noinfo'] # Common values that are not specific weaknesses
                    weaknesses: Dict[str, list[str]] = {}
                    for weakness in field:
                        if 'description' in weakness:
                            for desc in weakness['description']:                                
                                if not str(desc['value']).lower() in ignored_values:
                                    if desc['value'] not in weaknesses:
                                        weaknesses[desc['value']] = []                                    
                                    weaknesses[desc['value']].append(self.parse_source(weakness['source']))
                    if len(weaknesses) > 0:
                        for key, value in weaknesses.items():
                            if isinstance(value, list):                            
                                joined = ", ".join(str(v) for v in value)
                            else:
                                joined = str(value)
                            result = f'{result}\n' if result else ''
                            result = f'{result}{key}: {joined}'                
            
            case 'configurations':     
                if isinstance(field, list):
                    result = ''                    
                    config_number = 1                    
                    for config in field:
                        if 'operator' in config:
                            result += f'Config {config_number} ({config['operator']})\n' # TODO: remove ending line feed
                        else:
                            result += f'Config {config_number}\n'
                        for node in config['nodes']:   
                            if 'operator' in node:
                                result += f'{node['operator']}\n'
                            for cpe in node['cpeMatch']:                            
                                result += f'\t{str(node['negate'])}: {str(cpe['criteria'])}\n'   
                        config_number += 1
            
            case 'vendorComments':       
                if isinstance(field, list):
                    result = ''                    
                    for comment in field:                        
                        result = f'{result}\n' if result else ''
                        result = f'{result}{comment['organization']} {comment['lastModified']}: \'{str(comment['comment']).replace('\'', '')}\''

        return result
        

    def get_field(self, cve, column_name) -> str:   
        # Get the list of column keys from the path string in supported_columns
        if column_name in supported_columns:
            column_keys = supported_columns[column_name].split('.')
        else:
            return ''
        
        # Traverse the cve dict until we've found the value of the last element of column_keys
        current = cve        
        for key in column_keys:
            try:
                # Replace generic v3 metric key with latest version available before evaluating further             
                if key == 'cvssMetricV3x':
                    if isinstance(current, dict) and 'cvssMetricV31' in current:
                        key = 'cvssMetricV31'
                    else:
                        key = 'cvssMetricV30'

                if isinstance(current, dict) and key in current:                    
                    current = current[key]
                    # Look ahead to see if we just landed on a list. We need to choose an element before moving on.
                    if isinstance(current, list) and (len(current) > 0):
                        # special case: keep the whole array when we arrive at a formattable field
                        if column_name in formattable_columns and key == column_name:
                            break

                        # Look for the primary element of the list
                        found = False
                        for element in current:
                            if isinstance(element, dict) and 'type' in element:
                                if element['type'].lower() == 'primary':
                                    current = element
                                    found = True
                                    break
                        # Default to the first element if not found
                        if not found:
                            current = current[0]
                else:
                    return ''
            except:
                pass # TODO: is this appropriate?
        
        if column_name in self.formatters:
            return self.format_field(column_name, current)
        else: # TODO: output unformatted dicts as JSON
            return self.parse_line_feeds(str(current))

    def parse_cve(self, vuln_data: Dict) -> Dict[str, str]:
        """
        Parse CVE data from raw NVD API response
        
        Args:
            vuln_data: Raw data on a single vulnerability (assumes NVD API format)
            
        Returns:
            Dictionary with final CVE data as processed
        """
        result = []
        
        for column in self.columns:
            result.append(self.get_field(vuln_data, column))            

        return result
    
    def download_all_cves(self, output_file: str = 'nvd_cves.csv') -> None:
        """
        Download all CVEs available in the NVD API and save to CSV file
        Uses direct API calls with resultsPerPage and startIndex for pagination
        
        Args:
            output_file: Path to output CSV file
        """        
        try:
        
            start_time = time.perf_counter()

            logger.info("Starting CVE download through NVD API...")
            logger.info(f"Rate limit: {self.rate_limit_delay} seconds between requests")
            logger.info(f"Results per page: {self.results_per_page}")
            
            # CSV headers
            headers = self.columns        
            
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
                                writer.writerow(cve_info)                            
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
                        logger.info(f"Download interrupted by user. Processed {processed_count:,} CVEs in {time.perf_counter() - start_time:.2f}s.")
                        raise
                    except Exception as e:
                        logger.error(f"Error downloading page at index {start_index}: {e}")
                        logger.info("Retrying in 30 seconds...")
                        time.sleep(30)
                        continue
            logger.info(f"Download complete! Processed {processed_count:,} CVEs in {time.perf_counter() - start_time:.2f}s")
            logger.info(f"Results saved to: {output_file}")
        except Exception as e:
            logger.error(f"Download failed: {e}")
            raise