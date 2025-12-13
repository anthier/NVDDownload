# NVD CVE Downloader

A Python script to download all CVEs (Common Vulnerabilities and Exposures) from the National Vulnerability Database (NVD) API and save them to a CSV file.

## Features

- Downloads all available CVEs from the NVD API
- Extracts and optionally formats a customizable list of fields
- Handles rate limiting and pagination automatically
- Supports optional API key for removing rate limits
- Comprehensive error handling and logging
- Progress tracking during download
- Saves results in a CSV format

## Installation

1. Install Python 3.10 or higher
Note: no additional libraries required.

## Usage

### Basic Usage (without API key)
```
python nvddownload
```

This will download all CVEs and save the default fields to `nvd_cves.csv`.

### With NVD API Key
```bash
python nvddownload --api-key YOUR_API_KEY
```

Using an API key removes the 6 second delay between downloads.

### Custom Columns, Formatters, and Output File
```bash
python nvddownload --columns id,sourceId,description,weaknesses --formatters sourceId,weaknesses --output_opts LINE_FEEDS_TO_ESCAPES --output cve_weaknesses.csv
```

All used fields in the NVD API can be chosen for column output, and complex fields as well as source fields can be formatted to improve output readability. Output options determine post-processing on all data.

### Read Arguments From File
```bash
python nvddownload args.txt
```

For easy storage and retrieval of configuration info, arguments can be read from a file instead of the command line. Example argument files are included for common output scenarios.

## Getting an NVD API Key

Visit [NVD API Key Request](https://nvd.nist.gov/developers/request-an-api-key)

## Output Format

The script generates a CSV file with any of the following columns corresponding to the NVD API:

| ID / Column Name | Description | Attributes |
|---|---|---|
|id|CVE ID (e.g., CVE-2023-12345)|Default|
|sourceId|CVE Source ID|Formatter (Replace ID with source name)|
|vulnStatus|CVE Status||
|published|CVE Published Date/Time||
|lastModified|CVE Last Modified Date/Time||
|evaluatorComment|CVE Evaluator Comment||
|evaluatorSolution|CVE Evaluator Solution||
|evaluatorImpact|CVE Evaluator Impact (Notes)||
|cisaExploitAdd|CISA Known Exploited Vulnerabilities Add Date||
|cisaActionDue|CISA Action Due Date||
|cisaRequiredAction|CISA Required Action||
|cisaVulnerabilityName|CISA Vulnerability Name||
|tags|CVE Tags|Formatter (JSON conversion)|
|description|CVE Description|Default|
|references|CVE References|Formatter (JSON conversion)|
|weaknesses|CVE Weaknesses|Formatter (JSON conversion)|
|configurations|CVE Configurations (CPEs)|Formatter (JSON conversion)|
|vendorComments|CVE Vendor Comments|Formatter (JSON conversion)|
|v2Source|CVSS V2 Source|Formatter (Replace ID with source name)|
|v2BaseSeverity|CVSS V2 Base Severity||
|v2ExploitabilityScore|CVSS V2 Exploitability Score||
|v2Impact|CVSS V2 Impact||
|v2acInsufInfo|CVSS V2 acInsufInfo Flag ||
|v2ObtainAllPrivilege|CVSS V2 obtainAllPrivilege Flag||
|v2ObtainUserPrivilege|CVSS V2 obtainUserPrivilege Flag||
|v2ObtainOtherPrivilege|CVSS V2 obtainOtherPrivilege Flag||
|v2UserInteractionRequired|CVSS V2 userInteractionRequired Flag||
|v2VectorString|CVSS V2 Vector String|Default|
|v2AccessVector|CVSS V2 Access Vector (AV)||
|v2AccessComplexity|CVSS V2 Access Complexity (AC)||
|v2Authentication|CVSS V2 Authentication (Au)||
|v2ConfidentialityImpact|CVSS V2 Confidentiality Impact (C)||
|v2IntegrityImpact|CVSS V2 Integrity Impact (I)||
|v2AvailabilityImpact|CVSS V2 Availability Impact (A)||
|v2BaseScore|CVSS V2 Base Score|Default|
|v3Source|CVSS V3.x Source|Formatter (Replace ID with source name)|
|v3ExploitabilityScore|CVSS V3.x Exploitability Score||
|v3ImpactScore|CVSS V3.x Impact Score||
|v3VectorString|CVSS V3.x Vector String|Default|
|v3AttackVector|CVSS V3.x Attack Vector (AV)||
|v3AttackComplexity|CVSS V3.x Attack Complexity (AC)||
|v3PrivilegesRequired|CVSS V3.x Privileges Required (PR)||
|v3UserInteraction|CVSS V3.x User Interaction (UI)||
|v3Scope|CVSS V3.x Scope (S)||
|v3ConfidentialityImpact|CVSS V3.x Confidentiality Impact (C)||
|v3IntegrityImpact|CVSS V3.x Integrity Impact (I)||
|v3AvailabilityImpact|CVSS V3.x Availability Impact (A)||
|v3BaseScore|CVSS V3.x Base Score|Default|
|v3BaseSeverity|CVSS V3.x Base Severity||
|v4Source|CVSS V4.0 Source|Formatter (Replace ID with source name)|
|v4VectorString|CVSS V4.0 Vector String|Default|
|v4BaseScore|CVSS V4.0 Base Score|Default|
|v4BaseSeverity|CVSS V4.0 Base Severity||
|v4AttackVector|CVSS V4.0 Attack Vector (AV)||
|v4AttackComplexity|CVSS V4.0 Attack Complexity (AC)||
|v4AttackRequirements|CVSS V4.0 Attack Requirements (AT)||
|v4PrivilegesRequired|CVSS V4.0 Privileges Required (PR)||
|v4UserInteraction|CVSS V4.0 User Interaction (UI)||
|v4VulnConfidentialityImpact|CVSS V4.0 Vulnerable System Confidentiality Impact (VC)||
|v4VulnIntegrityImpact|CVSS V4.0 Vulnerable System Integrity Impact (VI) ||
|v4VulnAvailabilityImpact|CVSS V4.0 Vulnerable System Availability Impact (VA)||
|v4SubConfidentialityImpact|CVSS V4.0 Subsequent System Confidentiality Impact (SC)||
|v4SubIntegrityImpact|CVSS V4.0 Subsequent System Integrity Impact (SI)||
|v4SubAvailabilityImpact|CVSS V4.0 Subsequent System Availability Impact (SA)||
|v4ExploitMaturity|CVSS V4.0 Exploit Maturity (E)||
|v4ConfidentialityRequirement|CVSS V4.0 Confidentiality Requirements (CR)||
|v4IntegrityRequirement|CVSS V4.0 Integrity Requirements (IR) ||
|v4AvailabilityRequirement|CVSS V4.0 Availability Requirements (AR)||
|v4ModifiedAttackVector|CVSS V4.0 Modified Attack Vector (MAV)||
|v4ModifiedAttackComplexity|CVSS V4.0 Modified Attack Complexity (MAC)||
|v4ModifiedAttackRequirements|CVSS V4.0 Modified Attack Requirements (MAT)||
|v4ModifiedPrivilegesRequired|CVSS V4.0 Modified Privileges Required (MPR)||
|v4ModifiedUserInteraction|CVSS V4.0 Modified User Interaction (MUI)||
|v4ModifiedVulnConfidentialityImpact|CVSS V4.0 Modified Vulnerable System Confidentiality Impact (MVC)||
|v4ModifiedVulnIntegrityImpact|CVSS V4.0 Modified Vulnerable System Integrity Impact (MVI)||
|v4ModifiedVulnAvailabilityImpact|CVSS V4.0 Modified Vulnerable System Availability Impact (MVA)||
|v4ModifiedSubConfidentialityImpact|CVSS V4.0 Modified Subsequent System Confidentiality Impact (MSC)||
|v4ModifiedSubIntegrityImpact|CVSS V4.0 Modified Subsequent System Integrity Impact (MSI)||
|v4ModifiedSubAvailabilityImpact|CVSS V4.0 Modified Subsequent System Availability Impact (MSA)||
|v4Safety|CVSS V4.0 Safety (S)||
|v4Automatable|CVSS V4.0 Automatable (AU)||
|v4Recovery|CVSS V4.0 Recovery (R)||
|v4ValueDensity|CVSS V4.0 Value Density (V)||
|v4VulnResponseEffort|CVSS V4.0 Vulnerability Response Effort (RE)||
|v4ProviderUrgency|CVSS V4.0 Provider Urgency (U)||

## Rate Limiting

The script automatically handles NVD API rate limits:

- **Without API key**: 6 seconds between requests (10 requests per minute)
- **With API key**: 0.6 seconds between requests (100 requests per minute)

## Logging

The script creates a log file (`nvd_download.log`) and displays progress information in the console. This includes:

- Download progress
- Error messages
- API response information
- Completion statistics

## Error Handling

The script includes error handling for:

- Network connectivity issues
- API rate limit violations
- Malformed API responses
- File I/O errors

If an error occurs, the script will retry automatically after a delay.

## Performance

- **Without API key**: Approximately 10 CVEs per minute
- **With API key**: Approximately 100 CVEs per minute

The total download time depends on the number of CVEs in the database (currently 300,000+), which may be in excess of 30 minutes.

## Example Output

```csv
CVE,Description,CVSS v2,CVSS v2 Vector,CVSS v3,CVSS v3 Vector,CVSS v4,CVSS v4 Vector,CISA Required Action
CVE-2007-0671,"Unspecified vulnerability in Microsoft Excel 2000, XP, 2003, and 2004 for Mac, and possibly other Office products, allows remote user-assisted attackers to execute arbitrary code via unknown attack vectors, as demonstrated by Exploit-MSExcel.h in targeted zero-day attacks.",9.3,AV:N/AC:M/Au:N/C:C/I:C/A:C,8.8,CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H,,,"Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable."
CVE-2021-44228,"Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.",9.3,AV:N/AC:M/Au:N/C:C/I:C/A:C,10.0,CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H,,,"For all affected software assets for which updates exist, the only acceptable remediation actions are: 1) Apply updates; OR 2) remove affected assets from agency networks. Temporary mitigations using one of the measures provided at https://www.cisa.gov/uscert/ed-22-02-apache-log4j-recommended-mitigation-measures are only acceptable until updates are available."
```

## Troubleshooting

### Common Issues

1. **Rate Limit Errors**: The script handles these automatically. If you see frequent rate limit errors, consider getting an API key.

2. **Network Timeouts**: The script will retry failed requests. Ensure you have a stable internet connection. Consider retrying later, in case the NVD server is experiencing issues.

3. **Large File Size**: The complete CVE database is large (100MB+ when complete). Ensure you have sufficient disk space.

### Getting Help

Run the script with `-h` for command-line help:

```bash
python nvd_cve_downloader.py -h
```

## License


This script is provided as-is for educational and research purposes. Please respect the NVD API terms of service and rate limits.






