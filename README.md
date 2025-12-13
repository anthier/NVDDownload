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

### Basic Usage (without API key) TODO: Update starting here.
```bash
python nvd_cve_downloader.py
```

This will download all CVEs and save them to `nvd_cves.csv` with a 6-second delay between API requests.

### With NVD API Key (recommended)
```bash
python nvd_cve_downloader.py --api-key YOUR_API_KEY
```

Using an API key reduces the delay between requests from 6 seconds to 0.6 seconds, significantly speeding up the download.

### Custom Output File
```bash
python nvd_cve_downloader.py --output my_cves.csv --api-key YOUR_API_KEY
```

## Getting an NVD API Key

1. Visit [NVD API Key Request](https://nvd.nist.gov/developers/request-an-api-key)
2. Fill out the form to request an API key
3. Use the provided key with the `--api-key` parameter

## Output Format

The script generates a CSV file with the following columns:

- **CVE**: CVE identifier (e.g., CVE-2023-12345)
- **Description**: English description of the vulnerability
- **CVSS v2**: CVSS version 2.0 base score (if available)
- **CVSS v2 Vector String**: CVSS version 2 vector string (if available)
- **CVSS v3**: CVSS version 3.0/3.1 base score (if available)
- **CVSS v3 Vector String**: CVSS version 3.0/3.1 vector string (if available)
- **CVSS v4**: CVSS version 4.0 base score (if available)
- **CVSS v4 Vector String**: CVSS version 4.0 vector string (if available)

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
