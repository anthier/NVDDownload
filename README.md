# NVD CVE Downloader

A Python script to download all CVEs (Common Vulnerabilities and Exposures) from the National Vulnerability Database (NVD) API and save them to a CSV file.

Written primarily by AI.

## Features

- Downloads all available CVEs from the NVD API
- Extracts CVE ID, description, and CVSS scores (v2, v3, v4)
- Handles API rate limiting automatically
- Supports optional API key for higher rate limits
- Comprehensive error handling and logging
- Progress tracking during download
- Saves results to CSV format

## Installation

1. Install Python 3.7 or higher
2. Install required dependencies:

```bash
pip install nvdlib
```

## Usage

### Basic Usage (without API key)
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
- **CVSS v2**: CVSS version 2 base score (if available)
- **CVSS v3**: CVSS version 3.0/3.1 base score (if available)
- **CVSS v4**: CVSS version 4.0 base score (if available)

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

The script includes robust error handling for:

- Network connectivity issues
- API rate limit violations
- Malformed API responses
- File I/O errors

If an error occurs, the script will retry automatically after a delay.

## Performance

- **Without API key**: Approximately 10 CVEs per minute
- **With API key**: Approximately 100 CVEs per minute

The total download time depends on the number of CVEs in the database (currently 200,000+).

## Example Output

```csv
CVE,Description,CVSS v2,CVSS v3,CVSS v4
CVE-2023-12345,"Buffer overflow vulnerability in example software",7.5,9.8,
CVE-2023-12346,"SQL injection in web application",6.8,8.1,7.3
```

## Troubleshooting

### Common Issues

1. **Rate Limit Errors**: The script handles these automatically. If you see frequent rate limit errors, consider getting an API key.

2. **Network Timeouts**: The script will retry failed requests. Ensure you have a stable internet connection.

3. **Large File Size**: The complete CVE database is large (several GB when complete). Ensure you have sufficient disk space.

### Getting Help

Run the script with `-h` for command-line help:

```bash
python nvd_cve_downloader.py -h
```

## License

This script is provided as-is for educational and research purposes. Please respect the NVD API terms of service and rate limits.