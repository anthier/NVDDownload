#!/usr/bin/env python3
import argparse
from argparse import RawTextHelpFormatter
import logging
import sys
from nvd_cve_downloader import NVDDownloader
from nvd_cve_downloader import supported_columns

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]       
)
logger = logging.getLogger(__name__)

def comma_separated_list(arg_string):
    return arg_string.replace(' ', '').split(',')

def parse_args_from_file(parser: argparse.ArgumentParser, file_path: str) -> argparse.Namespace:
    with open(file_path, 'r', encoding='utf-8') as f:
        # Split on whitespace – this mimics how the shell parses arguments.
        # If you need quoted strings or comments, use shlex.split instead.
        raw_args = f.read().split()
    return parser.parse_args(raw_args)

def main():    
    # Configure arguments    
    parser = argparse.ArgumentParser(
        description='Download all CVEs from NVD API \n\n' \
            'Notes:\n' \
            '- Only outputs English CVE descriptions, when available.\n' 
            '- Only outputs CVSS data from the primary source.\n' 
            '- Only outputs one CVSS v3.x score (v3.1 if available).\n'
            '- Some column options from the first.org spec are omitted because NVD has never used them (e.g. "reportConfidence")\n'
            '- Fields not returned by the NVD API are left blank.\n'
            '- Arguments can be provided via text file by setting the first argument to the file path (no dashes).\n'
            '- Some fields are exported in raw NVD-style JSON. Use formatters (--formatters) for a focused tabular representation.',
        formatter_class=RawTextHelpFormatter
    )      
    parser.add_argument(
        '--list-columns',
        action='store_true',
        help='list all available columns for the --columns parameter',
        default=False, 
    )
    parser.add_argument(
        '--api-key',
        help='NVD API key for higher rate limits (optional)',
        default=None
    )
    parser.add_argument( 
        '--columns',
        type=comma_separated_list,
        help='list of columns to output (in order, comma-separated). Defaults to id,  description, base scores, and vector strings. For full list of available columns, use --list-columns.', 
        default=['id', 'description', 'v2BaseScore', 'v2VectorString', 'v3BaseScore', 'v3VectorString', 'v4BaseScore', 'v4VectorString']
    )
    parser.add_argument( 
        '--formatters',
        type=comma_separated_list,
        help='list of formatters (comma-separated) to apply to raw JSON columns (these ignore lf parsing settings):\n'
             '- weaknesses: output one weakness per line\n'
             '- configurations: output one configuration per line\n'
             '- vendorComments: output one vendor/comment key-value pair per line',
        default=[]
    )
    parser.add_argument(
        '--lf-parsing',
        help='- SPACE or S: replace line feeds in CVE data with spaces\n'
             '- PRESERVE or P: preserve original line feed characters.',
        default='space'
    )    
    parser.add_argument(
        '--output',
        help='output file path',
        default='nvd_cves.csv'
    )
    parser.add_argument(
        '--log-to-file',
        action='store_true',
        help='save log entries to file',
        default=False
    )
    
    # Parse arguments
    if len(sys.argv) <= 1 or (len(sys.argv) > 1 and sys.argv[1].startswith('-')):
        args = parser.parse_args()
    else:
        # Assume the argument is a config file when it isn't formatted like a switch (-)
        args = parse_args_from_file(parser, sys.argv[1])   
    
    # Execute    
    if args.list_columns:
        # Print supported column list (no CVE processing)
        print('Supported columns:')
        for column in supported_columns:
            print(column)
    else:
        if args.log_to_file:
            logging.getLogger().addHandler(logging.FileHandler('nvd_cve_downloader.log')) # add to root
        
        # Download CVEs
        downloader = NVDDownloader(logger=logger, api_key=args.api_key, columns=args.columns, formatters=args.formatters, lf_parsing=args.lf_parsing)    
        try:        
            downloader.download_all_cves(output_file=args.output)
        except KeyboardInterrupt:
            pass
        except Exception as e:
            return 1
    
    return 0

if __name__ == "__main__":
    exit(main())