# vt_hash_checker.py

from __future__ import annotations
import argparse
from datetime import datetime, timezone, timedelta
from pathlib import Path
import sys
import logging
import asyncio
import vt
import pandas as pd
from typing import List, Dict, Any, Union

# --- Script Version ---
SCRIPT_VERSION = "0.8.4"

# ---------------- Logging Setup ---------------- #
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler("vt_hash_checker.log"), logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# ---------------- Utility Functions ---------------- #

def validate_input_file(file_path: Path) -> None:
    """Validates the input file's existence, size, and extension."""
    if not file_path.exists():
        logger.error(f'The input file does not exist: {file_path}')
        sys.exit(1)
    if file_path.stat().st_size == 0:
        logger.error(f'The input file is empty: {file_path}')
        sys.exit(1)
    if file_path.suffix.lower() != '.txt':
        logger.error(f'The input file must be a .txt file. Found: {file_path.suffix}')
        sys.exit(1)

def hash_verdict(file_data: Dict[str, Any], found: bool) -> str:
    """Determines the verdict (red, yellow, green, gray) based on VirusTotal analysis stats.
    
    Args:
        file_data: A dictionary containing file analysis data from VirusTotal.
        found: Boolean indicating if the hash was found on VirusTotal.
    
    Returns:
        A string representing the verdict.
    """
    if not found:
        return 'gray'
    
    malicious = file_data.get("malicious", 0)
    reputation = file_data.get("reputation", 0)

    if malicious > 5 and reputation < -5:
        return 'red'
    if 1 <= malicious <= 5 and -5 <= reputation <= -1:
        return 'yellow'
    if malicious == 0 and reputation >= 0:
        return 'green'
    if found:
        return 'yellow'
    return 'gray'

def format_vt_date_to_utc(date_input: Union[str, datetime, None]) -> str:
    """
    Formats a date input (string, datetime object, or None) to 'YYYY-MM-DD HH:MM:SS UTC' string.
    Handles both 'YYYY-MM-DD HH:MM:SS+00:00' strings and direct datetime objects.
    """
    if date_input is None or date_input == '-':
        return '-'

    dt_object = None
    
    try:
        if isinstance(date_input, datetime):
            dt_object = date_input
        elif isinstance(date_input, str):
            try:
                dt_object = datetime.fromisoformat(date_input)
            except ValueError:
                if '+' in date_input:
                    date_input = date_input.split('+')[0].strip()
                elif 'Z' in date_input:
                    date_input = date_input.replace('Z', '').strip()
                dt_object = datetime.strptime(date_input, '%Y-%m-%d %H:%M:%S')
        else:
            logger.warning(f"Unexpected date input type: {type(date_input)}. Value: {date_input}")
            return '-'

        if dt_object.tzinfo is None:
            dt_object = dt_object.replace(tzinfo=timezone.utc)
        elif dt_object.tzinfo.utcoffset(dt_object) is not None and dt_object.tzinfo.utcoffset(dt_object) != timedelta(0):
            dt_object = dt_object.astimezone(timezone.utc)

        return dt_object.strftime('%Y-%m-%d %H:%M:%S UTC')
    except (ValueError, TypeError, AttributeError) as e:
        logger.warning(f"Could not process date input '{date_input}' (Type: {type(date_input)}): {e}")
        return '-'


async def query_vt_hash_async(client: vt.Client, file_hash: str) -> Dict[str, Union[str, int]]:
    """Queries VirusTotal for a given file hash asynchronously.
    
    Args:
        client: The VirusTotal API client.
        file_hash: The hash to query.
    
    Returns:
        A dictionary containing the analysis results.
    """
    try:
        file = await client.get_object_async(f"/files/{file_hash}")
        stats = file.last_analysis_stats
        
        file_data_for_verdict = {
            "malicious": stats.get("malicious", 0),
            "reputation": file.reputation
        }

        creation_date_utc = format_vt_date_to_utc(getattr(file, 'creation_date', None))
        first_submission_date_utc = format_vt_date_to_utc(getattr(file, 'first_submission_date', None))
        last_submission_date_utc = format_vt_date_to_utc(getattr(file, 'last_submission_date', None))
        last_analysis_date_utc = format_vt_date_to_utc(getattr(file, 'last_analysis_date', None))

        vt_url = f"https://www.virustotal.com/gui/file/{file.id}/detection"

        return {
            'File Hash': file.id,
            'Verdict': hash_verdict(file_data_for_verdict, True),
            'Found on VT': 'Y',
            'Reputation': file.reputation,
            'Malicious': stats.get("malicious", 0),
            'Failure': stats.get("failure", 0),
            'Harmless': stats.get("harmless", 0),
            'Suspicious': stats.get("suspicious", 0),
            'Timeout': stats.get("timeout", 0),
            'Type-unsupported': stats.get("type-unsupported", 0),
            'Undetected': stats.get("undetected", 0),
            'Creation Date (UTC)': creation_date_utc,
            'First Submission Date (UTC)': first_submission_date_utc,
            'Last Submission Date (UTC)': last_submission_date_utc,
            'Last Analysis Date (UTC)': last_analysis_date_utc,
            'VT URL': vt_url
        }
    except vt.APIError as err:
        if err.code == 'NotFoundError':
            return {
                'File Hash': file_hash,
                'Verdict': 'gray',
                'Found on VT': 'N',
                'Reputation': '-', 'Malicious': '-', 'Failure': '-',
                'Harmless': '-', 'Suspicious': '-', 'Timeout': '-',
                'Type-unsupported': '-', 'Undetected': '-',
                'Creation Date (UTC)': '-', 'First Submission Date (UTC)': '-',
                'Last Submission Date (UTC)': '-', 'Last Analysis Date (UTC)': '-',
                'VT URL': '-'
            }
        logger.error(f"API Error for hash {file_hash}: {err.code} - {err.message}")
        return {
            'File Hash': file_hash,
            'Verdict': 'error',
            'Found on VT': 'E',
            'Reputation': '-', 'Malicious': '-', 'Failure': '-',
            'Harmless': '-', 'Suspicious': '-', 'Timeout': '-',
            'Type-unsupported': '-', 'Undetected': '-',
            'Creation Date (UTC)': '-', 'First Submission Date (UTC)': '-',
            'Last Submission Date (UTC)': '-', 'Last Analysis Date (UTC)': '-',
            'VT URL': '-', 'Error Message': f"{err.code} - {err.message}"
        }
    except Exception as e:
        logger.error(f"An unexpected error occurred while querying hash {file_hash}: {e}")
        return {
            'File Hash': file_hash,
            'Verdict': 'error',
            'Found on VT': 'E',
            'Reputation': '-', 'Malicious': '-', 'Failure': '-',
            'Harmless': '-', 'Suspicious': '-', 'Timeout': '-',
            'Type-unsupported': '-', 'Undetected': '-',
            'Creation Date (UTC)': '-', 'First Submission Date (UTC)': '-',
            'Last Submission Date (UTC)': '-', 'Last Analysis Date (UTC)': '-',
            'VT URL': '-', 'Error Message': str(e)
        }

async def process_single_hash_with_lock(client: vt.Client, file_hash: str, semaphore: asyncio.Semaphore,
                                       c_min: int, c_day: int, calls_minute: Dict[str, Any], calls_day: Dict[str, int], lock: asyncio.Lock):
    """A wrapper around process_single_hash to manage counter updates with a lock."""
    result = None
    async with semaphore:
        while True:
            current_time = datetime.now()

            async with lock: # Acquire lock to access counters
                # Reset minute counter at the beginning of each new minute
                if 'last_reset' not in calls_minute or (current_time - calls_minute['last_reset']).total_seconds() >= 60:
                    calls_minute['count'] = 0
                    calls_minute['last_reset'] = current_time

                # Check daily limit
                if calls_day['count'] >= c_day:
                    logger.warning(f"Daily API limit reached ({c_day}). Skipping hash: {file_hash}")
                    result = {
                        'File Hash': file_hash, 'Verdict': 'skipped', 'Found on VT': 'N',
                        'Reputation': '-', 'Malicious': '-', 'Failure': '-',
                        'Harmless': '-', 'Suspicious': '-', 'Timeout': '-',
                        'Type-unsupported': '-', 'Undetected': '-',
                        'Creation Date (UTC)': '-', 'First Submission Date (UTC)': '-',
                        'Last Submission Date (UTC)': '-', 'Last Analysis Date (UTC)': '-',
                        'VT URL': '-', 'Error Message': 'Daily API limit reached'
                    }
                    break

                # Check minute limit
                if c_min > 0 and calls_minute['count'] >= c_min:
                    delay = 60 - (current_time - calls_minute['last_reset']).total_seconds()
                    if delay <= 0:
                        calls_minute['count'] = 0
                        calls_minute['last_reset'] = current_time
                        continue
                    logger.info(f"Rate limit reached for this minute ({c_min} calls/min). Sleeping {delay:.1f}s...")
                    lock.release() 
                    await asyncio.sleep(delay + 0.1)
                    await lock.acquire()
                    continue
            
            result = await query_vt_hash_async(client, file_hash)
            
            async with lock:
                if result and result.get('Verdict') not in ['skipped', 'error']:
                    calls_minute['count'] += 1
                    calls_day['count'] += 1
            break
            
    return result

async def process_hashes_async(file_path: Path, client: vt.Client, is_premium: bool, c_min: int, c_day: int, concurrent_requests: int = 4) -> List[Dict]:
    """Reads hashes from a file, queries VirusTotal, and collects results using asyncio.
    
    Args:
        file_path: Path to the input file containing hashes.
        client: The VirusTotal API client.
        is_premium: Boolean indicating if a premium API key is used.
        c_min: API calls limit per minute.
        c_day: API calls limit per day.
        concurrent_requests: Maximum number of concurrent requests to VirusTotal.
        
    Returns:
        A list of dictionaries, where each dictionary is the result for a hash.
    """
    hashes_to_process = []
    with file_path.open('r', encoding='utf-8') as f:
        for line in f:
            file_hash = line.strip()
            if file_hash:
                hashes_to_process.append(file_hash)

    if not hashes_to_process:
        logger.info("No hashes found in the input file.")
        return []

    if not is_premium:
        if concurrent_requests > c_min:
             logger.warning(f"Public API key detected. Reducing concurrent requests from {concurrent_requests} to {c_min} (max calls per minute).")
             concurrent_requests = c_min
        if concurrent_requests == 0 and c_min > 0:
            concurrent_requests = 1
        if c_min == 0 and not is_premium:
            c_min = 4

    semaphore = asyncio.Semaphore(concurrent_requests)

    calls_minute = {'count': 0, 'last_reset': datetime.now()}
    calls_day = {'count': 0}
    
    counter_lock = asyncio.Lock()


    logger.info(f"Starting VirusTotal hash checking with {concurrent_requests} concurrent requests.")
    logger.info(f"API limits: {c_min} calls/min, {c_day} calls/day.")

    tasks = []
    for h in hashes_to_process:
        tasks.append(process_single_hash_with_lock(client, h, semaphore, c_min, c_day, calls_minute, calls_day, counter_lock))

    results = await asyncio.gather(*tasks)

    return [r for r in results if r is not None]


def write_to_excel(results: List[Dict]) -> None:
    """Writes the results to an Excel file with conditional formatting and clickable URLs."""
    if not results:
        logger.info("No results to write to Excel.")
        return

    df = pd.DataFrame(results)

    def color_rows(row):
        colors = {
            'red': 'background-color: #FFCCCC',
            'yellow': 'background-color: #FFFFCC',
            'green': 'background-color: #CCFFCC',
            'gray': 'background-color: #EEEEEE',
            'error': 'background-color: #FFDDAA',
            'skipped': 'background-color: #DDEEFF'
        }
        styles = []
        for col_name in row.index:
            if col_name == 'VT URL':
                styles.append('')
            else:
                styles.append(colors.get(row['Verdict'], ''))
        return styles

    file_name = datetime.now().strftime("%Y%m%d_%H%M%S_%f_hashes_check_on_VT.xlsx")
    
    try:
        with pd.ExcelWriter(file_name, engine='xlsxwriter') as writer:
            df_styled = df.style.apply(color_rows, axis=1)
            
            df_without_url = df.drop(columns=['VT URL'])
            
            df_styled.to_excel(writer, index=False, sheet_name='Hashes_check_on_VT')
            
            worksheet = writer.sheets['Hashes_check_on_VT']
            
            header_row = 0
            url_col_idx = -1
            for col_idx, col_name in enumerate(df.columns):
                if col_name == 'VT URL':
                    url_col_idx = col_idx
                    break
            
            if url_col_idx != -1:
                for row_num, url_val in enumerate(df['VT URL']):
                    if url_val != '-':
                        worksheet.write_url(row_num + header_row + 1, url_col_idx, url_val, string='Link to VT')
                    else:
                        worksheet.write(row_num + header_row + 1, url_col_idx, url_val)
            
        logger.info(f"Results successfully written to {file_name}")
    except Exception as e:
        logger.error(f"Error writing to Excel file {file_name}: {e}")
        logger.error("Make sure you have 'xlsxwriter' installed (pip install xlsxwriter).")


    found = sum(1 for r in results if r.get('Found on VT') == 'Y')
    not_found = sum(1 for r in results if r.get('Found on VT') == 'N')
    errors = sum(1 for r in results if r.get('Found on VT') == 'E' or r.get('Verdict') == 'error')
    skipped = sum(1 for r in results if r.get('Verdict') == 'skipped')
    
    logger.info(f"Total hashes processed: {len(results)}")
    logger.info(f"  - Found on VT: {found}")
    logger.info(f"  - Not found on VT: {not_found}")
    logger.info(f"  - Errors during query: {errors}")
    logger.info(f"  - Skipped due to API limits: {skipped}")

# ---------------- Main ---------------- #

async def main_async():
    """Main asynchronous function to parse arguments and orchestrate the hash checking process."""
    parser = argparse.ArgumentParser(
        description=f"Check file hashes on VirusTotal (Version: {SCRIPT_VERSION})" # Version in help
    )
    parser.add_argument("file_path", type=Path, help="Path to the input .txt file containing hashes.")
    parser.add_argument("vt_key", type=str, help="Your VirusTotal API key.")
    parser.add_argument("-prem", "--premium", type=str, default="n", choices=["y", "n"],
                        help="Set to 'y' if you have a premium VirusTotal API key (default: n).")
    parser.add_argument("-c_min", "--calls_per_minute", type=int, default=4,
                        help="Maximum API calls per minute (default: 4 for public key, adjust for premium).")
    parser.add_argument("-c_day", "--calls_per_day", type=int, default=500,
                        help="Maximum API calls per day (default: 500 for public key, adjust for premium).")
    parser.add_argument("-cr", "--concurrent_requests", type=int, default=4,
                        help="Maximum number of concurrent API requests (default: 4). Be cautious with public keys.")
    args = parser.parse_args()

    logger.info(f"Starting VirusTotal hash checker (Version: {SCRIPT_VERSION}) with arguments: {args}") # Version in log

    try:
        validate_input_file(args.file_path)
    except SystemExit as e:
        logger.error(f"Input file validation failed: {e}")
        sys.exit(1)

    is_premium = args.premium.lower() == 'y'
    
    if not is_premium:
        if args.calls_per_minute > 4:
            logger.warning("Using a public API key. Recommended calls_per_minute is 4.")
        if args.calls_per_day > 500:
            logger.warning("Using a public API key. Recommended calls_per_day is 500.")
        if args.concurrent_requests > args.calls_per_minute:
            logger.warning(f"Public API key detected. Reducing concurrent requests from {args.concurrent_requests} to {args.calls_per_minute} (max calls per minute).")
            args.concurrent_requests = args.calls_per_minute
        if args.concurrent_requests == 0 and args.calls_per_minute > 0:
            args.concurrent_requests = 1
        if args.calls_per_minute == 0 and not is_premium:
            args.calls_per_minute = 4

    client = None
    try:
        client = vt.Client(args.vt_key)
        results = await process_hashes_async(args.file_path, client, is_premium,
                                             args.calls_per_minute, args.calls_per_day,
                                             args.concurrent_requests)
        write_to_excel(results)
    except vt.APIError as e:
        logger.critical(f"VirusTotal API initialization failed: {e.code} - {e.message}. Please check your API key.")
        sys.exit(1)
    except Exception as e:
        logger.critical(f"An unhandled error occurred: {e}", exc_info=True)
        sys.exit(1)
    finally:
        if client:
            await client.close_async()
            logger.info("VirusTotal client closed.")

if __name__ == "__main__":
    asyncio.run(main_async())
