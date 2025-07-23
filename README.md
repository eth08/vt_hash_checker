# VirusTotal Hash Checker

![Python CI/CD](https://github.com/eth08/vt_hash_checker/actions/workflows/main.yml/badge.svg)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Version](https://img.shields.io/badge/version-0.8.4-orange)

A powerful asynchronous Python script to efficiently check a list of file hashes against the VirusTotal API.
It generates an Excel report with detailed analysis statistics, including verdict, reputation, various detection counts,
and important timestamps (creation, first/last submission, last analysis dates) all in UTC,
along with clickable links to the VirusTotal analysis page for each hash.


## Features

* **Asynchronous Processing:** Utilizes `asyncio` for highly efficient concurrent querying of VirusTotal API, significantly speeding up the analysis of large hash lists.
* **Rate Limiting Management:** Intelligently handles VirusTotal API rate limits (calls per minute and calls per day) to prevent exceeding quotas, with special considerations for public API keys.
* **Comprehensive Output:** Generates an `.xlsx` Excel report with the following columns:
    * `File Hash`
    * `Verdict` (Red: Malicious, Yellow: Suspicious/Uncertain, Green: Clean, Gray: Not Found, Error: API Query Error, Skipped: Due to API limits)
    * `Found on VT` (Y/N/E)
    * `Reputation`
    * `Malicious`
    * `Failure`
    * `Harmless`
    * `Suspicious`
    * `Timeout`
    * `Type-unsupported`
    * `Undetected`
    * `Creation Date (UTC)`
    * `First Submission Date (UTC)`
    * `Last Submission Date (UTC)`
    * `Last Analysis Date (UTC)`
    * `VT URL` (Clickable link to the VirusTotal analysis page)
* **Conditional Formatting:** Excel rows are color-coded based on the `Verdict` for quick visual inspection.
* **Robust Error Handling:** Catches API errors, network issues, and unexpected errors, logging them and marking affected hashes in the report.
* **Input Validation:** Ensures the input hash file exists, is not empty, and has the correct `.txt` extension.
* **Detailed Logging:** Provides verbose logs to `vt_hash_checker.log` and stdout for monitoring script execution and debugging.

## Prerequisites

Before running the script, ensure you have the following installed:

* Python 3.8+ (recommended 3.10+)
* A VirusTotal API Key (Public or Premium)

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/eth08/vt_hash_checker.git
    cd vt_hash_checker
    ```

2.  **Install dependencies:**
    It's highly recommended to use a virtual environment.
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    pip install -r requirements.txt
    ```

## Usage

1.  **Prepare your hash list:** Create a `.txt` file (e.g., `hashes.txt`) with one hash per line. Supported hash types (MD5, SHA1, SHA256) are automatically detected by VirusTotal.

    ```
    d41d8cd98f00b204e9800998ecf8427e
    2fd4e1ce67f2b28fcd7894a42b10be5f
    c3b88b0a9c8e8d8c3f4a4b4c4d4e4f5a6b6c6d6e6f7a7b7c7d7e7f8a8b8c8d8e
    ```

2.  **Run the script:**

    ```bash
    python vt_hash_checker.py <path_to_hash_file.txt> <YOUR_VIRUSTOTAL_API_KEY> [OPTIONS]
    ```

    **Example (Public API Key):**
    ```bash
    python vt_hash_checker.py hashes.txt YOUR_VT_API_KEY
    ```

    **Example (Premium API Key with higher limits and concurrency):**
    ```bash
    python vt_hash_checker.py hashes.txt YOUR_VT_PREMIUM_API_KEY -prem y -c_min 1000 -c_day 100000 -cr 20
    ```

### Command Line Arguments

* `<path_to_hash_file.txt>` (Positional, required): Path to the input `.txt` file containing hashes.
* `<YOUR_VIRUSTOTAL_API_KEY>` (Positional, required): Your VirusTotal API key.
* `-prem, --premium` (Optional): Set to `'y'` if you have a premium VirusTotal API key. Defaults to `'n'`.
* `-c_min, --calls_per_minute` (Optional): Maximum API calls per minute. Defaults to `4` for public keys. Adjust for premium keys.
* `-c_day, --calls_per_day` (Optional): Maximum API calls per day. Defaults to `500` for public keys. Adjust for premium keys.
* `-cr, --concurrent_requests` (Optional): Maximum number of concurrent API requests. Defaults to `4`. Be cautious with public keys; this will be automatically limited to `calls_per_minute` if `-prem n` is used.

## Output

The script will generate an Excel file named `YYYYMMDD_HHMMSS_microseconds_hashes_check_on_VT.xlsx` in the same directory where the script is executed. A `vt_hash_checker.log` file will also be created for detailed logging.

## Development & Testing

### Running Tests

To run the unit tests, ensure you have `pytest` and `pytest-asyncio` installed (included in `requirements.txt`):

```bash
pip install -r requirements.txt
pytest test_vt_hash_checker.py
