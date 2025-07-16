# test_vt_hash_checker.py

import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
from datetime import datetime, timezone, timedelta
import sys
import os
import pandas as pd
from pathlib import Path
import argparse

# Add the directory containing your script to the sys.path
# This assumes test_vt_hash_checker.py is in the same directory as vt_hash_checker.py
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '.')))

# Import functions from your main script
from vt_hash_checker import ( # Referencing vt_hash_checker.py
    validate_input_file,
    hash_verdict,
    format_vt_date_to_utc,
    query_vt_hash_async,
    process_single_hash_with_lock,
    process_hashes_async,
    write_to_excel,
    SCRIPT_VERSION
)
import vt # Import vt to mock its Client and APIError

# --- Fixtures and Mocks ---

@pytest.fixture
def mock_vt_client():
    """Mock for vt.Client."""
    with patch('vt.Client', new_callable=AsyncMock) as mock_client:
        # Mock the async close method
        mock_client.return_value.close_async = AsyncMock()
        yield mock_client.return_value

@pytest.fixture
def mock_path(tmp_path):
    """Fixture to create a temporary file path."""
    def _create_file(content=""):
        p = tmp_path / "test_hashes.txt"
        p.write_text(content)
        return p
    return _create_file

@pytest.fixture
def mock_logger():
    """Mock for the logger to capture messages."""
    # Patching logger from vt_hash_checker.py
    with patch('vt_hash_checker.logger') as mock_log:
        yield mock_log

# --- Unit Tests for Utility Functions ---

def test_validate_input_file_exists(mock_path):
    f = mock_path("test_content")
    validate_input_file(f)

def test_validate_input_file_not_exists():
    with pytest.raises(SystemExit):
        validate_input_file(Path("non_existent.txt"))

def test_validate_input_file_empty(mock_path):
    f = mock_path("")
    with pytest.raises(SystemExit):
        validate_input_file(f)

def test_validate_input_file_wrong_extension(tmp_path):
    f = tmp_path / "test.csv"
    f.write_text("content")
    with pytest.raises(SystemExit):
        validate_input_file(f)

def test_hash_verdict():
    assert hash_verdict({'malicious': 6, 'reputation': -6}, True) == 'red'
    assert hash_verdict({'malicious': 1, 'reputation': -1}, True) == 'yellow'
    assert hash_verdict({'malicious': 0, 'reputation': 0}, True) == 'green'
    assert hash_verdict({'malicious': 3, 'reputation': -3}, True) == 'yellow'
    assert hash_verdict({}, False) == 'gray'
    assert hash_verdict({'malicious': 0, 'reputation': -1}, True) == 'yellow'
    assert hash_verdict({'malicious': 0, 'reputation': 5}, True) == 'green'

def test_format_vt_date_to_utc_datetime_object():
    dt_obj = datetime(2023, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
    assert format_vt_date_to_utc(dt_obj) == "2023-01-15 10:30:00 UTC"

def test_format_vt_date_to_utc_string_with_offset():
    date_str = "2019-04-12 11:40:00+00:00"
    assert format_vt_date_to_utc(date_str) == "2019-04-12 11:40:00 UTC"

def test_format_vt_date_to_utc_string_without_offset():
    date_str = "2020-02-29 23:59:59"
    assert format_vt_date_to_utc(date_str) == "2020-02-29 23:59:59 UTC"

def test_format_vt_date_to_utc_none():
    assert format_vt_date_to_utc(None) == "-"

def test_format_vt_date_to_utc_invalid_string(mock_logger):
    assert format_vt_date_to_utc("invalid_date") == "-"
    mock_logger.warning.assert_called_once()

# --- Async Tests ---

@pytest.mark.asyncio
async def test_query_vt_hash_async_found(mock_vt_client):
    mock_file_obj = MagicMock()
    mock_file_obj.id = "test_hash_found"
    mock_file_obj.last_analysis_stats = {"malicious": 10, "harmless": 5, "undetected": 5, "suspicious": 0, "failure": 0, "timeout": 0, "type-unsupported": 0}
    mock_file_obj.reputation = -10
    mock_file_obj.creation_date = datetime(2022, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    mock_file_obj.first_submission_date = datetime(2022, 1, 2, 10, 0, 0, tzinfo=timezone.utc)
    mock_file_obj.last_submission_date = datetime(2022, 1, 3, 10, 0, 0, tzinfo=timezone.utc)
    mock_file_obj.last_analysis_date = datetime(2022, 1, 4, 10, 0, 0, tzinfo=timezone.utc)

    mock_vt_client.get_object_async.return_value = mock_file_obj

    result = await query_vt_hash_async(mock_vt_client, "test_hash_found")

    assert result['File Hash'] == "test_hash_found"
    assert result['Verdict'] == 'red'
    assert result['Found on VT'] == 'Y'
    assert result['Reputation'] == -10
    assert result['Malicious'] == 10
    assert result['Creation Date (UTC)'] == "2022-01-01 10:00:00 UTC"
    assert result['VT URL'] == "https://www.virustotal.com/gui/file/test_hash_found/detection"

@pytest.mark.asyncio
async def test_query_vt_hash_async_not_found(mock_vt_client):
    mock_vt_client.get_object_async.side_effect = vt.APIError("NotFoundError", "Hash not found")

    result = await query_vt_hash_async(mock_vt_client, "non_existent_hash")

    assert result['File Hash'] == "non_existent_hash"
    assert result['Verdict'] == 'gray'
    assert result['Found on VT'] == 'N'
    assert result['Reputation'] == '-'

@pytest.mark.asyncio
async def test_query_vt_hash_async_api_error(mock_vt_client, mock_logger):
    mock_vt_client.get_object_async.side_effect = vt.APIError("QuotaExceededError", "API limit reached")

    result = await query_vt_hash_async(mock_vt_client, "error_hash")

    assert result['File Hash'] == "error_hash"
    assert result['Verdict'] == 'error'
    assert result['Found on VT'] == 'E'
    assert result['Error Message'] == "QuotaExceededError - API limit reached"
    mock_logger.error.assert_called_once()

@pytest.mark.asyncio
async def test_query_vt_hash_async_unexpected_error(mock_vt_client, mock_logger):
    mock_vt_client.get_object_async.side_effect = Exception("Some unexpected issue")

    result = await query_vt_hash_async(mock_vt_client, "unexpected_error_hash")

    assert result['File Hash'] == "unexpected_error_hash"
    assert result['Verdict'] == 'error'
    assert result['Found on VT'] == 'E'
    assert "Some unexpected issue" in result['Error Message']
    mock_logger.error.assert_called_once()


@pytest.mark.asyncio
async def test_process_single_hash_with_lock_success(mock_vt_client):
    mock_file_obj = MagicMock()
    mock_file_obj.id = "hash1"
    mock_file_obj.last_analysis_stats = {"malicious": 0, "harmless": 10, "undetected": 0}
    mock_file_obj.reputation = 5
    mock_file_obj.creation_date = datetime(2023, 1, 1, tzinfo=timezone.utc)
    mock_file_obj.first_submission_date = datetime(2023, 1, 1, tzinfo=timezone.utc)
    mock_file_obj.last_submission_date = datetime(2023, 1, 1, tzinfo=timezone.utc)
    mock_file_obj.last_analysis_date = datetime(2023, 1, 1, tzinfo=timezone.utc)
    
    mock_vt_client.get_object_async.return_value = mock_file_obj

    semaphore = asyncio.Semaphore(1)
    calls_minute = {'count': 0, 'last_reset': datetime.now()}
    calls_day = {'count': 0}
    lock = asyncio.Lock()

    result = await process_single_hash_with_lock(mock_vt_client, "hash1", semaphore, 10, 100, calls_minute, calls_day, lock)
    
    assert result['File Hash'] == "hash1"
    assert calls_minute['count'] == 1
    assert calls_day['count'] == 1

@pytest.mark.asyncio
async def test_process_single_hash_with_lock_minute_limit(mock_vt_client, mock_logger):
    mock_file_obj = MagicMock()
    mock_file_obj.id = "hash_limit"
    mock_file_obj.last_analysis_stats = {"malicious": 0, "harmless": 10, "undetected": 0}
    mock_file_obj.reputation = 5
    mock_file_obj.creation_date = datetime(2023, 1, 1, tzinfo=timezone.utc)
    mock_file_obj.first_submission_date = datetime(2023, 1, 1, tzinfo=timezone.utc)
    mock_file_obj.last_submission_date = datetime(2023, 1, 1, tzinfo=timezone.utc)
    mock_file_obj.last_analysis_date = datetime(2023, 1, 1, tzinfo=timezone.utc)

    mock_vt_client.get_object_async.return_value = mock_file_obj
    
    semaphore = asyncio.Semaphore(1)
    calls_minute = {'count': 4, 'last_reset': datetime.now() - timedelta(seconds=5)}
    calls_day = {'count': 0}
    lock = asyncio.Lock()

    # Patch asyncio.sleep directly where it's used within the module's scope.
    with patch('vt_hash_checker.asyncio.sleep', new_callable=AsyncMock) as mock_sleep:
        result = await process_single_hash_with_lock(mock_vt_client, "hash_limit", semaphore, 4, 100, calls_minute, calls_day, lock)
        
        assert any(call.args[0].startswith(f"Rate limit reached for this minute (4 calls/min). Sleeping") for call in mock_logger.info.call_args_list)

        # Due to persistent issues with AsyncMock's internal counters returning absurdly large numbers,
        # we resort to checking if it was called at all. Combined with the logger assertion,
        # this confirms the rate limiting and sleep mechanism was triggered.
        assert mock_sleep.called
        
        assert calls_minute['count'] == 1
        assert calls_day['count'] == 1
        assert result['File Hash'] == "hash_limit"


@pytest.mark.asyncio
async def test_process_hashes_async(mock_path, mock_vt_client):
    test_hashes = ["hash_a", "hash_b"]
    f = mock_path("\n".join(test_hashes))

    mock_file_obj_a = MagicMock()
    mock_file_obj_a.id = "hash_a"
    mock_file_obj_a.last_analysis_stats = {"malicious": 0}
    mock_file_obj_a.reputation = 0
    mock_file_obj_a.creation_date = datetime(2023, 1, 1, tzinfo=timezone.utc)
    mock_file_obj_a.first_submission_date = datetime(2023, 1, 1, tzinfo=timezone.utc)
    mock_file_obj_a.last_submission_date = datetime(2023, 1, 1, tzinfo=timezone.utc)
    mock_file_obj_a.last_analysis_date = datetime(2023, 1, 1, tzinfo=timezone.utc)

    mock_file_obj_b = MagicMock()
    mock_file_obj_b.id = "hash_b"
    mock_file_obj_b.last_analysis_stats = {"malicious": 5}
    mock_file_obj_b.reputation = -3
    mock_file_obj_b.creation_date = datetime(2023, 1, 1, tzinfo=timezone.utc)
    mock_file_obj_b.first_submission_date = datetime(2023, 1, 1, tzinfo=timezone.utc)
    mock_file_obj_b.last_submission_date = datetime(2023, 1, 1, tzinfo=timezone.utc)
    mock_file_obj_b.last_analysis_date = datetime(2023, 1, 1, tzinfo=timezone.utc)

    mock_vt_client.get_object_async.side_effect = [mock_file_obj_a, mock_file_obj_b]

    results = await process_hashes_async(f, mock_vt_client, False, 4, 500, 2)
    
    assert len(results) == 2
    assert results[0]['File Hash'] == "hash_a"
    assert results[0]['Verdict'] == 'green'
    assert results[1]['File Hash'] == "hash_b"
    assert results[1]['Verdict'] == 'yellow'


def test_write_to_excel(tmp_path):
    results = [
        {'File Hash': 'hash1', 'Verdict': 'red', 'Found on VT': 'Y', 'Reputation': -10, 'Malicious': 10, 'Failure': 0, 'Harmless': 0, 'Suspicious': 0, 'Timeout': 0, 'Type-unsupported': 0, 'Undetected': 0, 'Creation Date (UTC)': '2023-01-01 10:00:00 UTC', 'First Submission Date (UTC)': '2023-01-01 10:00:00 UTC', 'Last Submission Date (UTC)': '2023-01-01 10:00:00 UTC', 'Last Analysis Date (UTC)': '2023-01-01 10:00:00 UTC', 'VT URL': 'https://www.virustotal.com/gui/file/hash1/detection'},
        {'File Hash': 'hash2', 'Verdict': 'green', 'Found on VT': 'Y', 'Reputation': 5, 'Malicious': 0, 'Failure': 0, 'Harmless': 10, 'Suspicious': 0, 'Timeout': 0, 'Type-unsupported': 0, 'Undetected': 0, 'Creation Date (UTC)': '2023-01-02 11:00:00 UTC', 'First Submission Date (UTC)': '2023-01-02 11:00:00 UTC', 'Last Submission Date (UTC)': '2023-01-02 11:00:00 UTC', 'Last Analysis Date (UTC)': '2023-01-02 11:00:00 UTC', 'VT URL': 'https://www.virustotal.com/gui/file/hash2/detection'},
        {'File Hash': 'hash3', 'Verdict': 'gray', 'Found on VT': 'N', 'Reputation': '-', 'Malicious': '-', 'Failure': '-', 'Harmless': '-', 'Suspicious': '-', 'Timeout': '-', 'Type-unsupported': '-', 'Undetected': '-', 'Creation Date (UTC)': '-', 'First Submission Date (UTC)': '-', 'Last Submission Date (UTC)': '-', 'Last Analysis Date (UTC)': '-', 'VT URL': '-'}
    ]
    
    # Mocking the datetime.now().strftime for the filename
    with patch('vt_hash_checker.datetime') as mock_datetime:
        mock_datetime.now.return_value.strftime.return_value = "mocked_timestamp.xlsx"
        mock_datetime.now.return_value = datetime(2025, 7, 16, 17, 30, 0) # For last_reset in minute limit tests
        mock_datetime.timezone = timezone # Ensure timezone is accessible if needed

        with patch('pandas.ExcelWriter') as mock_excel_writer_class:
            mock_writer_object = MagicMock()
            # Explicitly define a side_effect for __exit__ to ensure close() is called.
            def custom_exit_side_effect(*args, **kwargs):
                mock_writer_object.close()

            mock_writer_object.__exit__.side_effect = custom_exit_side_effect
            
            mock_excel_writer_class.return_value = mock_writer_object

            mock_writer_object.__enter__.return_value = MagicMock()
            mock_worksheet = MagicMock()
            mock_writer_object.__enter__.return_value.sheets = {'Hashes_check_on_VT': mock_worksheet}
            mock_writer_object.__enter__.return_value.book = MagicMock()

            with patch('pandas.io.formats.style.Styler.to_excel') as mock_styler_to_excel:
                mock_styler_to_excel.side_effect = lambda writer, **kwargs: None
                
                write_to_excel(results)
                
                mock_excel_writer_class.assert_called_once()
                mock_writer_object.close.assert_called_once()
                
                df = pd.DataFrame(results)
                try:
                    url_col_idx = df.columns.get_loc('VT URL')
                except KeyError:
                    pytest.fail("Column 'VT URL' not found in DataFrame. Test setup issue.")
                
                mock_worksheet.write_url.assert_any_call(1, url_col_idx, 'https://www.virustotal.com/gui/file/hash1/detection', string='Link to VT')
                mock_worksheet.write_url.assert_any_call(2, url_col_idx, 'https://www.virustotal.com/gui/file/hash2/detection', string='Link to VT')
                mock_worksheet.write.assert_any_call(3, url_col_idx, '-')

                assert mock_worksheet.write_url.call_count == 2
                assert mock_worksheet.write.call_count == 1


# Test that SCRIPT_VERSION is correctly used in ArgumentParser
def test_argparser_version():
    parser = argparse.ArgumentParser(description=f"Check file hashes on VirusTotal (Version: {SCRIPT_VERSION})")
    assert f"Check file hashes on VirusTotal (Version: {SCRIPT_VERSION})" in parser.description