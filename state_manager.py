"""
state_manager.py
Persists the last successful check timestamp in Azure Blob Storage
so the agent knows which advisories are "new" on each run.
"""

import os
import json
import logging
from typing import Optional
from datetime import datetime, timezone, timedelta
from azure.storage.blob import BlobServiceClient
from azure.core.exceptions import ResourceNotFoundError

CONTAINER_NAME = "patch-monitor-state"
BLOB_NAME = "last_check_state.json"
DATE_FORMAT = "%Y-%m-%d"


def _get_blob_client():
    conn_str = os.environ.get("AZURE_STORAGE_CONNECTION_STRING")
    if not conn_str:
        raise EnvironmentError("AZURE_STORAGE_CONNECTION_STRING environment variable is not set.")
    service_client = BlobServiceClient.from_connection_string(conn_str)
    container_client = service_client.get_container_client(CONTAINER_NAME)
    # Create container if it doesn't exist
    try:
        container_client.create_container()
        logging.info(f"Created blob container: {CONTAINER_NAME}")
    except Exception:
        pass  # Already exists
    return container_client.get_blob_client(BLOB_NAME)


def get_last_check_time() -> str:
    """
    Retrieve the last check date from Azure Blob Storage.
    Defaults to yesterday if no state exists yet.

    Returns:
        ISO date string (YYYY-MM-DD)
    """
    try:
        blob_client = _get_blob_client()
        data = blob_client.download_blob().readall()
        state = json.loads(data)
        last_check = state.get("last_check_date")
        logging.info(f"Last check date retrieved: {last_check}")
        return last_check
    except ResourceNotFoundError:
        # First run — default to yesterday to catch any patches missed today
        default_date = (datetime.now(timezone.utc) - timedelta(days=1)).strftime(DATE_FORMAT)
        logging.info(f"No prior state found. Defaulting to: {default_date}")
        return default_date
    except Exception as e:
        logging.error(f"Error reading state from blob: {e}")
        return (datetime.now(timezone.utc) - timedelta(days=1)).strftime(DATE_FORMAT)


def update_last_check_time(check_date: Optional[str] = None) -> None:
    """
    Persist the latest check timestamp to Azure Blob Storage.

    Args:
        check_date: ISO date string to store. Defaults to today (UTC).
    """
    if not check_date:
        check_date = datetime.now(timezone.utc).strftime(DATE_FORMAT)

    state = {
        "last_check_date": check_date,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        blob_client = _get_blob_client()
        blob_client.upload_blob(json.dumps(state), overwrite=True)
        logging.info(f"State updated — last check date set to: {check_date}")
    except Exception as e:
        logging.error(f"Failed to update state in blob storage: {e}")
