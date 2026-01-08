# installation.pyx
import dns.resolver
import dns.exception
from datetime import datetime
import pymongo
import os
import json
import sys
from pathlib import Path
import jwt
import socket
import pyautogui
import time
import subprocess
import psutil
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QProgressBar, QMessageBox, QInputDialog
import shutil
import zipfile
import sqlite3
import requests
#import permission as permission
import autostart as install_module
from utils.service import connect_service,register_agent,user_onboarding
import ctypes
from encryption import decrypt_response
import urllib3
from urllib.parse import urlparse
import warnings
import certifi
from uninstallation import run_uninstallation
from utils.config import get_branch_id_from_json,EXE_DIREC,UPDATE_FOLDER_PATH,UTILS_PATH, DOWNLOAD_ZIP_PATH, UPDATION_DIREC, DATA_FILE_PATH,get_tenant_id_from_json,INSTALLATION_SLEEP,json_file_path,TRANSACTION_ID_FILE,DB_PATH,USERS_FOLDER,CLOUD_DOWNLOAD_API,STARTUP_FOLDER,logger
urllib3.disable_warnings()
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", message=".*deprecated.*")

# Global variables for tenant information
cdef str GLOBAL_TENANT_ID = ""
cdef str GLOBAL_COMPANY_ID = ""
cdef str GLOBAL_BRANCH_ID = ""

cdef bint startup_flag = False

def extract_branch_id_from_filename():
    """
    Extract branch_id from the executable filename.
    Expected format: EbantisTracker_{branch_id}.exe or .msi
   
    Returns:
        str: The extracted branch_id or None if not found
    """
    try:
        # Get the executable filename
        exe_name = os.path.basename(sys.executable)
        logger.info(f"Executable name: {exe_name}")
       
        # Try to extract branch_id from format: EbantisTracker_{branch_id}.exe
        if "EbantisTracker_" in exe_name:
            # Split by underscore and get the part after "EbantisTracker_"
            parts = exe_name.split("EbantisTracker_")
            if len(parts) > 1:
                # Remove the file extension (.exe or .msi)
                branch_id = parts[1].rsplit('.', 1)[0]
                logger.info(f"Extracted branch_id from filename: {branch_id}")
                #return "8b56528f-eedd-4d34-8250-a2b4a07763d4"
                return branch_id
       
        logger.warning(f"Could not extract branch_id from filename: {exe_name}")
        return None
    except Exception as e:
        logger.error(f"Error extracting branch_id from filename: {e}", exc_info=True)
        return None

def get_tenant_info_by_branch_id(branch_id):
    """
    Fetch tenant, company, and branch information from API using branch_id.
    
    Args:
        branch_id (str): The branch unique ID
    
    Returns:
        dict: Dictionary with tenantId, companyId, branchId or None if failed
    """
    try:
        # Get authentication token
        auth_token = get_auth_token()
        if not auth_token:
            logger.error("Failed to obtain authentication token for branch lookup.")
            return None
        
        # API endpoint to get branch details
        api_url = f"https://qaebantisv4service.thekosmoz.com/api/v1/branches/branch/{branch_id}"
        headers = {
            "Authorization": f"Bearer {auth_token}"
        }
        
        logger.info(f"Fetching tenant info from API for branch_id: {branch_id}")
        
        response = requests.get(api_url, headers=headers, verify=False, timeout=30)
        response.raise_for_status()
        
        branch_data = response.json()
        
        if branch_data:
            tenant_id = branch_data.get("tenantUniqueId", "")
            company_id = branch_data.get("companyUniqueId", "")
            
            logger.info(f"Retrieved tenant info - tenant_id: {tenant_id}, company_id: {company_id}, branch_id: {branch_id}")
            
            return {
                "tenantId": tenant_id,
                "companyId": company_id,
                "branchId": branch_id
            }
        
        logger.warning(f"No data found for branch_id: {branch_id}")
        return None
        
    except requests.exceptions.RequestException as e:
        logger.error(f"API request error while fetching tenant info for branch_id {branch_id}: {e}", exc_info=True)
        return None
    except Exception as e:
        logger.error(f"Error fetching tenant info for branch_id {branch_id}: {e}", exc_info=True)
        return None

def initialize_tenant_info():
    """
    Initialize global tenant information by extracting branch_id from executable filename
    and fetching tenant details from API.
    This should be called once at the start of installation.
    """
    global GLOBAL_TENANT_ID, GLOBAL_COMPANY_ID, GLOBAL_BRANCH_ID
    
    try: 
        # Extract branch_id from executable filename
        branch_id = extract_branch_id_from_filename()
        
        if not branch_id:
            logger.error("Failed to extract branch_id from executable filename.")
            return False
        
        # Save branch_id to JSON file

        
        # Fetch tenant info from API using branch_id
        tenant_info = get_tenant_info_by_branch_id(branch_id)
        
        if not tenant_info:
            logger.error("Failed to fetch tenant information from API.")
            return False
        
        # Set global variables
        GLOBAL_TENANT_ID = tenant_info.get("tenantId", "")
        GLOBAL_COMPANY_ID = tenant_info.get("companyId", "")
        GLOBAL_BRANCH_ID = tenant_info.get("branchId", "")

        # Save tenant info to JSON file
        if not save_tenant_name_to_json(GLOBAL_TENANT_ID, GLOBAL_COMPANY_ID, GLOBAL_BRANCH_ID):
            logger.warning("Failed to save tenant info to JSON file.")
        
        logger.info(f"Tenant info initialized - tenant_id: {GLOBAL_TENANT_ID}, company_id: {GLOBAL_COMPANY_ID}, branch_id: {GLOBAL_BRANCH_ID}")
        return True
    except Exception as e:
        logger.error(f"Failed to initialize tenant info: {e}", exc_info=True)
        return False

cdef void remove(str path):
    try:
        if os.path.isfile(path) or os.path.islink(path):
            os.remove(path)  # remove the file
            logger.info(f"Removed file: {path}")
        elif os.path.isdir(path):
            shutil.rmtree(path)  # remove dir and all contents
            logger.info(f"Removed directory: {path}")
    except Exception as e:
        logger.error(f"Error removing {path}: {str(e)}", exc_info=True)

cdef bint is_connected():
    try:
        socket.create_connection(("1.1.1.1", 53), timeout=5)
        logger.info("Internet connection is available.")
        return True
    except OSError as e:
        logger.warning(f"Internet connection check failed: {e}")
        return False
import psutil
import threading
import subprocess
import shutil
import os
import time




cdef void End_task():
    # import psutil, shutil, os, time, subprocess, threading
 
    try:
        def kill_processes_by_exe_name(exe_list):
            """Kill all running processes by their .exe names."""
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    if proc.info['name'] in exe_list:
                        logger.info(f"Killing process {proc.info['name']} (PID {proc.info['pid']})")
                        proc.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    logger.warning(f"Could not kill process: {proc.info['name']}")
                    continue
 
        def wait_until_processes_killed(exe_list, timeout=10):
            """Wait for processes to fully terminate."""
            end_time = time.time() + timeout
            while time.time() < end_time:
                alive = False
                for proc in psutil.process_iter(['name']):
                    if proc.info['name'] in exe_list:
                        alive = True
                        break
                if not alive:
                    logger.info(f"All processes terminated: {exe_list}")
                    return True
                time.sleep(1)
            logger.warning(f"Timeout waiting for processes to close: {exe_list}")
            return False
 
        def remove_path(path, max_retries=5, delay=1):
            for attempt in range(max_retries):
                try:
                    if os.path.isfile(path) or os.path.islink(path):
                        os.remove(path)
                    elif os.path.isdir(path):
                        shutil.rmtree(path)
                    logger.info(f"Removed: {path}")
                    return
                except Exception as e:
                    logger.warning(f"Attempt {attempt+1}: Error removing {path}: {e}")
                    time.sleep(delay)
            logger.error(f"Failed to remove {path} after {max_retries} attempts.")
 
        # --- STEP 1: Identify EXE files ---
        exe_list = []
        for folder in [UTILS_PATH, UPDATE_FOLDER_PATH,EXE_DIREC]:
            if os.path.exists(folder):
                for f in os.listdir(folder):
                    if f.lower().endswith(".exe"):
                        exe_list.append(f)
        logger.info(f"EXE files found to terminate: {exe_list}")
        # --- STEP 2: Kill processes before deletion ---
        if exe_list:
            kill_processes_by_exe_name(exe_list)
            wait_until_processes_killed(exe_list)
 
        time.sleep(2)  # give Windows time to release file handles
 
        # --- STEP 3: Now remove directories safely ---
        threads = []
        for path in [UTILS_PATH, UPDATE_FOLDER_PATH,EXE_DIREC]:
            if os.path.exists(path):
                t = threading.Thread(target=remove_path, args=(path,))
                t.start()
                threads.append(t)
 
        for t in threads:
            t.join()
        logger.info("End_task completed successfully.")
 
    except Exception as e:
        logger.error(f"Error ending task: {str(e)}")
 
 
 
 

def get_sqlite_connection():
    """
    Get a SQLite connection to the database.
    Returns:
        sqlite3.Connection: SQLite connection object
    """
    try:
        sqlite_db_path = DB_PATH
        conn = sqlite3.connect(sqlite_db_path)
        logger.info(f"Connected to SQLite database at: {sqlite_db_path}")
        return conn
    except sqlite3.Error as e:
        logger.error(f"Failed to connect to SQLite database at {DB_PATH}: {e}")
        return None
def get_agent_install_dir():
    """
    Returns the installation directory of the OSSEC agent.
    Checks common paths and logs which one is used.
    """
    path_86 = r"C:\Program Files (x86)\ossec-agent"
    path_64 = r"C:\Program Files\ossec-agent"

    if os.path.exists(path_86):
        logger.info(f"OSSEC agent directory found: {path_86}")
        return path_86
    elif os.path.exists(path_64):
        logger.info(f"OSSEC agent directory found: {path_64}")
        return path_64
    else:
        logger.warning(f"OSSEC agent directory not found. Defaulting to: {path_86}")
        return path_86
def is_service_running(service_name):
    """
    Checks if a Windows service is running.

    Args:
        service_name (str): Name of the service.

    Returns:
        bool: True if service is running, False otherwise.
    """
    try:
        service = psutil.win_service_get(service_name).as_dict()
        running = service.get("status") == "running"
        logger.info(f"Service '{service_name}' status: {service.get('status')}")
        return running
    except Exception as e:
        logger.error(f"Error checking service '{service_name}': {e}")
        return False

def upsert_installation_data(tenant_id,branch_id, status_flag, installation_flag, status):
    """
    Save installation data to SQL database through API.
    
    Args:
        tenant_id (str): Tenant Unique ID
        status_flag (bool): Download status flag
        installation_flag (bool): Installation status flag
        status (str): Installation status (inprogress/installed/failed)
    """
    try:
        from utils.config import user_name, email, display_name
        
        # Get version ID from API
        version_id = update_version_details(branch_id)
        
        # Get current system information
        hostname = socket.gethostname()
        installed_date = datetime.now().isoformat()
        
        # Get user information - use display_name as fallback for userName
        user_name_value = display_name if display_name else user_name
        email_value = email if email else ""
        
        # Get userExternalId from decoded credentials or set to 0 as default
        user_external_id = 0
        try:
            dec_data = get_decoded_credentials()
            if dec_data:
                user_external_id = dec_data.get('userexternalid', 0)
        except:
            pass
        
        # Prepare API payload
        payload = {
            "branchUniqueId": str(branch_id),
            "tenantUniqueId": str(tenant_id),
            "hostName": hostname,
            "installedOn": installed_date,
            "isDownloaded": status_flag,
            "isInstalled": installation_flag,
            "versionId": version_id,
            "status": status,
            "userName": user_name_value,
            "userExternalId": user_external_id,
            "email": email_value
        }
        
        # Get authentication token
        auth_token = get_auth_token()
        if not auth_token:
            logger.error("Failed to obtain authentication token for saving installation data.")
            return False
        
        #api_url = "https://ebantisv4service.thekosmoz.com/api/v1/AppVersion/SaveAppInstallation"
        api_url = "https://qaebantisv4service.thekosmoz.com/api/v1/app-installations"
        headers = {
            "Authorization": f"Bearer {auth_token}"
        }
        
        logger.info(f"Saving installation data to API for host: {hostname}")
        logger.info(f"Payload: {payload}")
        
        response = requests.post(api_url, json=payload, headers=headers, verify=False, timeout=30)
        response.raise_for_status()
        
        logger.info(f"Installation data saved successfully for host: {hostname}")
        return True
        
    except requests.exceptions.RequestException as e:
        logger.error(f"API request failed while saving installation data for host {hostname}: {e}", exc_info=True)
        return False
    except Exception as e:
        logger.error(f"Failed to save installation data for host {hostname}: {e}", exc_info=True)
        return False

def get_auth_token():
    """
    Authenticate and get access token from the authentication API.
    
    Returns:
        str | None: Access token if successful, None otherwise.
    """
    try:
        auth_api_url = "https://qaebantisv4service.thekosmoz.com/api/v1/users/auth/login"
        payload = {
            "userName": "internalmanager@mail.com",
            "password": "#@Admin&eu1"
        }
        
        logger.info("Authenticating to get access token...")
        
        response = requests.post(auth_api_url, json=payload, verify=False, timeout=30)
        response.raise_for_status()
        
        auth_data = response.json()
        access_token = auth_data.get("accessToken")
        
        if access_token:
            logger.info("Access token obtained successfully.")
            return access_token
        else:
            logger.warning("No access token found in authentication response.")
            return None
            
    except requests.exceptions.RequestException as e:
        logger.error(f"Authentication API request failed: {e}", exc_info=True)
        return None
    except Exception as e:
        logger.error(f"Error during authentication: {e}", exc_info=True)
        return None

def get_tenant_id_by_name(tenant_name):
    """
    Fetch the Tenant Unique ID from the API based on tenant name
    """

    try:
        # Get authentication token
        auth_token = get_auth_token()
        print("auth_token",auth_token)
        if not auth_token:
            logger.error("Failed to obtain authentication token.")
            return None
        
        api_url = f"https://ebantisv4service.thekosmoz.com/api/v1/Tenant/GetTenantByName/{tenant_name}"
        headers = {
            "Authorization": f"Bearer {auth_token}"
        }
        
        logger.info(f"Fetching tenant unique ID from API: {api_url}")
        
        response = requests.get(api_url, headers=headers, verify=False)
        response.raise_for_status()
        
        tenant_data = response.json()
        
        if tenant_data and "tenantUniqueId" in tenant_data:
            tenant_unique_id = tenant_data["tenantUniqueId"]
            logger.info(f"Tenant Unique ID found for '{tenant_name}': {tenant_unique_id}")
            return tenant_unique_id

        logger.warning(f"No tenant unique ID found in response for tenant name '{tenant_name}'")
        return None

    except requests.exceptions.RequestException as e:
        logger.error(
            f"API request error while fetching Tenant ID for '{tenant_name}': {e}",
            exc_info=True
        )
        return None
    except Exception as e:
        logger.error(
            f"Error fetching Tenant ID for '{tenant_name}': {e}",
            exc_info=True
        )
        return None


def check_installation_allowed(branch_id):
    """
    Checks if installation is allowed for a given tenant ID based on installed vs allowed device count.

    Parameters:
        tenant_id (str): Tenant Unique ID to check.

    Returns:
        (bool, str): Tuple of (is_allowed, message)
    """
    branch_id_str = str(branch_id)
    try:
        # Get authentication token
        auth_token = get_auth_token()
        if not auth_token:
            msg = "Failed to obtain authentication token for installation check."
            logger.error(msg)
            return False, msg
        
        api_url = f"https://qaebantisv4service.thekosmoz.com/api/v1/app-versions/branches/{branch_id_str}"
        headers = {
            "Authorization": f"Bearer {auth_token}"
        }
        
        logger.info(f"Fetching app version details from API: {api_url}")
        
        response = requests.get(api_url, headers=headers, verify=False)
        response.raise_for_status()
        
        version_data = response.json()
        print("version data",version_data)
        
        if version_data:
            allowed_count = version_data.get("allowedInstallationCount", 0)
            installed_count = version_data.get("installedDeviceCount", 0)

            if installed_count < allowed_count:
                msg = f"Installation allowed for tenant {branch_id_str} ({installed_count}/{allowed_count})"
                logger.info(msg)
                return True, msg
            else:
                msg = f"Installation not allowed for tenant {branch_id_str}: Maximum installations reached ({installed_count}/{allowed_count})"
                logger.warning(msg)
                return False, msg
        else:
            msg = f"No data found for tenant_id: {branch_id_str}"
            logger.warning(msg)
            return False, msg

    except requests.exceptions.RequestException as e:
        msg = f"API request error while checking installation for tenant {branch_id_str}: {e}"
        logger.error(msg, exc_info=True)
        return False, msg
    except Exception as e:
        msg = f"Error checking installation for tenant {branch_id_str}: {e}"
        logger.error(msg, exc_info=True)
        return False, msg
def update_installed_device_count(branch_id):
    """
    Update the installed_device_count for a tenant after a successful installation via API.

    Args:
        branch_id (int | str): Branch ID whose device count needs to be updated.

    Returns:
        (bool, str): Tuple (success, message)
    """
    branch_id_str = str(branch_id)
    try:
        # Get authentication token
        auth_token = get_auth_token()
        if not auth_token:
            msg = "Failed to obtain authentication token for device count update."
            logger.error(msg)
            return False, msg
        
        api_url = f"https://qaebantisv4service.thekosmoz.com/api/v1/app-versions/branches/{branch_id_str}/installed-count"
        headers = {
            "Authorization": f"Bearer {auth_token}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "tenantUniqueId": branch_id_str,
            "installedDeviceCount": 1
        }
        
        logger.info(f"Updating installed device count for tenant_id: {branch_id_str}")
        logger.info(f"Payload: {payload}")

        response = requests.put(api_url, json=payload, headers=headers, verify=False, timeout=30)
        response.raise_for_status()

        msg = f"Installed device count updated successfully for tenant_id: {branch_id_str}"
        logger.info(msg)
        return True, msg

    except requests.exceptions.RequestException as e:
        msg = f"API request error while updating device count for tenant_id {branch_id_str}: {e}"
        logger.error(msg, exc_info=True)
        return False, msg
    except Exception as e:
        msg = f"Error updating installed device count for tenant_id {branch_id_str}: {e}"
        logger.error(msg, exc_info=True)
        return False, msg

def update_version_details(branch_id):
    """
    Fetches the latest version ID from API.

    Args:
        tenant_id (str): Tenant Unique ID.

    Returns:
        str | None: The Version_Id if found, otherwise None.
    """
    branch_id_str = str(branch_id)
    try:
        # Get authentication token
        auth_token = get_auth_token()
        if not auth_token:
            logger.error("Failed to obtain authentication token for version details.")
            return None
        
        api_url = f"https://qaebantisv4service.thekosmoz.com/api/v1/app-versions/branches/{branch_id_str}"
        headers = {
            "Authorization": f"Bearer {auth_token}"
        }
        
        logger.info(f"Fetching version details from API: {api_url}")
        
        response = requests.get(api_url, headers=headers, verify=False, timeout=30)
        response.raise_for_status()
        
        version_data = response.json()
        
        if version_data and "versionId" in version_data:
            version_id = version_data.get("versionId")
            logger.info(f"Latest Version_Id retrieved from API: {version_id}")
            return version_id
        
        logger.warning(f"No version_id found in API response for tenant_id: {branch_id_str}")
        return None

    except requests.exceptions.RequestException as e:
        logger.error(f"API request error while fetching version details for tenant {branch_id_str}: {e}", exc_info=True)
        return None
    except Exception as e:
        logger.error(f"Error fetching version details for tenant {branch_id_str}: {e}", exc_info=True)
        return None
def extract_hostname_from_connection_string(connection_string):
    """
    Extracts the base hostname from a MongoDB(+srv) connection string.
    Returns None if parsing fails.
    """
    if not connection_string:
        return None
    try:
        # Handle potential 'mongodb+srv://' or 'mongodb://' prefixes
        if connection_string.startswith("mongodb+srv://"):
            parse_target = connection_string
        elif connection_string.startswith("mongodb://"):
             parse_target = connection_string
        else:
            # Assume it might just be the host part if no prefix (less robust)
            # Or handle as an error depending on expected input
            print("Warning: Connection string doesn't start with mongodb:// or mongodb+srv://")
            # Basic attempt: find first '/' or '?' if no prefix
            host_part = connection_string.split('/')[0].split('?')[0]
            # Remove potential user:pass@ part
            if '@' in host_part:
                 host_part = host_part.split('@', 1)[1]
            # Remove potential port
            if ':' in host_part:
                 host_part = host_part.rsplit(':', 1)[0]
            return host_part


        parsed = urlparse(parse_target)
        hostname = parsed.hostname
        return hostname # This should be the part like 'ebantis.y2lgplz.mongodb.net'

    except Exception as e:
        print(f"Error parsing connection string '{connection_string}': {e}")
        return None


def check_mongodb_srv_record(cluster_hostname, timeout=10):
    """
    Checks if the MongoDB SRV DNS record exists for the given cluster hostname.
    Uses PyQt QMessageBox for errors.

    Args:
        cluster_hostname (str): The base hostname of the MongoDB Atlas cluster
                                (e.g., 'ebantis.y2lgplz.mongodb.net').
        timeout (int): DNS query timeout in seconds.

    Returns:
        bool: True if the SRV record name likely exists, False otherwise.
    """
    if not cluster_hostname:
        print("Configuration Error", "Cannot check DNS: MongoDB cluster hostname is missing or could not be extracted.")
        return False

    srv_query_name = f"_mongodb._tcp.{cluster_hostname}"
    print(f"Checking for DNS SRV record: {srv_query_name}...")

    try:
        # Configure a resolver with a specific timeout
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout

        # Attempt to resolve the SRV record
        answers = resolver.resolve(srv_query_name, 'SRV') # Raises exception on failure
        print(f"DNS SRV record check successful for {cluster_hostname}.")
        return True

    except dns.resolver.NXDOMAIN:
        error_msg = (f"The required DNS record '{srv_query_name}' does not exist.\n\n"
                     f"Please verify:\n"
                     f"1. The MongoDB Atlas cluster hostname ('{cluster_hostname}') derived from your connection string is correct.\n"
                     f"2. The cluster is active and running in MongoDB Atlas.\n"
                     f"3. Your network allows DNS SRV record lookups.")
        print("Installation Blocked - DNS Error", error_msg)
        return False
    except dns.resolver.NoAnswer:
        # Name exists, but no SRV records. Treat as success for existence check, but warn.
        print(f"Warning: DNS name '{srv_query_name}' exists, but returned no SRV records. "
              f"This might indicate an issue with the cluster configuration, but proceeding.")
        return True # Name exists
    except dns.exception.Timeout:
        error_msg = (f"Checking DNS for '{srv_query_name}' timed out after {timeout} seconds.\n\n"
                     f"Please check:\n"
                     f"1. Your internet connection.\n"
                     f"2. Your DNS server configuration.\n"
                     f"3. Any firewall or proxy settings that might block DNS queries.")
        print("Installation Blocked - DNS Timeout", error_msg)
        return False
    except dns.exception.DNSException as e:
        # Catch other potential DNS errors
        error_msg = (f"A DNS error occurred while looking up '{srv_query_name}':\n{e}\n\n"
                     f"Check network/firewall settings and ensure the hostname derived is correct.")
        print("Installation Blocked - DNS Error", error_msg)
        return False
    except Exception as e:
        # Catch unexpected errors during the check
        error_msg = f"An unexpected error occurred during DNS check: {e}"
        print("Installation Error", error_msg)
        return False
cdef void remove_startup_file():
    """
    Removes specific .bat files from the Windows startup folder.
    """
    cdef str start_up_location = STARTUP_FOLDER
    cdef list batch_filenames = ["ebantis"]
    cdef str batch_location

    try:
        for filename in batch_filenames:
            batch_location = os.path.join(start_up_location, filename + '.bat')
            if os.path.exists(batch_location):
                logger.info(f"Removing startup file: {batch_location}")
                remove(batch_location)
                logger.info(f"Startup file removed successfully: {batch_location}")
            else:
                logger.warning(f"Startup file not found: {batch_location}")

    except Exception as e:
        logger.error(f"Startup file removal error: {e}", exc_info=True)

def save_tenant_name_to_json(tenant_id, company_id, branch_id):
    """
    Save tenant, company, and branch IDs to JSON file.
    
    Args:
        tenant_id (str): Tenant unique ID
        company_id (str): Company unique ID
        branch_id (str): Branch unique ID
    
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        tenant_data = {
            "tenant_id": tenant_id,
            "company_id": company_id,
            "branch_id": branch_id
        }
        
        # Ensure the directory exists
        os.makedirs(os.path.dirname(json_file_path), exist_ok=True)
        
        with open(json_file_path, "w") as file:
            json.dump(tenant_data, file, indent=4)
        
        logger.info(f"Tenant info saved successfully to JSON file: {json_file_path}")
        return True
    except Exception as e:
        logger.error(f"Error writing tenant info to JSON file '{json_file_path}': {e}", exc_info=True)
        return False

def get_decoded_credentials():
    """
    Fetch and decode encrypted API credentials from SQLite database.
    Returns a dictionary with lowercase keys if successful, otherwise None.
    """
    sqlite_con = None
    try:
        sqlite_con = get_sqlite_connection()
        db_cursor = sqlite_con.cursor()

        credential = db_cursor.execute(
            """SELECT * FROM api_data WHERE id = 1"""
        ).fetchone()

        if not credential:
            logger.warning("No credential record found in database.")
            return None

        json_string = credential[1]
        credential_data = json.loads(json_string)
        encr_data = credential_data.get('obfuscatedEncryptedData')

        if not encr_data:
            logger.warning("Encrypted data missing from credentials.")
            return None

        dec_data = decrypt_response(encr_data)
        dec_data_lower = {key.lower(): value for key, value in dec_data.items()}

        logger.info("Credentials successfully decoded from database.")
        return dec_data_lower

    except Exception as e:
        logger.error(f"Error decoding data from database: {e}", exc_info=True)
        return None

    finally:
        if sqlite_con:
            sqlite_con.close()


# Helper function for robust zip extraction, potentially stripping a single top-level directory
def _robust_extract_zip(zip_ref, extract_dir):
    """
    Extracts a zip file robustly.
    zip_ref: either a string path to zip or a ZipFile object
    extract_dir: target directory for extraction
    """
    try:
        members = zip_ref.namelist()

        # Detect if there's an unnecessary root directory
        root_dir = os.path.commonpath(members)
        if root_dir in members and len(root_dir) > 0:
            for member in members:
                target_path = os.path.join(extract_dir, os.path.relpath(member, root_dir))
                zip_ref.extract(member, extract_dir)
        else:
            zip_ref.extractall(extract_dir)

        logger.info(f"Zip extracted successfully to: {extract_dir}")

    except Exception as e:
        logger.error(f"Error during robust zip extraction to {extract_dir}: {str(e)}", exc_info=True)
        raise


   


cdef bint cloud_dwnld():
    global GLOBAL_TENANT_ID
    cdef str utils_path
    cdef str download_path
    cdef str extract_path
    cdef dict dec_data_lower
    cdef str tenant_id_to_use = GLOBAL_TENANT_ID if GLOBAL_TENANT_ID else None
    cdef str branch_id_to_use = GLOBAL_BRANCH_ID if GLOBAL_BRANCH_ID else None
    cdef bint download_flag = False

    # Define paths
    utils_path = UTILS_PATH
    download_path = DATA_FILE_PATH
    extract_path = UPDATION_DIREC
    update_path = UPDATE_FOLDER_PATH

    # Create necessary directories
    os.makedirs(os.path.dirname(download_path), exist_ok=True)
    os.makedirs(extract_path, exist_ok=True)

    # dec_data_lower = get_decoded_credentials()
    # if not dec_data_lower:
    #     logger.error("Failed to fetch or decode credentials from SQLite.")
    #     return False
    # if dec_data_lower:
    #     if os.path.exists(utils_path) or os.path.exists(update_path):
    #         End_task()

    api_url = f"{CLOUD_DOWNLOAD_API}?branch_id={branch_id_to_use}"

    logger.info(f"api_url: {api_url}")

    # Get tenant_id for API calls
    #tenant_id = get_tenant_id_from_json()
    #if not tenant_id:
        #logger.error(f"Failed to get tenant_id for tenant: {tenant_id}")
        #return False

    download_flag = False
    installation_flag = False
    status = "inprogress"

    # Upsert installation data
    upsert_installation_data(tenant_id_to_use,branch_id_to_use, download_flag, installation_flag, status)

    try:
        # Download the file using API (multi-threaded if possible)
        logger.info("Starting main package download from API...")
        import logging
        def download_part(start, end, url, file_path, idx, results):
            headers = {'Range': f'bytes={start}-{end}'}
            try:
                r = requests.post(url, headers=headers, stream=True)
                r.raise_for_status()
                with open(file_path, "r+b") as f:
                    f.seek(start)
                    for chunk in r.iter_content(chunk_size=8192):
                        f.write(chunk)
                results[idx] = True
                logger.info(f"Part {idx} downloaded successfully.")
            except Exception as e:
                logger.error(f"Download part {idx} failed: {e}", exc_info=True)
                results[idx] = False

        # Get file size from server (if supported)
        try:
            head = requests.head(api_url)
            file_size = int(head.headers.get('Content-Length', 0))
            logger.info(f"File size from API: {file_size} bytes")
        except Exception as e:
            file_size = 0
            logger.warning(f"Could not get file size from API: {e}")


        download_success = False
        if file_size > 0 and file_size > 1024 * 1024 * 5:  # Only multi-thread for files >5MB
            num_threads = 4
            part_size = file_size // num_threads
            with open(download_path, "wb") as f:
                f.truncate(file_size)
            threads = []
            results = [False] * num_threads
            for i in range(num_threads):
                start = i * part_size
                end = (start + part_size - 1) if i < num_threads - 1 else file_size - 1
                t = threading.Thread(target=download_part, args=(start, end, api_url, download_path, i, results))
                t.start()
                threads.append(t)
            for t in threads:
                t.join()
            if all(results):
                download_success = True
            else:
                logger.warning("Multi-threaded download failed, falling back to single-threaded.")
                # fallback to single-threaded
                with requests.post(api_url, stream=True) as response:
                    response.raise_for_status()
                    with open(download_path, "wb") as file:
                        for chunk in response.iter_content(chunk_size=8192):
                            file.write(chunk)
                download_success = True
        else:
            with requests.post(api_url, stream=True) as response:
                response.raise_for_status()
                with open(download_path, "wb") as file:
                    for chunk in response.iter_content(chunk_size=8192):
                        file.write(chunk)
            download_success = True

        # Check if file exists after download
        if not (download_success and os.path.exists(download_path) and os.path.getsize(download_path) > 0):
            msg = f"Download failed or file missing: {download_path}"
            logger.error(msg)
            pyautogui.alert(text=msg, title="Ebantis Installation")
            return False
        logger.info("Downloaded main package successfully.")
        # Validate the downloaded file
        if not zipfile.is_zipfile(download_path):
            msg = f"Downloaded file is not a valid ZIP: {download_path}"
            logger.error(msg)
            pyautogui.alert(text=msg, title="Ebantis Installation")
            os.remove(download_path)
            return False

        # Existing directory removal (utils_path, update_path) is handled by initial End_task
        # in InstallWorker.run and remove(UPDATION_DIREC) right after.

        # Extract the ZIP file using the robust helper
        logger.info(f"Extracting main package from {download_path} to {extract_path}...")
        with zipfile.ZipFile(download_path, "r") as zip_ref:
            _robust_extract_zip(zip_ref, extract_path)

        logger.info("Main package extracted successfully.")
        download_flag = True
    except Exception as e:
        msg = f"Main package download/extraction failed: {e}"
        logger.error(msg, exc_info=True)
        pyautogui.alert(text=msg, title="Ebantis Installation")
        return False
    
    upsert_installation_data(tenant_id_to_use, branch_id_to_use, download_flag, installation_flag, status)
    
    return download_flag

cdef bint trigger_download():
    cdef bint download_flag
    try:
        download_flag = cloud_dwnld()
        if download_flag:
            try:
                remove(DATA_FILE_PATH)  # Remove the downloaded ZIP file after successful extraction
                logger.info(f"Cleanup successful: {DATA_FILE_PATH} removed.")
                return True
            except Exception as e:
                logger.error(f"Error during cleanup of {DATA_FILE_PATH}: {str(e)}", exc_info=True)
                return False
        else:
            logger.warning("Download failed; skipping cleanup.")
            return False
    except Exception as e:
        logger.error(f"trigger_download encountered an error: {str(e)}", exc_info=True)
        return False


class InstallWorker(QThread):
    progress_updated = pyqtSignal(int, str)
    installation_complete = pyqtSignal(bool)

    def run(self):
        import concurrent.futures
        logger.info("InstallWorker started.")
        self.progress_updated.emit(30, 'Clearing previous version (if installed)')
        try:
            if os.path.exists(EXE_DIREC):
                logger.info(f"Existing utils path found: {UTILS_PATH}. Ending running tasks.")
                End_task()
                logger.info(f"Removing update directory: {UPDATION_DIREC}")
                remove(UPDATION_DIREC)
            remove_startup_file()
            logger.info("Previous version removed successfully.")
        except Exception as e:
            logger.error(f"Error clearing previous version: {str(e)}", exc_info=True)
            self.progress_updated.emit(100, "Error: Unable to clear previous version.")
            self.installation_complete.emit(False)
            return

        self.progress_updated.emit(40, 'Downloading main and model packages in parallel')
        logger.info("Starting download of main and model packages in parallel.")
        main_package_download_and_extract_success = False # Flag for main package (download + extract)
        #model_zip_download_success = False # Flag for model zip download only
        #model_download_path = MODEL_ZIP

        # Function to download the main package, which also performs extraction and cleanup of its zip.
        def download_main_package_with_extraction():
            result = trigger_download()
            logger.info(f"Main package download/extraction result: {result}")
            return result # This downloads DATA_FILE_PATH, extracts to UPDATION_DIREC, then removes DATA_FILE_PATH

        # Function to download only the model zip file.
     #   def download_model_package_only():
            #try:
                # Ensure parent directory for MODEL_ZIP exists
                #os.makedirs(os.path.dirname(model_download_path), exist_ok=True)
                #api_url_model = f"{CLOUD_DOWNLOAD_API}?model_download=True"
                #logger.info(f"Downloading model package from {api_url_model} to {model_download_path}...")
                #with requests.post(api_url_model, stream=True) as response:
                   # response.raise_for_status()
                   # with open(model_download_path, "wb") as file:
                        #for chunk in response.iter_content(chunk_size=8192):
                         #   file.write(chunk)
                #logger.info("Model package downloaded successfully.")
               # return True
            #except Exception as e:
                #logger.error(f"Model download failed: {str(e)}", exc_info=True)
               # pyautogui.alert(text=f"Model download failed: {str(e)}", title="Ebantis Installation")
                #r#eturn False
        try:
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future_main_dl_extract = executor.submit(download_main_package_with_extraction)
                #future_model_dl_only = executor.submit(download_model_package_only)
                main_package_download_and_extract_success = future_main_dl_extract.result()
                #model_zip_download_success = future_model_dl_only.result()

            #if not main_package_download_and_extract_success or not model_zip_download_success:
            if not main_package_download_and_extract_success :
                logger.error("One or more package downloads/extractions failed.")
                self.progress_updated.emit(100, "Error: One or more package downloads/extractions failed.")
                self.installation_complete.emit(False)
                return
            #self.progress_updated.emit(50, 'Running model extraction, permission updates, and Wazuh install in parallel')
            self.progress_updated.emit(50, 'Running permission updates, and Wazuh install in parallel')

            logger.info("Proceeding folder permission updates, and Wazuh installation.")
        except Exception as e:
            logger.error(f"Error during parallel download: {str(e)}", exc_info=True)
            self.progress_updated.emit(100, "Error: Parallel download failed.")
            self.installation_complete.emit(False)
            return

        # The main package is already handled (downloaded and extracted) by download_main_package_with_extraction.
        # Now, we only need a function to extract the *model* zip.
        #def extract_model_package():
            # parallel_extract is now defined at the module level
            #result = parallel_extract(model_download_path, MODEL_FOLDER)
            #logger.info(f"Model extraction result: {result}")
           # return result

        folders_to_modify = [USERS_FOLDER, DOWNLOAD_ZIP_PATH,EXE_DIREC]
        # MODIFIED: Removed the 'Get-Acl' line to prevent potential folder opening
        command_template = """
        $folderPath = '{folder}';
        if (-not (Test-Path $folderPath)) {{
            Write-Host "Folder does not exist: $folderPath. Creating it.";
            New-Item -ItemType Directory -Path $folderPath -Force;
        }}
 
        try {{
            $acl = Get-Acl $folderPath;
            $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit;
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                "BUILTIN\\Users",
                [System.Security.AccessControl.FileSystemRights]::Modify,
                $inheritanceFlags,
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow
            );
            $acl.AddAccessRule($rule);
            Set-Acl -Path $folderPath -AclObject $acl;
            Write-Host "Successfully set permissions for '$folderPath' for BUILTIN\\Users.";
            # Removed the line that outputs ACL details to prevent unintended folder opening:
            # Get-Acl $folderPath | Select-Object Path, Owner, Group, AccessToString;
        }} catch {{
            Write-Error "Failed to set permissions for '$folderPath'. Error: $($_.Exception.Message)";
        }}
        """
 
        st_inf = subprocess.STARTUPINFO()
        st_inf.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        st_inf.wShowWindow = subprocess.SW_HIDE  # Hide the console window

        def update_permission(folder):
            try:
                Path(folder).mkdir(parents=True, exist_ok=True)
                ps_command = command_template.format(folder=folder)
                result = subprocess.run(
                    args=["powershell", "-noprofile", "-command", ps_command],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    startupinfo=st_inf,
                )
                if result.returncode != 0:
                    logger.warning(f"PowerShell error for {folder}: {result.stderr.decode()}")
                else:
                    logger.info(f"Permissions successfully updated for {folder}")
                return True
            except Exception as e:
                logger.error(f"Error updating permissions for {folder}: {e}", exc_info=True)
                return False

        def install_wazuh():
            try:
                print("wazhzhzhzh")
                startup_status_flag = install_module.Autostart(startup_flag)
                wazuh_download_url = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.0-1.msi"
                agent_msi_file = os.path.expandvars(r"%TEMP%\wazuh-agent.msi")
                wazuh_manager = "135.235.18.31"
                wazuh_agent_group = "default,Windows"
                wazuh_agent_name = socket.gethostname()  
                # Prepare startupinfo to hide console windows
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = subprocess.SW_HIDE
                print(wazuh_download_url,agent_msi_file,wazuh_manager,wazuh_agent_group,wazuh_agent_name)
                # Step 1: Download the MSI
                logger.info("Wazuh agent installation started.")
                print("Downloading Wazuh agent installer...")

                download_command = [
                    "powershell", "-ExecutionPolicy", "Bypass", "-Command",
                    f"Invoke-WebRequest -Uri \"{wazuh_download_url}\" -OutFile \"{agent_msi_file}\""
                ]
                download_result = subprocess.run(download_command, startupinfo=startupinfo)

                if download_result.returncode != 0 or not os.path.exists(agent_msi_file):
                    raise Exception("Wazuh agent MSI download failed or file missing.")

                # Step 2: Install MSI silently
                print("Installing Wazuh agent MSI silently...")

                msiexec_command = [
                    "msiexec.exe", "/i", agent_msi_file, "/qn",
                    f"WAZUH_MANAGER={wazuh_manager}",
                    f"WAZUH_AGENT_GROUP={wazuh_agent_group}",
                    f"WAZUH_AGENT_NAME={wazuh_agent_name}"
                ]
                install_result = subprocess.run(msiexec_command, startupinfo=startupinfo)
                print("Installation return code:", install_result.returncode)

                if install_result.returncode not in [0, 3010, 1641]:
                    raise Exception(f"MSI installation failed with code: {install_result.returncode}")
                elif install_result.returncode == 3010:
                    print("Installation succeeded but requires a reboot to complete.")

                # Step 3: Start Wazuh Agent service
                print("Starting WazuhSvc service...")
                subprocess.run(["NET", "START", "WazuhSvc"], shell=True, startupinfo=startupinfo)
                time.sleep(5)

                if not is_service_running("WazuhSvc"):
                    raise Exception("Wazuh Agent service is not running")

                # Step 4: Verify agent connection state
                agent_dir = get_agent_install_dir()
                state_file = os.path.join(agent_dir, "wazuh-agent.state")
                print(f"Checking agent state file: {state_file}")

                max_wait = 120  # seconds
                wait_interval = 5
                waited = 0
                connected = False

                if os.path.exists(state_file):
                    while waited < max_wait:
                        with open(state_file, "r") as f:
                            content = f.read()
                            if "connected" in content:
                                print("✅ Wazuh agent is connected to the manager.")
                                connected = True
                                break
                            elif "pending" in content:
                                print(f"Wazuh agent state is 'pending'... waiting {wait_interval}s.")
                        time.sleep(wait_interval)
                        waited += wait_interval

                    if not connected:
                        warning_msg = (
                            f"Wazuh agent state is still 'pending' after {max_wait} seconds.\n"
                            "Installation will continue, but the agent may not be fully registered yet."
                        )
                        print(warning_msg)
                        pyautogui.alert(text=warning_msg, title="Ebantis Installation")

                else:
                    raise Exception("State file not found. Agent may not be installed correctly.")

                logger.info("Wazuh agent installed and running successfully.")
                return startup_status_flag

            except Exception as e:
                logger.error(f"Wazuh installation failed: {str(e)}", exc_info=True)
                return False

        try:
            with concurrent.futures.ThreadPoolExecutor() as executor:
                # The main package is already downloaded AND extracted by download_main_package_with_extraction
                # in the previous step. No need to call extract_main or similar here.
                #future_extract_model = executor.submit(extract_model_package)
                permission_futures = [executor.submit(update_permission, folder) for folder in folders_to_modify]
                future_wazuh = executor.submit(install_wazuh)

                model_extracted = True
                permission_results = [f.result() for f in permission_futures]
                wazuh_status = future_wazuh.result()
                #installation_status = "installed" if wazuh_status and model_extracted else "failed"
                installation_status = "installed" if wazuh_status else "failed"
                
                # Use global tenant_id
                global GLOBAL_TENANT_ID
                tenant_id = GLOBAL_TENANT_ID if GLOBAL_TENANT_ID else get_tenant_id_from_json()
                branch_id = GLOBAL_BRANCH_ID if GLOBAL_BRANCH_ID else get_branch_id_from_json()
                if not tenant_id:
                    logger.error(f"Failed to get tenant_id")
                    self.progress_updated.emit(100, "Error: Failed to get tenant information.")
                    self.installation_complete.emit(False)
                    return
                
                upsert_installation_data(tenant_id, branch_id, model_extracted, wazuh_status, installation_status)
                count_modify_flag, message = update_installed_device_count(tenant_id)
                logger.info(f"Installed device count update: {count_modify_flag}, message: {message}")

           # if not model_extracted:
               # logger.error("Model extraction failed.")
                ##self.progress_updated.emit(100, "Error: Model extraction failed.")
                #self.installation_complete.emit(False)
                #return

            if not all(permission_results):
                logger.error("One or more folder permission updates failed.")
                self.progress_updated.emit(100, "Error: Permission update failed.")
                self.installation_complete.emit(False)
                return

            if not wazuh_status:
                logger.error("Wazuh agent installation failed.")
                self.progress_updated.emit(100, "Error: Wazuh agent installation failed.")
                self.installation_complete.emit(False)
                return
            self.progress_updated.emit(100, "Installation Completed")
            logger.info("Installation completed successfully.")
            time.sleep(INSTALLATION_SLEEP)
            self.installation_complete.emit(True)
        except Exception as e:
            logger.error(f"Error during installation finalization: {str(e)}", exc_info=True)
            self.progress_updated.emit(100, "Installation failed due to an unexpected error.")
            self.installation_complete.emit(False)
    

class InstallerUI(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.install_worker = InstallWorker()
        self.install_worker.progress_updated.connect(self.update_progress)
        self.install_worker.installation_complete.connect(self.on_installation_complete)
        self.installation_complete_shown = False

    def initUI(self):
        global progress_label, progress_bar, start_button, exit_button

        self.setWindowTitle('Ebantis Installation')
        self.setFixedSize(650, 350)
        layout = QVBoxLayout()

        progress_label = QLabel('Installation starting automatically...')
        layout.addWidget(progress_label, alignment=Qt.AlignmentFlag.AlignCenter)

        progress_bar = QProgressBar()
        progress_bar.setValue(0)
        layout.addWidget(progress_bar)

        button_layout = QHBoxLayout()

        exit_button = QPushButton('Exit')
        exit_button.setEnabled(False)  # Disabled until installation completes
        exit_button.clicked.connect(self.close)  # This will close the widget
        exit_button.clicked.connect(QApplication.instance().quit)  # Exit the application
        button_layout.addWidget(exit_button)

        layout.addLayout(button_layout)

        self.setLayout(layout)
        
        # Auto-start installation after UI is shown
        from PyQt6.QtCore import QTimer
        QTimer.singleShot(500, self.start_installation_process)  # Start after 500ms



    def start_installation_process(self, checked=None):
        # Initialize global tenant information from JWT token
        if not initialize_tenant_info():
            logger.error("Failed to initialize tenant information.")
            QMessageBox.critical(self, "Configuration Error", "Failed to initialize tenant information. Cannot proceed.")
            return
        
        # Use global variables
        global GLOBAL_TENANT_ID, GLOBAL_COMPANY_ID, GLOBAL_BRANCH_ID
        
        tenant_id = GLOBAL_TENANT_ID
        company_id = GLOBAL_COMPANY_ID
        branch_id = GLOBAL_BRANCH_ID
        
        
        logger.info(f"Starting installation - branch_id: {branch_id}, company_id: {company_id}, tenant_id: {tenant_id}")
        
        is_allowed, message = check_installation_allowed(branch_id)
        if not is_allowed:
            QMessageBox.critical(self, "Installation Blocked", message)
            self.close()
            return

        logger.info("Installation allowed. Proceeding to register the agent...")
        
        logger.info("Starting installation...")
        self.start_installation(tenant_id)

    def ask_tenant_name(self, checked):
        # This method is now deprecated - kept for reference only
        # The tenant name is hardcoded in start_installation_process
        pass

    def start_installation(self, tenant_id):
        # Proceed with the installation after obtaining the tenant ID
        self.install_worker.start()

    def update_progress(self, value, text):
        progress_bar.setValue(value)
        progress_label.setText(text)

    def on_installation_complete(self, success):
        if not self.installation_complete_shown:
            self.installation_complete_shown = True
            exit_button.setEnabled(True)
            msg_box = QMessageBox(self)
            msg_box.setWindowTitle("Ebantis Installation")
            if success:
                msg_box.setText("Installation has been completed successfully.")
                msg_box.setIcon(QMessageBox.Icon.Information)
                msg_box.buttonClicked.connect(self.exe_run)
            else:
                msg_box.setText("Installation failed. Please check the logs.")
                msg_box.setIcon(QMessageBox.Icon.Critical)
            #print("Showing message box")
            msg_box.exec()
            self.close()  # Close the current widget
            QApplication.instance().quit()  # Exit the application
    def exe_run(self, _=None):
        try:
            paths_to_check = [UTILS_PATH, UPDATE_FOLDER_PATH]  # List of directories to check

            for path in paths_to_check:
                if os.path.exists(path):  # Ensure the path exists
                    executables = [os.path.join(path, f) for f in os.listdir(path) if f.endswith('.exe')]

                    for exe in executables:
                        try:
                            os.startfile(exe)  # Start the executable
                            logger.info(f"Started executable: {exe}")
                        except Exception as e:
                            logger.error(f"Exception occurred while running {exe}: {e}", exc_info=True)
                else:
                    logger.warning(f"Path does not exist: {path}")  # Log if the folder is missing

        except Exception as e:
            logger.error("Error occurred in running executables", exc_info=True)

class OperationSelector(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Ebantis Setup")
        self.setFixedSize(400, 200)

        layout = QVBoxLayout()
        label = QLabel("Select the operation you want to perform:")
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(label)

        button_layout = QHBoxLayout()
        install_button = QPushButton("Installation")
        uninstall_button = QPushButton("Uninstallation")

        install_button.clicked.connect(self.launch_installation)
        uninstall_button.clicked.connect(self.launch_uninstallation)

        button_layout.addWidget(install_button)
        button_layout.addWidget(uninstall_button)
        layout.addLayout(button_layout)

        self.setLayout(layout)

    def launch_installation(self, checked=False):
        self.close()
        self.installer_ui = InstallerUI()
        self.installer_ui.show()

    def launch_uninstallation(self,checked=False):
        self.close()
        run_uninstallation()

def main():
    app = QApplication(sys.argv)
    # Skip OperationSelector - directly launch installation
    installer_ui = InstallerUI()
    installer_ui.show()
    sys.exit(app.exec())

#if __name__ == "__main__":
   # main()