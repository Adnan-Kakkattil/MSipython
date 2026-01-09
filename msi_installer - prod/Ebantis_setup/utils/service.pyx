# service.pyx

import base64
from libc.stdlib cimport malloc, free
from pathlib import Path
import os
import json
import socket
import requests
import sqlite3
import win32api
import subprocess
from encryption import decrypt_response
from utils.config import get_onboard_url, get_api_url, DB_PATH, machine_id, display_name, upn, email, user_name, hostname, get_register_url
from utils.config import logger

db_path = DB_PATH

def get_sqlite_connection():
    """
    Returns a connection to the SQLite database.
    """
    try:
        logger.info(f"Connecting to SQLite database at path: {db_path}")
        return sqlite3.connect(db_path)
    except Exception as e:
        logger.exception(f"Failed to connect to SQLite database: {e}")
        raise

cpdef dict connect_service():
    """
    Connects to an external service API using user details, retrieves credentials, decrypts them, 
    and stores them in a local SQLite database.
    """
    # Fetch credentials from the external API
    try:
        
        #tenant_name=get_tenant_name_from_json()
        api_url = get_api_url()
        headers = {
            "IsInternalCall": "true",
            "ClientId": "EbantisTrack"
        }
        # Fetch data from API
        #logger.info(f"Fetching credentials from API: {api_url} for tenant: {tenant_name}")
        response = requests.get(api_url, headers=headers, verify=True)
        data_list = response.json()
        if not data_list:
            logger.error("Empty response received from API.")
            raise ValueError("Empty response from API.")
        try:
            sqlite_con = get_sqlite_connection()
            db_cursor = sqlite_con.cursor()
            db_cursor.execute("""
                CREATE TABLE IF NOT EXISTS api_data (
                    id TEXT PRIMARY KEY,
                    data TEXT
                )
            """)
            sqlite_con.commit()

            db_cursor.execute("DELETE FROM api_data")
            sqlite_con.commit()

            db_cursor.execute("INSERT INTO api_data (id, data) VALUES (?, ?)", ("1", json.dumps(data_list)))
            sqlite_con.commit()
            logger.info("API credentials successfully stored in SQLite.")
        except Exception as e:
            logger.exception(f"Error while handling SQLite operations: {e}")
            raise

        finally:
            if db_cursor:
                db_cursor.close()
                logger.info("SQLite connection closed.")

        # Decrypt and return credentials
        encrypted_data = data_list.get('obfuscatedEncryptedData')
        decoded_data = decrypt_response(encrypted_data)
        if not decoded_data:
            logger.error("Missing credentials in API response.")
            raise ValueError("Missing credentials in API response.")
        logger.info("Credentials successfully decrypted.")
        return {key.lower(): value for key, value in decoded_data.items()}
    except requests.RequestException as e:
    
        logger.exception(f"Network error while fetching credentials: {e}")
        return None
    except Exception as e:
        logger.exception(f"Unexpected error during service connection: {e}")
        return None





cpdef dict user_onboarding(branch_id):
    """
    Registers the agent with the central API using machine & user details
    fetched from utils.config.
    """
    cdef str user_email

    try:

        
        user_onboarding_url = get_onboard_url()
        user_email = email if email is not None else ""

        # Prepare payload using values from utils.config
        payload={
            
            "userName": user_name,
            "email":user_email,
            "machineId": machine_id,
            "hostName": hostname,
            "displayName":display_name,
            "ipAddress": "10.244.9.42",
            "upnId": upn,
            "roleName": "Employee",
            "branchId": branch_id,
        }

        headers = {
            "Content-Type": "application/json",
            "IsInternalCall": "true",
            "ClientId": "EbantisTrack"
        }

        logger.info(f"User Onboarding at: {user_onboarding_url}")
        logger.info(f"Payload being sent: {payload}")

        response = requests.post(user_onboarding_url, json=payload, headers=headers, timeout=300)

        logger.info(f"User Onboarding API returned status: {response.status_code}")

        # If success (2xx)
        if response.status_code >= 200 and response.status_code < 300:
            try:
                return response.json()
            except Exception:
                return {"status": "success", "raw_response": response.text}

        # Non-success
        logger.error(f"user Onboarding API error: {response.text}")
        return None

    except Exception as e:
        logger.exception(f"Unexpected error in user_onboarding: {e}")
        return None












cpdef dict register_agent(tenant_id):
    """
    Registers the agent with the central API using machine & user details
    fetched from utils.config.
    """

    try:

        register_url = get_register_url()

        # Prepare payload using values from utils.config
        payload = {
            "machine_id": machine_id,
            "hostname": hostname,
            "display_name":display_name,
            "email": email,
            "upn": upn,
            "username": user_name,
            "tenant_id": tenant_id
        }

        headers = {
            "Content-Type": "application/json",
            "IsInternalCall": "true",
            "ClientId": "EbantisTrack"
        }

        logger.info(f"Registering agent at: {register_url}")
        logger.info(f"Payload being sent: {payload}")

        response = requests.post(register_url, json=payload, headers=headers, timeout=300)

        logger.info(f"Register Agent API returned status: {response.status_code}")

        # If success (2xx)
        if response.status_code >= 200 and response.status_code < 300:
            try:
                return response.json()
            except Exception:
                return {"status": "success", "raw_response": response.text}

        # Non-success
        logger.error(f"Register Agent API error: {response.text}")
        return None

    except Exception as e:
        logger.exception(f"Unexpected error in register_agent: {e}")
        return None



