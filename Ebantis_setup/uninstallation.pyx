# -----------------------------
# Standard Imports
# -----------------------------

import os
import shutil
import time
import json
import ctypes
import socket
import sqlite3
import subprocess
import winreg
import pymongo
import certifi
import urllib3

urllib3.disable_warnings()

from utils.config import UPDATE_FOLDER_PATH, UTILS_PATH, PROGRAM_DATA_PATH, PROGRAM_FILES_PATH, STARTUP_FOLDER, DB_PATH, logger
from encryption import decrypt_response


# -----------------------------
# SQLite Helper
# -----------------------------
def get_sqlite_connection():
    sqlite_db_path = DB_PATH
    return sqlite3.connect(sqlite_db_path)

def get_wazuh_product_code():
    try:
        reg_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path) as uninstall_key:
            for i in range(winreg.QueryInfoKey(uninstall_key)[0]):
                subkey_name = winreg.EnumKey(uninstall_key, i)
                try:
                    with winreg.OpenKey(uninstall_key, subkey_name) as subkey:
                        display_name, _ = winreg.QueryValueEx(subkey, "DisplayName")
                        if "Wazuh Agent" in display_name:
                            return subkey_name
                except FileNotFoundError:
                    pass
    except Exception as e:
        logger.error(f"Error getting Wazuh product code: {e}", exc_info=True)
    return None

# -----------------------------
# Collect Credentials
# -----------------------------
cdef dict collect_credentials():
    cdef dict dec_data_lower = {}
    sqlite_con = None
    db_cursor = None
    try:
        sqlite_con = get_sqlite_connection()
        db_cursor = sqlite_con.cursor()
        credential = sqlite_con.execute("SELECT * FROM api_data WHERE id = 1").fetchone()
        json_string = credential[1]
        credential_data = json.loads(json_string)
        encr_data = credential_data.get('obfuscatedEncryptedData', None)
        dec_data = decrypt_response(encr_data)
        dec_data_lower = {key.lower(): value for key, value in dec_data.items()}
        logger.info("Successfully decoded API credentials from DB.")
        return dec_data_lower
    except Exception as e:
        logger.error(f"Error decoding data from database: {e}", exc_info=True)
        return dec_data_lower
    finally:
        if db_cursor:
            db_cursor.close()
        if sqlite_con:
            sqlite_con.close()

# -----------------------------
# Update MongoDB Record
# -----------------------------
cdef bint uninstall_record():
    cdef dict json_cred_data
    cdef object mongo_client
    cdef object mydb
    cdef object mycol
    cdef dict query
    cdef dict result
    cdef str hostname = socket.gethostname()

    try:
        json_cred_data = collect_credentials()
        mongoconnectionstring = json_cred_data.get("mongoconnectionstring", None)
        mongo_client = pymongo.MongoClient(mongoconnectionstring, tlsCAFile=certifi.where())
        mydb = mongo_client['EbantisV3']
        mycol = mydb["installed_users"]

        query = {"hostname": hostname}
        result = mycol.find_one(query)

        if result:
            mycol.update_one({"hostname": hostname}, {"$set": {"status": "Uninstalled"}}, upsert=True)
            logger.info(f"Status updated to 'Uninstalled'. Hostname: {hostname}")
        else:
            logger.warning(f"No matching record found. Status not updated. Hostname: {hostname}")

        mongo_client.close()
    except Exception as e:
        logger.error(f"Uninstall record error: {e}", exc_info=True)
        return False
    return True

# -----------------------------
# Remove a file/folder
# -----------------------------
cpdef bint remove(str path):
    try:
        End_task()
        if os.path.isfile(path) or os.path.islink(path):
            os.remove(path)
            logger.info(f"Removed file: {path}")
        elif os.path.isdir(path):
            shutil.rmtree(path)
            logger.info(f"Removed directory: {path}")
    except Exception as e:
        logger.error(f"Remove error: {e}", exc_info=True)
        return False
    return True

# -----------------------------
# Thread Helper Functions
# -----------------------------
cdef void kill_processes_thread(str path):
    if os.path.exists(path) and os.path.isdir(path):
        for exe in os.listdir(path):
            if exe.lower().endswith('.exe'):
                subprocess.run(['taskkill', '/IM', exe, '/F'], creationflags=0x08000000)
                logger.info(f"Ended process: {exe}")

cdef void remove_shortcut_thread(str shortcut, str startup_folder):
    shortcut_path_local = os.path.join(startup_folder, shortcut)
    if os.path.exists(shortcut_path_local):
        os.remove(shortcut_path_local)
        logger.info(f"Removed shortcut: {shortcut}")

# -----------------------------
# End Task Function
# -----------------------------
cpdef bint End_task():
    from threading import Thread
    cdef list threads = []
    try:
        t1 = Thread(target=kill_processes_thread, args=(UTILS_PATH,))
        t1.start()
        threads.append(t1)

        t2 = Thread(target=kill_processes_thread, args=(UPDATE_FOLDER_PATH,))
        t2.start()
        threads.append(t2)

        for t in threads:
            t.join()
        logger.info("End_task completed successfully.")
    except Exception as e:
        logger.error(f"Error ending task: {e}", exc_info=True)
        return False
    return True

# -----------------------------
# Uninstall Wazuh Agent
# -----------------------------
cpdef bint uninstall_wazuh():
    try:
        logger.info("Starting Wazuh uninstallation...")
        product_code = get_wazuh_product_code() or "{45F86F88-FE8F-4F39-90B6-BA91CFC9FADC}"
        uninstall_command = ["msiexec.exe", "/x", product_code, "/qn", "/norestart"]

        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE

        result = subprocess.run(uninstall_command, startupinfo=startupinfo)
        if result.returncode not in [0, 3010, 1605, 1614]:
            logger.error(f"Wazuh uninstallation failed with exit code: {result.returncode}")
            return False

        subprocess.run(["NET", "STOP", "WazuhSvc"], shell=True, startupinfo=startupinfo)
        logger.info("Wazuh agent uninstallation completed successfully.")
        return True
    except Exception as e:
        logger.error(f"Error during Wazuh uninstallation: {e}", exc_info=True)
        return False

# -----------------------------
# Remove Startup Shortcuts
# -----------------------------
cpdef bint remove_startup_file():
    from threading import Thread
    cdef list threads = []
    cdef list exe_names = []

    try:
        for path in [UTILS_PATH, UPDATE_FOLDER_PATH]:
            if os.path.exists(path):
                for exe in os.listdir(path):
                    if exe.lower().endswith('.exe'):
                        exe_names.append(os.path.splitext(exe)[0] + '.lnk')

        for shortcut in os.listdir(STARTUP_FOLDER):
            if shortcut in exe_names:
                t = Thread(target=remove_shortcut_thread, args=(shortcut, STARTUP_FOLDER))
                t.start()
                threads.append(t)

        for t in threads:
            t.join()
        logger.info("Startup shortcut removal completed.")
    except Exception as e:
        logger.error(f"Startup shortcut removal error: {e}", exc_info=True)
        return False
    return True

# -----------------------------
# Show Alert Box
# -----------------------------
cpdef int show_alert(str message, str title, bint is_confirmation=False):
    try:
        if is_confirmation:
            return ctypes.windll.user32.MessageBoxW(0, message, title, 1)
        else:
            ctypes.windll.user32.MessageBoxW(0, message, title, 0)
    except Exception as e:
        logger.error(f"Error displaying alert: {e}", exc_info=True)
        return 0

# -----------------------------
# Main Uninstallation Function
# -----------------------------
cpdef void run_uninstallation():
    cdef int success_count = 0
    cdef int total_steps = 6

    user_response = show_alert(
        "Are you sure you want to uninstall Ebantis? Click 'OK' to confirm or 'Cancel' to abort.",
        "Ebantis Alert",
        is_confirmation=True
    )

    if user_response == 2:
        show_alert("Uninstallation cancelled by the user.", "Ebantis Alert")
        logger.info("Uninstallation cancelled by the user.")
        return

    if os.path.exists(PROGRAM_FILES_PATH) and os.path.exists(PROGRAM_DATA_PATH):
        logger.info("Starting uninstallation process...")
        if End_task():
            time.sleep(3)
            success_count += 1

        if remove(PROGRAM_FILES_PATH):
            success_count += 1

        if remove_startup_file():
            success_count += 1

        if uninstall_wazuh():
            success_count += 1

        if uninstall_record():
            success_count += 1

        if remove(PROGRAM_DATA_PATH):
            success_count += 1

        if success_count == total_steps:
            show_alert("Ebantis uninstallation process completed without any errors.", "Ebantis Alert")
            logger.info("Uninstallation completed successfully.")
        else:
            show_alert("Please run the uninstallation again, some errors occurred.", "Ebantis Alert")
            logger.warning(f"Uninstallation completed with some errors. Success count: {success_count}/{total_steps}")
    else:
        show_alert("Ebantis is not installed on this system.", "Ebantis Alert")
        logger.warning("Ebantis is not installed on this system.")
