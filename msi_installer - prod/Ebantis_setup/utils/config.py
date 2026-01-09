from datetime import datetime
import os
import json
import platform
import subprocess
import time
import socket
from pathlib import Path
from loguru import logger
user_name = os.getlogin()
hostname=socket.gethostname()
PROGRAM_FILES_PATH = r"C:/Program Files/EbantisV4"
PROGRAM_DATA_PATH = r"C:/ProgramData/EbantisV4"
Path(PROGRAM_FILES_PATH).mkdir(parents=True, exist_ok=True)
Path(PROGRAM_DATA_PATH).mkdir(parents=True, exist_ok=True)
# LOG_FOLDER = r"D:\EbantisSetup"
LOG_FOLDER = os.getcwd()

CLOUD_DOWNLOAD_API = "https://qaebantisapiv4.thekosmoz.com/DownloadLatestversion"
# CLOUD_DOWNLOAD_API = "https://ebantisaiv3api.thekosmoz.com/api/v1.0/DownloadLatestversion"
UPDATE_FOLDER_PATH = os.path.join(PROGRAM_FILES_PATH, "data", "EbantisV4", "update")
UPDATION_DIREC = os.path.join(PROGRAM_FILES_PATH, "data")
EXE_DIREC = os.path.join(PROGRAM_FILES_PATH, "data","EbantisV4")
UTILS_PATH = os.path.join(PROGRAM_FILES_PATH, "data", "EbantisV4","utils")
USERS_FOLDER = os.path.join(PROGRAM_DATA_PATH,"user_collection")
MODEL_FOLDER = os.path.join(UPDATION_DIREC,"Model")
MODEL_ZIP = os.path.join(UPDATION_DIREC,"model.zip")
ONNX_FOLDER= os.path.join(UTILS_PATH,"onnx")

DATA_FILE_PATH = os.path.join(PROGRAM_DATA_PATH, "Ebantisv4.zip")
STARTUP_FOLDER = r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
DATA_DIR = os.path.join(USERS_FOLDER, user_name)
DB_PATH = os.path.join(DATA_DIR, "tracking_system.db")
TRANSACTION_ID_FILE = os.path.join(DATA_DIR, "transaction_id.json")
folder_path = os.path.join(PROGRAM_DATA_PATH, "tenant_info")
json_file_path = os.path.join(folder_path, "tenant_details.json")
DOWNLOAD_ZIP_PATH = os.path.join(PROGRAM_FILES_PATH,"data","downloaded_version")

directories = [
    folder_path,
    USERS_FOLDER,
    DATA_DIR,
    ONNX_FOLDER
]

# Ensure all directories exist
for directory in directories:
    Path(directory).mkdir(parents=True, exist_ok=True)

# Create tenant JSON file if it doesn't exist
Path(json_file_path).touch(exist_ok=True)




AUTO_START_SLEEP = 20
INSTALLATION_SLEEP = 1
def get_machine_id():
        if platform.system() == 'Windows':
            try:
                result = subprocess.check_output('wmic csproduct get uuid', shell=True, stderr=subprocess.DEVNULL)
                print("result ",result)
                uuid = result.decode().split('\n')[1].strip()
                if uuid and uuid.lower() != 'uuid':
                    return uuid
            except:
                pass
        import uuid
        mac = uuid.getnode()
        return __import__('hashlib').sha256(str(mac).encode()).hexdigest()[:32]
 

 
def get_display_name():
    if platform.system() == 'Windows':
        try:
            result = subprocess.check_output('whoami /user', shell=True, stderr=subprocess.DEVNULL)
            output = result.decode(errors="ignore").splitlines()

            # Find the line containing domain\username (contains a backslash)
            for line in output:
                line = line.strip()
                if "\\" in line:   # example: azuread\afnamohammed S-1-...
                    first_part = line.split()[0]  # "azuread\afnamohammed"
                    return first_part.split("\\")[-1]  # "afnamohammed"

        except Exception as e:
            print("Error:", e)

    return None

 
def get_upn():
    if platform.system() == 'Windows':
        try:
            result = subprocess.check_output('whoami /upn', shell=True, stderr=subprocess.DEVNULL)
            upn = result.decode().strip()
            if upn and '@' in upn:
                return upn
        except:
            pass
    return ''
def get_user_email():
    """
    Retrieves the user's email (UPN) using Win32 API and fallback PowerShell.
    """
    try:
        # Try Win32API first (format: user@domain)
        user_email = win32api.GetUserNameEx(8)
        if user_email:
            return user_email
    except:
        pass

    # Fallback: PowerShell WHOAMI /UPN
    try:
        st_inf = subprocess.STARTUPINFO()
        st_inf.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        proc = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-command",
                "whoami /upn"
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            startupinfo=st_inf,
            shell=False
        )

        output = proc.stdout.decode().strip()

        # If WHOAMI returned nothing, treat as no email
        if not output:
            logger.error("WHOAMI returned empty output. Cannot fetch email.")
            return None

        # If output contains JSON (rare), attempt to load; else keep as raw string
        if output.startswith("{") or output.startswith("["):
            try:
                return json.loads(output)
            except:
                return output

        return output

    except Exception as e:
        logger.exception(f"Exception in get_user_email: {e}")
        return None


machine_id=get_machine_id()
display_name=get_display_name()
upn=get_upn()
email=get_user_email()
print("machine_id,display_name,upn,email",machine_id,display_name,upn,email)
def get_tenant_id_from_json():
    try:
        # Open and load the JSON data
        with open(json_file_path, "r") as file:
            tenant_data = json.load(file)
        tenant_id = tenant_data.get("tenant_id", None)
        
        if tenant_id is None:
            raise ValueError("No tenant_id found in the JSON file.")
        
        return tenant_id
    except FileNotFoundError:
        raise FileNotFoundError(f"File not found: {json_file_path}")
    except json.JSONDecodeError:
        raise ValueError("Error decoding JSON from the file.")
    except Exception as e:
        print("Exception occured: ",e)

def get_branch_id_from_json():
    try:
        # Open and load the JSON data
        with open(json_file_path, "r") as file:
            branch_id = json.load(file)
        branch_id = branch_id.get("branch_id", None)
        
        if branch_id is None:
            raise ValueError("No branch_id found in the JSON file.")
        
        return branch_id
    except FileNotFoundError:
        raise FileNotFoundError(f"File not found: {json_file_path}")
    except json.JSONDecodeError:
        raise ValueError("Error decoding JSON from the file.")
    except Exception as e:
        print("Exception occured: ",e)

def get_api_url():
    tenant_name = get_tenant_name_from_json()
    #return f'https://qaebantisaiv3api.ebantis.com/api/v1.0/get-env-values?tenant_name={tenant_name}'
    #return f'https://qatrackerservice.metlone.com/api/v1/Connection/GetAllConnections?tenant={tenant_name}'
    return f'https://ebantistrackapi.metlone.com/api/v1/Connection/GetAllConnections?tenant={tenant_name}'

def get_register_url():
    return f'https://ebantisapiv4.thekosmoz.com/register-agent'




def get_onboard_url():
    return f'https://ebantisapiv4.thekosmoz.com/user_onboard/'



# def setup_logger():
#     # For a frozen exe, use sys.executable; fallback to script dir
#     # exe_dir = os.path.dirname(sys.executable) if getattr(sys, "frozen", False) else os.path.dirname(os.path.abspath(__file__))
#     Path(LOG_FOLDER).mkdir(parents=True, exist_ok=True)
 
#     # Construct log file path like EbantisTracker_2025-10-15.log
#     log_filename = f"Ebantis_setup_{time.strftime('%Y-%m-%d')}.log"
#     log_file_path = os.path.join(LOG_FOLDER, log_filename)
 
#     # logger.remove()  # remove default console handler
#     logger.add(
#         log_file_path,
#         level="INFO",
#         enqueue=True,      # async/thread-safe
#         backtrace=True,
#         diagnose=True,
#         format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {message}"
#     )
 
#     logger.info(f"Logging initialized at: {log_file_path,}")
#     return logger



def setup_logger():
    # For a frozen exe, use sys.executable; fallback to script dir
    # exe_dir = os.path.dirname(sys.executable) if getattr(sys, "frozen", False) else os.path.dirname(os.path.abspath(__file__))
    Path(LOG_FOLDER).mkdir(parents=True, exist_ok=True)
 
    # Construct log file path like EbantisTracker_2025-10-15.log
    log_filename = f"Ebantis_setup_{time.strftime('%Y-%m-%d')}.log"
    log_file_path = os.path.join(LOG_FOLDER, log_filename)
 
    # logger.remove()  # remove default console handler
    logger.add(
        log_file_path,
        level="INFO",
        rotation="00:00",

        enqueue=True,      # async/thread-safe
        backtrace=True,
        diagnose=True,
        format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {message}"
    )
 
    logger.info(f"Logging initialized at: {log_file_path,}")
    return logger
 
# Initialize once
logger = setup_logger()
 