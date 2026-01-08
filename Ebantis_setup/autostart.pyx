import wmi
 
import os
 
import time
 
from win32com.client import Dispatch
 
import winreg as reg
 
from datetime import datetime
 
from utils.config import logger
 
 
# -------------------------------------------------------------------
 
#  CONSTANT PATHS
 
# -------------------------------------------------------------------
 
MAIN_FOLDER = r"C:\Program Files\EbantisV4\data\EbantisV4"
 
TARGET_EXE = os.path.join(MAIN_FOLDER, "EbantisV4.exe")
 
AUTO_UPDATE_EXE = os.path.join(MAIN_FOLDER, "AutoUpdationService.exe")
 
STARTUP_FOLDER = r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
 
 
# -------------------------------------------------------------------
 
#  TERMINATE PROCESS BY NAME
 
# -------------------------------------------------------------------
 
def terminate_process(process_name):
 
    try:
 
        f = wmi.WMI()
 
        terminated = False
 
        for p in f.Win32_Process():
 
            if p.Name.lower() == process_name.lower():
 
                p.Terminate()
 
                logger.info(f"Terminated process: {process_name}")
 
                terminated = True
 
        if not terminated:
 
            logger.info(f"No running instance found for: {process_name}")
 
        return terminated
 
    except Exception as e:
 
        logger.error(f"Error terminating {process_name}: {e}", exc_info=True)
 
        return False
 
 
# -------------------------------------------------------------------
 
#  START EXE
 
# -------------------------------------------------------------------
 
def start_exe(exe_path):
 
    try:
 
        if not os.path.exists(exe_path):
 
            logger.error(f"Executable not found: {exe_path}")
 
            return False
 
        os.startfile(exe_path)
 
        logger.info(f"Started: {exe_path}")
 
        return True
 
    except Exception as e:
 
        logger.error(f"Error starting {exe_path}: {e}", exc_info=True)
 
        return False
 
 
# -------------------------------------------------------------------
 
#  ADD BOTH EXES TO WINDOWS STARTUP
 
# -------------------------------------------------------------------
 
def add_to_startup():
 
    try:
 
        shell = Dispatch("WScript.Shell")
 
        # Remove only EbantisV4 and AutoUpdationService shortcuts
 
        shortcuts_to_remove = ["EbantisV4.lnk", "AutoUpdationService.lnk"]
 
        for shortcut_name in shortcuts_to_remove:
 
            full_path = os.path.join(STARTUP_FOLDER, shortcut_name)
 
            if os.path.exists(full_path):
 
                try:
 
                    os.remove(full_path)
 
                    logger.info(f"Removed old startup shortcut: {shortcut_name}")
 
                except Exception as e:
 
                    logger.warning(f"Could not remove {shortcut_name}: {e}")
 
        # EbantisV4 shortcut
 
        ebantis_shortcut = shell.CreateShortCut(
 
            os.path.join(STARTUP_FOLDER, "EbantisV4.lnk")
 
        )
 
        ebantis_shortcut.Targetpath = TARGET_EXE
 
        ebantis_shortcut.WorkingDirectory = MAIN_FOLDER
 
        ebantis_shortcut.save()
 
        # AutoUpdation shortcut
 
        autoupdate_shortcut = shell.CreateShortCut(
 
            os.path.join(STARTUP_FOLDER, "AutoUpdationService.lnk")
 
        )
 
        autoupdate_shortcut.Targetpath = AUTO_UPDATE_EXE
 
        autoupdate_shortcut.WorkingDirectory = MAIN_FOLDER
 
        autoupdate_shortcut.save()
 
        logger.info("Startup entries added for EbantisV4 and AutoUpdation.")
 
        return True
 
    except Exception as e:
 
        logger.error(f"Error adding startup entries: {e}", exc_info=True)
 
        return False
 
 
# -------------------------------------------------------------------
 
#  MAIN AUTOSTART FUNCTION
 
# -------------------------------------------------------------------
 
def Autostart(startup_flag=False):
 
    logger.info("=== Autostart Process Started ===")
 
    try:
 
        # 1. Kill existing processes
 
        terminate_process("EbantisV4.exe")
 
        terminate_process("AutoUpdationService.exe")
 
        time.sleep(2)
 
        # 2. Start processes
 
        ebantis_started = start_exe(TARGET_EXE)
 
        updater_started = start_exe(AUTO_UPDATE_EXE)
 
        # 3. Add to startup if both started successfully
 
        if ebantis_started and updater_started:
 
            startup_flag = add_to_startup()
 
            if startup_flag:
 
                logger.info("EbantisV4 and AutoUpdation successfully configured for autostart.")
 
        else:
 
            startup_flag = False
 
    except Exception as e:
 
        logger.error(f"Autostart error: {e}", exc_info=True)
 
        startup_flag = False
 
    logger.info("=== Autostart Process Finished ===")
 
    return startup_flag
 
 
 