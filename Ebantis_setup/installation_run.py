import ctypes
import sys

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except (AttributeError, OSError):
        return False

if __name__ == "__main__":
    try:
        if is_admin():
            # Only now import logger, after admin elevation
            from utils.config import logger
            logger.info("Running with administrative privileges.")

            # Import and execute main installation logic
            from installation import main
            logger.info("Starting Ebantis installer/uninstaller process...")
            main()
        else:
            # Relaunch the same EXE with admin privileges
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, " ".join(sys.argv), None, 1
            )
            # Optional: print/log before logger is available
            print("Elevation requested via ShellExecuteW.")

    except Exception as e:
        # If logger not imported yet, fallback to print
        try:
            logger.error(f"Fatal error in setup launcher: {e}", exc_info=True)
        except NameError:
            print(f"Fatal error in setup launcher: {e}")
