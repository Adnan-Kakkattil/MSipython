import requests
import json
import time
import socket
import zipfile
import shutil
import os
import subprocess
import win32service
import win32serviceutil
import win32event

class UpdaterService(win32serviceutil.ServiceFramework):
    _svc_name_ = "UpdaterServiceEbantisV3"
    _svc_display_name_ = "Updater Service for Ebantis V3"
    _svc_description_ = "This service checks for updates and automatically downloads and installs them."
    def __init__(self, args):
        # if not args:
        #     args = ["AutoUpdaterServiceEbantisV3"]  # Providing a default name for testing
        # self.tenant_name = None
        # self.host = None
        # self.stop_requested = False
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.service_stopped = False
        self.stop_requested = False
    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.stop_event)
        self.service_stopped = True
        
    def SvcDoRun(self):

        while not self.service_stopped:
            try:
                # Main logic of the updater service
                self.run_updater()
            except Exception as e:
                print(f"Error in AutoUpdaterService: {e}")
            time.sleep(60)  # Poll every 60 seconds

        print("AutoUpdaterService has stopped.")
    
    def run_updater(self):
        self.tenant_name = self.get_tenant_name_from_json()
        self.host = socket.gethostname()
        while not self.stop_requested:
            try:
                self.update_check_and_run()
                time.sleep(60)  # Check for updates every 5 minutes
            except Exception as e:
                print("Error in updater loop: %s", str(e))
                time.sleep(60)  # Retry after 1 minute

    def get_tenant_name_from_json(self):
        try:
            json_file_path = r"C:\ProgramData\EbantisV3\tenant_info\tenant_details.json"
            with open(json_file_path, "r") as file:
                tenant_data = json.load(file)
            tenant_name = tenant_data["tenant_name"]
            return tenant_name.lower()
        except Exception as e:
            print("Error while reading tenant name:")
            raise

    def update_check_and_run(self):
        try:
            latest_version=""
            url = f"https://ebantisaiv3api.thekosmoz.com/api/v1.0/GetVersionInfo/?tenant_name={self.tenant_name}&system_name={self.host}&update_status=False&version_installed={latest_version}"

            # url = f"https://ebantisaiv3api.ebantis.com/api/v1.0/GetVersionInfo/?tenant_name={self.tenant_name}&system_name={self.host}&update_status=False&version_installed={latest_version}"
            response = requests.get(url, verify=True)
            response.raise_for_status()
            version_detail = response.json()

            if not version_detail:
                print("Empty response from API.")
                return

            latest_version = version_detail["latest_cloud_version_id"]
            current_version = version_detail["local_version_installed"]

            if latest_version != current_version:
                print("Update available: %s -> %s", current_version, latest_version)
                if self.download_and_replace():
                    if self.write_version_to_db(latest_version, True):
                        print("Updated to version %s successfully.", latest_version)
                    else:
                        print("Failed to update version in database.")
                else:
                    print("Failed to download and replace files.")
            else:
                print("No updates available. Current version: %s", current_version)

        except requests.exceptions.RequestException as e:
            print("Error fetching version information: %s", e)
        except Exception as e:
            print("Unexpected error during update check:")
    def start_executables(self, installed_utils_path):
        print("Starting executables...:%s",installed_utils_path)
        try:
            installed_utils_path= os.path.join(installed_utils_path, "utils")
            process_name = os.listdir(installed_utils_path)
            process_name = list(filter(lambda x: x.endswith('.exe'), process_name))
            
            for executable in process_name:
                try:
                    executables=installed_utils_path+'/'+executable
                    
                    try:
                        os.startfile(executables) 
                    except:pass
                except:pass
        except Exception as e:
           print("Unexpected error while starting executables:")

    def download_and_replace(self):
        api_url = "https://ebantisaiv3api.thekosmoz.com/api/v1.0/DownloadLatestversion"

        # api_url = "https://ebantisaiv3api.ebantis.com/api/v1.0/DownloadLatestversion"
        download_path = r"C:\Program Files\EbantisV3\data\downloaded_version.zip"
        extract_path = r"C:\Program Files\EbantisV3\data"
        installed_utils_path = r"C:\Program Files\EbantisV3\data\ebantisV3"
        os.makedirs(os.path.dirname(download_path), exist_ok=True)
        os.makedirs(extract_path, exist_ok=True)

        try:
            self.end_task(installed_utils_path)
            # Download the file
            print("Downloading update...")
            with requests.post(api_url, stream=True) as response:
                response.raise_for_status()
                with open(download_path, "wb") as file:
                    for chunk in response.iter_content(chunk_size=8192):
                        file.write(chunk)
            print("Downloaded successfully.")

            # Check if the downloaded file is a valid ZIP file
            if not zipfile.is_zipfile(download_path):
                print("Downloaded file is not a valid ZIP file: %s", download_path)
                os.remove(download_path)
                return False

            # Remove the existing directory
            if os.path.exists(installed_utils_path):
                print("Removing existing installation directory...")
                shutil.rmtree(installed_utils_path)

            # Extract the ZIP file
            print("Extracting update...")
            with zipfile.ZipFile(download_path, "r") as zip_ref:
                members = zip_ref.namelist()

                # Detect if there's an unnecessary root directory
                root_dir = os.path.commonpath(members)
                if root_dir in members and len(root_dir) > 0:
                    for member in members:
                        target_path = os.path.join(extract_path, os.path.relpath(member, root_dir))
                        zip_ref.extract(member, extract_path)
                else:
                    zip_ref.extractall(extract_path)
            print("Extracted successfully.")

            # Start executables
            self.start_executables(installed_utils_path)
            print("Files replaced successfully.")
            return True
        except requests.exceptions.RequestException as e:
            print("Error downloading update: %s", e)
        except zipfile.BadZipFile as e:
            print("Error extracting update: %s", e)
        except Exception as e:
            print("Unexpected error during download and replace:")
        return False

    def end_task(self, installed_utils_path):
        print("Terminating running processes...")
        try:
            installed_utils_path= os.path.join(installed_utils_path, "utils")
            for name in os.listdir(installed_utils_path):
                if name.endswith('.exe'):
                    subprocess.run(['taskkill', '/IM', name, '/F'], creationflags=subprocess.CREATE_NO_WINDOW, check=True)
                    print("Terminated process: %s", name)
        except Exception as e:
            print("Unexpected error while terminating processes:")

    def write_version_to_db(self, latest_version, update_status):
        try:
            url = f"https://ebantisaiv3api.thekosmoz.com/api/v1.0/GetVersionInfo/?tenant_name={self.tenant_name}&system_name={self.host}&update_status={update_status}&version_installed={latest_version}"

            # url = f"https://ebantisaiv3api.ebantis.com/api/v1.0/GetVersionInfo/?tenant_name={self.tenant_name}&system_name={self.host}&update_status={update_status}&version_installed={latest_version}"
            response = requests.get(url, verify=True)
            response.raise_for_status()
            return True  # Indicate success
        except requests.exceptions.RequestException as e:
            print("Error updating version in database: %s", e)
        except Exception as e:
            print("Unexpected error while updating version in database:")
        return False  # Indicate failure

# # Test the service logic without installing it
# def test_service():
#     """ Function to test the service logic directly without installing it """
#     try:
#         # Directly initialize the class without using win32serviceutil
#         service = AutoUpdaterService([])  # Empty args for testing purposes
#         service.run_updater()  # Simulate the updater logic
#     except Exception as e:
#         logging.error("Error during service test: %s", e)

# if __name__ == "__main__":
#     # Test the service logic
#     test_service()
if __name__ == "__main__":
    import sys
    if len(sys.argv) == 1:
        print("Usage: python AutoUpdaterServiceEbantisV3.py [install | start | stop | remove | debug]")
    else:
        win32serviceutil.HandleCommandLine(UpdaterService)