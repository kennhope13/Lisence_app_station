import os

def find_services_dll():
    dlls_dir = r"d:\Anh_Tung\Phần mềm\License\extracted_dlls"
    
    for file in os.listdir(dlls_dir):
        if not file.endswith(".dll"):
            continue
        file_path = os.path.join(dlls_dir, file)
        try:
            with open(file_path, "rb") as f:
                data = f.read()
            
            # Look for the assembly name string "StationMonitor.Services"
            # It will be in ASCII or UTF-16
            if b"StationMonitor.Services" in data:
                print(f"File {file} contains 'StationMonitor.Services'")
        except:
            pass

if __name__ == "__main__":
    find_services_dll()
