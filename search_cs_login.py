import os
import re

def search_dlls():
    dll_dir = r"d:\Anh_Tung\Phần mềm\License\extracted_dlls"
    files = [f for f in os.listdir(dll_dir) if f.endswith(".dll")]
    
    # We look for binary patterns or strings
    # "licenseInfo" or "licenseKey" or "LicenseKey" or "LicenseInfo"
    patterns = [
        b"licenseInfo", b"LicenseInfo",
        b"licenseKey", b"LicenseKey",
        b"MaxConcurrentSessions"
    ]
    
    for filename in files:
        file_path = os.path.join(dll_dir, filename)
        try:
            with open(file_path, "rb") as f:
                content = f.read()
        except Exception as e:
            continue
            
        found = []
        for pat in patterns:
            if pat in content:
                found.append(pat.decode())
                
        if found:
            print(f"File {filename} matches: {found}")

if __name__ == "__main__":
    search_dlls()
