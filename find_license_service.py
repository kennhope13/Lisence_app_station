import os

def find_license_service():
    target_dlls = ["extracted_370.dll", "extracted_92.dll", "extracted_93.dll", "extracted_94.dll"]
    dlls_dir = r"d:\Anh_Tung\Phần mềm\License\extracted_dlls"
    
    terms = [b"LicenseService", b"ILicenseService", b"VerifyLicense", b"DecodeLicense", b"decrypt", b"Decrypt"]
    
    for filename in target_dlls:
        file_path = os.path.join(dlls_dir, filename)
        if not os.path.exists(file_path):
            continue
        try:
            with open(file_path, "rb") as f:
                data = f.read()
            print(f"\n--- {filename} ---")
            for term in terms:
                if term in data:
                    print(f"  Found term: {term.decode()}")
        except Exception as e:
            print(f"Error reading {filename}: {e}")

if __name__ == "__main__":
    find_license_service()
