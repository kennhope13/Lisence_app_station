import os

def find_dlls():
    dlls_dir = r"d:\Anh_Tung\Phần mềm\License\extracted_dlls"
    target_terms = [b"ValidateAndRetrieveLicenseDetails", b"ValidateLicense", b"LicenseController", b"appsettings.json"]
    
    for file in os.listdir(dlls_dir):
        if not file.endswith(".dll"):
            continue
        file_path = os.path.join(dlls_dir, file)
        try:
            with open(file_path, "rb") as f:
                data = f.read()
                
            for term in target_terms:
                if term in data:
                    print(f"Found term '{term.decode()}' in {file}")
                    # Let's print the size and a few surrounding bytes if possible, or just the file name
        except Exception as e:
            pass

if __name__ == "__main__":
    find_dlls()
