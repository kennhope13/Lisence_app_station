import os
import re

def find_assembly_name(file_path):
    with open(file_path, "rb") as f:
        data = f.read()
    
    # Assembly name is usually stored near the BSJB header or in the PE resources
    # Let's look for .pdb paths inside the DLL, which contain the original compilation path and filename!
    pdb_re = re.compile(b'[a-zA-Z0-9_\\-\\\\\\/]+\\.pdb')
    matches = pdb_re.findall(data)
    if matches:
        return matches[0].decode('utf-8', errors='ignore')
        
    # Or search for string with assembly name
    # Let's search for "AssemblyTitle" or similar
    return "Unknown"

def check_candidates():
    candidates = ["extracted_111.dll", "extracted_178.dll", "extracted_72.dll", "extracted_94.dll", "extracted_92.dll", "extracted_93.dll", "extracted_370.dll"]
    dlls_dir = r"d:\Anh_Tung\Phần mềm\License\extracted_dlls"
    
    for filename in candidates:
        file_path = os.path.join(dlls_dir, filename)
        if os.path.exists(file_path):
            name = find_assembly_name(file_path)
            print(f"{filename}: {name}")

if __name__ == "__main__":
    check_candidates()
