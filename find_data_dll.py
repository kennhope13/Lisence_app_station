import os
import re

def find_data_dll():
    dlls_dir = r"d:\Anh_Tung\Phần mềm\License\extracted_dlls"
    pdb_re = re.compile(b'[a-zA-Z0-9_\\-\\\\\\/]+\\.pdb')
    
    for file in os.listdir(dlls_dir):
        if not file.endswith(".dll"):
            continue
        file_path = os.path.join(dlls_dir, file)
        try:
            with open(file_path, "rb") as f:
                data = f.read()
            matches = pdb_re.findall(data)
            if matches:
                pdb_path = matches[0].decode('utf-8', errors='ignore')
                if "Data.pdb" in pdb_path:
                    print(f"{file}: {pdb_path} (Size: {len(data)} bytes)")
        except:
            pass

if __name__ == "__main__":
    find_data_dll()
