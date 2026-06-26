import os
import re
import sys

sys.stdout.reconfigure(encoding='utf-8')

def find_assembly_name(file_path):
    with open(file_path, "rb") as f:
        data = f.read()
    
    pdb_re = re.compile(b'[a-zA-Z0-9_\\-\\.\\\\\\/]+\\.pdb')
    matches = pdb_re.findall(data)
    if matches:
        # Find first matching StationMonitor PDB
        for m in matches:
            decoded = m.decode('utf-8', errors='ignore')
            if "StationMonitor" in decoded:
                return decoded
        return matches[0].decode('utf-8', errors='ignore')
    return "Unknown"

def scan_all():
    dlls_dir = r"d:\Anh_Tung\Phần mềm\License\extracted_dlls"
    files = [f for f in os.listdir(dlls_dir) if f.endswith(".dll")]
    
    results = []
    for filename in files:
        file_path = os.path.join(dlls_dir, filename)
        pdb_path = find_assembly_name(file_path)
        if "StationMonitor" in pdb_path or "Unknown" not in pdb_path:
            results.append((filename, pdb_path))
            
    # Sort by filename
    results.sort(key=lambda x: int(re.search(r'\d+', x[0]).group()) if re.search(r'\d+', x[0]) else 0)
    for r in results:
        print(f"{r[0]} -> {r[1]}")

if __name__ == "__main__":
    scan_all()
