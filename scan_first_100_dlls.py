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
        for m in matches:
            decoded = m.decode('utf-8', errors='ignore')
            if "StationMonitor" in decoded:
                return decoded
        return matches[0].decode('utf-8', errors='ignore')
    return "Unknown"

def scan_first_100():
    dlls_dir = r"d:\Anh_Tung\Phần mềm\License\extracted_dlls"
    files = [f for f in os.listdir(dlls_dir) if f.endswith(".dll")]
    
    results = []
    for filename in files:
        file_path = os.path.join(dlls_dir, filename)
        # Parse number out of filename
        num_match = re.search(r'\d+', filename)
        if num_match:
            num = int(num_match.group())
            if num < 100:
                pdb_path = find_assembly_name(file_path)
                results.append((filename, num, pdb_path))
                
    results.sort(key=lambda x: x[1])
    for filename, num, pdb_path in results:
        # Show all results, but highlight StationMonitor assemblies
        if "StationMonitor" in pdb_path:
            print(f"*** {filename} -> {pdb_path}")
        else:
            print(f"    {filename} -> {pdb_path}")

if __name__ == "__main__":
    scan_first_100()
