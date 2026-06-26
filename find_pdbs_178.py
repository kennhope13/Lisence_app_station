import re

def find_pdbs():
    file_path = r"d:\Anh_Tung\Phần mềm\License\extracted_dlls\extracted_178.dll"
    with open(file_path, "rb") as f:
        data = f.read()
    
    pdb_re = re.compile(b'[a-zA-Z0-9_\\-\\\\\\/]+\\.pdb')
    matches = pdb_re.findall(data)
    print("PDB paths found in extracted_178.dll:")
    for m in matches:
        print(m.decode('utf-8', errors='ignore'))

if __name__ == "__main__":
    find_pdbs()
