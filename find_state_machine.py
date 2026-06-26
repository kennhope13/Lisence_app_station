import sys
import dnfile

sys.stdout.reconfigure(encoding='utf-8')

def find_state_machines(dll_path, target_method):
    pe = dnfile.dnPE(dll_path)
    typedefs = pe.net.mdtables.TypeDef
    
    print(f"Searching for state machines related to '{target_method}':")
    for td in typedefs:
        ns = str(td.TypeNamespace) if td.TypeNamespace else ""
        name = str(td.TypeName) if td.TypeName else ""
        full_name = f"{ns}.{name}" if ns else name
        if target_method in name:
            print(f"Class: {full_name}")

if __name__ == "__main__":
    find_state_machines(r"d:\Anh_Tung\Phần mềm\License\extracted_dlls\extracted_92.dll", "LoginAsync")
