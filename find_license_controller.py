import sys
import dnfile

sys.stdout.reconfigure(encoding='utf-8')

def find_license_controller_classes(dll_path):
    pe = dnfile.dnPE(dll_path)
    typedefs = pe.net.mdtables.TypeDef
    
    print(f"\n================ LicenseController classes in {dll_path} ================")
    for td in typedefs:
        ns = str(td.TypeNamespace) if td.TypeNamespace else ""
        name = str(td.TypeName) if td.TypeName else ""
        full_name = f"{ns}.{name}" if ns else name
        
        if ns.startswith("System") or ns.startswith("Microsoft"):
            continue
            
        if "LicenseController" in full_name or "License" in name:
            print(f"Class: {full_name}")
            for m_ref in td.MethodList:
                if m_ref and m_ref.row:
                    print(f"  Method: {m_ref.row.Name} (RVA: {hex(m_ref.row.Rva)})")

if __name__ == "__main__":
    find_license_controller_classes(r"d:\Anh_Tung\Phần mềm\License\extracted_dlls\extracted_94.dll")
