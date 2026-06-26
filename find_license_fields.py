import sys
import dnfile

sys.stdout.reconfigure(encoding='utf-8')

def scan_license_fields(dll_path):
    pe = dnfile.dnPE(dll_path)
    typedefs = pe.net.mdtables.TypeDef
    
    print(f"\n================ License Fields in {dll_path} ================")
    for td in typedefs:
        ns = str(td.TypeNamespace) if td.TypeNamespace else ""
        name = str(td.TypeName) if td.TypeName else ""
        full_name = f"{ns}.{name}" if ns else name
        
        if ns.startswith("System") or ns.startswith("Microsoft") or not name or name == "<Module>":
            continue
            
        if "License" in name or "Auth" in name:
            print(f"Class: {full_name}")
            # print fields
            for f_idx in range(len(pe.net.mdtables.Field)):
                # Fields belonging to this class
                pass
            # Just print the method names / properties
            for m_ref in td.MethodList:
                if m_ref and m_ref.row:
                    m_name = str(m_ref.row.Name)
                    if m_name.startswith("get_") or m_name.startswith("set_"):
                        print(f"  Property accessor: {m_name}")

if __name__ == "__main__":
    scan_license_fields(r"d:\Anh_Tung\Phần mềm\License\extracted_dlls\extracted_91.dll")
    scan_license_fields(r"d:\Anh_Tung\Phần mềm\License\extracted_dlls\extracted_92.dll")
    scan_license_fields(r"d:\Anh_Tung\Phần mềm\License\extracted_dlls\extracted_94.dll")
