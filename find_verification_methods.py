import sys
import dnfile

sys.stdout.reconfigure(encoding='utf-8')

def find_licensing_methods(dll_path):
    pe = dnfile.dnPE(dll_path)
    typedefs = pe.net.mdtables.TypeDef
    
    keywords = ["verify", "parse", "check", "license"]
    print(f"\nSearching for methods matching {keywords} in {dll_path}:")
    for td in typedefs:
        ns = str(td.TypeNamespace) if td.TypeNamespace else ""
        name = str(td.TypeName) if td.TypeName else ""
        full_name = f"{ns}.{name}" if ns else name
        
        if ns.startswith("System") or ns.startswith("Microsoft"):
            continue
            
        matched_methods = []
        for m_ref in td.MethodList:
            if m_ref and m_ref.row:
                m_name = str(m_ref.row.Name)
                m_name_lower = m_name.lower()
                if any(k in m_name_lower for k in keywords):
                    matched_methods.append(m_name)
                    
        if matched_methods:
            print(f"Class: {full_name}")
            for m in matched_methods:
                print(f"  Method: {m}")

if __name__ == "__main__":
    find_licensing_methods(r"d:\Anh_Tung\Phần mềm\License\extracted_dlls\extracted_91.dll")
    find_licensing_methods(r"d:\Anh_Tung\Phần mềm\License\extracted_dlls\extracted_92.dll")
    find_licensing_methods(r"d:\Anh_Tung\Phần mềm\License\extracted_dlls\extracted_94.dll")
