import sys
import dnfile

sys.stdout.reconfigure(encoding='utf-8')

def print_methods(dll_path, target_class):
    pe = dnfile.dnPE(dll_path)
    typedefs = pe.net.mdtables.TypeDef
    
    for td in typedefs:
        ns = str(td.TypeNamespace) if td.TypeNamespace else ""
        name = str(td.TypeName) if td.TypeName else ""
        full_name = f"{ns}.{name}" if ns else name
        if full_name == target_class:
            print(f"\nMethods in {full_name}:")
            for m_ref in td.MethodList:
                if m_ref and m_ref.row:
                    print(f"  {m_ref.row.Name}")
                    
        # Also check nested or state machines
        elif target_class in full_name:
            print(f"Subclass: {full_name}")

if __name__ == "__main__":
    print_methods(
        r"d:\Anh_Tung\Phần mềm\License\extracted_dlls\extracted_92.dll",
        "StationMonitor.Services.Auth.AuthService"
    )
