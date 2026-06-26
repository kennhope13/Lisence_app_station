import sys
import dnfile

sys.stdout.reconfigure(encoding='utf-8')

def inspect_dll(path):
    print(f"\n================ Inspecting {path} ================")
    pe = dnfile.dnPE(path)
    
    if not pe.net:
        print("Not a .NET assembly.")
        return
        
    typedefs = pe.net.mdtables.TypeDef
    
    output = []
    
    for td in typedefs:
        ns = str(td.TypeNamespace) if td.TypeNamespace else ""
        name = str(td.TypeName) if td.TypeName else ""
        
        if ns.startswith("System") or ns.startswith("Microsoft") or not name or name == "<Module>":
            continue
            
        class_str = f"Class: {ns}.{name}"
        output.append(class_str)
        
        for method_ref in td.MethodList:
            if method_ref and method_ref.row:
                m_name = str(method_ref.row.Name) if method_ref.row.Name else ""
                output.append(f"  Method: {m_name}")

    out_file = path.replace(".dll", "_structure.txt")
    with open(out_file, "w", encoding="utf-8") as f:
        f.write("\n".join(output))
    print(f"Saved structure to {out_file}")

if __name__ == "__main__":
    inspect_dll(r"d:\Anh_Tung\Phần mềm\License\extracted_dlls\extracted_92.dll")
    inspect_dll(r"d:\Anh_Tung\Phần mềm\License\extracted_dlls\extracted_94.dll")
