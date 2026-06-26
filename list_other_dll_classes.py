import sys
import dnfile

sys.stdout.reconfigure(encoding='utf-8')

def inspect_dll(path):
    print(f"\n================ Inspecting {path} ================")
    pe = dnfile.dnPE(path)
    if not pe.net:
        print("Not a .NET assembly.")
        return
    for td in pe.net.mdtables.TypeDef:
        ns = str(td.TypeNamespace) if td.TypeNamespace else ""
        name = str(td.TypeName) if td.TypeName else ""
        if ns.startswith("System") or ns.startswith("Microsoft") or not name or name == "<Module>":
            continue
        print(f"Class: {ns}.{name}")

if __name__ == "__main__":
    inspect_dll(r"d:\Anh_Tung\Phần mềm\License\extracted_dlls\extracted_111.dll")
    inspect_dll(r"d:\Anh_Tung\Phần mềm\License\extracted_dlls\extracted_178.dll")
