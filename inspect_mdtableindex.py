import dnfile

def inspect():
    pe = dnfile.dnPE(r"d:\Anh_Tung\Phần mềm\License\extracted_dlls\extracted_92.dll")
    typedefs = pe.net.mdtables.TypeDef
    for td in typedefs:
        if td.MethodList:
            ref = td.MethodList[0]
            print("Attributes of MDTableIndex:")
            print(dir(ref))
            print(f"ref.table: {ref.table}")
            print(f"ref.row_index: {getattr(ref, 'row_index', 'N/A')}")
            print(f"ref.index: {getattr(ref, 'index', 'N/A')}")
            break

if __name__ == "__main__":
    inspect()
