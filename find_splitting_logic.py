import sys
import dnfile

sys.stdout.reconfigure(encoding='utf-8')

def find_splitting_logic(dll_path):
    pe = dnfile.dnPE(dll_path)
    typedefs = pe.net.mdtables.TypeDef
    
    print(f"\n================ Splitting Logic in {dll_path} ================")
    for td in typedefs:
        ns = str(td.TypeNamespace) if td.TypeNamespace else ""
        name = str(td.TypeName) if td.TypeName else ""
        full_name = f"{ns}.{name}" if ns else name
        
        if ns.startswith("System") or ns.startswith("Microsoft") or not name or name == "<Module>":
            continue
            
        for method_ref in td.MethodList:
            if method_ref and method_ref.row:
                m_name = str(method_ref.row.Name)
                if method_ref.row.Rva == 0:
                    continue
                try:
                    from dncil.cil.body.reader import CilMethodBodyReaderBase
                    from dncil.cil.body import CilMethodBody
                    
                    class SimpleReader(CilMethodBodyReaderBase):
                        def __init__(self, pe, rva):
                            super().__init__()
                            self.pe = pe
                            self.offset = self.pe.get_offset_from_rva(rva)
                        def read(self, n):
                            data = self.pe.get_data(self.offset, n)
                            self.offset += n
                            return data
                            
                    reader = SimpleReader(pe, method_ref.row.Rva)
                    body = CilMethodBody(reader)
                    
                    # Look for String.Split(char) or String.Split(string) calls
                    # In MSIL: Split is usually represented as a call to String::Split
                    for instr in body.instructions:
                        if instr.operand is not None and hasattr(instr.operand, "value"):
                            t_val = instr.operand.value
                            table_kind = t_val >> 24
                            row_index = t_val & 0x00FFFFFF
                            if table_kind == 0x0A: # MemberRef
                                try:
                                    row = pe.net.mdtables.MemberRef[row_index - 1]
                                    m_ref_name = str(row.Name)
                                    class_name = ""
                                    if hasattr(row, "Class") and row.Class:
                                        if hasattr(row.Class, "row") and row.Class.row:
                                            class_name = getattr(row.Class.row, "Name", str(row.Class.row))
                                        else:
                                            class_name = str(row.Class)
                                    if m_ref_name == "Split" or m_ref_name == "Substring":
                                        print(f"  Method {full_name}.{m_name} calls {class_name}.{m_ref_name}")
                                except: pass
                except Exception as e:
                    pass

if __name__ == "__main__":
    find_splitting_logic(r"d:\Anh_Tung\Phần mềm\License\extracted_dlls\extracted_91.dll")
    find_splitting_logic(r"d:\Anh_Tung\Phần mềm\License\extracted_dlls\extracted_92.dll")
    find_splitting_logic(r"d:\Anh_Tung\Phần mềm\License\extracted_dlls\extracted_93.dll")
    find_splitting_logic(r"d:\Anh_Tung\Phần mềm\License\extracted_dlls\extracted_94.dll")
