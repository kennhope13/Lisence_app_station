import sys
import dnfile

sys.stdout.reconfigure(encoding='utf-8')

def find_references(dll_path):
    pe = dnfile.dnPE(dll_path)
    typedefs = pe.net.mdtables.TypeDef
    
    print(f"\n================ References in {dll_path} ================")
    for td in typedefs:
        ns = str(td.TypeNamespace) if td.TypeNamespace else ""
        name = str(td.TypeName) if td.TypeName else ""
        full_name = f"{ns}.{name}" if ns else name
        
        if ns.startswith("System") or ns.startswith("Microsoft") or not name or name == "<Module>":
            continue
            
        # Scan methods of this type
        for method_ref in td.MethodList:
            if method_ref and method_ref.row:
                m_name = str(method_ref.row.Name)
                # Let's inspect the body instructions of this method to find references to LicenseController or DB tables
                if method_ref.row.Rva == 0:
                    continue
                try:
                    # Let's read instructions
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
                    
                    # Look for references to LicenseKeys or licensing tables
                    for instr in body.instructions:
                        if instr.operand is not None and hasattr(instr.operand, "value"):
                            t_val = instr.operand.value
                            # Resolve token type
                            table_kind = t_val >> 24
                            row_index = t_val & 0x00FFFFFF
                            if table_kind == 0x0A: # MemberRef
                                try:
                                    row = pe.net.mdtables.MemberRef[row_index - 1]
                                    m_ref_name = str(row.Name)
                                    if "License" in m_ref_name or "license" in m_ref_name:
                                        print(f"  Method {full_name}.{m_name} calls {m_ref_name}")
                                except: pass
                except: pass

if __name__ == "__main__":
    find_references(r"d:\Anh_Tung\Phần mềm\License\extracted_dlls\extracted_94.dll")
