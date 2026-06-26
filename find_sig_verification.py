import sys
import dnfile

sys.stdout.reconfigure(encoding='utf-8')

def find_signature_verification(dll_path):
    pe = dnfile.dnPE(dll_path)
    typedefs = pe.net.mdtables.TypeDef
    
    print(f"\n================ Signature Verification in {dll_path} ================")
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
                    
                    for instr in body.instructions:
                        if instr.opcode.name == "ldstr" and instr.operand is not None:
                            # Check if operand matches string patterns
                            if hasattr(instr.operand, "value"):
                                us = pe.net.user_strings.get(instr.operand.value & 0x00FFFFFF)
                                if us and ("-" in us or "invalid" in us.lower() or "hợp lệ" in us):
                                    print(f"  Method {full_name}.{m_name} contains ldstr: \"{us}\"")
                except Exception as e:
                    pass

if __name__ == "__main__":
    find_signature_verification(r"d:\Anh_Tung\Phần mềm\License\extracted_dlls\extracted_92.dll")
