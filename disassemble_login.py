import sys
import dnfile
from dncil.cil.body.reader import CilMethodBodyReaderBase
from dncil.cil.body import CilMethodBody

sys.stdout.reconfigure(encoding='utf-8')

def resolve_token_string(pe, token_val):
    # String tokens are in user strings heap: their token starts with 0x70
    if (token_val & 0xFF000000) == 0x70000000:
        offset = token_val & 0x00FFFFFF
        # read string from user string stream using offset
        try:
            # UserString heap starts at offset. First byte is length, etc.
            # dnfile provides a way to get the string from offset or heap:
            us = pe.net.user_strings.get(offset)
            if us:
                return f"\"{us}\""
        except:
            pass
    return f"token({hex(token_val)})"

def resolve_member_ref(pe, token_val):
    table_kind = token_val >> 24
    row_index = token_val & 0x00FFFFFF
    
    # We can inspect different tables: MemberRef (0x0A), MethodDef (0x06), FieldDef (0x04)
    try:
        if table_kind == 0x0A: # MemberRef
            row = pe.net.mdtables.MemberRef[row_index - 1]
            return f"MemberRef: {row.Class.row.Name if hasattr(row.Class, 'row') else str(row.Class)}.{row.Name}"
        elif table_kind == 0x06: # MethodDef
            row = pe.net.mdtables.MethodDef[row_index - 1]
            return f"MethodDef: {row.Name}"
        elif table_kind == 0x04: # FieldDef
            row = pe.net.mdtables.Field[row_index - 1]
            return f"FieldDef: {row.Name}"
    except Exception as e:
        pass
    return f"token({hex(token_val)})"

class DnfileMethodBodyReader(CilMethodBodyReaderBase):
    def __init__(self, pe, row):
        super().__init__()
        self.pe = pe
        self.offset = self.pe.get_offset_from_rva(row.Rva)

    def read(self, n):
        data = self.pe.get_data(self.offset, n)
        self.offset += n
        return data

    def tell(self):
        return self.offset

    def seek(self, offset, whence=0):
        if whence == 0:
            self.offset = offset
        elif whence == 1:
            self.offset += offset
        elif whence == 2:
            raise NotImplementedError("Seek from end not supported")

def disassemble_and_resolve(dll_path, target_class, target_method):
    pe = dnfile.dnPE(dll_path)
    typedefs = pe.net.mdtables.TypeDef
    
    target_td = None
    for td in typedefs:
        ns = str(td.TypeNamespace) if td.TypeNamespace else ""
        name = str(td.TypeName) if td.TypeName else ""
        full_name = f"{ns}.{name}" if ns else name
        if full_name == target_class:
            target_td = td
            break

    if not target_td:
        print(f"Class {target_class} not found.")
        return

    # Find method
    md = None
    for method_ref in target_td.MethodList:
        if method_ref and method_ref.row:
            m_name = str(method_ref.row.Name) if method_ref.row.Name else ""
            if m_name == target_method:
                md = method_ref.row
                break
                
    if not md:
        print(f"Method {target_method} not found.")
        return

    reader = DnfileMethodBodyReader(pe, md)
    body = CilMethodBody(reader)
    
    print(f"\n================ MoveNext resolved disasm ================")
    for instr in body.instructions:
        operand_str = ""
        if instr.operand is not None:
            if hasattr(instr.operand, "value"):
                t_val = instr.operand.value
                if (t_val & 0xFF000000) == 0x70000000:
                    operand_str = resolve_token_string(pe, t_val)
                else:
                    operand_str = resolve_member_ref(pe, t_val)
            else:
                operand_str = str(instr.operand)
        print(f"  IL_{instr.offset:04x}: {instr.opcode.name:<12} {operand_str}")

if __name__ == "__main__":
    disassemble_and_resolve(
        r"d:\Anh_Tung\Phần mềm\License\extracted_dlls\extracted_92.dll",
        "<LoginAsync>d__3",
        "MoveNext"
    )
