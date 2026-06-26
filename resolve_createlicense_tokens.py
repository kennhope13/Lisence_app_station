import sys
import dnfile
from dncil.cil.body.reader import CilMethodBodyReaderBase
from dncil.cil.body import CilMethodBody

sys.stdout.reconfigure(encoding='utf-8')

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

def resolve_token(pe, token_val):
    if token_val is None:
        return ""
        
    table_kind = token_val >> 24
    row_index = token_val & 0x00FFFFFF
    
    if table_kind == 0x70:
        try:
            us = pe.net.user_strings.get(row_index)
            if us:
                return f"\"{us}\""
        except: pass
        return f"UserString_offset({hex(row_index)})"
        
    try:
        if table_kind == 0x01:
            row = pe.net.mdtables.TypeRef[row_index - 1]
            return f"TypeRef: {row.TypeName}"
        elif table_kind == 0x02:
            row = pe.net.mdtables.TypeDef[row_index - 1]
            return f"TypeDef: {row.TypeName}"
        elif table_kind == 0x04:
            row = pe.net.mdtables.Field[row_index - 1]
            return f"FieldDef: {row.Name}"
        elif table_kind == 0x06:
            row = pe.net.mdtables.MethodDef[row_index - 1]
            return f"MethodDef: {row.Name}"
        elif table_kind == 0x0A:
            row = pe.net.mdtables.MemberRef[row_index - 1]
            class_str = ""
            if hasattr(row, "Class") and row.Class:
                if hasattr(row.Class, "row") and row.Class.row:
                    class_str = getattr(row.Class.row, "Name", str(row.Class.row))
                else:
                    class_str = str(row.Class)
            return f"MemberRef: {class_str}.{row.Name}"
        elif table_kind == 0x1B:
            row = pe.net.mdtables.TypeSpec[row_index - 1]
            return f"TypeSpec: row_index({row_index})"
        elif table_kind == 0x2B:
            row = pe.net.mdtables.MethodSpec[row_index - 1]
            method_name = ""
            if hasattr(row, "Method") and row.Method:
                if hasattr(row.Method, "row") and row.Method.row:
                    method_name = getattr(row.Method.row, "Name", str(row.Method.row))
                else:
                    method_name = str(row.Method)
            return f"MethodSpec: {method_name}"
    except Exception as e:
        return f"token_err({hex(token_val)}: {e})"
        
    return f"token({hex(token_val)})"

def disassemble_full(dll_path, target_class, target_method, output_file):
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
    
    lines = []
    lines.append(f"Disassembly of {target_class}.{target_method}:")
    for instr in body.instructions:
        operand_str = ""
        if instr.operand is not None:
            if hasattr(instr.operand, "value"):
                operand_str = resolve_token(pe, instr.operand.value)
            else:
                operand_str = str(instr.operand)
        lines.append(f"  IL_{instr.offset:04x}: {instr.opcode.name:<12} {operand_str}")
        
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"Saved resolved disassembly to {output_file}")

if __name__ == "__main__":
    disassemble_full(
        r"d:\Anh_Tung\Phần mềm\License\extracted_dlls\extracted_94.dll",
        "<CreateLicense>d__3",
        "MoveNext",
        "resolved_createlicense_il.txt"
    )
