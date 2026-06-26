import sys
import dnfile
import re

sys.stdout.reconfigure(encoding='utf-8')

def dump_strings(path):
    print(f"\n================ User Strings in {path} ================")
    pe = dnfile.dnPE(path)
    if not pe.net or not pe.net.user_strings:
        print("No User Strings stream.")
        return
        
    # Get raw data of the heap
    data = pe.net.user_strings.get_bytes()
    
    # We can extract strings by parsing the heap.
    # The heap is structured as:
    # - 0 byte at start
    # - entries: [length (compressed integer)][utf-16le bytes][suffix byte (usually 0 or 1)]
    # Let's write a parser for the compressed integer:
    idx = 0
    # skip the first byte (usually empty)
    if len(data) > 0 and data[idx] == 0:
        idx += 1
        
    strings = []
    while idx < len(data):
        # Read compressed length
        b1 = data[idx]
        idx += 1
        if b1 == 0:
            # Padding/alignment
            continue
            
        if (b1 & 0x80) == 0:
            length = b1
        elif (b1 & 0xC0) == 0x80:
            if idx >= len(data): break
            b2 = data[idx]
            idx += 1
            length = ((b1 & 0x3F) << 8) | b2
        else:
            if idx + 3 >= len(data): break
            b2 = data[idx]
            b3 = data[idx+1]
            b4 = data[idx+2]
            idx += 3
            length = ((b1 & 0x1F) << 24) | (b2 << 16) | (b3 << 8) | b4
            
        if length == 0:
            continue
            
        if idx + length > len(data):
            break
            
        string_bytes = data[idx:idx + length - 1] # exclude the suffix byte
        idx += length
        
        try:
            val = string_bytes.decode("utf-16-le")
            strings.append(val)
        except Exception:
            pass

    # Unique and sorted
    strings = sorted(list(set(filter(None, strings))))
    
    out_file = path.replace(".dll", "_strings.txt")
    with open(out_file, "w", encoding="utf-8") as f:
        f.write("\n".join(strings))
    print(f"Saved {len(strings)} strings to {out_file}")

if __name__ == "__main__":
    dump_strings(r"d:\Anh_Tung\Phần mềm\License\extracted_dlls\extracted_92.dll")
    dump_strings(r"d:\Anh_Tung\Phần mềm\License\extracted_dlls\extracted_94.dll")
