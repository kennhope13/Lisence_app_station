import sys
import re

sys.stdout.reconfigure(encoding='utf-8')

def scan_strings(path):
    print(f"\n================ Scanning Strings in {path} ================")
    with open(path, "rb") as f:
        data = f.read()
        
    # Find UTF-16LE strings: sequences of readable ASCII characters (and some common Vietnamese/accents)
    # followed by a null byte.
    # Pattern: a character in range [0x20-0x7E, Vietnamese Unicode range] followed by \x00, repeated 3+ times.
    # Let's keep it simple: match ASCII-in-UTF16 first.
    # [ -~] is space to tilde
    pattern = re.compile(b'(?:[\x20-\x7E]\x00){3,}')
    matches = pattern.findall(data)
    
    strings = []
    for m in matches:
        try:
            s = m.decode("utf-16-le")
            strings.append(s)
        except:
            pass
            
    # Also scan for standard ASCII strings
    pattern_ascii = re.compile(b'[\x20-\x7E]{4,}')
    matches_ascii = pattern_ascii.findall(data)
    for m in matches_ascii:
        try:
            s = m.decode("ascii")
            strings.append(s)
        except:
            pass

    strings = sorted(list(set(filter(None, strings))))
    
    out_file = path.replace(".dll", "_scanned_strings.txt")
    with open(out_file, "w", encoding="utf-8") as f:
        f.write("\n".join(strings))
    print(f"Saved {len(strings)} scanned strings to {out_file}")

if __name__ == "__main__":
    scan_strings(r"d:\Anh_Tung\Phần mềm\License\extracted_dlls\extracted_92.dll")
    scan_strings(r"d:\Anh_Tung\Phần mềm\License\extracted_dlls\extracted_94.dll")
