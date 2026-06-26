import os
import re

def dump_strings(file_path):
    print(f"\n================ Strings in {os.path.basename(file_path)} ================")
    with open(file_path, "rb") as f:
        data = f.read()
        
    # Extract ASCII strings
    ascii_re = re.compile(b'[a-zA-Z0-9_\\-\\.]{4,100}')
    ascii_strings = [s.decode('utf-8', errors='ignore') for s in ascii_re.findall(data)]
    
    # Extract UTF-16 LE strings
    utf16_strings = []
    utf16_re = re.compile(b'(?:[a-zA-Z0-9_\\-\\.]{2,100}\x00){2,}')
    for s in utf16_re.findall(data):
        try:
            decoded = s.decode('utf-16le', errors='ignore')
            if len(decoded) >= 4:
                utf16_strings.append(decoded)
        except:
            pass
            
    all_strings = sorted(list(set(ascii_strings + utf16_strings)))
    
    # Filter for interesting words
    keywords = ["license", "split", "hmac", "secret", "validate", "parse", "expire", "session", "device", "camera", "point", "roi", "pd", "solo", "team", "ent"]
    for s in all_strings:
        lower_s = s.lower()
        if any(kw in lower_s for kw in keywords):
            if len(s) < 150:
                print(s)

if __name__ == "__main__":
    dump_strings(r"d:\Anh_Tung\Phần mềm\License\extracted_dlls\extracted_111.dll")
    dump_strings(r"d:\Anh_Tung\Phần mềm\License\extracted_dlls\extracted_94.dll")
