import re

def search_services():
    file_path = r"d:\Anh_Tung\Phần mềm\License\extracted_dlls\extracted_92.dll"
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
    
    # Look for any strings that contain "license" (case-insensitive)
    print("--- LICENSE RELATED STRINGS IN SERVICES.DLL ---")
    for s in all_strings:
        if "license" in s.lower() or "secret" in s.lower() or "hmac" in s.lower():
            print(s)

if __name__ == "__main__":
    search_services()
