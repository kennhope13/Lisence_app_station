import re

def search_patterns(file_path):
    with open(file_path, "rb") as f:
        data = f.read()
    
    # We will look for ASCII and UTF-16 strings
    # Match patterns like: TEAM-, SOLO-, ENT-, etc.
    patterns = [
        re.compile(b'SOLO|TEAM|ENT'),
        re.compile(b'[A-Z]{3,4}-[0-9]{6}'),
        re.compile(b'VendorSecret|License')
    ]
    
    # Let's extract all readable ASCII strings first
    ascii_re = re.compile(b'[a-zA-Z0-9_\\-\\.]{4,120}')
    ascii_strings = [s.decode('utf-8', errors='ignore') for s in ascii_re.findall(data)]
    
    # Let's extract all readable UTF-16 LE strings
    utf16_strings = []
    # UTF-16 LE strings look like: s\x00t\x00r\x00
    utf16_re = re.compile(b'(?:[a-zA-Z0-9_\\-\\.]{2,120}\x00){2,}')
    for s in utf16_re.findall(data):
        try:
            decoded = s.decode('utf-16le', errors='ignore')
            if len(decoded) >= 4:
                utf16_strings.append(decoded)
        except:
            pass
            
    all_strings = list(set(ascii_strings + utf16_strings))
    
    # Print strings that look like they contain license format or keys
    print("--- Strings matching license-like formats ---")
    license_format_re = re.compile(r'^[A-Z]{3,4}-[0-9]{6}-[0-9]+')
    for s in all_strings:
        if license_format_re.match(s) or "license" in s.lower() or "vendor" in s.lower() or "secret" in s.lower():
            if len(s) < 150: # Ignore very long lines
                print(s)

if __name__ == "__main__":
    search_patterns(r"C:\Program Files\StationMonitor\backend\StationMonitor.Api.exe")
