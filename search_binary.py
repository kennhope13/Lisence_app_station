import re

def extract_strings(file_path):
    with open(file_path, "rb") as f:
        data = f.read()
    
    # Simple ASCII string regex
    ascii_re = re.compile(b'[a-zA-Z0-9_\\-\\.]{4,100}')
    matches = ascii_re.findall(data)
    
    keywords = [b"License", b"VendorSecret", b"hmac", b"SOLO", b"TEAM", b"ENT", b"Split"]
    
    results = set()
    for m in matches:
        for kw in keywords:
            if kw.lower() in m.lower():
                results.add(m.decode("utf-8", errors="ignore"))
                
    # Also look for Unicode strings (UTF-16 LE)
    unicode_re = re.compile(b'(?:[a-zA-Z0-9_\\-\\.]{4,100}\x00){1,}')
    # For simplicity, we can decode all potential UTF-16 strings
    # but let's just write the ascii ones first and see.
    
    print(f"Found {len(results)} potential strings:")
    for r in sorted(results):
        print(r)

if __name__ == "__main__":
    extract_strings(r"C:\Program Files\StationMonitor\backend\StationMonitor.Api.exe")
