import sys

sys.stdout.reconfigure(encoding='utf-8')

def find_strings(path):
    print(f"\n================ Matching strings in {path} ================")
    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()
        
    keywords = ["license", "key", "secret", "session", "limit", "invalid", "expired", "database", "station", "free", "standard", "demo"]
    for line in lines:
        line_lower = line.lower()
        if any(k in line_lower for k in keywords):
            print(line.strip())

if __name__ == "__main__":
    find_strings(r"d:\Anh_Tung\Phần mềm\License\extracted_dlls\extracted_92_scanned_strings.txt")
