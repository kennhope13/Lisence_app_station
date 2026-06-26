import sys

sys.stdout.reconfigure(encoding='utf-8')

def find_keywords(path):
    print(f"\n================ Keywords in {path} ================")
    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()
        
    keywords = ["giới hạn", "vượt quá", "tối đa", "thiết bị", "camera", "limit", "exceeded", "maximum", "max"]
    for line in lines:
        line_lower = line.lower()
        if any(k in line_lower for k in keywords):
            print(line.strip())

if __name__ == "__main__":
    find_keywords(r"d:\Anh_Tung\Phần mềm\License\extracted_dlls\extracted_92_scanned_strings.txt")
    find_keywords(r"d:\Anh_Tung\Phần mềm\License\extracted_dlls\extracted_94_scanned_strings.txt")
