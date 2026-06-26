import sys

sys.stdout.reconfigure(encoding='utf-8')

def find_js_logic(path):
    print(f"\n================ Matching lines in {path} ================")
    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()
        
    keywords = ["team", "license", "solo", "enterprise"]
    for i, line in enumerate(lines):
        line_lower = line.lower()
        if any(k in line_lower for k in keywords):
            # Show line number and trimmed line (limit output length to 300 chars per line)
            print(f"Line {i+1}: {line.strip()[:300]}")

if __name__ == "__main__":
    find_js_logic(r"d:\Anh_Tung\Phần mềm\License\search_js_output.txt")
