import sys

sys.stdout.reconfigure(encoding='utf-8')

def search_struct(path):
    print(f"\n================ Searching {path} ================")
    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()
        
    current_class = ""
    keywords = ["license", "auth", "login", "session", "verify", "check", "key", "limit", "tier", "hashing", "hmac", "sha256"]
    
    for line in lines:
        if line.startswith("Class:"):
            current_class = line.strip()
        else:
            line_lower = line.lower()
            if any(k in line_lower for k in keywords):
                if current_class:
                    print(current_class)
                    current_class = "" # only print once
                print(line.strip())

if __name__ == "__main__":
    search_struct(r"d:\Anh_Tung\Phần mềm\License\extracted_dlls\extracted_92_structure.txt")
    search_struct(r"d:\Anh_Tung\Phần mềm\License\extracted_dlls\extracted_94_structure.txt")
