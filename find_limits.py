import sys

sys.stdout.reconfigure(encoding='utf-8')

def find_limits(path):
    print(f"\n================ Limits in {path} ================")
    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()
        
    current_class = ""
    for line in lines:
        if line.startswith("Class:"):
            current_class = line.strip()
        elif "get_Max" in line or "Limit" in line:
            if current_class:
                print(current_class)
                current_class = ""
            print(line.strip())

if __name__ == "__main__":
    find_limits(r"d:\Anh_Tung\Phần mềm\License\extracted_dlls\extracted_92_structure.txt")
    find_limits(r"d:\Anh_Tung\Phần mềm\License\extracted_dlls\extracted_94_structure.txt")
