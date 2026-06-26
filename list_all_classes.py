import sys

sys.stdout.reconfigure(encoding='utf-8')

def list_classes(path):
    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()
    for line in lines:
        if line.startswith("Class:"):
            print(line.strip())

if __name__ == "__main__":
    list_classes(r"d:\Anh_Tung\Phần mềm\License\extracted_dlls\extracted_92_structure.txt")
