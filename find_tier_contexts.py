import os

def find_tier_contexts():
    dlls_dir = r"d:\Anh_Tung\Phần mềm\License\extracted_dlls"
    files = ["extracted_92.dll", "extracted_94.dll"]
    tiers = [b"SOLO", b"TEAM", b"ENT"]
    
    for filename in files:
        file_path = os.path.join(dlls_dir, filename)
        if not os.path.exists(file_path):
            continue
        print(f"\n================ Context in {filename} ================")
        with open(file_path, "rb") as f:
            data = f.read()
            
        for tier in tiers:
            idx = 0
            while True:
                idx = data.find(tier, idx)
                if idx == -1:
                    break
                start = max(0, idx - 100)
                end = min(len(data), idx + len(tier) + 100)
                context = data[start:end]
                printable = "".join(chr(c) if 32 <= c < 127 else "." for c in context)
                print(f"Match for '{tier.decode()}' at {idx}: {printable}")
                idx += len(tier)

if __name__ == "__main__":
    find_tier_contexts()
