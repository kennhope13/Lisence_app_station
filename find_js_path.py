import re
import sys
import os

sys.stdout.reconfigure(encoding='utf-8')

def find_giftcode_format():
    assets_dir = r"C:\Program Files\StationMonitor\backend\wwwroot\assets"
    files = [f for f in os.listdir(assets_dir) if f.endswith(".js")]
    
    for filename in files:
        path = os.path.join(assets_dir, filename)
        print(f"\n================ Scanning {filename} ================")
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            
        # Let's search for '-' splitting
        matches = re.finditer(r"\.split\(['\"]-['\"]\)", content)
        for m in matches:
            start = max(0, m.start() - 150)
            end = min(len(content), m.end() + 150)
            print(f"Index {m.start()}: ... {content[start:end].strip()} ...")
            print("-" * 50)

if __name__ == "__main__":
    find_giftcode_format()
