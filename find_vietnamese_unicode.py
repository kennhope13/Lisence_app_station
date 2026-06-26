import os

def to_js_unicode(s):
    res = ""
    for c in s:
        code = ord(c)
        if code > 127:
            res += f"\\u{code:04x}"
        else:
            res += c
    return res

def find_escaped_labels():
    assets_dir = r"C:\Program Files\StationMonitor\backend\wwwroot\assets"
    files = [f for f in os.listdir(assets_dir) if f.endswith(".js")]
    
    labels = ["Gói sản phẩm", "Số thiết bị tối đa", "Số camera tối đa", "Số điểm nhiệt tối đa"]
    
    for filename in files:
        file_path = os.path.join(assets_dir, filename)
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            
        for label in labels:
            escaped = to_js_unicode(label)
            # Try both lowercase and uppercase hex in \uXXXX
            escaped_upper = escaped.replace("a", "A").replace("b", "B").replace("c", "C").replace("d", "D").replace("e", "E").replace("f", "F")
            
            idx = content.find(escaped)
            if idx == -1:
                idx = content.find(escaped_upper)
                
            if idx != -1:
                print(f"Found '{label}' (escaped: {escaped}) in {filename} at index {idx}")
                start = max(0, idx - 200)
                end = min(len(content), idx + len(escaped) + 300)
                print(content[start:end])
                print("-" * 50)

if __name__ == "__main__":
    find_escaped_labels()
