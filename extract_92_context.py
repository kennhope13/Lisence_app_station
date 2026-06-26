def print_context():
    file_path = r"d:\Anh_Tung\Phần mềm\License\extracted_dlls\extracted_92.dll"
    with open(file_path, "rb") as f:
        data = f.read()
        
    targets = [b"fallbackKey", b"payload", b"licenseKey"]
    for t in targets:
        idx = 0
        while True:
            idx = data.find(t, idx)
            if idx == -1:
                break
            start = max(0, idx - 150)
            end = min(len(data), idx + len(t) + 150)
            context = data[start:end]
            printable = "".join(chr(c) if 32 <= c < 127 else "." for c in context)
            print(f"\n--- Match for {t.decode()} at {idx} ---")
            print(printable)
            idx += len(t)

if __name__ == "__main__":
    print_context()
