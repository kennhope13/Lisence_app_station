import os
import re

def search_custom():
    dlls_dir = r"d:\Anh_Tung\Phần mềm\License\extracted_dlls"
    files = ["extracted_91.dll", "extracted_92.dll", "extracted_93.dll", "extracted_94.dll"]
    
    terms = [b"ValidateAndRetrieveLicenseDetails", b"ValidateLicense", b"Verify", b"Decode", b"Parse", b"Signature", b"Secret", b"Hmac", b"SHA256", b"giftcode", b"Giftcode", b"license", b"License"]
    
    for filename in files:
        file_path = os.path.join(dlls_dir, filename)
        if not os.path.exists(file_path):
            continue
        print(f"\n================ Scanning {filename} ================")
        with open(file_path, "rb") as f:
            data = f.read()
            
        # Search for exact binary terms
        for term in terms:
            idx = 0
            while True:
                idx = data.find(term, idx)
                if idx == -1:
                    break
                # Print 40 bytes around the match to see the context
                start = max(0, idx - 20)
                end = min(len(data), idx + len(term) + 20)
                context = data[start:end]
                # Filter printable characters
                printable_context = "".join(chr(c) if 32 <= c < 127 else "." for c in context)
                print(f"Match for '{term.decode()}': {printable_context}")
                idx += len(term)

if __name__ == "__main__":
    search_custom()
