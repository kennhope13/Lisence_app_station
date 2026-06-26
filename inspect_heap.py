import dnfile

def inspect():
    pe = dnfile.dnPE(r"d:\Anh_Tung\Phần mềm\License\extracted_dlls\extracted_92.dll")
    print("UserStringHeap attributes:")
    print(dir(pe.net.user_strings))
    # Let's see if we can iterate directly or read via a method
    # e.g., if there's a dictionary or items
    if hasattr(pe.net.user_strings, "get"):
        print("Has get method")

if __name__ == "__main__":
    inspect()
