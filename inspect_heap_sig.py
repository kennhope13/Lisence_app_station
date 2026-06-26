import dnfile
import inspect

def inspect_heap():
    pe = dnfile.dnPE(r"d:\Anh_Tung\Phần mềm\License\extracted_dlls\extracted_92.dll")
    heap = pe.net.user_strings
    print("UserStringHeap.get_bytes signature:")
    print(inspect.signature(heap.get_bytes))
    print("UserStringHeap.get signature:")
    print(inspect.signature(heap.get))
    # We can also access heap._data or heap.data or similar
    print("heap vars:")
    print(vars(heap))

if __name__ == "__main__":
    inspect_heap()
