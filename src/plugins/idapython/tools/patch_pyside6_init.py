
import argparse
p = argparse.ArgumentParser()
p.add_argument("--input", required=True, type=str)
p.add_argument("--output", required=True, type=str)
args = p.parse_args()

with open(args.input, "rb") as fin:
    clob = fin.read().decode("UTF-8")

insertion_point = clob.index("def _additional_dll_directories")
insertion_text = """
def _verify_prerequisites():
    import ida_kernwin
    if not ida_kernwin.is_idaq():
        raise ImportError("PySide6 can only be used from the GUI version of IDA")
    
    if sys.version_info[1] < 9:
        raise Exception("PySide requires at least Python 3.9 to run")
    elif sys.version_info[1] >= 14:
        print("PySide has not been widely tested on Python >= 3.14; IDA cannot guarantee that it will function as expected.")

_verify_prerequisites()

"""

clob = clob[0:insertion_point] + insertion_text + clob[insertion_point:]

with open(args.output, "wb") as fout:
    fout.write(clob.encode("UTF-8"))
