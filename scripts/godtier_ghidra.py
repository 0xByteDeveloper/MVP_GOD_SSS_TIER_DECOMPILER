# =============================================================================
#  i4M GodTier Engine — scripts/godtier_ghidra.py
#  Ghidra headless köprüsü: GodTier'ın çağırdığı postScript.
#  Kullanim (GodTier icinden otomatik):
#    analyzeHeadless /tmp/gt_ghidra_proj GT -import <dosya> \
#        -postScript godtier_ghidra.py <cikti.json> -deleteProject
#  Çıktı: fonksiyon listesi + pseudocode içeren JSON (GodTier içine geri okunur)
# =============================================================================
# @category i4M.GodTier
# @runtime Jython

import json
import os
import sys


def main():
    if len(sys.argv) < 2:
        print("Kullanim: godtier_ghidra.py <cikti.json>")
        return
    out_path = sys.argv[1]

    fm = currentProgram.getFunctionManager()
    listing = currentProgram.getListing()

    funcs = []
    for f in fm.getFunctions(True):
        entry = {
            "name": f.getName(),
            "entry": str(f.getEntryPoint()),
            "body": str(f.getBody()),
        }
        # pseudocode (Decompiler API)
        try:
            from ghidra.app.decompiler import DecompInterface
            from ghidra.util.task import ConsoleTaskMonitor
            if not hasattr(main, "_di"):
                main._di = DecompInterface()
                main._di.openProgram(currentProgram)
            res = main._di.decompileFunction(f, 60, ConsoleTaskMonitor())
            if res.decompileCompleted():
                entry["pseudocode"] = res.getDecompiledFunction().getC()
        except Exception as e:
            entry["pseudocode_error"] = str(e)
        funcs.append(entry)

    data = {
        "program": currentProgram.getName(),
        "language": currentProgram.getLanguageID().toString(),
        "function_count": len(funcs),
        "functions": funcs,
    }
    with open(out_path, "w") as fh:
        json.dump(data, fh, indent=1)
    print("GodTier kopru: %d fonksiyon -> %s" % (len(funcs), out_path))


main()
