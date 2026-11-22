# =============================================================================
#  i4M GodTier v9.2 — Ghidra 12.2 karsilastirma olcegi (benchmark postScript)
#  Olculenler:
#   - fonksiyon sayisi / analiz suresi (pyghidra loglarindan)
#   - DOLAYLI cagri evreni (call reg / call [mem] — COMPUTED_CALL dahil)
#     + kac tanesi somut fonksiyona baglanmis (reference manager)
#   - izlenen cagri adreslerinde: cozuldu mu? (somut hedef referansi var mi)
#   - fonksiyon-kesif problari: verilen adreslerde fonksiyon VAR mi?
#  Kullanim (pyghidra):
#    python3 -m pyghidra --install-dir <ghidra> <exe> gh_bench.py <out.json> \
#        watchCall:hex,hex probeFunc:hex,hex
# =============================================================================
# @category i4M.GodTier
# @runtime PyGhidra

import json
import sys


def flow_is_indirect_call(ft):
    if ft is None or not ft.isCall():
        return False
    return ft.isIndirect() or ft.isComputed()


def main():
    out_path = sys.argv[1] if len(sys.argv) > 1 else "/tmp/gh_bench.json"
    watch_calls = []
    probe_funcs = []
    for arg in sys.argv[2:]:
        if arg.startswith("watchCall:"):
            for a in arg.split(":", 1)[1].split(","):
                if a.strip():
                    watch_calls.append(int(a.strip(), 16))
        elif arg.startswith("probeFunc:"):
            for a in arg.split(":", 1)[1].split(","):
                if a.strip():
                    probe_funcs.append(int(a.strip(), 16))

    fm = currentProgram.getFunctionManager()
    listing = currentProgram.getListing()
    rm = currentProgram.getReferenceManager()

    funcs = list(fm.getFunctions(True))

    # --- dolayli cagri evreni + somut baglanti ---
    total_indirect = 0
    concrete_linked = 0
    ins_iter = listing.getInstructions(True)
    for ins in ins_iter:
        if flow_is_indirect_call(ins.getFlowType()):
            total_indirect += 1
            refs = rm.getReferencesFrom(ins.getAddress())
            for r in refs:
                if r.getReferenceType().isCall() and r.getToAddress() is not None:
                    if fm.getFunctionAt(r.getToAddress()) is not None:
                        concrete_linked += 1
                        break

    # --- izlenen cagrilar: somut hedef referansi var mi? ---
    watch_results = []
    for wa in watch_calls:
        info = {"addr": "0x%x" % wa, "found": False, "resolved": False,
                "target": None}
        ins = listing.getInstructionAt(toAddr(wa))
        if ins is not None:
            info["found"] = True
            info["mnemonic"] = ins.getMnemonicString()
            refs = rm.getReferencesFrom(ins.getAddress())
            for r in refs:
                if r.getReferenceType().isCall() and r.getToAddress() is not None:
                    tf = fm.getFunctionAt(r.getToAddress())
                    if tf is not None:
                        info["resolved"] = True
                        info["target"] = tf.getName() + "@0x%x" % r.getToAddress().getOffset()
                        break
        watch_results.append(info)

    # --- fonksiyon kesif problari ---
    probe_results = []
    for pa in probe_funcs:
        f = fm.getFunctionContaining(toAddr(pa))
        probe_results.append({
            "addr": "0x%x" % pa,
            "discovered": f is not None,
            "at_start": (fm.getFunctionAt(toAddr(pa)) is not None),
        })

    data = {
        "program": currentProgram.getName(),
        "language": currentProgram.getLanguageID().toString(),
        "function_count": len(funcs),
        "indirect_call_universe": total_indirect,
        "indirect_call_linked_concrete": concrete_linked,
        "watch_calls": watch_results,
        "probe_funcs": probe_results,
    }
    fh = open(out_path, "w")
    fh.write(json.dumps(data, indent=1))
    fh.close()
    print("[gh_bench] %s: %d fonksiyon, %d dolayli cagri, %d somut bagli" %
          (out_path, len(funcs), total_indirect, concrete_linked))


main()
