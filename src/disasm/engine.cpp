// ============================================================================
//  i4M GodTier Engine — disasm/engine.cpp
// ============================================================================
#include "disasm/engine.h"
#include "core/log.h"
#include <cstring>
#include <cstdio>

namespace gt {

DisasmEngine::DisasmEngine() = default;
DisasmEngine::~DisasmEngine() {
    if (handle_) cs_close(&handle_);
}

bool DisasmEngine::Init(Arch arch) {
    if (handle_) { cs_close(&handle_); handle_ = 0; }
    arch_ = arch;
    // v6: çoklu mimari — x86-64/32 + ARM64/AArch64 + ARM32 (Capstone çekirdeği)
    bool ok = false;
    switch (arch) {
        case Arch::X86_64:
            ok = cs_open(CS_ARCH_X86, CS_MODE_64, &handle_) == CS_ERR_OK; break;
        case Arch::X86_32:
            ok = cs_open(CS_ARCH_X86, CS_MODE_32, &handle_) == CS_ERR_OK; break;
        case Arch::ARM64:
            ok = cs_open(CS_ARCH_ARM64, (cs_mode)CS_MODE_LITTLE_ENDIAN, &handle_) == CS_ERR_OK; break;
        case Arch::ARM32:
            ok = cs_open(CS_ARCH_ARM, (cs_mode)(CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN), &handle_) == CS_ERR_OK; break;
        default: return false;
    }
    if (!ok) { LogErr("Capstone acilamadi (mimari destegi yok)"); return false; }
    if (arch == Arch::X86_64 || arch == Arch::X86_32)
        cs_option(handle_, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
    cs_option(handle_, CS_OPT_DETAIL, CS_OPT_ON);
    return true;
}

bool DisasmEngine::DisasmOne(const u8* code, size_t size, u64 va, Ins& out) {
    if (!handle_ || !code || !size) return false;
    cs_insn* ins = nullptr;
    size_t n = cs_disasm(handle_, code, size, va, 1, &ins);
    if (!n) return false;
    out = Ins{};
    out.addr = ins[0].address;
    out.len = (u8)ins[0].size;
    memcpy(out.bytes, ins[0].bytes, out.len);
    out.mnemonic = ins[0].mnemonic;
    out.opStr = ins[0].op_str;

    // --- detay analizi: hedef/m bellek çözümü (analyzer'a yardım) ---
    cs_detail* d = ins[0].detail;
    if (d) {
        for (int i = 0; i < d->groups_count; i++) {
            if (d->groups[i] == CS_GRP_CALL) out.isCall = true;
            else if (d->groups[i] == CS_GRP_JUMP) {
                if (arch_ == Arch::X86_64 || arch_ == Arch::X86_32) {
                    if (ins[0].id == X86_INS_JMP) out.isJmp = true;
                    else out.isJcc = true;
                } else {
                    // ARM/ARM64: koşulsuz dal mnemonic'e göre (b/b.w vs b.cond/cbz)
                    out.isJcc = true;
                }
            }
            else if (d->groups[i] == CS_GRP_RET) out.isRet = true;
        }
        if (arch_ == Arch::ARM64 || arch_ == Arch::ARM32) {
            // ---- v6: ARM ailesi hedef/bellek çözümü ----
            // koşulsuz dal tespiti: b / b.w (ARM64: mnemonic tam "b")
            if ((arch_ == Arch::ARM64 && out.isJcc && ins[0].mnemonic[0] == 'b' &&
                 ins[0].mnemonic[1] == 0) ||
                (arch_ == Arch::ARM32 && out.isJcc &&
                 strcmp(ins[0].mnemonic, "b") == 0)) {
                out.isJcc = false;
                out.isJmp = true;
            }
            // bx lr = dönüş (ARM32'de grup bazen VERİLMEZ)
            if (arch_ == Arch::ARM32 && ins[0].mnemonic[0] == 'b' &&
                ins[0].op_str && strstr(ins[0].op_str, "lr"))
                out.isRet = true;
            // dal hedefi: ilk IMM operand (b/bl/b.cond/cbz/tbz)
            if (out.isCall || out.isJmp || out.isJcc) {
                const int opc = (arch_ == Arch::ARM64)
                    ? d->arm64.op_count : d->arm.op_count;
                for (int i = 0; i < opc; i++) {
                    bool isImm = (arch_ == Arch::ARM64)
                        ? d->arm64.operands[i].type == ARM64_OP_IMM
                        : d->arm.operands[i].type == ARM_OP_IMM;
                    if (isImm) {
                        out.target = (arch_ == Arch::ARM64)
                            ? (u64)d->arm64.operands[i].imm
                            : (u64)d->arm.operands[i].imm;
                        break;
                    }
                }
                if (!out.target) out.isIndirect = true;  // br x0 / blr x0 gibi
            }
            // veri adresi kanıtı: adr/adrp (ARM64) — string/rodata xref kaynağı
            if (arch_ == Arch::ARM64 &&
                (ins[0].mnemonic[0] == 'a') &&
                (strncmp(ins[0].mnemonic, "adr", 3) == 0) &&
                d->arm64.op_count >= 2 &&
                d->arm64.operands[1].type == ARM64_OP_IMM) {
                out.hasMemRef = true;
                out.memRef = (u64)d->arm64.operands[1].imm;
            }
        } else {
            // ---- x86 ailesi ----
            if (out.isCall || out.isJmp || out.isJcc) {
                if (d->x86.op_count) {
                    cs_x86_op& op = d->x86.operands[0];
                    if (op.type == X86_OP_IMM) {
                        out.target = (u64)op.imm;
                    } else {
                        out.isIndirect = true; // call rax / jmp [rax+8] / jmp qword [table+idx*8]
                    }
                }
            }
            for (int i = 0; i < d->x86.op_count; i++) {
                cs_x86_op& op = d->x86.operands[i];
                if (op.type == X86_OP_MEM) {
                    out.hasMemRef = true;
                    // RIP-göreli veya taban-sabit bellek erişimi: [rip+X] veya [imm]
                    if (op.mem.base == X86_REG_RIP) {
                        out.memRef = out.addr + out.len + op.mem.disp;
                    } else if (op.mem.base == X86_REG_INVALID && op.mem.index == X86_REG_INVALID) {
                        out.memRef = (u64)op.mem.disp;
                    }
                }
            }
        }
    }
    cs_free(ins, n);
    return true;
}

std::vector<Ins> DisasmEngine::Disasm(const u8* code, size_t size, u64 va, size_t maxCount) {
    std::vector<Ins> out;
    if (!handle_) return out;
    cs_insn* ins = nullptr;
    size_t n = cs_disasm(handle_, code, size, va, maxCount, &ins);
    out.reserve(n);
    for (size_t i = 0; i < n; i++) {
        Ins x;
        DisasmOne(&code[ins[i].address - va], size - (size_t)(ins[i].address - va),
                  ins[i].address, x);
        out.push_back(x);
    }
    cs_free(ins, n);
    return out;
}

std::vector<Ins> DisasmEngine::DisasmRange(u64 va, size_t maxCount) {
    std::vector<Ins> out;
    if (!handle_ || !reader_) return out;
    u8 buf[64];
    u64 cur = va;
    for (size_t i = 0; i < maxCount; i++) {
        if (!reader_(cur, buf, sizeof(buf))) break;
        Ins x;
        if (!DisasmOne(buf, sizeof(buf), cur, x)) break;
        out.push_back(x);
        cur += x.len;
    }
    return out;
}

} // namespace gt
