// ============================================================================
//  i4M GodTier Engine — analysis/msvcrtti.cpp
//  MSVC RTTI atlasi uygulaması. İki aşama:
//    A) COL (CompleteObjectLocator) avı: .rdata/.data içindeki her dword'ü
//       COL adayı olarak doğrula (signature + TypeDescriptor isim kontrolü)
//    B) vftable kurulumu: COL'u işaret eden dword'lerin +4'ünden itibaren
//       kod işaretçisi olan slotları oku; ilk kod-dışı işaretçide dur
//
//  x86 (sig=0): COL alanları MUTLAK VA; x64 (sig=1): RVA (ImageBase ekle).
//  (metin2client.exe x86: TypeDescriptor'lar .data içinde — VA okuma şart)
// ============================================================================
#include "analysis/msvcrtti.h"
#include "core/log.h"
#include <cstring>

namespace gt {

// ----------------------------------------------------------------------------
// MSVC tip adı demangle (temel düzey):
//   .?AVName@@              -> Name                     (class)
//   .?AUName@@              -> Name                     (struct)
//   .?AW4Name@@             -> Name                     (enum)
//   .?AV?$A@VInner@@@@      -> A<Inner>                 (template, tek seviye)
//   .?AVOuter@Inner@@       -> Outer::Inner             (nested — MSVC ters sırada)
// ----------------------------------------------------------------------------
std::string MsvcRtti::DemangleTypeId(const std::string& raw) {
    if (raw.size() < 4 || raw.rfind(".?A", 0) != 0) return raw;
    // 4. karakter: 'V' class, 'U' struct, 'W' enum (W4...), digerleri: oldugu gibi
    size_t start = 4;
    if (raw[3] == 'W') start = 6;   // ".?AW4Enum@@" -> "Enum"
    std::string body = raw.substr(start);
    // sondaki @@'leri kes (1 veya 2 tane olabilir)
    while (body.size() >= 2 && body.substr(body.size() - 2) == "@@")
        body = body.substr(0, body.size() - 2);
    if (body.empty()) return raw;

    // sablon: $ ile basliyorsa $ ... @ arasi sablon adi + argumanlari
    if (!body.empty() && body[0] == '$') {
        size_t at = body.find('@');
        if (at != std::string::npos) {
            std::string tmpl = body.substr(1, at - 1);
            std::string rest = body.substr(at + 1);
            // argumanlar: V...@ / U...@ / sayi ($0x)
            std::vector<std::string> args;
            size_t p = 0;
            while (p < rest.size()) {
                if (rest[p] == 'V' || rest[p] == 'U') {
                    size_t q = rest.find('@', p + 1);
                    if (q == std::string::npos) break;
                    std::string a = rest.substr(p + 1, q - p - 1);
                    // ic ice sablon (nadir): basit tut — ham birak
                    args.push_back(a);
                    p = q + 1;
                } else if (rest[p] == 'A') {   // reference: V gibi isle
                    size_t q = rest.find('@', p + 1);
                    if (q == std::string::npos) break;
                    args.push_back(rest.substr(p + 1, q - p - 1));
                    p = q + 1;
                } else if (rest[p] == '$') {   // $0X sayi literali
                    size_t q = rest.find('@', p);
                    if (q == std::string::npos) q = rest.size();
                    args.push_back(rest.substr(p, q - p));
                    p = q;
                } else {
                    break;
                }
            }
            std::string out = tmpl + "<";
            for (size_t i = 0; i < args.size(); i++) {
                if (i) out += ",";
                out += args[i];
            }
            out += ">";
            return out;
        }
    }
    // nested: "Player@Python@CP" (MSVC: en icerdekten disa) -> "CP::Python::Player"
    std::vector<std::string> parts;
    size_t p = 0;
    while (p < body.size()) {
        size_t q = body.find('@', p);
        if (q == std::string::npos) { parts.push_back(body.substr(p)); break; }
        parts.push_back(body.substr(p, q - p));
        p = q + 1;
    }
    std::string out;
    for (int i = (int)parts.size() - 1; i >= 0; i--) {
        if (parts[i].empty()) continue;
        if (!out.empty()) out += "::";
        out += parts[i];
    }
    return out.empty() ? raw : out;
}

bool MsvcRtti::IsExecPtr(u64 va) const {
    for (auto& s : az_.Bin().Sections())
        if (s.executable && va >= s.va && va < s.va + std::max(s.vsize, s.rawSize))
            return true;
    return false;
}

bool MsvcRtti::IsDataPtr(u64 va) const {
    for (auto& s : az_.Bin().Sections())
        if (!s.executable && s.readable && va >= s.va &&
            va < s.va + std::max(s.vsize, s.rawSize))
            return true;
    return false;
}

// COL doğrulaması: 5 dword — sig, offset, cdOffset, pTypeDescriptor, pClassDescriptor
bool MsvcRtti::ValidCol(u64 colVa, u64* tdVaOut, u32* objOffOut,
                        u32* nBasesOut, std::vector<std::string>* baseNamesOut) const {
    if (!IsDataPtr(colVa)) return false;
    u32 sig = 0;
    if (!az_.Image().ReadBytes(colVa, (u8*)&sig, 4)) return false;
    if (sig != 0 && sig != 1) return false;          // 0=x86, 1=x64
    u32 off = 0, cd = 0, tdField = 0, chdField = 0;
    if (!az_.Image().ReadBytes(colVa + 4, (u8*)&off, 4)) return false;
    if (!az_.Image().ReadBytes(colVa + 8, (u8*)&cd, 4)) return false;
    if (!az_.Image().ReadBytes(colVa + 12, (u8*)&tdField, 4)) return false;
    if (!az_.Image().ReadBytes(colVa + 16, (u8*)&chdField, 4)) return false;
    if (off > 0xFFFF) return false;                   // tam nesnede ofset
    // x86: mutlak VA; x64: RVA
    u64 tdVa = (sig == 1) ? az_.Bin().ImageBase() + tdField : (u64)tdField;
    u64 chdVa = (sig == 1) ? az_.Bin().ImageBase() + chdField : (u64)chdField;
    // TypeDescriptor: [vftable ptr][spare][isim ".?A..."]
    if (!IsDataPtr(tdVa)) return false;
    char name[6] = {};
    if (!az_.Image().ReadBytes(tdVa + 8, (u8*)name, 5)) return false;
    if (strncmp(name, ".?A", 3) != 0) return false;   // .?AV / .?AU / .?AW...
    // ClassHierarchyDescriptor: [sig][attributes][numBases][pBaseArray]
    u32 chdSig = 0, numBases = 0, pBaseArrayField = 0;
    if (!az_.Image().ReadBytes(chdVa, (u8*)&chdSig, 4)) return false;
    if (!az_.Image().ReadBytes(chdVa + 8, (u8*)&numBases, 4)) return false;
    if (!az_.Image().ReadBytes(chdVa + 12, (u8*)&pBaseArrayField, 4)) return false;
    if (chdSig != 0) return false;
    if (numBases == 0 || numBases > 128) return false;
    u64 baseArrayVa = (sig == 1) ? az_.Bin().ImageBase() + pBaseArrayField
                                 : (u64)pBaseArrayField;
    // BaseClassDescriptor: [pTypeDescriptor][numContainedBases][PMD x3][attributes]
    if (baseNamesOut && IsDataPtr(baseArrayVa)) {
        for (u32 i = 0; i < numBases && i < 16; i++) {
            u32 bcdTdField = 0;
            if (!az_.Image().ReadBytes(baseArrayVa + 4ull * i,
                                       (u8*)&bcdTdField, 4)) break;
            u64 bTd = (sig == 1) ? az_.Bin().ImageBase() + bcdTdField
                                 : (u64)bcdTdField;
            if (!IsDataPtr(bTd)) break;
            char bn[64] = {};
            if (!az_.Image().ReadBytes(bTd + 8, (u8*)bn, 8)) break;
            if (strncmp(bn, ".?A", 3) != 0) break;
            // tam isim oku
            std::string full;
            for (int k = 0; k < 96; k++) {
                char c = 0;
                if (!az_.Image().ReadBytes(bTd + 8 + k, (u8*)&c, 1)) break;
                if (!c) break;
                full += c;
            }
            baseNamesOut->push_back(DemangleTypeId(full));
        }
    }
    if (tdVaOut) *tdVaOut = tdVa;
    if (objOffOut) *objOffOut = off;
    if (nBasesOut) *nBasesOut = numBases;
    return true;
}

void MsvcRtti::Build() {
    classes_.clear();
    byVft_.clear();
    byCol_.clear();
    children_.clear();
    totalSlots_ = 0;

    const u64 ptrSize = az_.Bin().Is64() ? 8 : 4;
    std::map<u64, bool> colValid;   // COL VA -> gecerli (cache)

    // A) tum okunur veri bolumlerini dword/dqword tara; COL'a isaret eden
    //    deger = vftable basligi
    for (auto& sec : az_.Bin().Sections()) {
        if (sec.executable || !sec.readable) continue;
        if (sec.rawSize == 0) continue;
        u64 begin = sec.va & ~(ptrSize - 1);
        u64 end = sec.va + std::max(sec.vsize, sec.rawSize);
        for (u64 a = begin; a + ptrSize <= end; a += ptrSize) {
            u64 d = 0;
            if (!az_.Image().ReadBytes(a, (u8*)&d, ptrSize)) continue;
            if (!IsDataPtr(d)) continue;
            auto cv = colValid.find(d);
            if (cv == colValid.end()) {
                u64 tdVa = 0; u32 objOff = 0, nB = 0;
                std::vector<std::string> bases;
                cv = colValid.emplace(d, ValidCol(d, &tdVa, &objOff, &nB,
                                                   &bases)).first;
            }
            if (!cv->second) continue;

            // vftable: a + ptrSize'ten itibaren kod isaretcileri
            RttiClass rc;
            rc.colVa = d;
            rc.vftVa = a + ptrSize;
            u64 tdVa = 0; u32 objOff = 0, nB = 0;
            std::vector<std::string> bases;
            ValidCol(d, &tdVa, &objOff, &nB, &bases);   // (cache'li tekrar — ucuz)
            rc.tdVa = tdVa;
            rc.objectOffset = objOff;
            rc.numBases = nB;
            // TypeDescriptor ismi
            std::string rawName;
            for (int k = 0; k < 160; k++) {
                char c = 0;
                if (!az_.Image().ReadBytes(tdVa + 8 + k, (u8*)&c, 1)) break;
                if (!c) break;
                rawName += c;
            }
            rc.rawName = rawName;
            rc.name = DemangleTypeId(rawName);
            // slotlari oku
            u64 maxSlots = 512;
            for (u64 i = 0; i < maxSlots; i++) {
                u64 slotVa = rc.vftVa + i * ptrSize;
                u64 t = 0;
                if (!az_.Image().ReadBytes(slotVa, (u8*)&t, ptrSize)) {
                    rc.slotsComplete = false; break;
                }
                if (!IsExecPtr(t)) break;          // vftable sonu
                rc.slots.push_back(t);
            }
            classes_.push_back(std::move(rc));
        }
    }

    // B) indeksler + hiyerarsi
    for (auto& c : classes_) {
        byVft_[c.vftVa] = &c;
        byCol_[c.colVa].push_back(&c);
        totalSlots_ += c.slots.size();
    }
    // hiyerarsi: her COL'un BaseClassDescriptor zincirinden taban iliskileri
    for (auto& c : classes_) {
        u64 tdVa = 0; u32 objOff = 0, nB = 0;
        std::vector<std::string> bases;
        if (ValidCol(c.colVa, &tdVa, &objOff, &nB, &bases)) {
            // bases[0] = tam sinifin kendisi; sonraki = tabanlar
            for (size_t i = 1; i < bases.size(); i++) {
                if (bases[i] != c.name)
                    children_[bases[i]].insert(c.name);
            }
        }
    }
    // v8: ATLAS İNVERSİYONU — metot VA -> içeren vftable'lar (sıra: atlas
    // sırası = kararlı). Sanal metod gövdesindeki this alıcısının dinamik
    // tipi bu kümeyle kısıtlanır (CHA tabanı).
    methodOwners_.clear();
    for (auto& c : classes_)
        for (u64 m : c.slots)
            methodOwners_[m].push_back(&c);
    if (!classes_.empty())
        LogInfo("rtti: %zu sinif, %zu vftable slotu geri kazanildi",
                classes_.size(), totalSlots_);
}

const RttiClass* MsvcRtti::ByVftable(u64 vftVa) const {
    auto it = byVft_.find(vftVa);
    return it == byVft_.end() ? nullptr : it->second;
}

const RttiClass* MsvcRtti::ByName(const std::string& demangled) const {
    for (auto& c : classes_)
        if (c.name == demangled) return &c;
    return nullptr;
}

const std::vector<const RttiClass*>* MsvcRtti::VtablesContaining(u64 methodVa) const {
    auto it = methodOwners_.find(methodVa);
    return it == methodOwners_.end() ? nullptr : &it->second;
}

u64 MsvcRtti::ResolveSlot(u64 vftVa, u32 slotByteOff, std::string* why) const {
    const RttiClass* c = ByVftable(vftVa);
    if (!c) return 0;
    const u64 ptrSize = az_.Bin().Is64() ? 8 : 4;
    if (slotByteOff % ptrSize) return 0;    // hizali degil — supheli
    u64 slot = slotByteOff / ptrSize;
    if (slot >= c->slots.size()) {
        if (why) *why = c->name + " vftable'de slot " + std::to_string(slot) +
                        " yok (" + std::to_string(c->slots.size()) + " slot)";
        return 0;
    }
    if (why) *why = c->name + " vftable[" + std::to_string(slot) + "]";
    return c->slots[slot];
}

} // namespace gt
