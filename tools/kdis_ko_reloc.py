#!/usr/bin/env python3
"""Reloc-resolved aarch64 disassembler for relocatable kernel .ko files.

Why this exists
---------------
`tools/kdis_ko.py` already finds RELA sections by `sh_info` instead of by name
(on these OPPO builds every `.text` relocation lives in a section called
`.rela.text.__cfi_check`, so a name-based lookup finds nothing). But it prints
the relocation *symbol name*, and on this build almost every relocation in the
watchdog handlers points at a **SECTION symbol** — and section symbols have an
empty name in `.strtab`. Their identity is in `st_shndx`. So the old tool
printed `adrp x9, #0` with no annotation at all, which is exactly the hole that
made `g_boot_state` look unresolvable.

This tool resolves the target as:
    symbol name (if non-empty)  else  <section name from st_shndx> + addend
and folds ADRP+ADD / ADRP+LDR pairs into a single `; = <target>` annotation.

Usage:
    python kdis_ko_reloc.py <ko> <symbol|0xoff> [max_bytes]
    python kdis_ko_reloc.py <ko> --relocs [section]     # raw relocation dump
"""
import struct
import sys

from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs

SHT_SYMTAB = 2
SHT_RELA = 4
STT_FUNC = 2
STT_SECTION = 3

SHN_UNDEF = 0
SHN_ABS = 0xFFF1
SHN_COMMON = 0xFFF2


class Elf:
    def __init__(self, path):
        self.d = open(path, "rb").read()
        d = self.d
        assert d[:4] == b"\x7fELF", "not an ELF"
        assert d[4] == 2, "not ELF64"
        e_shoff = struct.unpack_from("<Q", d, 0x28)[0]
        e_shentsize = struct.unpack_from("<H", d, 0x3A)[0]
        e_shnum = struct.unpack_from("<H", d, 0x3C)[0]
        e_shstrndx = struct.unpack_from("<H", d, 0x3E)[0]
        self.secs = []
        for i in range(e_shnum):
            o = e_shoff + i * e_shentsize
            (name, typ, flags, addr, off, size, link, info, align,
             entsize) = struct.unpack_from("<IIQQQQIIQQ", d, o)
            self.secs.append(dict(name=name, type=typ, flags=flags, addr=addr,
                                  off=off, size=size, link=link, info=info,
                                  entsize=entsize, idx=i, sname=""))
        shstr = self.secs[e_shstrndx]
        self.shstr = d[shstr["off"]:shstr["off"] + shstr["size"]]
        for s in self.secs:
            s["sname"] = self._str(self.shstr, s["name"])

        self.syms = []          # (value, size, info, shndx, name)
        for s in self.secs:
            if s["type"] == SHT_SYMTAB:
                strtab = self.secs[s["link"]]
                st = d[strtab["off"]:strtab["off"] + strtab["size"]]
                for j in range(s["size"] // 24):
                    o = s["off"] + j * 24
                    (st_name, st_info, st_other, st_shndx, st_value,
                     st_size) = struct.unpack_from("<IBBHQQ", d, o)
                    self.syms.append((st_value, st_size, st_info, st_shndx,
                                      self._str(st, st_name)))
        self.byname = {}
        for v, sz, info, shndx, nm in self.syms:
            if nm:
                self.byname.setdefault(nm, (v, sz, info, shndx))

    @staticmethod
    def _str(tab, off):
        e = tab.find(b"\x00", off)
        return tab[off:e].decode("utf-8", "replace")

    def sec_by_idx(self, idx):
        return self.secs[idx] if 0 <= idx < len(self.secs) else None

    def sec(self, name):
        for s in self.secs:
            if s["sname"] == name:
                return s
        return None

    def describe_sym(self, symidx, addend):
        """Human-readable target of a relocation."""
        if symidx >= len(self.syms):
            return f"<sym#{symidx}>+0x{addend:x}"
        value, size, info, shndx, nm = self.syms[symidx]
        if nm:
            return nm + (f"+0x{addend:x}" if addend else "")
        if shndx == SHN_UNDEF:
            return f"<undef#{symidx}>"
        if shndx == SHN_ABS:
            return f"<abs 0x{value + addend:x}>"
        if shndx == SHN_COMMON:
            return f"<common#{symidx}>"
        s = self.sec_by_idx(shndx)
        base = s["sname"] if s else f"<sec{shndx}>"
        return base + (f"+0x{addend:x}" if addend else "")

    def relocs_for(self, sec_name):
        """{r_offset: (rtype, symidx, addend, description)} for the RELA
        section(s) whose sh_info points at `sec_name`."""
        tgt = self.sec(sec_name)
        if tgt is None:
            return {}
        out = {}
        for s in self.secs:
            if s["type"] == SHT_RELA and s["info"] == tgt["idx"]:
                for j in range(s["size"] // 24):
                    o = s["off"] + j * 24
                    r_off, r_info, r_add = struct.unpack_from("<QQq", self.d, o)
                    symidx = r_info >> 32
                    rtype = r_info & 0xFFFFFFFF
                    out[r_off] = (rtype, symidx, r_add,
                                  self.describe_sym(symidx, r_add))
        return out


RTYPE = {
    257: "ABS64", 258: "ABS32", 259: "ABS16",
    260: "PREL64", 261: "PREL32", 262: "PREL16",
    274: "ADR_PREL_LO21", 275: "ADR_PREL_PG_HI21", 276: "ADR_PREL_PG_HI21_NC",
    277: "ADD_ABS_LO12_NC", 278: "LDST8_ABS_LO12_NC",
    279: "TSTBR14", 280: "CONDBR19",
    282: "JUMP26", 283: "CALL26",
    284: "LDST16_ABS_LO12_NC", 285: "LDST32_ABS_LO12_NC",
    286: "LDST64_ABS_LO12_NC", 299: "LDST128_ABS_LO12_NC",
}
HI21 = {275, 276}
LO12 = {277, 278, 284, 285, 286, 299}


def disasm(e, off, maxb, title):
    text = e.sec(".text")
    rel = e.relocs_for(".text")
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    insns = list(md.disasm(e.d[text["off"] + off: text["off"] + off + maxb], off))
    print(f"### {title}")
    print(f"=== .text+0x{off:x}  (size 0x{maxb:x}) ===\n")
    for k, ins in enumerate(insns):
        ann = ""
        r = rel.get(ins.address)
        if r:
            rtype, symidx, addend, desc = r
            tname = RTYPE.get(rtype, f"type{rtype}")
            if rtype in HI21:
                # fold ADRP with the following ADD/LDR's LO12 relocation
                nxt = rel.get(ins.address + 4)
                if nxt and nxt[0] in LO12:
                    ann = f"   ; {tname} + {RTYPE[nxt[0]]} -> {desc}"
                else:
                    ann = f"   ; {tname} -> {desc}"
            else:
                ann = f"   ; {tname} -> {desc}"
        print(f"  0x{ins.address:04x}: {ins.mnemonic:<8}{ins.op_str}{ann}")
    print()


def dump_relocs(e, sec_name=".text"):
    rel = e.relocs_for(sec_name)
    print(f"# relocations for {sec_name}: {len(rel)} entries")
    print(f"# {'offset':<10} {'type':<22} {'target'}")
    for off in sorted(rel):
        rtype, symidx, addend, desc = rel[off]
        tname = RTYPE.get(rtype, f"type{rtype}")
        print(f"  0x{off:<8x} {tname:<22} {desc}")
    print()


def main():
    ko = sys.argv[1]
    e = Elf(ko)
    if len(sys.argv) > 2 and sys.argv[2] == "--relocs":
        dump_relocs(e, sys.argv[3] if len(sys.argv) > 3 else ".text")
        return 0
    target = sys.argv[2]
    maxb = int(sys.argv[3], 16) if len(sys.argv) > 3 else 0x400
    if target.lower().startswith("0x"):
        off, title = int(target, 16), target
    else:
        if target not in e.byname:
            print(f"symbol {target} not found")
            return 1
        off, sz, info, shndx = e.byname[target]
        title = target
        if maxb == 0x400 and sz:
            maxb = sz
    disasm(e, off, maxb, title)
    return 0


if __name__ == "__main__":
    sys.exit(main())
