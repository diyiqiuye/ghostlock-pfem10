#!/usr/bin/env python3
"""Disassemble a function inside a relocatable aarch64 .ko, resolving
bl/adrp/adr targets via ELF symtab + .rela.text.

Usage: python kdis_ko.py <ko_path> <symbol|0xoff> [max_bytes]
"""
import struct
import sys

from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs


class Elf:
    def __init__(self, path):
        self.d = open(path, "rb").read()
        d = self.d
        assert d[:4] == b"\x7fELF"
        self.is64 = d[4] == 2
        e_shoff = struct.unpack_from("<Q", d, 0x28)[0]
        e_shentsize = struct.unpack_from("<H", d, 0x3A)[0]
        e_shnum = struct.unpack_from("<H", d, 0x3C)[0]
        e_shstrndx = struct.unpack_from("<H", d, 0x3E)[0]
        self.secs = []
        for i in range(e_shnum):
            o = e_shoff + i * e_shentsize
            name, typ, flags, addr, off, size, link, info, align, entsize = \
                struct.unpack_from("<IIQQQQIIQQ", d, o)
            self.secs.append(dict(name=name, type=typ, flags=flags, addr=addr,
                                  off=off, size=size, link=link, info=info,
                                  entsize=entsize, idx=i))
        # section name string table
        shstr = self.secs[e_shstrndx]
        self.shstr = d[shstr["off"]:shstr["off"] + shstr["size"]]
        for s in self.secs:
            s["sname"] = self._str(self.shstr, s["name"])
        # symbol tables
        self.syms = []  # (value, size, info, shndx, name)
        for s in self.secs:
            if s["type"] == 2:  # SYMTAB
                strtab = self.secs[s["link"]]
                st = d[strtab["off"]:strtab["off"] + strtab["size"]]
                n = s["size"] // 24
                for j in range(n):
                    o = s["off"] + j * 24
                    st_name, st_info, st_other, st_shndx, st_value, st_size = \
                        struct.unpack_from("<IBBHQQ", d, o)
                    self.syms.append((st_value, st_size, st_info, st_shndx,
                                      self._str(st, st_name)))
        self.byname = {}
        self.byval = {}
        for v, sz, info, shndx, nm in self.syms:
            if nm:
                self.byname.setdefault(nm, (v, sz, info, shndx))
                if (info & 0xF) == 2:  # FUNC
                    self.byval.setdefault(v, nm)

    @staticmethod
    def _str(tab, off):
        e = tab.find(b"\x00", off)
        return tab[off:e].decode("utf-8", "replace")

    def sec(self, name):
        for s in self.secs:
            if s["sname"] == name:
                return s
        return None

    def relocs_for(self, target_sec_name):
        """Return {r_offset: symbol_name} for any RELA section whose sh_info
        points at the target section (handles the kernel's odd per-symbol
        section naming, e.g. .rela.text.<func>)."""
        tgt = self.sec(target_sec_name)
        if tgt is None:
            return {}
        tidx = tgt["idx"]
        rel = {}
        for s in self.secs:
            if s["type"] == 4 and s["info"] == tidx:
                n = s["size"] // 24
                for j in range(n):
                    o = s["off"] + j * 24
                    r_off, r_info, r_add = struct.unpack_from("<QQq", self.d, o)
                    symidx = r_info >> 32
                    nm = ""
                    if symidx < len(self.syms):
                        nm = self.syms[symidx][4]
                    rel[r_off] = nm
        return rel


def main():
    ko = sys.argv[1]
    target = sys.argv[2]
    maxb = int(sys.argv[3], 16) if len(sys.argv) > 3 else 0x400

    e = Elf(ko)
    text = e.sec(".text")
    rel = e.relocs_for(".text")

    if target.startswith("0x") or target.startswith("0X"):
        off = int(target, 16)
        name = f"<{target}>"
    else:
        if target not in e.byname:
            print(f"symbol {target} not found")
            return
        off, sz, info, shndx = e.byname[target]
        name = target
        if maxb == 0x400 and sz:
            maxb = sz

    start = text["off"] + off
    data = e.d[start:start + maxb]

    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    print(f"=== {name} @ .text+0x{off:x} (file 0x{start:x}) size~0x{maxb:x} ===")
    for ins in md.disasm(data, off):
        ann = ""
        rn = rel.get(ins.address)
        if rn:
            ann = f"   ; RELOC {rn}"
        print(f"  0x{ins.address:x}: {ins.mnemonic}\t{ins.op_str}{ann}")


if __name__ == "__main__":
    main()
