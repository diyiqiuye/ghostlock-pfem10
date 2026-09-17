#!/usr/bin/env python3
"""Disassemble a kernel function from the raw Image, annotating bl/adrp/adr
targets with kallsyms names. file_off = VA - relative_base (image maps _text
at payload start; validated by _text/_end bookends).

Usage: python kdis.py <symbol_name> [max_bytes=0x400]
"""
import json
import struct
import sys

from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs

OUT = "out"


def load():
    data = open(f"{OUT}/kernel_payload.bin", "rb").read()
    meta = json.load(open(f"{OUT}/kallsyms_meta.json"))
    rb = meta["relative_base"]
    syms = {}
    for line in open(f"{OUT}/syms.txt", encoding="utf-8"):
        a, t, n = line.split(None, 2)
        syms.setdefault(int(a, 16), n.strip())
    by_name = {}
    for a, n in syms.items():
        by_name.setdefault(n, a)
    return data, rb, syms, by_name


def disasm(name, max_bytes=0x400, show_all=True):
    data, rb, syms, by_name = load()
    va = by_name.get(name)
    if va is None:
        # allow symbol.addr form for aliases
        cands = [a for a, n in syms.items() if n.startswith(name)]
        if not cands:
            print(f"symbol {name} not found")
            return
        va = sorted(cands)[0]
        print(f"(prefix match -> {syms[va]})")
    off = va - rb
    print(f"===== {name} @ VA {va:#x} (file {off:#x}) =====")
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = False
    code = data[off:off + max_bytes]
    for ins in md.disasm(code, va):
        line = f"  {ins.address:#x} (+{ins.address - va:#06x})  {ins.mnemonic:<10} {ins.op_str}"
        extra = []
        if ins.mnemonic in ("bl", "b") and ins.op_str.startswith("#"):
            try:
                tgt = int(ins.op_str[1:], 16)
                if tgt in syms:
                    extra.append(f"-> {syms[tgt]}")
            except ValueError:
                pass
        if ins.mnemonic == "adrp":
            # resolve adrp page target
            m = ins.op_str.split(",")
            try:
                page = int(m[-1].strip().lstrip("#"), 16)
                extra.append(f"page={page:#x}")
            except (ValueError, IndexError):
                pass
        if extra:
            line += "   ; " + " ".join(extra)
        print(line)
        if ins.mnemonic == "ret" and ins.address > va + 0x40:
            break


if __name__ == "__main__":
    nm = sys.argv[1]
    mb = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0x400
    disasm(nm, mb)
