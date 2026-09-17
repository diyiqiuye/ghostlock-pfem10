#!/usr/bin/env python3
"""Resolve a range of arm64 syscall numbers to real function names.

Reads `sys_call_table` straight out of a kernel image and resolves each entry
against a kallsyms dump, so the names come from the kernel rather than from
anyone's memory of the ABI.

This is how the exempt table's labels were corrected on 2026-09-18: the numbers
143..214 were always right, but the names had been attached one lower than the
real arm64 numbering (146 is `setuid`, not `setresuid`; 210 is `shutdown`, not
`sendmsg`).

Usage:
    python sct_dump.py <kernel_image> <syms.txt> <sys_call_table_va> <base_va> <lo> <hi>
Example:
    python sct_dump.py kernel_payload.bin syms.txt \
        0xffffffc00a13d8c0 0xffffffc008000000 143 151
"""
import bisect
import struct
import sys


def load_syms(path):
    addrs, names = [], []
    for line in open(path):
        p = line.split()
        if len(p) >= 3:
            try:
                addrs.append(int(p[0], 16))
            except ValueError:
                continue
            names.append(p[2])
    return addrs, names


def main():
    if len(sys.argv) < 7:
        print(__doc__)
        return 1
    img, syms = sys.argv[1], sys.argv[2]
    sct = int(sys.argv[3], 16)
    base = int(sys.argv[4], 16)
    lo, hi = int(sys.argv[5]), int(sys.argv[6])

    addrs, names = load_syms(syms)
    data = open(img, "rb").read()
    for nr in range(lo, hi + 1):
        v = struct.unpack_from("<Q", data, sct - base + nr * 8)[0]
        i = bisect.bisect_right(addrs, v) - 1
        if i >= 0 and addrs[i] == v:
            nm = names[i]
        elif i >= 0 and v - addrs[i] < 0x4000:
            nm = f"{names[i]}+0x{v - addrs[i]:x}"
        else:
            nm = f"?0x{v:x}"
        print(f"{nr:5} {nm}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
