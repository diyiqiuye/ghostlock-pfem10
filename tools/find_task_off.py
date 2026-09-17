#!/usr/bin/env python3
"""Find every site in the kernel Image that reads/writes [current + OFF].

Pattern:  mrs Xt, sp_el0      (0xD5384100 | Rt)
     followed (within 5 instrs) by
          ldr/ldrb/str Xd, [Xt, #OFF]

Purpose: identify which task_struct member lives at a given offset on THIS build.
"""
import re, struct, bisect, collections, sys

IMG = r"D:\Desktop\cve202643499\out\kernel_payload.bin"
SYMS = r"D:\Desktop\cve202643499\out\syms.txt"
BASE = 0xFFFFFFC008000000
OFF = int(sys.argv[1], 0) if len(sys.argv) > 1 else 8

syms = []
for line in open(SYMS, encoding="utf-8", errors="replace"):
    p = line.split()
    if len(p) >= 3:
        try:
            a = int(p[0], 16)
        except ValueError:
            continue
        syms.append((a, p[2]))
syms.sort()
addrs = [a for a, _ in syms]


def symof(va):
    i = bisect.bisect_right(addrs, va) - 1
    return "?" if i < 0 else "%s+0x%x" % (syms[i][1], va - syms[i][0])


d = open(IMG, "rb").read()

# (mask, match, kind, scale)  -- scale converts imm12 to a byte offset
FORMS = [
    (0xFFC00000, 0xF9400000, "ldr x", 8),
    (0xFFC00000, 0xB9400000, "ldr w", 4),
    (0xFFC00000, 0x39400000, "ldrb", 1),
    (0xFFC00000, 0x39800000, "ldrsb", 1),
    (0xFFC00000, 0xB9800000, "ldrsw", 4),
    (0xFFC00000, 0xF9000000, "str x", 8),
    (0xFFC00000, 0xB9000000, "str w", 4),
    (0xFFC00000, 0x39000000, "strb", 1),
]

hits = collections.defaultdict(list)
for m in re.finditer(rb"[\x00-\x1f]\x41\x38\xd5", d):
    off = m.start()
    rt = d[off] & 31
    for j in range(1, 6):
        if off + 4 * j + 4 > len(d):
            break
        w2 = struct.unpack_from("<I", d, off + 4 * j)[0]
        for mask, match, kind, scale in FORMS:
            if (w2 & mask) == match:
                rn = (w2 >> 5) & 31
                imm = ((w2 >> 10) & 0xFFF) * scale
                if rn == rt and imm == OFF:
                    hits[symof(BASE + off)].append((BASE + off, kind))
                break

print("=== sites touching [current + %#x] ===" % OFF)
for s in sorted(hits, key=lambda k: -len(hits[k]))[:35]:
    kinds = collections.Counter(k for _, k in hits[s])
    print("  %-46s x%-4d %s" % (s[:46], len(hits[s]), dict(kinds)))
print("total sites: %d  unique symbols: %d" % (sum(len(v) for v in hits.values()), len(hits)))
