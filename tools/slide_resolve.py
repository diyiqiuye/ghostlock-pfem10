import sys, re, bisect

BASE = 0xFFFFFFC008000000
addrs, names = [], []
for line in open(r"D:\Desktop\cve202643499\out\syms.txt", encoding="utf-8", errors="replace"):
    p = line.split()
    if len(p) >= 3:
        try:
            a = int(p[0], 16)
        except ValueError:
            continue
        addrs.append(a); names.append(" ".join(p[2:]))

ips = []
for arg in sys.argv[1:]:
    ips.append(int(arg, 16))
# also read stdin lines "PROBE ip=0x... n=k"
for line in sys.stdin:
    m = re.search(r"ip=0x([0-9a-f]+) n=(\d+)", line)
    if m:
        ips.append(int(m.group(1), 16));
        globals().setdefault("counts", {})[int(m.group(1), 16)] = int(m.group(2))

counts = globals().get("counts", {})
print("resolving %d unique IPs" % len(ips))
slides = {}
for ip in set(ips):
    if ip < BASE:
        print("  %016llx  BELOW IMAGE?" % ip); continue
    off = ip - BASE
    i = bisect.bisect_right(addrs, ip) - 1
    if i < 0 or addrs[i] < BASE:
        print("  %016llx  off=%09x  NO-SYM" % (ip, off)); continue
    sym = names[i]; sym_off = addrs[i] - BASE
    delta = ip - addrs[i]
    cand_slide = (ip - BASE - sym_off) - (ip - BASE - sym_off) % 0x200000  # rounded delta from sym start
    r2m = (ip - addrs[i])
    key_slide = (ip - addrs[i])  # not a slide
    slides.setdefault((sym, sym_off), []).append((ip, counts.get(ip, 1)))
for (sym, off), lst in sorted(slides.items(), key=lambda kv: -sum(c for _, c in kv[1])):
    tot = sum(c for _, c in lst)
    # slide candidates: for each ip: s = ip - (BASE+off) ; true slide makes s a small in-func offset
    smin = min(ip - (BASE + off) for ip, _ in lst)
    smax = max(ip - (BASE + off) for ip, _ in lst)
    print("  %-52s off=%08x hits=%-4d ip_off_in_sym=[%#x..%#x] => slide_candidate=%#x" %
          (sym[:52], off, tot, smin, smax, smin & ~0x1FFFFF))
