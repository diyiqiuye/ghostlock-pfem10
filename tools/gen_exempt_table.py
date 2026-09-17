#!/usr/bin/env python3
"""Decode the kill-path jump table of oplus_security_guard.ko and name it.

The table is 72 int32 entries at `.rodata+0`. `oplus_root_check_post_handler`
dispatches with:

    sub  w9, w3, #0x8f        ; w9 = syscallno - 143
    cmp  w9, #0x47            ; 143..214
    b.hi -> kill
    adrp x10, #0 ; add x10, x10, #0        ; -> .rodata+0
    adr  x11, #0x47c
    ldrsw x12, [x10, x9, lsl #2]
    add  x11, x11, x12
    br   x11                  ; 0x47c + entry
    ; 0x48c = return (no kill)   0x4a0 = report + do_exit(SIGKILL)

so table index `i` belongs to syscall number `143 + i`. Names below come from
the public arm64 ABI (asm-generic/unistd.h) and were cross-checked against
`sys_call_table` in this device's kernel image, entry by entry.

NOTE (2026-09-18): an earlier revision of this table labelled every entry one
lower than the real number -- it called 146 `setresuid` (it is `setuid`), 210
`sendmsg` (it is `shutdown`) and 214 `munmap` (it is `brk`). The *numbers* were
always right; only the names were wrong. The consequences of the old labels are
real: `sendmsg` (211), `munmap` (215), `getsockopt` (209) and `getpeername`
(205) are NOT exempt -- a thread that blocks in one of those while its
credentials change gets killed.

Usage:
    python gen_exempt_table.py <oplus_security_guard.ko> [kernel_image syms]
"""
import os
import struct
import sys

RO_OFF = 0x2098          # .rodata file offset in these builds
BASE_ADR = 0x47C         # adr x11,#0x47c
REL, KILL = 0x48C, 0x4A0
FIRST = 143

# arm64 syscall names, 143..214 (asm-generic/unistd.h)
NAMES = {
    143: "setregid", 144: "setgid", 145: "setreuid", 146: "setuid",
    147: "setresuid", 148: "getresuid", 149: "setresgid", 150: "getresgid",
    151: "setfsuid", 152: "setfsgid", 153: "times", 154: "setpgid",
    155: "getpgid", 156: "getsid", 157: "setsid", 158: "getgroups",
    159: "setgroups", 160: "uname", 161: "sethostname", 162: "setdomainname",
    163: "getrlimit", 164: "setrlimit", 165: "getrusage", 166: "umask",
    167: "prctl", 168: "getcpu", 169: "gettimeofday", 170: "settimeofday",
    171: "adjtimex", 172: "getpid", 173: "getppid", 174: "getuid",
    175: "geteuid", 176: "getgid", 177: "getegid", 178: "gettid",
    179: "sysinfo", 180: "mq_open", 181: "mq_unlink", 182: "mq_timedsend",
    183: "mq_timedreceive", 184: "mq_notify", 185: "mq_getsetattr",
    186: "msgget", 187: "msgctl", 188: "msgrcv", 189: "msgsnd",
    190: "semget", 191: "semctl", 192: "semtimedop", 193: "semop",
    194: "shmget", 195: "shmctl", 196: "shmat", 197: "shmdt",
    198: "socket", 199: "socketpair", 200: "bind", 201: "listen",
    202: "accept", 203: "connect", 204: "getsockname", 205: "getpeername",
    206: "sendto", 207: "recvfrom", 208: "setsockopt", 209: "getsockopt",
    210: "shutdown", 211: "sendmsg", 212: "recvmsg", 213: "readahead",
    214: "brk",
}

SCT_VA = 0xffffffc00a13d8c0      # sys_call_table, this build
KIMG_BASE = 0xffffffc008000000


def names_from_image(img, syms):
    """Optional cross-check: resolve every entry via sys_call_table."""
    import bisect
    a, n = [], []
    for line in open(syms):
        p = line.split()
        if len(p) >= 3:
            try:
                a.append(int(p[0], 16))
            except ValueError:
                continue
            n.append(p[2])
    d = open(img, "rb").read()
    out = {}
    for nr in range(FIRST, FIRST + 72):
        fn = struct.unpack_from("<Q", d, SCT_VA - KIMG_BASE + nr * 8)[0]
        j = bisect.bisect_right(a, fn) - 1
        if j >= 0 and a[j] == fn:
            out[nr] = n[j].replace("__arm64_sys_", "").replace(".cfi_jt", "")
    return out


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    ko_path = sys.argv[1]
    names = dict(NAMES)
    if len(sys.argv) > 3 and os.path.exists(sys.argv[2]) and \
            os.path.exists(sys.argv[3]):
        names.update(names_from_image(sys.argv[2], sys.argv[3]))

    ko = open(ko_path, "rb").read()
    rows, exempt = [], []
    for i in range(72):
        rel = struct.unpack_from("<i", ko, RO_OFF + i * 4)[0]
        tgt = BASE_ADR + rel
        nr = FIRST + i
        if tgt == REL:
            exempt.append(nr)
        rows.append((nr, names.get(nr, f"nr{nr}"), tgt))

    print("# oplus_security_guard.ko - kill-path jump table @ .rodata+0")
    print(f"# 72 entries, syscall {FIRST}..{FIRST + 71}")
    print(f"# target = 0x{BASE_ADR:x} + int32(table[idx]); "
          f"0x{REL:x} = return (no kill), 0x{KILL:x} = report + do_exit(SIGKILL)")
    print()
    print(f"{'nr':>5}  {'syscall':<18} {'target':<9} verdict")
    for nr, nm, tgt in rows:
        v = "EXEMPT (no kill)" if tgt == REL else "report+kill"
        print(f"{nr:5}  {nm:<18} 0x{tgt:<7x} {v}")
    print()
    print(f"# EXEMPT ({len(exempt)}): " + " ".join(str(x) for x in exempt))
    print("# " + " ".join(f"{x} {names.get(x, '?')}" for x in exempt))
    return 0


if __name__ == "__main__":
    sys.exit(main())
