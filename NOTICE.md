# NOTICE

## Contents

| Path | Provenance | License |
|---|---|---|
| `artifacts/*` | disassembly listings derived from the vendor modules named in the README | this repository |
| `evidence/*` | captures from the researcher's own device | this repository |
| `src/*`, `tools/*` | exploit chain and analysis tooling | GPL-3.0 (see `LICENSE`) |

## What is not included

**Vendor modules.** The OPPO modules analysed in the README —
`oplus_security_guard.ko`, `oplus_secure_harden.ko`,
`oplus_security_keventupload.ko`, `oplus_secure_common.ko` — are **not**
redistributed here. They are proprietary, and they are not needed: pull them
from your own device and regenerate every artifact.

**Root solution binaries.** `kernelsu.ko`, `ksud` and `libkernelsu.so` are not
redistributed either. They are upstream KernelSU / ReSukiSU artifacts under
GPL-3.0 and are readily available from those projects; take them from upstream
so that the build you run is one you chose. This repository is the analysis of
one device's watchdog, not a turnkey root package.

## Reproducing the artifacts

```bash
adb pull /vendor/lib/modules/oplus_security_guard.ko
adb pull /vendor/lib/modules/oplus_secure_harden.ko

python tools/kdis_ko.py oplus_security_guard.ko oplus_root_check_post_handler
python tools/kdis_ko.py oplus_secure_harden.ko entry_handler_socket

# regenerate artifacts/ with relocations resolved
python tools/gen_guard_disasm.py oplus_security_guard.ko oplus_secure_harden.ko artifacts
python tools/gen_exempt_table.py oplus_security_guard.ko
```

`tools/kdis_ko.py` matches RELA sections by `sh_info`, not by name. On these builds the `.text` relocations live in an oddly-named section (`.rela.text.<function_name>`), so a name-based lookup returns zero entries and `bl` targets appear unresolved.

`tools/kdis_ko_reloc.py` goes one step further and resolves **section** symbols too. On this build almost every relocation in the watchdog handlers points at a section symbol, which has no name in `.strtab` — its identity has to come from `st_shndx`. That is what makes `g_boot_state` (the only byte in `.data..ro_after_init`) show up as a relocation target instead of an unresolved `adrp x9, #0`.

## Scope

Security research on hardware owned by the researcher. Nothing here is intended to help anyone access a device they do not own.
