# NOTICE

## Contents

| Path | Provenance | License |
|---|---|---|
| `modules/oplus_security_guard.ko` | pulled from the device's `/vendor/lib/modules/` | OPPO proprietary |
| `modules/oplus_secure_harden.ko` | same | OPPO proprietary |
| `modules/oplus_security_keventupload.ko` | same | OPPO proprietary |
| `modules/oplus_secure_common.ko` | same | OPPO proprietary |
| `modules/kernelsu.ko` | KernelSU LKM, KMI `android12-5.10`, as shipped with `ksud` | GPL-3.0 |
| `modules/ksud` | ReSukiSU `ksud` (bundles `kernelsu.ko`) | GPL-3.0 |
| `modules/libkernelsu.so` | ReSukiSU manager library | GPL-3.0 |
| `artifacts/*` | disassembly output derived from the modules above | this repository |
| `src/*`, `tools/*` | exploit chain and analysis tooling | see below |

The vendor modules are included so that every claim in `artifacts/` can be re-checked against the exact binaries it was derived from. They are not the author's to license.

The exploit chain derives from the public GhostLock / IonStack lineage (NebuSec CyberMeowfia, CVE-2026-43499). `tools/kdis.py` and `tools/kdis_ko.py` originate in this repository.

## Reproducing the artifacts

```bash
python tools/kdis_ko.py modules/oplus_security_guard.ko oplus_root_check_post_handler
python tools/kdis_ko.py modules/oplus_secure_harden.ko entry_handler_socket
```

`tools/kdis_ko.py` matches RELA sections by `sh_info`, not by name. On these builds the `.text` relocations live in an oddly-named section (`.rela.text.<function_name>`), so a name-based lookup returns zero entries and `bl` targets appear unresolved.

## Scope

Security research on hardware owned by the researcher. Nothing here is intended to help anyone access a device they do not own.
