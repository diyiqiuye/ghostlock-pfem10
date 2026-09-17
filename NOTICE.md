# NOTICE

## Contents

| Path | Provenance | License |
|---|---|---|
| `modules/kernelsu.ko` | KernelSU LKM, KMI `android12-5.10` | GPL-3.0 |
| `modules/ksud` | ReSukiSU `ksud` (bundles `kernelsu.ko`) | GPL-3.0 |
| `modules/libkernelsu.so` | ReSukiSU manager library | GPL-3.0 |
| `artifacts/*` | disassembly listings derived from the vendor modules named in the README | this repository |
| `src/*`, `tools/*` | exploit chain and analysis tooling | GPL-3.0 (see `LICENSE`) |

## What is not included

The OPPO vendor modules analysed in the README — `oplus_security_guard.ko`, `oplus_secure_harden.ko`, `oplus_security_keventupload.ko`, `oplus_secure_common.ko` — are **not** redistributed here. They are proprietary, and they are not needed: pull them from your own device and regenerate every artifact.

## Reproducing the artifacts

```bash
adb pull /vendor/lib/modules/oplus_security_guard.ko
adb pull /vendor/lib/modules/oplus_secure_harden.ko

python tools/kdis_ko.py oplus_security_guard.ko oplus_root_check_post_handler
python tools/kdis_ko.py oplus_secure_harden.ko entry_handler_socket
```

`tools/kdis_ko.py` matches RELA sections by `sh_info`, not by name. On these builds the `.text` relocations live in an oddly-named section (`.rela.text.<function_name>`), so a name-based lookup returns zero entries and `bl` targets appear unresolved.

## Scope

Security research on hardware owned by the researcher. Nothing here is intended to help anyone access a device they do not own.
