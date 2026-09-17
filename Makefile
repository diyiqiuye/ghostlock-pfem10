# GhostLock — OPPO Find X5 Pro (PFEM10)
#
# Build params are FIXED: -O1 / API 26 / -D__ARM=1 keeps the reclaim
# stack-frame geometry (delta=0 calibration). Changing any of them
# requires re-calibrating the stack geometry on device.

NDK_HOME ?= $(ANDROID_NDK_HOME)
HOST_CC  ?= cc
TARGET   := exploit_guard
MODEL    := model_check
SRC      := src/core/exploit.c
DEPS     := src/core/payload.c src/core/payload.h src/core/fdset_map.h \
            src/devices/pfem10/pfem10_target.h $(wildcard src/lib/*.h)
INC      := -Isrc/core -Isrc/devices/pfem10
CFLAGS   := -D__ARM=1 -O1 -Wall -Wextra -pthread $(INC)
API      := 26

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
  HOST_TAG := linux-x86_64
else ifeq ($(UNAME_S),Darwin)
  HOST_TAG := darwin-x86_64
else
  HOST_TAG := windows-x86_64
endif

CC := $(NDK_HOME)/toolchains/llvm/prebuilt/$(HOST_TAG)/bin/aarch64-linux-android$(API)-clang

.PHONY: all clean check model

all: check $(TARGET)

check:
	@test -x "$(CC)" || { \
	  echo "toolchain not found: $(CC)" >&2; \
	  echo "install NDK r28c and set ANDROID_NDK_HOME (or NDK_HOME)" >&2; \
	  exit 1; }

$(TARGET): $(SRC) $(DEPS)
	$(CC) $(CFLAGS) -o $@ $(SRC)
	@echo "built: $(CURDIR)/$(TARGET)   (-O1, API $(API), PFEM10 delta=0 calibration)"

# host-side rtmutex chain-walk model (no NDK needed)
model: model/model.c
	$(HOST_CC) -O2 -Wall -Wextra -o $(MODEL) model/model.c
	@echo "built: $(CURDIR)/$(MODEL)"

clean:
	rm -f $(TARGET) $(MODEL)
