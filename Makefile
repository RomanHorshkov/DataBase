# --- OpenSSL detection (required) ---
PKGCONFIG := $(shell command -v pkg-config 2>/dev/null)

ifeq ($(PKGCONFIG),)
  OPENSSL_CFLAGS :=
  OPENSSL_LIBS   := -lcrypto
  OPENSSL_FOUND  := $(shell printf 'int main(void){return 0;}\n' | \
                     $(CC) -x c - -o /dev/null -lcrypto >/dev/null 2>&1 && echo 1 || echo 0)
else
  OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null)
  OPENSSL_LIBS   := $(shell pkg-config --libs   openssl 2>/dev/null)
  OPENSSL_FOUND  := $(shell pkg-config --exists openssl && echo 1 || echo 0)
endif

# --- LMDB detection (required) ---
ifeq ($(PKGCONFIG),)
  LMDB_CFLAGS :=
  LMDB_LIBS   := -llmdb
  LMDB_FOUND  := $(shell printf '#include <lmdb.h>\nint main(){mdb_env_create(0);return 0;}\n' | \
                   $(CC) -x c - -o /dev/null -llmdb >/dev/null 2>&1 && echo 1 || echo 0)
else
  LMDB_CFLAGS := $(shell pkg-config --cflags lmdb 2>/dev/null)
  LMDB_LIBS   := $(shell pkg-config --libs   lmdb 2>/dev/null)
  LMDB_FOUND  := $(shell pkg-config --exists lmdb && echo 1 || echo 0)
  # Fallback if pkg has no .pc but lib exists:
  ifeq ($(LMDB_LIBS),)
    LMDB_LIBS := -llmdb
    LMDB_FOUND := $(shell printf '#include <lmdb.h>\nint main(){mdb_env_create(0);return 0;}\n' | \
                     $(CC) -x c - -o /dev/null -llmdb >/dev/null 2>&1 && echo 1 || echo 0)
  endif
endif

# --- Paths & sources ---
INCLUDES := -Iinclude -Iinclude/cryptography

SRCS := \
    src/main.c \
    src/fsutil.c \
    src/db_store.c \
    src/uuid.c \
    src/cryptography/sha256.c

# --- Tests ---
SRCS_TEST := \
    src/tests/tests.c \
    src/fsutil.c \
    src/db_store.c \
    src/uuid.c \
    src/cryptography/sha256.c

CFLAGS  += -O2 -Wall -Wextra -Wshadow -Wconversion -Werror $(INCLUDES) \
           $(OPENSSL_CFLAGS) $(LMDB_CFLAGS)
LDFLAGS += $(OPENSSL_LIBS) $(LMDB_LIBS)

# --- Targets ---
.PHONY: all clean test
all: build/bin/db_lmdb_demo


# Require both libs to build
ifeq ($(OPENSSL_FOUND)$(LMDB_FOUND),11)
build/bin/db_lmdb_demo: $(SRCS)
	@mkdir -p build/bin
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# --- NEW: test binary ---
build/bin/db_tests: $(SRCS_TEST)
	@mkdir -p build/bin
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)
else
build/bin/db_lmdb_demo:
	@echo "[skip] Missing deps:"
ifneq ($(OPENSSL_FOUND),1)
	@echo "  - OpenSSL headers/libs (install: sudo apt-get install -y libssl-dev)"
endif
ifneq ($(LMDB_FOUND),1)
	@echo "  - LMDB headers/libs (install: sudo apt-get install -y liblmdb-dev)"
endif
	@echo "  (pkg-config optional but recommended: sudo apt-get install -y pkg-config)"

# --- NEW: stub so `make test` explains deps when missing ---
build/bin/db_tests:
	@echo "[skip] Missing deps (tests not built). See notes above."
endif

# --- NEW: test runner ---
# Pass extra args: make test RUNARGS="--list" or "--filter upload --repeat 3"
test: build/bin/db_tests
	./build/bin/db_tests $(RUNARGS)

clean:
	rm -rf build