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
  ifeq ($(LMDB_LIBS),)
    LMDB_LIBS := -llmdb
    LMDB_FOUND := $(shell printf '#include <lmdb.h>\nint main(){mdb_env_create(0);return 0;}\n' | \
                     $(CC) -x c - -o /dev/null -llmdb >/dev/null 2>&1 && echo 1 || echo 0)
  endif
endif

# --- Paths ---
APP_DIR   := app
APP_INC   := $(APP_DIR)/include
APP_SRC   := $(APP_DIR)/src

TEST_DIR  := tests
TEST_INC  := $(TEST_DIR)/include
TEST_SRC  := $(TEST_DIR)/src

BIN_DIR   := build/bin

# --- Includes ---
INCLUDES := -I$(APP_INC) -I$(APP_INC)/cryptography -I$(TEST_INC)

# --- App sources (demo binary) ---
CORE_SRCS := \
    $(APP_SRC)/db_env.c \
    $(APP_SRC)/db_users.c \
    $(APP_SRC)/db_data.c \
    $(APP_SRC)/db_acl.c \
    $(APP_SRC)/fsutil.c \
    $(APP_SRC)/uuid.c \
    $(APP_SRC)/cryptography/sha256.c

SRCS := \
    $(APP_SRC)/main.c \
    $(CORE_SRCS)

# --- Tests sources (test binary) ---
SRCS_TEST := \
    $(TEST_SRC)/test_main.c \
    $(TEST_SRC)/test_func.c \
    $(TEST_SRC)/test_load.c \
    $(TEST_SRC)/test_utils.c \
    $(CORE_SRCS)

# --- Flags ---
CFLAGS  += -O2 -Wall -Wextra -Wshadow -Wconversion -Werror $(INCLUDES) \
           $(OPENSSL_CFLAGS) $(LMDB_CFLAGS)
LDFLAGS += $(OPENSSL_LIBS) $(LMDB_LIBS)

# --- Targets ---
.PHONY: all clean test
all: $(BIN_DIR)/db_lmdb_demo

ifeq ($(OPENSSL_FOUND)$(LMDB_FOUND),11)

$(BIN_DIR)/db_lmdb_demo: $(SRCS)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(BIN_DIR)/db_tests: $(SRCS_TEST)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

else

$(BIN_DIR)/db_lmdb_demo:
	@echo "[skip] Missing deps:"
ifneq ($(OPENSSL_FOUND),1)
	@echo "  - OpenSSL headers/libs (install: sudo apt-get install -y libssl-dev)"
endif
ifneq ($(LMDB_FOUND),1)
	@echo "  - LMDB headers/libs (install: sudo apt-get install -y liblmdb-dev)"
endif
	@echo "  (pkg-config optional but recommended: sudo apt-get install -y pkg-config)"

$(BIN_DIR)/db_tests:
	@echo "[skip] Missing deps (tests not built). See notes above."

endif

# --- Test runner (same UX) ---
# Pass extra args: make test RUNARGS="--list" or "--suite func" etc.
test: $(BIN_DIR)/db_tests
	./$(BIN_DIR)/db_tests $(RUNARGS)

clean:
	@rm -rf build && rm -rf med/ && rm -f blob_*


# --- Code formatting (clang-format only) ------------------------------------
CLANG_FORMAT := $(shell command -v clang-format 2>/dev/null)

# Prefer git; fall back to find (and avoid build/.git trees)
FMT_FILES := $(shell \
  if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then \
    git ls-files '*.c' '*.h'; \
  else \
    find . -type f \( -name '*.c' -o -name '*.h' \) \
      -not -path './build/*' -not -path './.git/*'; \
  fi )

.PHONY: format
format:
ifndef CLANG_FORMAT
	@echo "[fmt] clang-format not found. Install it (e.g., sudo apt-get install -y clang-format)"; exit 1
else
	@if [ ! -f .clang-format ]; then \
	  echo "[fmt] No .clang-format found;"; \
	fi
	@if [ -z "$(FMT_FILES)" ]; then \
	  echo "[fmt] No .c/.h files found to format."; \
	else \
	  echo "[fmt] Formatting $(words $(FMT_FILES)) files"; \
	  printf "%s\0" $(FMT_FILES) | xargs -0 -r $(CLANG_FORMAT) -i; \
	fi
endif
