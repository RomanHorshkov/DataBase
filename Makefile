# Require pkg-config
PKGCONFIG := $(shell command -v pkg-config 2>/dev/null)
ifeq ($(PKGCONFIG),)
$(error pkg-config is required. Install: Debian/Ubuntu: sudo apt install pkg-config)
endif

# --- OpenSSL ---
OPENSSL_FOUND := $(shell pkg-config --exists openssl && echo 1 || echo 0)
ifeq ($(OPENSSL_FOUND),0)
$(error OpenSSL not found. Install: Debian/Ubuntu: sudo apt install libssl-dev)
endif
OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl)
OPENSSL_LIBS   := $(shell pkg-config --libs   openssl)

# --- LMDB ---
LMDB_FOUND := $(shell pkg-config --exists lmdb && echo 1 || echo 0)
ifeq ($(LMDB_FOUND),0)
$(error LMDB not found. Install: Debian/Ubuntu: sudo apt install liblmdb-dev)
endif
LMDB_CFLAGS := $(shell pkg-config --cflags lmdb)
LMDB_LIBS   := $(shell pkg-config --libs   lmdb)

# --- libsodium ---
SODIUM_FOUND := $(shell pkg-config --exists libsodium && echo 1 || echo 0)
ifeq ($(SODIUM_FOUND),0)
$(error libsodium not found. Install: Debian/Ubuntu: sudo apt install libsodium-dev)
endif
SODIUM_CFLAGS := $(shell pkg-config --cflags libsodium)
SODIUM_LIBS   := $(shell pkg-config --libs   libsodium)

# --- Flags ---
CFLAGS  += -O2 -Wall -Wextra -Wshadow -Wconversion -Werror $(INCLUDES) \
           $(OPENSSL_CFLAGS) $(LMDB_CFLAGS) $(SODIUM_CFLAGS)
LDFLAGS += $(OPENSSL_LIBS) $(LMDB_LIBS) $(SODIUM_LIBS)

# --- Paths ---
APP_DIR   := app
APP_INC   := $(APP_DIR)/include
APP_SRC   := $(APP_DIR)/src

TEST_DIR  := tests
TEST_INC  := $(TEST_DIR)/include
TEST_SRC  := $(TEST_DIR)/src

BIN_DIR   := build/bin

# --- Library build ---
OBJ_DIR := build/obj
LIB_DIR := build/lib
LIB_STATIC := $(LIB_DIR)/libdb.a

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

# --- Library core objects ---
CORE_OBJS := $(patsubst $(APP_SRC)/%.c,$(OBJ_DIR)/%.o,$(CORE_SRCS))

# --- Flags ---

# --- Targets ---
.PHONY: all clean test lib
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
	@rm -rf build && rm -rf med/ && rm -f blob_* && rm -rf .test*


# --- Library compilation ---
lib: $(LIB_STATIC)

# Compile objects under build/obj/...
$(OBJ_DIR)/%.o: $(APP_SRC)/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

# Archive into build/lib/libdb_store.a
$(LIB_STATIC): $(CORE_OBJS)
	@mkdir -p $(LIB_DIR)
	$(AR) rcs $@ $^
	@echo "Built $@"

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
