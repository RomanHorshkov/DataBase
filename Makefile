# --- Shell: force bash so pipefail works ---
SHELL := /usr/bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.ONESHELL:
.DELETE_ON_ERROR:

# ------------------------------------------------------------
# Project
# ------------------------------------------------------------
APP_NAME     := db_lmdb_demo
TEST_NAME    := db_tests

APP_DIR      := app
APP_INC      := $(APP_DIR)/include
APP_SRC_DIR  := $(APP_DIR)/src

TEST_DIR     := tests
TEST_INC     := $(TEST_DIR)/include
TEST_SRC_DIR := $(TEST_DIR)/src

# ------------------------------------------------------------
# Build mode: release (default), debug, asan, ubsan
# ------------------------------------------------------------
MODE ?= release

# Per-mode build trees
BUILD_DIR    := build/$(MODE)
BIN_DIR      := $(BUILD_DIR)/bin
OBJ_DIR      := $(BUILD_DIR)/obj
LIB_DIR      := $(BUILD_DIR)/lib
LIB_STATIC   := $(LIB_DIR)/libdb.a

# ------------------------------------------------------------
# Tools
# ------------------------------------------------------------
CC ?= cc
AR ?= ar

# Quiet by default; set V=1 for verbose
ifeq ($(V),1)
Q :=
else
Q := @
endif

# ------------------------------------------------------------
# Dependencies (hard fail)
# ------------------------------------------------------------
PKGCONFIG := $(shell command -v pkg-config 2>/dev/null)
ifeq ($(PKGCONFIG),)
$(error pkg-config is required. Install: Debian/Ubuntu: sudo apt install pkg-config)
endif

OPENSSL_FOUND := $(shell pkg-config --exists openssl && echo 1 || echo 0)
ifeq ($(OPENSSL_FOUND),0)
$(error OpenSSL not found. Install: Debian/Ubuntu: sudo apt install libssl-dev)
endif
OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl)
OPENSSL_LIBS   := $(shell pkg-config --libs   openssl)

LMDB_FOUND := $(shell pkg-config --exists lmdb && echo 1 || echo 0)
ifeq ($(LMDB_FOUND),0)
$(error LMDB not found. Install: Debian/Ubuntu: sudo apt install liblmdb-dev)
endif
LMDB_CFLAGS := $(shell pkg-config --cflags lmdb)
LMDB_LIBS   := $(shell pkg-config --libs   lmdb)

SODIUM_FOUND := $(shell pkg-config --exists libsodium && echo 1 || echo 0)
ifeq ($(SODIUM_FOUND),0)
$(error libsodium not found. Install: Debian/Ubuntu: sudo apt install libsodium-dev)
endif
SODIUM_CFLAGS := $(shell pkg-config --cflags libsodium)
SODIUM_LIBS   := $(shell pkg-config --libs   libsodium)

# ------------------------------------------------------------
# Flags
# ------------------------------------------------------------
# Auto-discover include subfolders under app/include and tests/include
INC_APP_DIRS  := $(shell find $(APP_INC)  -type d 2>/dev/null)
INC_TEST_DIRS := $(shell [ -d $(TEST_INC) ] && find $(TEST_INC) -type d 2>/dev/null || true)

CPPFLAGS := -D_GNU_SOURCE \
            $(addprefix -I,$(INC_APP_DIRS) $(INC_TEST_DIRS)) \
            $(OPENSSL_CFLAGS) $(LMDB_CFLAGS) $(SODIUM_CFLAGS)

CSTD     := -std=c11
WARN     := -Wall -Wextra -Wshadow -Wconversion -Wpointer-arith -Wcast-qual -Wwrite-strings
DEPFLAGS := -MMD -MP

ifeq ($(MODE),release)
  CFLAGS  := $(CSTD) -O2 $(WARN) -fno-plt
  LDFLAGS :=
  # Enable if you want:
  # CFLAGS  += -flto
  # LDFLAGS += -flto
else ifeq ($(MODE),debug)
  CFLAGS  := $(CSTD) -Og -g3 $(WARN) -fno-omit-frame-pointer
  LDFLAGS :=
else ifeq ($(MODE),asan)
  CFLAGS  := $(CSTD) -O1 -g3 $(WARN) -fsanitize=address,undefined -fno-omit-frame-pointer
  LDFLAGS := -fsanitize=address,undefined
else ifeq ($(MODE),ubsan)
  CFLAGS  := $(CSTD) -O1 -g3 $(WARN) -fsanitize=undefined -fno-omit-frame-pointer
  LDFLAGS := -fsanitize=undefined
else
  $(error Unknown MODE '$(MODE)'. Use: release, debug, asan, ubsan)
endif

LDLIBS := $(OPENSSL_LIBS) $(LMDB_LIBS) $(SODIUM_LIBS)

# ------------------------------------------------------------
# Source discovery
# ------------------------------------------------------------
SRCS_APP  := $(shell find $(APP_SRC_DIR)  -type f -name '*.c')
SRCS_MAIN := $(filter %/main.c,$(SRCS_APP))
SRCS_CORE := $(filter-out $(SRCS_MAIN),$(SRCS_APP))
SRCS_TEST := $(shell find $(TEST_SRC_DIR) -type f -name '*.c')

# Mirror tree under obj/
OBJS_CORE := $(patsubst %.c,$(OBJ_DIR)/%.o,$(SRCS_CORE))
OBJS_MAIN := $(patsubst %.c,$(OBJ_DIR)/%.o,$(SRCS_MAIN))
OBJS_TEST := $(patsubst %.c,$(OBJ_DIR)/%.o,$(SRCS_TEST))

DEPS := $(OBJS_CORE:.o=.d) $(OBJS_MAIN:.o=.d) $(OBJS_TEST:.o=.d)

APP_BIN  := $(BIN_DIR)/$(APP_NAME)
TEST_BIN := $(BIN_DIR)/$(TEST_NAME)

# ------------------------------------------------------------
# Phony targets
# ------------------------------------------------------------
.PHONY: all clean distclean test run lib print-vars \
        debug asan ubsan release

all: $(APP_BIN) $(TEST_BIN)

# Convenience front-doors for modes
release:
	$(Q)$(MAKE) MODE=release all
debug:
	$(Q)$(MAKE) MODE=debug   all
asan:
	$(Q)$(MAKE) MODE=asan    all
ubsan:
	$(Q)$(MAKE) MODE=ubsan   all

lib: $(LIB_STATIC)

test: $(TEST_BIN)
	$(Q)$(TEST_BIN) $(RUNARGS)

run: $(APP_BIN)
	$(Q)$(APP_BIN) $(RUNARGS)

print-vars:
	@echo "MODE=$(MODE)"
	@echo "BUILD_DIR=$(BUILD_DIR)"
	@echo "APP_BIN=$(APP_BIN)"
	@echo "TEST_BIN=$(TEST_BIN)"
	@echo "SRCS_CORE count=$(words $(SRCS_CORE))  SRCS_TEST count=$(words $(SRCS_TEST))"

clean:
	$(Q)rm -rf $(BUILD_DIR)

distclean: clean
	$(Q)rm -f blob_* .test* 2>/dev/null || true

# ------------------------------------------------------------
# Build rules
# ------------------------------------------------------------
# App binary: main.o + static lib
$(APP_BIN): $(OBJS_MAIN) $(LIB_STATIC) | $(BIN_DIR)
	@echo "[LD] $@"
	$(Q)$(CC) $(CFLAGS) $(OBJS_MAIN) -o $@ $(LDFLAGS) $(LIB_STATIC) $(LDLIBS)

# Test binary: test objs + static lib
$(TEST_BIN): $(OBJS_TEST) $(LIB_STATIC) | $(BIN_DIR)
	@echo "[LD] $@"
	$(Q)$(CC) $(CFLAGS) $(OBJS_TEST) -o $@ $(LDFLAGS) $(LIB_STATIC) $(LDLIBS)

# Static library from core objs
$(LIB_STATIC): $(OBJS_CORE) | $(LIB_DIR)
	@echo "[AR] $@"
	$(Q)$(AR) rcs $@ $(OBJS_CORE)

# Generic compile rule (mirrors source tree under obj/)
$(OBJ_DIR)/%.o: %.c
	@mkdir -p $(@D)
	@echo "[CC] $<"
	$(Q)$(CC) $(CPPFLAGS) $(CFLAGS) $(DEPFLAGS) -c $< -o $@

# Ensure output dirs exist
$(BIN_DIR) $(LIB_DIR):
	$(Q)mkdir -p $@

# Include auto-generated dep files
-include $(DEPS)


# --- Code formatting (clang-format) -----------------------------------------
CLANG_FORMAT := $(shell command -v clang-format 2>/dev/null)
HAS_GIT      := $(shell git rev-parse --is-inside-work-tree >/dev/null 2>&1 && echo 1 || echo 0)

# Files to format
ifeq ($(HAS_GIT),1)
  FMT_FILES := $(shell git ls-files '*.c' '*.h')
else
  FMT_FILES := $(shell find $(APP_DIR) $(TEST_DIR) -type f \( -name '*.c' -o -name '*.h' \) \
                       -not -path '$(BUILD_DIR)/*')
endif

.PHONY: format format-check
format:
ifndef CLANG_FORMAT
	@echo "clang-format not found. Install it (e.g., sudo apt install clang-format)"; exit 1
endif
	@test -f .clang-format || { echo ".clang-format missing at repo root"; exit 1; }
	@if [ -z "$(FMT_FILES)" ]; then echo "[fmt] no files"; else \
	  echo "[fmt] formatting $(words $(FMT_FILES)) files"; \
	  printf "%s\0" $(FMT_FILES) | xargs -0 -r $(CLANG_FORMAT) -i -style=file; \
	fi

format-check:
ifndef CLANG_FORMAT
	@echo "clang-format not found. Install it (e.g., sudo apt install clang-format)"; exit 1
endif
	@test -f .clang-format || { echo ".clang-format missing at repo root"; exit 1; }
	@if [ -z "$(FMT_FILES)" ]; then echo "[fmt] no files"; else \
	  printf "%s\0" $(FMT_FILES) | xargs -0 -r $(CLANG_FORMAT) --dry-run --Werror -style=file; \
	fi
