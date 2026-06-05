CC ?= gcc
CFLAGS := -Wall -Wextra -g -Iinclude
ASMFLAGS := -g -Wa,--noexecstack
PIC_CFLAGS := $(CFLAGS) -fPIC
PIC_ASMFLAGS := $(ASMFLAGS) -fPIC
LDFLAGS_SO := -shared
LDLIBS := -lcapstone -ldl -lreadline

SRC_DIR := src
ISA_DIR := $(SRC_DIR)/isa
ISA_COMMON_DIR := $(ISA_DIR)/common
ISA_X86_64_DIR := $(ISA_DIR)/x86_64
ISA_AARCH64_DIR := $(ISA_DIR)/aarch64
TEST_DIR := src/test
BUILD_DIR := build
BIN_DIR := bin
TEST_BIN_DIR := $(BIN_DIR)/tests
ARCH ?= $(shell uname -m)

ifeq ($(ARCH),x86_64)
ARCH_SRC_C := $(ISA_X86_64_DIR)/arch.c $(ISA_X86_64_DIR)/trampoline_manager.c
ARCH_SRC_S := $(ISA_X86_64_DIR)/zt_stub.S
else ifeq ($(ARCH),aarch64)
ARCH_SRC_C := $(ISA_AARCH64_DIR)/arch.c $(ISA_AARCH64_DIR)/trampoline_manager.c
ARCH_SRC_S := $(ISA_AARCH64_DIR)/stub.S
else
$(error Unsupported ARCH=$(ARCH). Supported: x86_64 aarch64)
endif

SRC_C_ALL := \
	$(wildcard $(SRC_DIR)/*.c) \
	$(wildcard $(ISA_COMMON_DIR)/*.c) \
	$(wildcard $(ISA_X86_64_DIR)/*.c) \
	$(wildcard $(ISA_AARCH64_DIR)/*.c)
SRC_C := $(filter-out \
	$(ISA_X86_64_DIR)/arch.c \
	$(ISA_AARCH64_DIR)/arch.c \
	$(ISA_X86_64_DIR)/trampoline_manager.c \
	$(ISA_AARCH64_DIR)/trampoline_manager.c, \
	$(SRC_C_ALL)) $(ARCH_SRC_C)
SRC_S := $(ARCH_SRC_S)

OBJ_CORE := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRC_C)) \
            $(patsubst $(SRC_DIR)/%.S,$(BUILD_DIR)/%.o,$(SRC_S))

TEST_C_ALL := $(wildcard $(TEST_DIR)/*.c)
ifeq ($(ARCH),aarch64)
TEST_C := $(filter-out $(TEST_DIR)/test_trampoline_builder.c,$(TEST_C_ALL))
else
TEST_C := $(filter-out $(TEST_DIR)/test_trampoline_builder_aarch64.c,$(TEST_C_ALL))
endif
TEST_S := $(wildcard $(TEST_DIR)/*.S)

OBJ_TEST_HELPERS := $(patsubst $(TEST_DIR)/%.S, $(BUILD_DIR)/%.o, $(TEST_S))
PAYLOAD_SO := $(BIN_DIR)/libzt_payload.so
PAYLOAD_PIC_OBJ := $(BUILD_DIR)/zt_payload.pic.o $(patsubst $(SRC_DIR)/%.S,$(BUILD_DIR)/%.pic.o,$(ARCH_SRC_S))
.PRECIOUS: $(BUILD_DIR)/%.o

TEST_BINS := $(patsubst $(TEST_DIR)/%.c, $(TEST_BIN_DIR)/%, $(TEST_C))
TEST_TARGET_BINS := \
	$(TEST_BIN_DIR)/test_libc_io_loop \
	$(TEST_BIN_DIR)/test_context_target \
	$(TEST_BIN_DIR)/test_benchmark_target \
	$(TEST_BIN_DIR)/test_many_probes_target \
	$(TEST_BIN_DIR)/test_hot_update_target \
	$(TEST_BIN_DIR)/test_exit_race_target \
	$(TEST_BIN_DIR)/test_trace_buffer_target
MANUAL_TEST_BINS := \
	$(TEST_BIN_DIR)/test_loop
THREAD_TEST_TARGET_BINS := \
	$(TEST_BIN_DIR)/test_threaded_target \
	$(TEST_BIN_DIR)/test_thread_control_target \
	$(TEST_BIN_DIR)/test_signal_target
BENCHMARK_BINS := \
	$(TEST_BIN_DIR)/test_benchmark_target \
	$(TEST_BIN_DIR)/test_benchmark_runner \
	$(TEST_BIN_DIR)/test_benchmark_latency
NON_AUTO_TEST_BINS := $(TEST_TARGET_BINS) $(THREAD_TEST_TARGET_BINS) $(MANUAL_TEST_BINS)
CORE_TEST_BINS := $(filter-out $(NON_AUTO_TEST_BINS), $(TEST_BINS))
AUTO_TEST_BINS := $(filter-out $(BENCHMARK_BINS), $(CORE_TEST_BINS))
APP_TARGET := $(BIN_DIR)/ztrace

.PHONY: all clean directories test run-tests benchmark print-arch-config

all: directories $(APP_TARGET) $(PAYLOAD_SO) $(TEST_BINS)

test: all run-tests

benchmark: all $(BENCHMARK_BINS)
	python3 scripts/benchmark.py

run-tests:
	@echo "\n=============================="
	@echo "    Running Test Suite        "
	@echo "=============================="
	@for t in $(AUTO_TEST_BINS); do \
		echo "\n▶ Executing: $$t"; \
		./$$t || exit 1; \
	done
	@echo "\n▶ Executing: scripts/check_arch_config.py"
	@python3 scripts/check_arch_config.py
	@echo "\n▶ Executing: scripts/merge_trace_events.py --self-test"
	@python3 scripts/merge_trace_events.py --self-test

print-arch-config:
	@printf 'ARCH=%s\n' '$(ARCH)'
	@printf 'ARCH_SRC_C=%s\n' '$(ARCH_SRC_C)'
	@printf 'ARCH_SRC_S=%s\n' '$(ARCH_SRC_S)'
	@printf 'TEST_C=%s\n' '$(TEST_C)'

directories:
	@mkdir -p $(BUILD_DIR)
	@mkdir -p $(BUILD_DIR)/isa
	@mkdir -p $(BUILD_DIR)/isa/common
	@mkdir -p $(BUILD_DIR)/isa/x86_64
	@mkdir -p $(BUILD_DIR)/isa/aarch64
	@mkdir -p $(BIN_DIR)
	@mkdir -p $(TEST_BIN_DIR)

$(APP_TARGET): $(OBJ_CORE)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)
	@echo "[✓] Built main app: $@"

$(PAYLOAD_SO): $(PAYLOAD_PIC_OBJ)
	$(CC) $(LDFLAGS_SO) -o $@ $^
	@echo "[✓] Built payload shared library: $@"

$(CORE_TEST_BINS): $(TEST_BIN_DIR)/%: $(TEST_DIR)/%.c $(OBJ_CORE) $(OBJ_TEST_HELPERS)
	$(CC) $(CFLAGS) $< $(OBJ_CORE) $(OBJ_TEST_HELPERS) -o $@ $(LDLIBS)
	@echo "[✓] Built test: $@"

$(TEST_TARGET_BINS) $(MANUAL_TEST_BINS): $(TEST_BIN_DIR)/%: $(TEST_DIR)/%.c
	$(CC) $(CFLAGS) $< -o $@
	@echo "[✓] Built standalone test: $@"

$(THREAD_TEST_TARGET_BINS): $(TEST_BIN_DIR)/%: $(TEST_DIR)/%.c
	$(CC) $(CFLAGS) $< -o $@ -lpthread
	@echo "[✓] Built threaded standalone test: $@"

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/%.pic.o: $(SRC_DIR)/%.c
	$(CC) $(PIC_CFLAGS) -c $< -o $@

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.S
	$(CC) $(ASMFLAGS) -c $< -o $@

$(BUILD_DIR)/%.pic.o: $(SRC_DIR)/%.S
	$(CC) $(PIC_ASMFLAGS) -c $< -o $@

$(BUILD_DIR)/%.o: $(TEST_DIR)/%.S
	$(CC) $(ASMFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)
	@echo "Cleaned build artifacts."
