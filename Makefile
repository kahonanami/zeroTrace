CC := gcc
CFLAGS := -Wall -Wextra -g -Iinclude
ASMFLAGS := -g -Wa,--noexecstack
PIC_CFLAGS := $(CFLAGS) -fPIC
PIC_ASMFLAGS := $(ASMFLAGS) -fPIC
LDFLAGS_SO := -shared
LDLIBS := -lcapstone -ldl -lreadline

SRC_DIR := src
TEST_DIR := src/test
BUILD_DIR := build
BIN_DIR := bin
TEST_BIN_DIR := $(BIN_DIR)/tests

SRC_C := $(wildcard $(SRC_DIR)/*.c)
SRC_C_CORE := $(filter-out $(SRC_DIR)/zt_main.c, $(SRC_C))
SRC_S := $(wildcard $(SRC_DIR)/*.S)

OBJ_CORE := $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(SRC_C_CORE)) \
            $(patsubst $(SRC_DIR)/%.S, $(BUILD_DIR)/%.o, $(SRC_S))

OBJ_MAIN := $(BUILD_DIR)/zt_main.o

TEST_C := $(wildcard $(TEST_DIR)/*.c)
TEST_S := $(wildcard $(TEST_DIR)/*.S)

OBJ_TEST_HELPERS := $(patsubst $(TEST_DIR)/%.S, $(BUILD_DIR)/%.o, $(TEST_S))
PAYLOAD_SO := $(BIN_DIR)/libzt_payload.so
PAYLOAD_PIC_OBJ := $(BUILD_DIR)/zt_payload.pic.o $(BUILD_DIR)/zt_stub.pic.o
.PRECIOUS: $(BUILD_DIR)/%.o

TEST_BINS := $(patsubst $(TEST_DIR)/%.c, $(TEST_BIN_DIR)/%, $(TEST_C))
STANDALONE_TEST_BINS := \
	$(TEST_BIN_DIR)/test_loop \
	$(TEST_BIN_DIR)/test_libc_io_loop \
	$(TEST_BIN_DIR)/test_benchmark_target \
	$(TEST_BIN_DIR)/test_many_probes_target
THREAD_STANDALONE_TEST_BINS := \
	$(TEST_BIN_DIR)/test_threaded_target
BENCHMARK_BINS := \
	$(TEST_BIN_DIR)/test_benchmark_target \
	$(TEST_BIN_DIR)/test_benchmark_runner \
	$(TEST_BIN_DIR)/test_benchmark_latency
CORE_TEST_BINS := $(filter-out $(STANDALONE_TEST_BINS) $(THREAD_STANDALONE_TEST_BINS), $(TEST_BINS))
AUTO_TEST_BINS := $(filter-out $(BENCHMARK_BINS), $(CORE_TEST_BINS))
APP_TARGET := $(BIN_DIR)/ztrace

.PHONY: all clean directories test run-tests benchmark

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

directories:
	@mkdir -p $(BUILD_DIR)
	@mkdir -p $(BIN_DIR)
	@mkdir -p $(TEST_BIN_DIR)

$(APP_TARGET): $(OBJ_CORE) $(OBJ_MAIN)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)
	@echo "[✓] Built main app: $@"

$(PAYLOAD_SO): $(PAYLOAD_PIC_OBJ)
	$(CC) $(LDFLAGS_SO) -o $@ $^
	@echo "[✓] Built payload shared library: $@"

$(CORE_TEST_BINS): $(TEST_BIN_DIR)/%: $(TEST_DIR)/%.c $(OBJ_CORE) $(OBJ_TEST_HELPERS)
	$(CC) $(CFLAGS) $< $(OBJ_CORE) $(OBJ_TEST_HELPERS) -o $@ $(LDLIBS)
	@echo "[✓] Built test: $@"

$(STANDALONE_TEST_BINS): $(TEST_BIN_DIR)/%: $(TEST_DIR)/%.c
	$(CC) $(CFLAGS) $< -o $@
	@echo "[✓] Built standalone test: $@"

$(THREAD_STANDALONE_TEST_BINS): $(TEST_BIN_DIR)/%: $(TEST_DIR)/%.c
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
