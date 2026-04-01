CC := gcc
CFLAGS := -Wall -Wextra -g -Iinclude
ASMFLAGS := -g -Wa,--noexecstack

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
.PRECIOUS: $(BUILD_DIR)/%.o

TEST_BINS := $(patsubst $(TEST_DIR)/%.c, $(TEST_BIN_DIR)/%, $(TEST_C))
APP_TARGET := $(BIN_DIR)/ztrace

.PHONY: all clean directories test run-tests

all: directories $(APP_TARGET) $(TEST_BINS)

test: all run-tests

run-tests:
	@echo "\n=============================="
	@echo "    Running Test Suite        "
	@echo "=============================="
	@for t in $(TEST_BINS); do \
		echo "\n▶ Executing: $$t"; \
		./$$t || exit 1; \
	done

directories:
	@mkdir -p $(BUILD_DIR)
	@mkdir -p $(BIN_DIR)
	@mkdir -p $(TEST_BIN_DIR)

$(APP_TARGET): $(OBJ_CORE) $(OBJ_MAIN)
	$(CC) $(CFLAGS) -o $@ $^
	@echo "[✓] Built main app: $@"

$(TEST_BIN_DIR)/%: $(TEST_DIR)/%.c $(OBJ_CORE) $(OBJ_TEST_HELPERS)
	$(CC) $(CFLAGS) $< $(OBJ_CORE) $(OBJ_TEST_HELPERS) -o $@
	@echo "[✓] Built test: $@"

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.S
	$(CC) $(ASMFLAGS) -c $< -o $@

$(BUILD_DIR)/%.o: $(TEST_DIR)/%.S
	$(CC) $(ASMFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)
	@echo "Cleaned build artifacts."