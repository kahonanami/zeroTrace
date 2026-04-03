#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <getopt.h>
#include <string.h>
#include <capstone/capstone.h>

#include "../include/zt_log.h"
#include "../include/zt_injector.h"
#include "../include/zt_payload.h"
#include "../include/zt_thunk_manager.h"

#define ZT_THUNK_SUFFIX_SIZE 22

static void print_usage(const char *prog) {
    fprintf(stderr,
            "Usage:\n"
            "  %s -p <pid> -s <symbol>\n",
            prog);
}

static void zt_dump_thunk_disasm(const uint8_t *code, size_t code_size) {
    csh handle;
    cs_insn *insn;
    size_t count;
    size_t i;

    if (code == NULL || code_size == 0) {
        return;
    }

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        printf("failed to open capstone for thunk disassembly\n");
        return;
    }

    count = cs_disasm(handle, code, code_size, 0, 0, &insn);
    if (count == 0) {
        printf("failed to disassemble thunk bytes\n");
        cs_close(&handle);
        return;
    }

    printf("Thunk disassembly:\n");
    for (i = 0; i < count; ++i) {
        printf("  0x%04llx: %-8s %s\n",
               (unsigned long long)insn[i].address,
               insn[i].mnemonic,
               insn[i].op_str);
    }

    cs_free(insn, count);
    cs_close(&handle);
}

static void zt_dump_thunk_tail(const uint8_t *thunk_buf, size_t thunk_size) {
    uint64_t entry_stub_addr;
    uint64_t continue_addr;

    if (thunk_buf == NULL || thunk_size < ZT_THUNK_SUFFIX_SIZE) {
        return;
    }

    memcpy(&entry_stub_addr,
           thunk_buf + thunk_size - 16,
           sizeof(entry_stub_addr));
    memcpy(&continue_addr,
           thunk_buf + thunk_size - 8,
           sizeof(continue_addr));

    printf("Thunk data tail:\n");
    printf("  entry_stub_addr = 0x%llx\n", (unsigned long long)entry_stub_addr);
    printf("  continue_addr   = 0x%llx\n", (unsigned long long)continue_addr);
}

int main(int argc, char *argv[]) {
    int opt;
    long pid = -1;
    const char *symbol = NULL;
    bool p_flag_provided = false;

    while ((opt = getopt(argc, argv, "p:s:")) != -1) {
        switch (opt) {
            case 'p':
                p_flag_provided = true;
                
                char *endptr;
                pid = strtol(optarg, &endptr, 10);
                
                if (optarg == endptr || *endptr != '\0' || pid <= 0) {
                    fprintf(stderr, "Invalid pid: %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
                break;
                
            case 's':
                symbol = optarg;
                break;
                
            case '?':
                print_usage(argv[0]);
                exit(EXIT_FAILURE);
                
            default:
                exit(EXIT_FAILURE);
        }
    }

    if (!p_flag_provided) {
        fprintf(stderr, "Error: Missing required '-p' option.\n");
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    if (symbol == NULL) {
        fprintf(stderr, "Error: Missing required '-s' option.\n");
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    printf("ztrace get PID: %ld\n", pid);
    printf("ztrace get symbol: %s\n", symbol);

    zt_injector_session_t session;
    if(zt_injector_attach(&session, (pid_t)pid) != 0) {
        fprintf(stderr, "Failed to attach to process with PID %ld\n", pid);
        exit(EXIT_FAILURE);
    }

    printf("Successfully attached to process with PID %d, %s, is_pie: %d, image_base: 0x%lX\n",
           session.pid,
           session.exe_path,
           session.is_pie,
           session.image_base);

    zt_probe_info_t *probe = zt_register_probe(&session, symbol);
    if (probe == NULL) {
        fprintf(stderr, "Failed to register probe for symbol %s\n", symbol);
        exit(EXIT_FAILURE);
    }

    printf("Registered probe: id=%lu, symbol=%s, addr=0x%lX\n",
           probe->probe_id,
           probe->symbol,
           probe->symbol_addr);
    printf("Current probe count: %d\n", session.probe_count);

    if (zt_enable_probe(&session, probe->probe_id) != 0) {
        printf("zt_enable_probe failed for probe %lu\n", probe->probe_id);
    } else {
        int i;
        uint8_t thunk_buf[ZT_THUNK_MAX_SIZE];
        size_t thunk_size;
        uint64_t entry_stub_addr;

        printf("zt_enable_probe ok: orig_len=%u, orig_code=", probe->orig_len);
        for (i = 0; i < probe->orig_len; ++i) {
            printf("%02x ", probe->orig_code[i]);
        }
        printf("\n");

        entry_stub_addr = (uint64_t)(uintptr_t)zt_payload_get_entry_stub_addr();
        if (zt_build_thunk(probe, entry_stub_addr, thunk_buf, sizeof(thunk_buf), &thunk_size) != 0) {
            printf("zt_build_thunk failed for probe %lu\n", probe->probe_id);
        } else {
            size_t thunk_code_size = thunk_size - 16;

            printf("Thunk bytes (%zu): ", thunk_size);
            for (i = 0; i < (int)thunk_size; ++i) {
                printf("%02x ", thunk_buf[i]);
            }
            printf("\n");
            zt_dump_thunk_disasm(thunk_buf, thunk_code_size);
            zt_dump_thunk_tail(thunk_buf, thunk_size);
        }
    }

    zt_injector_detach(&session);

    return 0;
}
