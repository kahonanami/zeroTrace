#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <getopt.h>
#include <string.h>
#include <limits.h>
#include <signal.h>
#include <dlfcn.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
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

static void zt_test_remote_rw(pid_t pid, uint64_t remote_addr) {
    uint8_t before[16];
    uint8_t after[16];
    int i;

    if (zt_read_remote_memory(pid, remote_addr, before, sizeof(before)) != 0) {
        printf("zt_read_remote_memory failed at 0x%llx\n", (unsigned long long)remote_addr);
        return;
    }

    printf("Remote bytes before write: ");
    for (i = 0; i < (int)sizeof(before); ++i) {
        printf("%02x ", before[i]);
    }
    printf("\n");

    if (zt_write_remote_memory(pid, remote_addr, before, sizeof(before)) != 0) {
        printf("zt_write_remote_memory failed at 0x%llx\n", (unsigned long long)remote_addr);
        return;
    }

    if (zt_read_remote_memory(pid, remote_addr, after, sizeof(after)) != 0) {
        printf("zt_read_remote_memory(after) failed at 0x%llx\n", (unsigned long long)remote_addr);
        return;
    }

    printf("Remote bytes after write:  ");
    for (i = 0; i < (int)sizeof(after); ++i) {
        printf("%02x ", after[i]);
    }
    printf("\n");

    if (memcmp(before, after, sizeof(before)) == 0) {
        printf("remote read/write roundtrip ok\n");
    } else {
        printf("remote read/write roundtrip mismatch\n");
    }
}

static void zt_test_remote_thunk_rw(pid_t pid,
                                    uint64_t remote_addr,
                                    const uint8_t *thunk_buf,
                                    size_t thunk_size) {
    uint8_t remote_buf[ZT_THUNK_MAX_SIZE];
    int i;

    if (thunk_buf == NULL || thunk_size == 0 || thunk_size > sizeof(remote_buf)) {
        printf("invalid thunk buffer for remote write test\n");
        return;
    }

    if (zt_write_remote_memory(pid, remote_addr, thunk_buf, thunk_size) != 0) {
        printf("failed to write thunk to remote addr 0x%llx\n",
               (unsigned long long)remote_addr);
        return;
    }

    if (zt_read_remote_memory(pid, remote_addr, remote_buf, thunk_size) != 0) {
        printf("failed to read thunk back from remote addr 0x%llx\n",
               (unsigned long long)remote_addr);
        return;
    }

    printf("Remote thunk bytes (%zu): ", thunk_size);
    for (i = 0; i < (int)thunk_size; ++i) {
        printf("%02x ", remote_buf[i]);
    }
    printf("\n");

    if (memcmp(thunk_buf, remote_buf, thunk_size) == 0) {
        printf("remote thunk write/readback ok at 0x%llx\n",
               (unsigned long long)remote_addr);
    } else {
        printf("remote thunk write/readback mismatch at 0x%llx\n",
               (unsigned long long)remote_addr);
    }
}

static void zt_dump_remote_patch_bytes(pid_t pid, uint64_t remote_addr, size_t size) {
    uint8_t patch[ZT_PROBE_ORIG_CODE_MAX];
    int i;

    if (size == 0 || size > sizeof(patch)) {
        printf("invalid patch size: %zu\n", size);
        return;
    }

    if (zt_read_remote_memory(pid, remote_addr, patch, size) != 0) {
        printf("failed to read installed patch at 0x%llx\n",
               (unsigned long long)remote_addr);
        return;
    }

    printf("Installed patch bytes: ");
    for (i = 0; i < (int)size; ++i) {
        printf("%02x ", patch[i]);
    }
    printf("\n");
}

static void zt_dump_trace_events(const zt_trace_buffer_t *buffer, size_t max_events) {
    uint64_t write_seq;
    size_t start;
    size_t end;
    size_t i;

    if (buffer == NULL) {
        return;
    }

    if (buffer->magic != ZT_TRACE_BUFFER_MAGIC) {
        printf("trace buffer magic mismatch\n");
        return;
    }

    write_seq = buffer->write_seq;
    printf("Trace buffer write_seq: %llu\n", (unsigned long long)write_seq);
    if (write_seq == 0) {
        printf("No trace events captured yet\n");
        return;
    }

    start = 0;
    if (write_seq > max_events) {
        start = (size_t)(write_seq - max_events);
    }
    end = (size_t)write_seq;

    printf("Trace events:\n");
    for (i = start; i < end; ++i) {
        const zt_trace_event_t *event = &buffer->events[i % ZT_TRACE_EVENT_CAPACITY];

        if (event->committed_seq != i + 1) {
            continue;
        }

        printf("  seq=%zu probe=%llu type=%s values=[0x%llx 0x%llx 0x%llx 0x%llx 0x%llx 0x%llx]\n",
               i + 1,
               (unsigned long long)event->probe_id,
               event->event_type == ZT_TRACE_EVENT_ENTRY ? "entry" : "return",
               (unsigned long long)event->value0,
               (unsigned long long)event->value1,
               (unsigned long long)event->value2,
               (unsigned long long)event->value3,
               (unsigned long long)event->value4,
               (unsigned long long)event->value5);
    }
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
    char payload_so_path[PATH_MAX];
    char dlopen_module_path[PATH_MAX];
    uint64_t remote_dlopen_addr;
    uint64_t remote_payload_path_addr;
    uint64_t remote_entry_stub_addr;
    uint64_t remote_thunk_addr;
    uint64_t remote_trace_buffer_addr;
    uint64_t remote_payload_init_addr;
    uint64_t remote_payload_config_addr;
    uint64_t remote_call_ret;
    if(zt_injector_attach(&session, (pid_t)pid) != 0) {
        fprintf(stderr, "Failed to attach to process with PID %ld\n", pid);
        exit(EXIT_FAILURE);
    }

    printf("Successfully attached to process with PID %d, %s, is_pie: %d, image_base: 0x%lX\n",
           session.pid,
           session.exe_path,
           session.is_pie,
           session.image_base);

    if (realpath("bin/libzt_payload.so", payload_so_path) == NULL) {
        printf("Failed to resolve payload so path\n");
        zt_injector_detach(&session);
        exit(EXIT_FAILURE);
    }

    {
        Dl_info dl_info;

        if (dladdr((void *)dlopen, &dl_info) == 0 || dl_info.dli_fname == NULL) {
            printf("Failed to resolve local dlopen module path\n");
            zt_injector_detach(&session);
            exit(EXIT_FAILURE);
        }

        if (realpath(dl_info.dli_fname, dlopen_module_path) == NULL) {
            strncpy(dlopen_module_path, dl_info.dli_fname, sizeof(dlopen_module_path) - 1);
            dlopen_module_path[sizeof(dlopen_module_path) - 1] = '\0';
        }
    }

    if (zt_find_remote_symbol_addr(session.pid,
                                   dlopen_module_path,
                                   "dlopen",
                                   &remote_dlopen_addr) == 0) {
        printf("Remote dlopen addr: 0x%llx\n",
               (unsigned long long)remote_dlopen_addr);
    } else {
        printf("Failed to resolve remote dlopen addr from %s\n", dlopen_module_path);
        zt_injector_detach(&session);
        exit(EXIT_FAILURE);
    }

    if (zt_remote_mmap(session.pid,
                       4096,
                       PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_PRIVATE | MAP_ANONYMOUS,
                       &remote_thunk_addr) == 0) {
        printf("Remote mmap addr: 0x%llx\n", (unsigned long long)remote_thunk_addr);
    } else {
        printf("Failed to mmap remote thunk page\n");
    }

    if (zt_remote_mmap(session.pid,
                       strlen(payload_so_path) + 1,
                       PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS,
                       &remote_payload_path_addr) == 0) {
        printf("Remote payload path addr: 0x%llx\n",
               (unsigned long long)remote_payload_path_addr);
    } else {
        printf("Failed to mmap remote payload path\n");
        zt_injector_detach(&session);
        exit(EXIT_FAILURE);
    }

    if (zt_write_remote_memory(session.pid,
                               remote_payload_path_addr,
                               payload_so_path,
                               strlen(payload_so_path) + 1) != 0) {
        printf("Failed to write remote payload path\n");
        zt_injector_detach(&session);
        exit(EXIT_FAILURE);
    }

    if (zt_remote_call2(session.pid,
                        remote_dlopen_addr,
                        remote_payload_path_addr,
                        RTLD_NOW | RTLD_GLOBAL,
                        &remote_call_ret) == 0 && remote_call_ret != 0) {
        printf("Remote dlopen handle: 0x%llx\n",
               (unsigned long long)remote_call_ret);
    } else {
        printf("Failed to call remote dlopen for %s\n", payload_so_path);
        zt_injector_detach(&session);
        exit(EXIT_FAILURE);
    }

    if (zt_find_remote_symbol_addr(session.pid,
                                   payload_so_path,
                                   "entry_stub",
                                   &remote_entry_stub_addr) == 0) {
        printf("Remote entry_stub addr: 0x%llx\n",
               (unsigned long long)remote_entry_stub_addr);
    } else {
        printf("Failed to resolve remote entry_stub addr from %s\n", payload_so_path);
        zt_injector_detach(&session);
        exit(EXIT_FAILURE);
    }

    if (zt_find_remote_symbol_addr(session.pid,
                                   payload_so_path,
                                   "zt_payload_init",
                                   &remote_payload_init_addr) == 0) {
        printf("Remote zt_payload_init addr: 0x%llx\n",
               (unsigned long long)remote_payload_init_addr);
    } else {
        printf("Failed to resolve remote zt_payload_init addr from %s\n", payload_so_path);
        zt_injector_detach(&session);
        exit(EXIT_FAILURE);
    }

    if (zt_remote_mmap(session.pid,
                       sizeof(zt_trace_buffer_t),
                       PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS,
                       &remote_trace_buffer_addr) == 0) {
        printf("Remote trace buffer addr: 0x%llx\n",
               (unsigned long long)remote_trace_buffer_addr);
    } else {
        printf("Failed to mmap remote trace buffer\n");
        zt_injector_detach(&session);
        exit(EXIT_FAILURE);
    }

    if (zt_remote_mmap(session.pid,
                       sizeof(zt_payload_config_t),
                       PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS,
                       &remote_payload_config_addr) == 0) {
        zt_payload_config_t config = {
            .shared_buffer_addr = remote_trace_buffer_addr,
            .shared_buffer_size = sizeof(zt_trace_buffer_t),
        };

        printf("Remote payload config addr: 0x%llx\n",
               (unsigned long long)remote_payload_config_addr);

        if (zt_write_remote_memory(session.pid,
                                   remote_payload_config_addr,
                                   &config,
                                   sizeof(config)) != 0) {
            printf("Failed to write remote payload config\n");
            zt_injector_detach(&session);
            exit(EXIT_FAILURE);
        }
    } else {
        printf("Failed to mmap remote payload config\n");
        zt_injector_detach(&session);
        exit(EXIT_FAILURE);
    }

    if (zt_remote_call1(session.pid,
                        remote_payload_init_addr,
                        remote_payload_config_addr,
                        &remote_call_ret) == 0) {
        printf("Remote zt_payload_init returned: %llu\n",
               (unsigned long long)remote_call_ret);
    } else {
        printf("Failed to call remote zt_payload_init\n");
        zt_injector_detach(&session);
        exit(EXIT_FAILURE);
    }

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

    zt_test_remote_rw(session.pid, probe->symbol_addr);

    if (zt_enable_probe(&session, probe->probe_id) != 0) {
        printf("zt_enable_probe failed for probe %lu\n", probe->probe_id);
    } else {
        int i;
        uint8_t thunk_buf[ZT_THUNK_MAX_SIZE];
        size_t thunk_size;
        printf("zt_enable_probe ok: orig_len=%u, orig_code=", probe->orig_len);
        for (i = 0; i < probe->orig_len; ++i) {
            printf("%02x ", probe->orig_code[i]);
        }
        printf("\n");

        if (zt_build_thunk(probe,
                           remote_entry_stub_addr,
                           thunk_buf,
                           sizeof(thunk_buf),
                           &thunk_size) != 0) {
            printf("zt_build_thunk failed for probe %lu\n", probe->probe_id);
        } else {
            size_t thunk_code_size = thunk_size - 16;

            printf("Thunk bytes (%zu): ", thunk_size);
            for (i = 0; i < (int)thunk_size; ++i) {
                printf("%02x ", thunk_buf[i]);
            }
            printf("\n");
            zt_test_remote_thunk_rw(session.pid, remote_thunk_addr, thunk_buf, thunk_size);
            if (zt_install_probe_patch(&session, probe->probe_id, remote_thunk_addr) == 0) {
                zt_trace_buffer_t trace_buffer;
                int status;

                printf("probe patch installed at 0x%llx -> thunk 0x%llx\n",
                       (unsigned long long)probe->symbol_addr,
                       (unsigned long long)remote_thunk_addr);
                zt_dump_remote_patch_bytes(session.pid,
                                           probe->symbol_addr,
                                           ZT_PROBE_PATCH_LEN);

                if (ptrace(PTRACE_CONT, session.pid, NULL, NULL) == 0) {
                    sleep(2);
                    kill(session.pid, SIGSTOP);
                    if (waitpid(session.pid, &status, 0) > 0 && WIFSTOPPED(status)) {
                        if (zt_read_remote_memory(session.pid,
                                                  remote_trace_buffer_addr,
                                                  &trace_buffer,
                                                  sizeof(trace_buffer)) == 0) {
                            zt_dump_trace_events(&trace_buffer, 8);
                        } else {
                            printf("Failed to read remote trace buffer\n");
                        }
                    } else {
                        printf("Failed to stop target process for trace readback\n");
                    }
                } else {
                    printf("Failed to continue target process for trace capture\n");
                }

                if (zt_uninstall_probe_patch(&session, probe->probe_id) == 0) {
                    printf("probe patch restored at 0x%llx\n",
                           (unsigned long long)probe->symbol_addr);
                    zt_dump_remote_patch_bytes(session.pid,
                                               probe->symbol_addr,
                                               probe->orig_len);
                } else {
                    printf("failed to restore probe patch for probe %lu\n", probe->probe_id);
                }
            } else {
                printf("failed to install probe patch for probe %lu\n", probe->probe_id);
            }
            zt_dump_thunk_disasm(thunk_buf, thunk_code_size);
            zt_dump_thunk_tail(thunk_buf, thunk_size);
        }
    }

    zt_injector_detach(&session);

    return 0;
}
