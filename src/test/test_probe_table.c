#include <stdio.h>
#include <string.h>

#include "../../include/zt_injector.h"

int main(void) {
    zt_injector_session_t session = {0};
    zt_symbol_target_t target1 = {.symbol = "foo", .module_path = "/tmp/a.so", .remote_addr = 0x1234};
    zt_symbol_target_t target2 = {.symbol = "bar", .module_path = "/tmp/b.so", .remote_addr = 0x5678};
    zt_probe_info_t *probe1;
    zt_probe_info_t *probe1_dup;
    zt_probe_info_t *probe2;

    session.next_probe_id = 1;

    probe1 = zt_probe_alloc(&session, &target1);
    if (probe1 == NULL || probe1->probe_id != 1 || session.probe_count != 1) {
        fprintf(stderr, "failed to allocate first probe\n");
        return 1;
    }

    probe1_dup = zt_probe_alloc(&session, &target1);
    if (probe1_dup != probe1 || session.probe_count != 1) {
        fprintf(stderr, "duplicate probe allocation changed state\n");
        return 1;
    }

    probe2 = zt_probe_alloc(&session, &target2);
    if (probe2 == NULL || probe2->probe_id != 2 || session.probe_count != 2) {
        fprintf(stderr, "failed to allocate second probe\n");
        return 1;
    }

    if (zt_probe_find_by_symbol(&session, "foo") != probe1 ||
        zt_probe_find_by_id(&session, 2) != probe2) {
        fprintf(stderr, "probe lookup failed\n");
        return 1;
    }

    if (zt_unregister_probe(&session, probe1->probe_id) != 0 ||
        zt_probe_find_by_symbol(&session, "foo") != NULL ||
        session.probe_count != 1) {
        fprintf(stderr, "failed to unregister first probe\n");
        return 1;
    }

    if (zt_unregister_probe(&session, probe2->probe_id) != 0 || session.probe_count != 0) {
        fprintf(stderr, "failed to unregister second probe\n");
        return 1;
    }

    printf("probe table test passed\n");
    return 0;
}
