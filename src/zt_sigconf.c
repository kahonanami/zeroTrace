#define _GNU_SOURCE

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "zt_sigconf.h"

static zt_func_sig_t g_sig_table[ZT_SIGCONF_MAX_FUNCS];
static int g_sig_count;
static int g_sigconf_loaded;

static int zt_append_value(char *out,
                           size_t out_size,
                           size_t *offset,
                           const zt_injector_session_t *session,
                           zt_sig_type_t type,
                           uint64_t value);

static char *zt_trim(char *s) {
    char *end;

    while (*s != '\0' && isspace((unsigned char)*s)) {
        ++s;
    }

    if (*s == '\0') {
        return s;
    }

    end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) {
        *end-- = '\0';
    }

    return s;
}

static void zt_copy_str(char *dst, size_t dst_size, const char *src) {
    if (dst == NULL || dst_size == 0) {
        return;
    }

    if (src == NULL) {
        dst[0] = '\0';
        return;
    }

    snprintf(dst, dst_size, "%s", src);
}

static int zt_find_trailing_ident_span(const char *spec, size_t *start_out, size_t *end_out) {
    size_t end;
    size_t start;

    if (spec == NULL || start_out == NULL) {
        return 0;
    }

    end = strlen(spec);
    while (end > 0 && isspace((unsigned char)spec[end - 1])) {
        --end;
    }

    start = end;
    while (start > 0 &&
           (isalnum((unsigned char)spec[start - 1]) || spec[start - 1] == '_')) {
        --start;
    }

    if (start == end || start == 0) {
        return 0;
    }

    *start_out = start;
    if (end_out != NULL) {
        *end_out = end;
    }
    return 1;
}

static void zt_strip_param_name(char *spec) {
    size_t start;

    if (!zt_find_trailing_ident_span(spec, &start, NULL)) {
        return;
    }

    if (spec[start - 1] == '*') {
        spec[start] = '\0';
        return;
    }

    while (start > 0 && isspace((unsigned char)spec[start - 1])) {
        --start;
    }
    spec[start] = '\0';
}

static void zt_extract_param_name(const char *spec, char *name, size_t name_size) {
    size_t end;
    size_t start;
    size_t len;

    if (name == NULL || name_size == 0) {
        return;
    }
    name[0] = '\0';

    if (!zt_find_trailing_ident_span(spec, &start, &end)) {
        return;
    }

    len = end - start;
    if (len >= name_size) {
        len = name_size - 1;
    }
    memcpy(name, spec + start, len);
    name[len] = '\0';
}

typedef struct {
    const char *decl;
    zt_sig_type_t type;
} zt_sig_type_name_t;

static const zt_sig_type_name_t kExactSigTypes[] = {
    {"void", ZT_SIG_TYPE_VOID},
    {"buffer", ZT_SIG_TYPE_BUF},
    {"const buffer", ZT_SIG_TYPE_CONST_BUF},
    {"float", ZT_SIG_TYPE_FLOAT},
    {"double", ZT_SIG_TYPE_DOUBLE},
    {"size_t", ZT_SIG_TYPE_SIZE},
    {"ssize_t", ZT_SIG_TYPE_SSIZE},
    {"unsigned long", ZT_SIG_TYPE_ULONG},
    {"time_t", ZT_SIG_TYPE_ULONG},
    {"long", ZT_SIG_TYPE_LONG},
    {"off_t", ZT_SIG_TYPE_LONG},
    {"int", ZT_SIG_TYPE_INT},
    {"unsigned int", ZT_SIG_TYPE_INT},
    {"pid_t", ZT_SIG_TYPE_INT},
    {"mode_t", ZT_SIG_TYPE_INT},
    {"uid_t", ZT_SIG_TYPE_INT},
    {"gid_t", ZT_SIG_TYPE_INT},
    {"socklen_t", ZT_SIG_TYPE_INT},
};

static zt_sig_type_t zt_parse_sig_type(const char *decl) {
    size_t i;

    if (decl == NULL || decl[0] == '\0') {
        return ZT_SIG_TYPE_UNKNOWN;
    }

    for (i = 0; i < sizeof(kExactSigTypes) / sizeof(kExactSigTypes[0]); ++i) {
        if (strcmp(decl, kExactSigTypes[i].decl) == 0) {
            return kExactSigTypes[i].type;
        }
    }

    if (strstr(decl, "char *") != NULL) {
        return ZT_SIG_TYPE_CSTR;
    }

    if (strchr(decl, '*') != NULL) {
        return ZT_SIG_TYPE_PTR;
    }

    return ZT_SIG_TYPE_UNKNOWN;
}

static int zt_parse_sig_line(char *line, zt_func_sig_t *sig) {
    char *open_paren;
    char *close_paren;
    char *arrow;
    char *params;
    char *token;
    int count = 0;

    open_paren = strchr(line, '(');
    close_paren = strrchr(line, ')');
    arrow = strstr(line, "->");
    if (open_paren == NULL || close_paren == NULL || arrow == NULL || close_paren < open_paren) {
        return -1;
    }

    *open_paren = '\0';
    zt_copy_str(sig->symbol, sizeof(sig->symbol), zt_trim(line));
    if (sig->symbol[0] == '\0') {
        return -1;
    }

    *close_paren = '\0';
    params = open_paren + 1;
    arrow += 2;

    memset(sig->params, 0, sizeof(sig->params));
    sig->param_count = 0;
    sig->variadic = 0;

    token = strtok(params, ",");
    while (token != NULL) {
        char param_buf[64];
        char *trimmed = zt_trim(token);

        if (strcmp(trimmed, "...") == 0) {
            sig->variadic = 1;
            token = strtok(NULL, ",");
            continue;
        }

        if (trimmed[0] != '\0' && count < ZT_SIGCONF_MAX_PARAMS) {
            zt_copy_str(param_buf, sizeof(param_buf), trimmed);
            zt_extract_param_name(param_buf,
                                  sig->params[count].name,
                                  sizeof(sig->params[count].name));
            zt_strip_param_name(param_buf);
            zt_copy_str(sig->params[count].decl, sizeof(sig->params[count].decl), zt_trim(param_buf));
            sig->params[count].type = zt_parse_sig_type(sig->params[count].decl);
            ++count;
        }

        token = strtok(NULL, ",");
    }
    sig->param_count = count;

    zt_copy_str(sig->ret.decl, sizeof(sig->ret.decl), zt_trim(arrow));
    sig->ret.type = zt_parse_sig_type(sig->ret.decl);
    return 0;
}

int zt_sigconf_load(const char *path) {
    FILE *fp;
    char line[512];

    if (path == NULL) {
        return -1;
    }

    fp = fopen(path, "r");
    if (fp == NULL) {
        return -1;
    }

    g_sig_count = 0;
    while (fgets(line, sizeof(line), fp) != NULL) {
        char *trimmed = zt_trim(line);

        if (trimmed[0] == '\0' || trimmed[0] == '#' || trimmed[0] == ';') {
            continue;
        }

        if (g_sig_count >= ZT_SIGCONF_MAX_FUNCS) {
            break;
        }

        memset(&g_sig_table[g_sig_count], 0, sizeof(g_sig_table[g_sig_count]));
        if (zt_parse_sig_line(trimmed, &g_sig_table[g_sig_count]) == 0) {
            ++g_sig_count;
        }
    }

    fclose(fp);
    g_sigconf_loaded = 1;
    return 0;
}

int zt_sigconf_load_default(void) {
    if (g_sigconf_loaded) {
        return 0;
    }

    return zt_sigconf_load("conf/zttrace.conf");
}

const zt_func_sig_t *zt_sigconf_find(const char *symbol) {
    int i;

    if (symbol == NULL) {
        return NULL;
    }

    for (i = 0; i < g_sig_count; ++i) {
        if (strcmp(g_sig_table[i].symbol, symbol) == 0) {
            return &g_sig_table[i];
        }
    }

    return NULL;
}

static uint64_t zt_event_arg_value(const zt_trace_event_t *event, int index) {
    if (event == NULL || index < 0 || index >= ZT_TRACE_GP_ARG_COUNT) {
        return 0;
    }

    return event->args[index];
}

static uint64_t zt_event_fp_arg_value(const zt_trace_event_t *event, int index) {
    if (event == NULL || index < 0 || index >= ZT_TRACE_FP_ARG_COUNT) {
        return 0;
    }

    return event->fp_args[index];
}

static int zt_event_arg_value_ext(const zt_trace_event_t *event,
                                  int index,
                                  uint64_t *value_out) {
    if (event == NULL || value_out == NULL || index < 0) {
        return -1;
    }

    if (index < ZT_TRACE_GP_ARG_COUNT) {
        *value_out = zt_event_arg_value(event, index);
        return 0;
    }

    return -1;
}

static size_t zt_min_size(size_t lhs, size_t rhs) {
    return lhs < rhs ? lhs : rhs;
}

static int zt_read_remote_chunk_or_byte(const zt_injector_session_t *session,
                                        uint64_t remote_addr,
                                        unsigned char *buffer,
                                        size_t *len_inout) {
    size_t len;

    if (session == NULL || buffer == NULL || len_inout == NULL || *len_inout == 0) {
        return -1;
    }

    len = *len_inout;
    if (zt_read_remote_memory(session->pid, remote_addr, buffer, len) == 0) {
        return 0;
    }

    *len_inout = 1;
    return zt_read_remote_memory(session->pid, remote_addr, buffer, 1);
}

static int zt_read_remote_bytes_with_fallback(const zt_injector_session_t *session,
                                             uint64_t remote_addr,
                                             unsigned char *buffer,
                                             size_t len) {
    size_t i;

    if (session == NULL || buffer == NULL) {
        return -1;
    }

    if (len == 0 || zt_read_remote_memory(session->pid, remote_addr, buffer, len) == 0) {
        return 0;
    }

    for (i = 0; i < len; ++i) {
        if (zt_read_remote_memory(session->pid, remote_addr + i, &buffer[i], 1) != 0) {
            return -1;
        }
    }

    return 0;
}

static int zt_read_remote_cstr(const zt_injector_session_t *session,
                               uint64_t remote_addr,
                               char *buffer,
                               size_t buffer_size) {
    unsigned char chunk[64];
    size_t i;

    if (session == NULL || buffer == NULL || buffer_size == 0) {
        return -1;
    }

    if (remote_addr == 0) {
        snprintf(buffer, buffer_size, "NULL");
        return 0;
    }

    i = 0;
    while (i + 1 < buffer_size) {
        size_t chunk_len = zt_min_size(sizeof(chunk), buffer_size - 1 - i);
        size_t j;

        if (zt_read_remote_chunk_or_byte(session, remote_addr + i, chunk, &chunk_len) != 0) {
            return -1;
        }

        for (j = 0; j < chunk_len && i + 1 < buffer_size; ++j, ++i) {
            unsigned char ch = chunk[j];

            if (ch == '\0') {
                buffer[i] = '\0';
                return 0;
            }

            buffer[i] = isprint(ch) ? (char)ch : '.';
        }
    }

    buffer[buffer_size - 1] = '\0';
    return 0;
}

static int zt_append_raw(char *out, size_t out_size, size_t *offset, const char *text) {
    size_t len;

    if (out == NULL || offset == NULL || text == NULL) {
        return -1;
    }

    len = strlen(text);
    if (*offset + len >= out_size) {
        return -1;
    }

    memcpy(out + *offset, text, len);
    *offset += len;
    out[*offset] = '\0';
    return 0;
}

static int zt_sig_type_is_numeric(zt_sig_type_t type) {
    switch (type) {
    case ZT_SIG_TYPE_INT:
    case ZT_SIG_TYPE_LONG:
    case ZT_SIG_TYPE_ULONG:
    case ZT_SIG_TYPE_SIZE:
    case ZT_SIG_TYPE_SSIZE:
        return 1;
    default:
        return 0;
    }
}

static int zt_sig_param_is_numeric(const zt_func_sig_t *sig, int index) {
    return sig != NULL &&
           index >= 0 &&
           index < sig->param_count &&
           zt_sig_type_is_numeric(sig->params[index].type);
}

static int zt_sig_type_is_fp(zt_sig_type_t type) {
    return type == ZT_SIG_TYPE_FLOAT || type == ZT_SIG_TYPE_DOUBLE;
}

static size_t zt_cap_preview_len(size_t len) {
    const size_t kMaxPreview = 32;
    return len > kMaxPreview ? kMaxPreview : len;
}

static int zt_read_remote_buf_preview(const zt_injector_session_t *session,
                                      uint64_t remote_addr,
                                      size_t len,
                                      char *buffer,
                                      size_t buffer_size) {
    unsigned char bytes[32];
    size_t i;
    size_t offset = 0;

    if (session == NULL || buffer == NULL || buffer_size == 0) {
        return -1;
    }

    if (remote_addr == 0) {
        return snprintf(buffer, buffer_size, "NULL") >= 0 ? 0 : -1;
    }

    if (offset + 1 >= buffer_size) {
        return -1;
    }
    buffer[offset++] = '"';

    len = zt_cap_preview_len(len);
    if (zt_read_remote_bytes_with_fallback(session, remote_addr, bytes, len) != 0) {
        return -1;
    }

    for (i = 0; i < len; ++i) {
        unsigned char ch = bytes[i];
        int written;

        if (isprint(ch) && ch != '"' && ch != '\\') {
            if (offset + 1 >= buffer_size) {
                return -1;
            }
            buffer[offset++] = (char)ch;
            continue;
        }

        written = snprintf(buffer + offset, buffer_size - offset, "\\x%02x", ch);
        if (written < 0 || (size_t)written >= buffer_size - offset) {
            return -1;
        }
        offset += (size_t)written;
    }

    if (offset + 2 >= buffer_size) {
        return -1;
    }
    buffer[offset++] = '"';
    buffer[offset] = '\0';
    return 0;
}

static size_t zt_buffer_preview_len(const zt_func_sig_t *sig,
                                    const zt_trace_event_t *args_event,
                                    const zt_trace_event_t *ret_event,
                                    int param_index,
                                    int for_return) {
    uint64_t next;
    uint64_t next2;

    if (sig == NULL || args_event == NULL || param_index < 0 || param_index >= sig->param_count) {
        return 0;
    }

    if (for_return) {
        if (ret_event == NULL || (long long)ret_event->value0 <= 0) {
            return 0;
        }

        if (zt_sig_param_is_numeric(sig, param_index + 1) &&
            zt_sig_param_is_numeric(sig, param_index + 2)) {
            next = zt_event_arg_value(args_event, param_index + 1);
            return zt_cap_preview_len((size_t)(ret_event->value0 * next));
        }

        if (zt_sig_param_is_numeric(sig, param_index + 1)) {
            next = zt_event_arg_value(args_event, param_index + 1);
            return zt_cap_preview_len((size_t)((ret_event->value0 < next) ? ret_event->value0 : next));
        }

        return zt_cap_preview_len((size_t)ret_event->value0);
    }

    if (zt_sig_param_is_numeric(sig, param_index + 1) &&
        zt_sig_param_is_numeric(sig, param_index + 2)) {
        next = zt_event_arg_value(args_event, param_index + 1);
        next2 = zt_event_arg_value(args_event, param_index + 2);
        return zt_cap_preview_len((size_t)(next * next2));
    }

    if (zt_sig_param_is_numeric(sig, param_index + 1)) {
        next = zt_event_arg_value(args_event, param_index + 1);
        return zt_cap_preview_len((size_t)next);
    }

    return 0;
}

static int zt_find_format_param_index(const zt_func_sig_t *sig) {
    int i;

    if (sig == NULL || !sig->variadic) {
        return -1;
    }

    for (i = sig->param_count - 1; i >= 0; --i) {
        if (sig->params[i].type == ZT_SIG_TYPE_CSTR &&
            strcmp(sig->params[i].name, "fmt") == 0) {
            return i;
        }
    }

    return -1;
}

static void zt_count_fixed_param_regs(const zt_func_sig_t *sig,
                                      int *gp_count_out,
                                      int *fp_count_out) {
    int i;
    int gp_count = 0;
    int fp_count = 0;

    if (sig != NULL) {
        for (i = 0; i < sig->param_count; ++i) {
            if (zt_sig_type_is_fp(sig->params[i].type)) {
                ++fp_count;
            } else {
                ++gp_count;
            }
        }
    }

    if (gp_count_out != NULL) {
        *gp_count_out = gp_count;
    }
    if (fp_count_out != NULL) {
        *fp_count_out = fp_count;
    }
}

static void zt_skip_format_flags(const char **cursor, int *arg_index) {
    const char *p = *cursor;

    while (*p != '\0' && strchr("-+ #0'", *p) != NULL) {
        ++p;
    }

    if (*p == '*') {
        ++*arg_index;
        ++p;
    } else {
        while (isdigit((unsigned char)*p)) {
            ++p;
        }
    }

    if (*p == '.') {
        ++p;
        if (*p == '*') {
            ++*arg_index;
            ++p;
        } else {
            while (isdigit((unsigned char)*p)) {
                ++p;
            }
        }
    }

    *cursor = p;
}

static void zt_skip_format_length(const char **cursor) {
    const char *p = *cursor;

    if ((p[0] == 'h' && p[1] == 'h') ||
        (p[0] == 'l' && p[1] == 'l')) {
        *cursor = p + 2;
        return;
    }

    if (strchr("hljztL", *p) != NULL) {
        *cursor = p + 1;
    }
}

static int zt_append_variadic_arg(char *out,
                                  size_t out_size,
                                  size_t *offset,
                                  const zt_injector_session_t *session,
                                  const zt_trace_event_t *event,
                                  int *gp_index,
                                  int *fp_index,
                                  char conv) {
    uint64_t value;

    if (strchr("aAeEfFgG", conv) != NULL) {
        value = zt_event_fp_arg_value(event, (*fp_index)++);
        if (zt_append_raw(out, out_size, offset, ", ") != 0) {
            return -1;
        }
        return zt_append_value(out, out_size, offset, session, ZT_SIG_TYPE_DOUBLE, value);
    }

    if (zt_event_arg_value_ext(event, *gp_index, &value) != 0) {
        return zt_append_raw(out, out_size, offset, ", <unreadable>");
    }
    ++*gp_index;

    if (zt_append_raw(out, out_size, offset, ", ") != 0) {
        return -1;
    }

    switch (conv) {
    case 'd':
    case 'i':
        return zt_append_value(out, out_size, offset, session, ZT_SIG_TYPE_LONG, value);
    case 'u':
    case 'o':
    case 'x':
    case 'X':
        return zt_append_value(out, out_size, offset, session, ZT_SIG_TYPE_ULONG, value);
    case 'p':
    case 'n':
        return zt_append_value(out, out_size, offset, session, ZT_SIG_TYPE_PTR, value);
    case 's':
        return zt_append_value(out, out_size, offset, session, ZT_SIG_TYPE_CSTR, value);
    case 'c':
        return zt_append_value(out, out_size, offset, session, ZT_SIG_TYPE_INT, value);
    default:
        return zt_append_raw(out, out_size, offset, "<arg>");
    }
}

static int zt_append_variadic_args(char *out,
                                   size_t out_size,
                                   size_t *offset,
                                   const zt_injector_session_t *session,
                                   const zt_func_sig_t *sig,
                                   const zt_trace_event_t *event) {
    int fmt_index;
    int gp_index;
    int fp_index;
    uint64_t fmt_addr;
    char fmt[192];
    const char *p;

    fmt_index = zt_find_format_param_index(sig);
    if (fmt_index < 0 ||
        zt_event_arg_value_ext(event, fmt_index, &fmt_addr) != 0 ||
        zt_read_remote_cstr(session, fmt_addr, fmt, sizeof(fmt)) != 0) {
        return zt_append_raw(out, out_size, offset, ", ...");
    }

    zt_count_fixed_param_regs(sig, &gp_index, &fp_index);
    p = fmt;
    while (*p != '\0') {
        if (*p++ != '%') {
            continue;
        }

        if (*p == '%') {
            ++p;
            continue;
        }

        zt_skip_format_flags(&p, &gp_index);
        zt_skip_format_length(&p);
        if (*p == '\0') {
            break;
        }

        if (*p != 'm' && zt_append_variadic_arg(out,
                                                out_size,
                                                offset,
                                                session,
                                                event,
                                                &gp_index,
                                                &fp_index,
                                                *p) != 0) {
            return -1;
        }
        ++p;
    }

    return 0;
}

static int zt_append_value(char *out,
                           size_t out_size,
                           size_t *offset,
                           const zt_injector_session_t *session,
                           zt_sig_type_t type,
                           uint64_t value) {
    int written;
    char text[96];

    switch (type) {
    case ZT_SIG_TYPE_INT:
        written = snprintf(text, sizeof(text), "%lld", (long long)(int)value);
        break;
    case ZT_SIG_TYPE_LONG:
    case ZT_SIG_TYPE_SSIZE:
        written = snprintf(text, sizeof(text), "%lld", (long long)value);
        break;
    case ZT_SIG_TYPE_ULONG:
    case ZT_SIG_TYPE_SIZE:
        written = snprintf(text, sizeof(text), "%llu", (unsigned long long)value);
        break;
    case ZT_SIG_TYPE_FLOAT: {
        float fp_value;
        uint32_t raw = (uint32_t)value;

        memcpy(&fp_value, &raw, sizeof(fp_value));
        written = snprintf(text, sizeof(text), "%g", (double)fp_value);
        break;
    }
    case ZT_SIG_TYPE_DOUBLE: {
        double fp_value;

        memcpy(&fp_value, &value, sizeof(fp_value));
        written = snprintf(text, sizeof(text), "%g", fp_value);
        break;
    }
    case ZT_SIG_TYPE_CSTR: {
        char str[64];

        if (zt_read_remote_cstr(session, value, str, sizeof(str)) != 0) {
            written = snprintf(text, sizeof(text), "0x%llx", (unsigned long long)value);
        } else {
            written = snprintf(text, sizeof(text), "\"%s\"", str);
        }
        break;
    }
    case ZT_SIG_TYPE_BUF:
    case ZT_SIG_TYPE_CONST_BUF:
    case ZT_SIG_TYPE_PTR:
        written = snprintf(text, sizeof(text), "0x%llx", (unsigned long long)value);
        break;
    case ZT_SIG_TYPE_VOID:
        written = snprintf(text, sizeof(text), "void");
        break;
    default:
        written = snprintf(text, sizeof(text), "0x%llx", (unsigned long long)value);
        break;
    }

    if (written < 0 || (size_t)written >= sizeof(text)) {
        return -1;
    }

    return zt_append_raw(out, out_size, offset, text);
}

int zt_format_trace_event_with_sig(const zt_injector_session_t *session,
                                   const zt_probe_info_t *probe,
                                   const zt_trace_event_t *entry_event,
                                   const zt_trace_event_t *event,
                                   char *out,
                                   size_t out_size) {
    const zt_func_sig_t *sig;
    size_t offset = 0;
    int i;
    int gp_index = 0;
    int fp_index = 0;
    int written;

    if (session == NULL || probe == NULL || event == NULL || out == NULL || out_size == 0) {
        return -1;
    }

    sig = zt_sigconf_find(probe->target.symbol);
    if (sig == NULL) {
        return -1;
    }

    if (event->event_type == ZT_TRACE_EVENT_ENTRY) {
        written = snprintf(out, out_size, "%s(", probe->target.symbol);
        if (written < 0 || (size_t)written >= out_size) {
            return -1;
        }
        offset = (size_t)written;

        for (i = 0; i < sig->param_count; ++i) {
            uint64_t raw_value;

            if (i > 0) {
                if (zt_append_raw(out, out_size, &offset, ", ") != 0) {
                    return -1;
                }
            }

            if (zt_sig_type_is_fp(sig->params[i].type)) {
                raw_value = zt_event_fp_arg_value(event, fp_index++);
            } else {
                raw_value = zt_event_arg_value(event, gp_index++);
            }

            if (zt_append_value(out,
                                out_size,
                                &offset,
                                session,
                                sig->params[i].type,
                                raw_value) != 0) {
                return -1;
            }

            if (sig->params[i].type == ZT_SIG_TYPE_CONST_BUF) {
                char preview[192];
                size_t preview_len = zt_buffer_preview_len(sig, event, NULL, i, 0);

                if (preview_len > 0 &&
                    zt_read_remote_buf_preview(session,
                                               raw_value,
                                               preview_len,
                                               preview,
                                               sizeof(preview)) == 0) {
                    if (zt_append_raw(out, out_size, &offset, "=") != 0 ||
                        zt_append_raw(out, out_size, &offset, preview) != 0) {
                        return -1;
                    }
                }
            }
        }

        if (sig->variadic) {
            if (zt_append_variadic_args(out,
                                        out_size,
                                        &offset,
                                        session,
                                        sig,
                                        event) != 0) {
                return -1;
            }
        }

        return zt_append_raw(out, out_size, &offset, ")\n");
    }

    if (event->event_type == ZT_TRACE_EVENT_RETURN) {
        written = snprintf(out, out_size, "%s -> ", probe->target.symbol);
        if (written < 0 || (size_t)written >= out_size) {
            return -1;
        }
        offset = (size_t)written;

        if (zt_append_value(out,
                            out_size,
                            &offset,
                            session,
                            sig->ret.type,
                            zt_sig_type_is_fp(sig->ret.type) ? event->fp0 : event->value0) != 0) {
            return -1;
        }

        for (i = 0; i < sig->param_count; ++i) {
            if (sig->params[i].type == ZT_SIG_TYPE_BUF) {
                char preview[192];
                size_t preview_len = zt_buffer_preview_len(sig, entry_event, event, i, 1);

                if (preview_len > 0 &&
                    zt_read_remote_buf_preview(session,
                                               zt_event_arg_value(entry_event, i),
                                               preview_len,
                                               preview,
                                               sizeof(preview)) == 0) {
                    if (zt_append_raw(out, out_size, &offset, " ") != 0 ||
                        zt_append_raw(out, out_size, &offset, preview) != 0) {
                        return -1;
                    }
                }
                break;
            }
        }

        return zt_append_raw(out, out_size, &offset, "\n");
    }

    return -1;
}
