#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zt_filter.h"

typedef struct {
    const zt_probe_filter_t *filter;
    const zt_trace_event_t *event;
    size_t pos;
    int ok;
    int eval_enabled;
} zt_filter_eval_t;

typedef uint64_t (*zt_filter_parse_fn_t)(zt_filter_eval_t *ctx);

typedef struct {
    const char *text;
    zt_probe_filter_token_type_t type;
} zt_filter_op_rule_t;

static const zt_filter_op_rule_t k_two_char_ops[] = {
    {"==", ZT_PROBE_FILTER_TOK_EQ},
    {"!=", ZT_PROBE_FILTER_TOK_NE},
    {">=", ZT_PROBE_FILTER_TOK_GE},
    {"<=", ZT_PROBE_FILTER_TOK_LE},
    {"&&", ZT_PROBE_FILTER_TOK_AND},
    {"||", ZT_PROBE_FILTER_TOK_OR},
};

static const zt_filter_op_rule_t k_one_char_ops[] = {
    {">", ZT_PROBE_FILTER_TOK_GT},
    {"<", ZT_PROBE_FILTER_TOK_LT},
    {"!", ZT_PROBE_FILTER_TOK_NOT},
    {"+", ZT_PROBE_FILTER_TOK_ADD},
    {"-", ZT_PROBE_FILTER_TOK_SUB},
    {"*", ZT_PROBE_FILTER_TOK_MUL},
    {"/", ZT_PROBE_FILTER_TOK_DIV},
    {"(", ZT_PROBE_FILTER_TOK_LPAREN},
    {")", ZT_PROBE_FILTER_TOK_RPAREN},
};

#define ZT_ARRAY_LEN(x) (sizeof(x) / sizeof((x)[0]))

static uint64_t zt_filter_event_arg(const zt_trace_event_t *event, uint64_t arg_index) {
    if (event == NULL || arg_index >= ZT_TRACE_GP_ARG_COUNT) {
        return 0;
    }

    return event->args[arg_index];
}

static zt_filter_eval_t zt_filter_eval_init(const zt_probe_filter_t *filter,
                                            const zt_trace_event_t *event) {
    zt_filter_eval_t ctx = {
        .filter = filter,
        .event = event,
        .pos = 0,
        .ok = 1,
        .eval_enabled = event != NULL,
    };

    return ctx;
}

static int zt_filter_set_eval_enabled(zt_filter_eval_t *ctx, int enabled) {
    int previous;

    if (ctx == NULL) {
        return 0;
    }

    previous = ctx->eval_enabled;
    ctx->eval_enabled = enabled;
    return previous;
}

static const zt_probe_filter_token_t *zt_filter_peek(zt_filter_eval_t *ctx) {
    if (ctx->pos >= ctx->filter->token_count) {
        return NULL;
    }

    return &ctx->filter->tokens[ctx->pos];
}

static int zt_filter_take(zt_filter_eval_t *ctx, uint8_t type) {
    const zt_probe_filter_token_t *token = zt_filter_peek(ctx);

    if (token == NULL || token->type != type) {
        return 0;
    }

    ++ctx->pos;
    return 1;
}

static uint64_t zt_filter_parse_or(zt_filter_eval_t *ctx);

static uint64_t zt_filter_parse_primary(zt_filter_eval_t *ctx) {
    const zt_probe_filter_token_t *token = zt_filter_peek(ctx);
    uint64_t value;

    if (token == NULL) {
        ctx->ok = 0;
        return 0;
    }

    if (zt_filter_take(ctx, ZT_PROBE_FILTER_TOK_NUM)) {
        return token->value;
    }

    if (zt_filter_take(ctx, ZT_PROBE_FILTER_TOK_ARG)) {
        if (!ctx->eval_enabled || ctx->event == NULL) {
            return 0;
        }
        return zt_filter_event_arg(ctx->event, token->arg_index);
    }

    if (zt_filter_take(ctx, ZT_PROBE_FILTER_TOK_LPAREN)) {
        value = zt_filter_parse_or(ctx);
        if (!zt_filter_take(ctx, ZT_PROBE_FILTER_TOK_RPAREN)) {
            ctx->ok = 0;
        }
        return value;
    }

    ctx->ok = 0;
    return 0;
}

static uint64_t zt_filter_parse_unary(zt_filter_eval_t *ctx) {
    if (zt_filter_take(ctx, ZT_PROBE_FILTER_TOK_NOT)) {
        return !zt_filter_parse_unary(ctx);
    }

    return zt_filter_parse_primary(ctx);
}

static uint64_t zt_filter_parse_mul(zt_filter_eval_t *ctx) {
    uint64_t lhs = zt_filter_parse_unary(ctx);

    while (ctx->ok) {
        if (zt_filter_take(ctx, ZT_PROBE_FILTER_TOK_MUL)) {
            lhs *= zt_filter_parse_unary(ctx);
        } else if (zt_filter_take(ctx, ZT_PROBE_FILTER_TOK_DIV)) {
            uint64_t rhs = zt_filter_parse_unary(ctx);
            if (!ctx->eval_enabled) {
                lhs = 0;
            } else if (rhs == 0) {
                ctx->ok = 0;
                return 0;
            } else {
                lhs /= rhs;
            }
        } else {
            break;
        }
    }

    return lhs;
}

static uint64_t zt_filter_parse_add(zt_filter_eval_t *ctx) {
    uint64_t lhs = zt_filter_parse_mul(ctx);

    while (ctx->ok) {
        if (zt_filter_take(ctx, ZT_PROBE_FILTER_TOK_ADD)) {
            lhs += zt_filter_parse_mul(ctx);
        } else if (zt_filter_take(ctx, ZT_PROBE_FILTER_TOK_SUB)) {
            lhs -= zt_filter_parse_mul(ctx);
        } else {
            break;
        }
    }

    return lhs;
}

static int zt_filter_token_is_cmp(uint8_t type) {
    switch (type) {
        case ZT_PROBE_FILTER_TOK_EQ:
        case ZT_PROBE_FILTER_TOK_NE:
        case ZT_PROBE_FILTER_TOK_GT:
        case ZT_PROBE_FILTER_TOK_GE:
        case ZT_PROBE_FILTER_TOK_LT:
        case ZT_PROBE_FILTER_TOK_LE:
            return 1;
        default:
            return 0;
    }
}

static int zt_filter_take_cmp(zt_filter_eval_t *ctx, uint8_t *type_out) {
    const zt_probe_filter_token_t *token = zt_filter_peek(ctx);

    if (token == NULL || type_out == NULL || !zt_filter_token_is_cmp(token->type)) {
        return 0;
    }

    *type_out = token->type;
    ++ctx->pos;
    return 1;
}

static uint64_t zt_filter_apply_cmp(uint8_t type, uint64_t lhs, uint64_t rhs) {
    switch (type) {
        case ZT_PROBE_FILTER_TOK_EQ: return lhs == rhs;
        case ZT_PROBE_FILTER_TOK_NE: return lhs != rhs;
        case ZT_PROBE_FILTER_TOK_GT: return lhs > rhs;
        case ZT_PROBE_FILTER_TOK_GE: return lhs >= rhs;
        case ZT_PROBE_FILTER_TOK_LT: return lhs < rhs;
        case ZT_PROBE_FILTER_TOK_LE: return lhs <= rhs;
        default: return 0;
    }
}

static uint64_t zt_filter_parse_cmp(zt_filter_eval_t *ctx) {
    uint64_t lhs = zt_filter_parse_add(ctx);

    while (ctx->ok) {
        uint8_t type = 0;

        if (!zt_filter_take_cmp(ctx, &type)) {
            break;
        }

        lhs = zt_filter_apply_cmp(type, lhs, zt_filter_parse_add(ctx));
    }

    return lhs;
}

static uint64_t zt_filter_parse_with_eval(zt_filter_eval_t *ctx,
                                          int eval_enabled,
                                          zt_filter_parse_fn_t parse) {
    int previous_eval;
    uint64_t value;

    previous_eval = zt_filter_set_eval_enabled(ctx, eval_enabled);
    value = parse(ctx);
    zt_filter_set_eval_enabled(ctx, previous_eval);
    return value;
}

static uint64_t zt_filter_parse_maybe_skipped(zt_filter_eval_t *ctx,
                                              int skip_eval,
                                              zt_filter_parse_fn_t parse) {
    return skip_eval
        ? zt_filter_parse_with_eval(ctx, 0, parse)
        : parse(ctx);
}

static uint64_t zt_filter_parse_and(zt_filter_eval_t *ctx) {
    uint64_t lhs = zt_filter_parse_cmp(ctx);

    while (ctx->ok && zt_filter_take(ctx, ZT_PROBE_FILTER_TOK_AND)) {
        uint64_t rhs = zt_filter_parse_maybe_skipped(ctx,
                                                     ctx->eval_enabled && !lhs,
                                                     zt_filter_parse_cmp);

        lhs = lhs && rhs;
    }

    return lhs;
}

static uint64_t zt_filter_parse_or(zt_filter_eval_t *ctx) {
    uint64_t lhs = zt_filter_parse_and(ctx);

    while (ctx->ok && zt_filter_take(ctx, ZT_PROBE_FILTER_TOK_OR)) {
        uint64_t rhs = zt_filter_parse_maybe_skipped(ctx,
                                                     ctx->eval_enabled && lhs,
                                                     zt_filter_parse_and);

        lhs = lhs || rhs;
    }

    return lhs;
}

static int zt_filter_validate(const zt_probe_filter_t *filter) {
    zt_filter_eval_t ctx;

    if (filter == NULL || !filter->enabled || filter->token_count == 0) {
        return -1;
    }

    ctx = zt_filter_eval_init(filter, NULL);
    (void)zt_filter_parse_or(&ctx);
    return ctx.ok && ctx.pos == filter->token_count ? 0 : -1;
}

static int zt_filter_append_token(zt_probe_filter_t *filter,
                                  zt_probe_filter_token_type_t type,
                                  uint64_t value,
                                  uint8_t arg_index) {
    zt_probe_filter_token_t token = {
        .type = (uint8_t)type,
        .value = value,
        .arg_index = arg_index,
    };

    if (filter->token_count >= ZT_PROBE_FILTER_TOKEN_CAP) {
        return -1;
    }

    filter->tokens[filter->token_count++] = token;
    return 0;
}

static int zt_filter_append_operator(zt_probe_filter_t *filter,
                                     const char **cursor,
                                     const zt_filter_op_rule_t *rules,
                                     size_t rule_count) {
    size_t i;

    for (i = 0; i < rule_count; ++i) {
        size_t len = strlen(rules[i].text);

        if (strncmp(*cursor, rules[i].text, len) != 0) {
            continue;
        }

        if (zt_filter_append_token(filter, rules[i].type, 0, 0) != 0) {
            return -1;
        }

        *cursor += len;
        return 1;
    }

    return 0;
}

static int zt_filter_append_arg(zt_probe_filter_t *filter, const char **cursor) {
    char *endptr;
    unsigned long index;

    if (strncmp(*cursor, "arg", 3) != 0 || !isdigit((unsigned char)(*cursor)[3])) {
        return 0;
    }

    index = strtoul(*cursor + 3, &endptr, 10);
    if (*cursor + 3 == endptr || index >= ZT_TRACE_GP_ARG_COUNT) {
        return -1;
    }

    if (zt_filter_append_token(filter,
                               ZT_PROBE_FILTER_TOK_ARG,
                               0,
                               (uint8_t)index) != 0) {
        return -1;
    }

    *cursor = endptr;
    return 1;
}

static int zt_filter_append_number(zt_probe_filter_t *filter, const char **cursor) {
    char *endptr;
    unsigned long long value;

    if (!isdigit((unsigned char)**cursor)) {
        return 0;
    }

    errno = 0;
    value = strtoull(*cursor, &endptr, 0);
    if (*cursor == endptr || errno != 0) {
        return -1;
    }

    if (zt_filter_append_token(filter,
                               ZT_PROBE_FILTER_TOK_NUM,
                               value,
                               0) != 0) {
        return -1;
    }

    *cursor = endptr;
    return 1;
}

static int zt_filter_append_next_token(zt_probe_filter_t *filter, const char **cursor) {
    int rc;

    while (isspace((unsigned char)**cursor)) {
        ++*cursor;
    }

    if (**cursor == '\0') {
        return 0;
    }

    rc = zt_filter_append_arg(filter, cursor);
    if (rc != 0) {
        return rc;
    }

    rc = zt_filter_append_number(filter, cursor);
    if (rc != 0) {
        return rc;
    }

    rc = zt_filter_append_operator(filter,
                                   cursor,
                                   k_two_char_ops,
                                   ZT_ARRAY_LEN(k_two_char_ops));
    if (rc != 0) {
        return rc;
    }

    return zt_filter_append_operator(filter,
                                     cursor,
                                     k_one_char_ops,
                                     ZT_ARRAY_LEN(k_one_char_ops));
}

int zt_probe_filter_compile(const char *expr, zt_probe_filter_t *filter) {
    const char *p;

    if (expr == NULL || filter == NULL) {
        return -1;
    }

    memset(filter, 0, sizeof(*filter));
    p = expr;
    while (isspace((unsigned char)*p)) {
        ++p;
    }

    if (*p == '\0' || strlen(p) >= sizeof(filter->expr)) {
        return -1;
    }

    snprintf(filter->expr, sizeof(filter->expr), "%s", p);
    filter->enabled = 1;

    while (*p != '\0') {
        int rc = zt_filter_append_next_token(filter, &p);

        if (rc <= 0) {
            return -1;
        }
    }

    return zt_filter_validate(filter);
}

int zt_probe_filter_eval(const zt_probe_filter_t *filter, const zt_trace_event_t *event) {
    zt_filter_eval_t ctx;
    uint64_t result;

    if (filter == NULL || !filter->enabled) {
        return 1;
    }

    ctx = zt_filter_eval_init(filter, event);
    result = zt_filter_parse_or(&ctx);
    if (!ctx.ok || ctx.pos != filter->token_count) {
        return 0;
    }

    return result != 0;
}
