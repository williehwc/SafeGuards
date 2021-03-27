#include <stdio.h>
#include <stdlib.h>
#include <z3.h>

// Source: https://github.com/Z3Prover/z3/blob/master/examples/c/test_capi.c

// Helper functions:

Z3_solver mk_solver(Z3_context ctx) {
  Z3_solver s = Z3_mk_solver(ctx);
  Z3_solver_inc_ref(ctx, s);
  return s;
}

void del_solver(Z3_context ctx, Z3_solver s) {
  Z3_solver_dec_ref(ctx, s);
}

Z3_ast mk_var(Z3_context ctx, const char * name, Z3_sort ty) {
    Z3_symbol   s  = Z3_mk_string_symbol(ctx, name);
    return Z3_mk_const(ctx, s, ty);
}

Z3_ast mk_bool_var(Z3_context ctx, const char * name) {
    Z3_sort ty = Z3_mk_bool_sort(ctx);
    return mk_var(ctx, name, ty);
}

Z3_ast mk_int_var(Z3_context ctx, const char * name) {
    Z3_sort ty = Z3_mk_int_sort(ctx);
    return mk_var(ctx, name, ty);
}

Z3_ast mk_int(Z3_context ctx, int v) {
    Z3_sort ty = Z3_mk_int_sort(ctx);
    return Z3_mk_int(ctx, v, ty);
}

void error_handler(Z3_context c, Z3_error_code e) {
    printf("Error code: %d\n", e);
    exit(1);
}

Z3_context mk_context_custom(Z3_config cfg, Z3_error_handler err) {
    Z3_context ctx;

    Z3_set_param_value(cfg, "model", "true");
    ctx = Z3_mk_context(cfg);
    Z3_set_error_handler(ctx, err);

    return ctx;
}

Z3_context mk_context() {
    Z3_config  cfg;
    Z3_context ctx;
    cfg = Z3_mk_config();
    ctx = mk_context_custom(cfg, error_handler);
    Z3_del_config(cfg);
    return ctx;
}

void check(Z3_context ctx, Z3_solver s, Z3_lbool expected_result) {
    Z3_model m      = 0;
    Z3_lbool result = Z3_solver_check(ctx, s);
    switch (result) {
    case Z3_L_FALSE:
        printf("unsat\n");
        break;
    case Z3_L_UNDEF:
        printf("unknown\n");
        m = Z3_solver_get_model(ctx, s);
        if (m) Z3_model_inc_ref(ctx, m);
        printf("potential model:\n%s\n", Z3_model_to_string(ctx, m));
        break;
    case Z3_L_TRUE:
        m = Z3_solver_get_model(ctx, s);
        if (m) Z3_model_inc_ref(ctx, m);
        printf("sat\n%s\n", Z3_model_to_string(ctx, m));
        break;
    }
    if (result != expected_result) {
        printf("unexpected result");
        exit(1);
    }
    if (m) Z3_model_dec_ref(ctx, m);
}

// Examples:

void display_version() {
    unsigned major, minor, build, revision;
    Z3_get_version(&major, &minor, &build, &revision);
    printf("Z3 %d.%d.%d.%d\n", major, minor, build, revision);
}

void find_model_example1() {
    Z3_context ctx;
    Z3_ast x, y, x_xor_y;
    Z3_solver s;

    printf("\nfind_model_example1\n");
    Z3_append_log("find_model_example1");

    ctx     = mk_context();
    s       = mk_solver(ctx);

    x       = mk_bool_var(ctx, "x");
    y       = mk_bool_var(ctx, "y");
    x_xor_y = Z3_mk_xor(ctx, x, y);

    Z3_solver_assert(ctx, s, x_xor_y);

    printf("model for: x xor y\n");
    check(ctx, s, Z3_L_TRUE);

    del_solver(ctx, s);
    Z3_del_context(ctx);
}

void find_model_example2() {
    Z3_context ctx;
    Z3_ast x, y, one, two, y_plus_one;
    Z3_ast x_eq_y;
    Z3_ast args[2];
    Z3_ast c1, c2, c3;
    Z3_solver s;

    printf("\nfind_model_example2\n");
    Z3_append_log("find_model_example2");

    ctx        = mk_context();
    s          = mk_solver(ctx);
    x          = mk_int_var(ctx, "x");
    y          = mk_int_var(ctx, "y");
    one        = mk_int(ctx, 1);
    two        = mk_int(ctx, 2);

    args[0]    = y;
    args[1]    = one;
    y_plus_one = Z3_mk_add(ctx, 2, args);

    c1         = Z3_mk_lt(ctx, x, y_plus_one);
    c2         = Z3_mk_gt(ctx, x, two);

    Z3_solver_assert(ctx, s, c1);
    Z3_solver_assert(ctx, s, c2);

    printf("model for: x < y + 1, x > 2\n");
    check(ctx, s, Z3_L_TRUE);

    /* assert not(x = y) */
    x_eq_y     = Z3_mk_eq(ctx, x, y);
    c3         = Z3_mk_not(ctx, x_eq_y);
    Z3_solver_assert(ctx, s,c3);

    printf("model for: x < y + 1, x > 2, not(x = y)\n");
    check(ctx, s, Z3_L_TRUE);

    del_solver(ctx, s);
    Z3_del_context(ctx);
}

int main() {
    // Log Z3 calls
    Z3_open_log("z3.log");
    // Go over some examples
    display_version();
    find_model_example1();
    find_model_example2();
}