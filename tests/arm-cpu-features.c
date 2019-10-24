/*
 * Arm CPU feature test cases
 *
 * Copyright (c) 2019 Red Hat Inc.
 * Authors:
 *  Andrew Jones <drjones@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */
#include "qemu/osdep.h"
#include "qemu/bitops.h"
#include "libqtest.h"
#include "qapi/qmp/qdict.h"
#include "qapi/qmp/qjson.h"

/*
 * We expect the SVE max-vq to be 16. Also it must be <= 64
 * for our test code, otherwise 'vls' can't just be a uint64_t.
 */
#define SVE_MAX_VQ 16

#define MACHINE    "-machine virt,gic-version=max "
#define QUERY_HEAD "{ 'execute': 'query-cpu-model-expansion', " \
                     "'arguments': { 'type': 'full', "
#define QUERY_TAIL "}}"

static QDict *do_query_no_props(QTestState *qts, const char *cpu_type)
{
    return qtest_qmp(qts, QUERY_HEAD "'model': { 'name': %s }"
                          QUERY_TAIL, cpu_type);
}

static QDict *do_query(QTestState *qts, const char *cpu_type,
                       const char *fmt, ...)
{
    QDict *resp;

    if (fmt) {
        QDict *args;
        va_list ap;

        va_start(ap, fmt);
        args = qdict_from_vjsonf_nofail(fmt, ap);
        va_end(ap);

        resp = qtest_qmp(qts, QUERY_HEAD "'model': { 'name': %s, "
                                                    "'props': %p }"
                              QUERY_TAIL, cpu_type, args);
    } else {
        resp = do_query_no_props(qts, cpu_type);
    }

    return resp;
}

static const char *resp_get_error(QDict *resp)
{
    QDict *qdict;

    g_assert(resp);

    qdict = qdict_get_qdict(resp, "error");
    if (qdict) {
        return qdict_get_str(qdict, "desc");
    }
    return NULL;
}

#define assert_error(qts, cpu_type, expected_error, fmt, ...)          \
({                                                                     \
    QDict *_resp;                                                      \
    const char *_error;                                                \
                                                                       \
    _resp = do_query(qts, cpu_type, fmt, ##__VA_ARGS__);               \
    g_assert(_resp);                                                   \
    _error = resp_get_error(_resp);                                    \
    g_assert(_error);                                                  \
    g_assert(g_str_equal(_error, expected_error));                     \
    qobject_unref(_resp);                                              \
})

static bool resp_has_props(QDict *resp)
{
    QDict *qdict;

    g_assert(resp);

    if (!qdict_haskey(resp, "return")) {
        return false;
    }
    qdict = qdict_get_qdict(resp, "return");

    if (!qdict_haskey(qdict, "model")) {
        return false;
    }
    qdict = qdict_get_qdict(qdict, "model");

    return qdict_haskey(qdict, "props");
}

static QDict *resp_get_props(QDict *resp)
{
    QDict *qdict;

    g_assert(resp);
    g_assert(resp_has_props(resp));

    qdict = qdict_get_qdict(resp, "return");
    qdict = qdict_get_qdict(qdict, "model");
    qdict = qdict_get_qdict(qdict, "props");
    return qdict;
}

#define assert_has_feature(qts, cpu_type, feature)                     \
({                                                                     \
    QDict *_resp = do_query_no_props(qts, cpu_type);                   \
    g_assert(_resp);                                                   \
    g_assert(resp_has_props(_resp));                                   \
    g_assert(qdict_get(resp_get_props(_resp), feature));               \
    qobject_unref(_resp);                                              \
})

#define assert_has_not_feature(qts, cpu_type, feature)                 \
({                                                                     \
    QDict *_resp = do_query_no_props(qts, cpu_type);                   \
    g_assert(_resp);                                                   \
    g_assert(!resp_has_props(_resp) ||                                 \
             !qdict_get(resp_get_props(_resp), feature));              \
    qobject_unref(_resp);                                              \
})

static void assert_type_full(QTestState *qts)
{
    const char *error;
    QDict *resp;

    resp = qtest_qmp(qts, "{ 'execute': 'query-cpu-model-expansion', "
                            "'arguments': { 'type': 'static', "
                                           "'model': { 'name': 'foo' }}}");
    g_assert(resp);
    error = resp_get_error(resp);
    g_assert(error);
    g_assert(g_str_equal(error,
                         "The requested expansion type is not supported"));
    qobject_unref(resp);
}

static void assert_bad_props(QTestState *qts, const char *cpu_type)
{
    const char *error;
    QDict *resp;

    resp = qtest_qmp(qts, "{ 'execute': 'query-cpu-model-expansion', "
                            "'arguments': { 'type': 'full', "
                                           "'model': { 'name': %s, "
                                                      "'props': false }}}",
                     cpu_type);
    g_assert(resp);
    error = resp_get_error(resp);
    g_assert(error);
    g_assert(g_str_equal(error,
                         "Invalid parameter type for 'props', expected: dict"));
    qobject_unref(resp);
}

static uint64_t resp_get_sve_vls(QDict *resp)
{
    QDict *props;
    const QDictEntry *e;
    uint64_t vls = 0;
    int n = 0;

    g_assert(resp);
    g_assert(resp_has_props(resp));

    props = resp_get_props(resp);

    for (e = qdict_first(props); e; e = qdict_next(props, e)) {
        if (strlen(e->key) > 3 && !strncmp(e->key, "sve", 3) &&
            g_ascii_isdigit(e->key[3])) {
            char *endptr;
            int bits;

            bits = g_ascii_strtoll(&e->key[3], &endptr, 10);
            if (!bits || *endptr != '\0') {
                continue;
            }

            if (qdict_get_bool(props, e->key)) {
                vls |= BIT_ULL((bits / 128) - 1);
            }
            ++n;
        }
    }

    g_assert(n == SVE_MAX_VQ);

    return vls;
}

#define assert_sve_vls(qts, cpu_type, expected_vls, fmt, ...)          \
({                                                                     \
    QDict *_resp = do_query(qts, cpu_type, fmt, ##__VA_ARGS__);        \
    g_assert(_resp);                                                   \
    g_assert(resp_has_props(_resp));                                   \
    g_assert(resp_get_sve_vls(_resp) == expected_vls);                 \
    qobject_unref(_resp);                                              \
})

static void sve_tests_default(QTestState *qts, const char *cpu_type)
{
    /*
     * With no sve-max-vq or sve<N> properties on the command line
     * the default is to have all vector lengths enabled. This also
     * tests that 'sve' is 'on' by default.
     */
    assert_sve_vls(qts, cpu_type, BIT_ULL(SVE_MAX_VQ) - 1, NULL);

    /* With SVE off, all vector lengths should also be off. */
    assert_sve_vls(qts, cpu_type, 0, "{ 'sve': false }");

    /* With SVE on, we must have at least one vector length enabled. */
    assert_error(qts, cpu_type, "cannot disable sve128", "{ 'sve128': false }");

    /* Basic enable/disable tests. */
    assert_sve_vls(qts, cpu_type, 0x7, "{ 'sve384': true }");
    assert_sve_vls(qts, cpu_type, ((BIT_ULL(SVE_MAX_VQ) - 1) & ~BIT_ULL(2)),
                   "{ 'sve384': false }");

    /*
     * ---------------------------------------------------------------------
     *               power-of-two(vq)   all-power-            can      can
     *                                  of-two(< vq)        enable   disable
     * ---------------------------------------------------------------------
     * vq < max_vq      no                MUST*              yes      yes
     * vq < max_vq      yes               MUST*              yes      no
     * ---------------------------------------------------------------------
     * vq == max_vq     n/a               MUST*              yes**    yes**
     * ---------------------------------------------------------------------
     * vq > max_vq      n/a               no                 no       yes
     * vq > max_vq      n/a               yes                yes      yes
     * ---------------------------------------------------------------------
     *
     * [*] "MUST" means this requirement must already be satisfied,
     *     otherwise 'max_vq' couldn't itself be enabled.
     *
     * [**] Not testable with the QMP interface, only with the command line.
     */

    /* max_vq := 8 */
    assert_sve_vls(qts, cpu_type, 0x8b, "{ 'sve1024': true }");

    /* max_vq := 8, vq < max_vq, !power-of-two(vq) */
    assert_sve_vls(qts, cpu_type, 0x8f,
                   "{ 'sve1024': true, 'sve384': true }");
    assert_sve_vls(qts, cpu_type, 0x8b,
                   "{ 'sve1024': true, 'sve384': false }");

    /* max_vq := 8, vq < max_vq, power-of-two(vq) */
    assert_sve_vls(qts, cpu_type, 0x8b,
                   "{ 'sve1024': true, 'sve256': true }");
    assert_error(qts, cpu_type, "cannot disable sve256",
                 "{ 'sve1024': true, 'sve256': false }");

    /* max_vq := 3, vq > max_vq, !all-power-of-two(< vq) */
    assert_error(qts, cpu_type, "cannot disable sve512",
                 "{ 'sve384': true, 'sve512': false, 'sve640': true }");

    /*
     * We can disable power-of-two vector lengths when all larger lengths
     * are also disabled. We only need to disable the power-of-two length,
     * as all non-enabled larger lengths will then be auto-disabled.
     */
    assert_sve_vls(qts, cpu_type, 0x7, "{ 'sve512': false }");

    /* max_vq := 3, vq > max_vq, all-power-of-two(< vq) */
    assert_sve_vls(qts, cpu_type, 0x1f,
                   "{ 'sve384': true, 'sve512': true, 'sve640': true }");
    assert_sve_vls(qts, cpu_type, 0xf,
                   "{ 'sve384': true, 'sve512': true, 'sve640': false }");
}

static void sve_tests_sve_max_vq_8(const void *data)
{
    QTestState *qts;

    qts = qtest_init(MACHINE "-cpu max,sve-max-vq=8");

    assert_sve_vls(qts, "max", BIT_ULL(8) - 1, NULL);

    /*
     * Disabling the max-vq set by sve-max-vq is not allowed, but
     * of course enabling it is OK.
     */
    assert_error(qts, "max", "cannot disable sve1024", "{ 'sve1024': false }");
    assert_sve_vls(qts, "max", 0xff, "{ 'sve1024': true }");

    /*
     * Enabling anything larger than max-vq set by sve-max-vq is not
     * allowed, but of course disabling everything larger is OK.
     */
    assert_error(qts, "max", "cannot enable sve1152", "{ 'sve1152': true }");
    assert_sve_vls(qts, "max", 0xff, "{ 'sve1152': false }");

    /*
     * We can enable/disable non power-of-two lengths smaller than the
     * max-vq set by sve-max-vq, but, while we can enable power-of-two
     * lengths, we can't disable them.
     */
    assert_sve_vls(qts, "max", 0xff, "{ 'sve384': true }");
    assert_sve_vls(qts, "max", 0xfb, "{ 'sve384': false }");
    assert_sve_vls(qts, "max", 0xff, "{ 'sve256': true }");
    assert_error(qts, "max", "cannot disable sve256", "{ 'sve256': false }");

    qtest_quit(qts);
}

static void sve_tests_sve_off(const void *data)
{
    QTestState *qts;

    qts = qtest_init(MACHINE "-cpu max,sve=off");

    /* SVE is off, so the map should be empty. */
    assert_sve_vls(qts, "max", 0, NULL);

    /* The map stays empty even if we turn lengths off. */
    assert_sve_vls(qts, "max", 0, "{ 'sve128': false }");

    /* It's an error to enable lengths when SVE is off. */
    assert_error(qts, "max", "cannot enable sve128", "{ 'sve128': true }");

    /* With SVE re-enabled we should get all vector lengths enabled. */
    assert_sve_vls(qts, "max", BIT_ULL(SVE_MAX_VQ) - 1, "{ 'sve': true }");

    /* Or enable SVE with just specific vector lengths. */
    assert_sve_vls(qts, "max", 0x3,
                   "{ 'sve': true, 'sve128': true, 'sve256': true }");

    qtest_quit(qts);
}

static void test_query_cpu_model_expansion(const void *data)
{
    QTestState *qts;

    qts = qtest_init(MACHINE "-cpu max");

    /* Test common query-cpu-model-expansion input validation */
    assert_type_full(qts);
    assert_bad_props(qts, "max");
    assert_error(qts, "foo", "The CPU type 'foo' is not a recognized "
                 "ARM CPU type", NULL);
    assert_error(qts, "max", "Parameter 'not-a-prop' is unexpected",
                 "{ 'not-a-prop': false }");
    assert_error(qts, "host", "The CPU type 'host' requires KVM", NULL);

    /* Test expected feature presence/absence for some cpu types */
    assert_has_feature(qts, "max", "pmu");
    assert_has_feature(qts, "cortex-a15", "pmu");
    assert_has_not_feature(qts, "cortex-a15", "aarch64");

    if (g_str_equal(qtest_get_arch(), "aarch64")) {
        assert_has_feature(qts, "max", "aarch64");
        assert_has_feature(qts, "max", "sve");
        assert_has_feature(qts, "max", "sve128");
        assert_has_feature(qts, "cortex-a57", "pmu");
        assert_has_feature(qts, "cortex-a57", "aarch64");

        sve_tests_default(qts, "max");

        /* Test that features that depend on KVM generate errors without. */
        assert_error(qts, "max",
                     "'aarch64' feature cannot be disabled "
                     "unless KVM is enabled and 32-bit EL1 "
                     "is supported",
                     "{ 'aarch64': false }");
    }

    qtest_quit(qts);
}

static void test_query_cpu_model_expansion_kvm(const void *data)
{
    QTestState *qts;

    qts = qtest_init(MACHINE "-accel kvm -cpu host");

    if (g_str_equal(qtest_get_arch(), "aarch64")) {
        assert_has_feature(qts, "host", "aarch64");
        assert_has_feature(qts, "host", "pmu");

        assert_has_feature(qts, "max", "sve");

        assert_error(qts, "cortex-a15",
            "We cannot guarantee the CPU type 'cortex-a15' works "
            "with KVM on this host", NULL);
    } else {
        assert_has_not_feature(qts, "host", "aarch64");
        assert_has_not_feature(qts, "host", "pmu");

        assert_has_not_feature(qts, "max", "sve");
    }

    qtest_quit(qts);
}

int main(int argc, char **argv)
{
    bool kvm_available = false;

    if (!access("/dev/kvm",  R_OK | W_OK)) {
#if defined(HOST_AARCH64)
        kvm_available = g_str_equal(qtest_get_arch(), "aarch64");
#elif defined(HOST_ARM)
        kvm_available = g_str_equal(qtest_get_arch(), "arm");
#endif
    }

    g_test_init(&argc, &argv, NULL);

    qtest_add_data_func("/arm/query-cpu-model-expansion",
                        NULL, test_query_cpu_model_expansion);

    if (g_str_equal(qtest_get_arch(), "aarch64")) {
        qtest_add_data_func("/arm/max/query-cpu-model-expansion/sve-max-vq-8",
                            NULL, sve_tests_sve_max_vq_8);
        qtest_add_data_func("/arm/max/query-cpu-model-expansion/sve-off",
                            NULL, sve_tests_sve_off);
    }

    if (kvm_available) {
        qtest_add_data_func("/arm/kvm/query-cpu-model-expansion",
                            NULL, test_query_cpu_model_expansion_kvm);
    }

    return g_test_run();
}
