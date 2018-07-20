/* Avoid logging anything */
#define _DEBUG_H
#define DBG(...)

/* Including this directly allows us to poke into the implementation. */
#include "handler.c"

#include <glib.h>
#include <assert.h>

char *save_name = "test.dat";

/* The communication buffer. */
static uint8_t buf[16 * 4096];

/* Wide char support */

typedef struct {
    uint16_t *data;
    size_t length;
} dstring;

static char nullguid[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

/* Sample data */
static dstring *tname1;

static char tguid1[] = {1, 0, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
static uint8_t tdata1[] = {1, 0, 5, 6, 7};

static dstring *tname2;
static char tguid2[] = {1, 0, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
static uint8_t tdata2[] = {0, 8, 6, 9, 0, 4, 5};

static dstring *tname3;
static char tguid3[] = {6, 4, 5, 7, 3, 8, 9, 1, 3, 2, 3, 4, 5, 6, 7, 8};
static uint8_t tdata3[] = {9};

static dstring *tname4;
static char tguid4[] = {7, 4, 3, 2, 1, 7, 9, 10, 15, 2, 5, 6, 14, 15, 10, 1};
static uint8_t tdata4[] = {10, 255, 0, 6, 7, 8, 120, 244};

static dstring *tname5;
static char tguid5[] = {1, 3, 5, 7, 9, 8, 6, 4, 2, 10, 11, 12, 13, 14, 15, 0};
static uint8_t tdata5[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};

#define BSIZ 1024 /* general buffer size */

/* 
 * dstring handling functions
 */

static size_t dstring_data_size(const dstring *name)
{
    return name->length * sizeof(uint16_t);
}

static dstring *alloc_dstring_unset(size_t length)
{
    dstring *dstr = malloc(sizeof(dstring));
    assert(dstr);
    dstr->length = length;
    dstr->data = malloc(length * sizeof(uint16_t));
    assert(dstr->data);
    return dstr;
}

static dstring *alloc_dstring(const char *string)
{
    size_t i;
    size_t len = strlen(string);
    dstring *dstr = alloc_dstring_unset(len);

    for (i = 0; i < len; i++)
        dstr->data[i] = string[i];

    return dstr;
}

static void free_dstring(dstring *d)
{
    if (d)
        free(d->data);
    free(d);
}

/*
 * Helper functions
 */

static void setup_globals(void)
{
    tname1 = alloc_dstring("foo");
    tname2 = alloc_dstring("foobar");
    tname3 = alloc_dstring("foobar");
    tname4 = alloc_dstring("baz");
    tname5 = alloc_dstring("xyzabcdefgh");
}

static void reset_vars(void)
{
    struct efi_variable *l, *tmp;

    l = var_list;
    while (l) {
        tmp = l;
        l = tmp->next;
        free(tmp->name);
        free(tmp->data);
        free(tmp);
    }
    var_list = NULL;
}

static void call_get_variable(const dstring *name, const char *guid,
                              UINTN avail, BOOLEAN at_runtime)
{
    uint8_t *ptr = buf;
    serialize_uint32(&ptr, 1);
    serialize_uint32(&ptr, (UINT32)COMMAND_GET_VARIABLE);
    serialize_data(&ptr, (uint8_t *)name->data, dstring_data_size(name));
    serialize_guid(&ptr, guid);
    serialize_uintn(&ptr, avail);
    *ptr++ = at_runtime;

    dispatch_command(buf);
}

static void call_query_variable_info(void)
{
    uint8_t *ptr = buf;
    serialize_uint32(&ptr, 1);
    serialize_uint32(&ptr, (UINT32)COMMAND_QUERY_VARIABLE_INFO);
    serialize_uint32(&ptr, 0);

    dispatch_command(buf);
}

static void call_get_next_variable(UINTN avail, const dstring *name,
                                   const char *guid, BOOLEAN at_runtime)
{
    uint8_t *ptr = buf;
    size_t len = name ? dstring_data_size(name) : 0;
    const uint8_t *data = (uint8_t *)(name ? name->data : NULL);

    serialize_uint32(&ptr, 1);
    serialize_uint32(&ptr, (UINT32)COMMAND_GET_NEXT_VARIABLE);
    serialize_uintn(&ptr, avail);
    serialize_data(&ptr, data, len);
    serialize_guid(&ptr, guid);
    *ptr++ = at_runtime;

    dispatch_command(buf);
}

static void call_set_variable(const dstring *name, const char *guid,
                              const uint8_t *data, UINTN data_len,
                              UINT32 attr, BOOLEAN at_runtime)
{
    uint8_t *ptr = buf;
    size_t name_size = dstring_data_size(name);

    serialize_uint32(&ptr, 1);
    serialize_uint32(&ptr, (UINT32)COMMAND_SET_VARIABLE);
    serialize_data(&ptr, (uint8_t *)name->data, name_size);
    serialize_guid(&ptr, guid);
    serialize_data(&ptr, data, data_len);
    serialize_uint32(&ptr, attr);
    *ptr++ = at_runtime;

    dispatch_command(buf);
}

/* Call SetVariable (before calling ExitBootServices) and assert success */
static void sv_ok(const dstring *name, const char *guid, const uint8_t *data,
                  UINTN len, UINT32 attr)
{
    uint8_t *ptr;
    EFI_STATUS status;

    call_set_variable(name, guid, data, len, attr, 0);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_SUCCESS);
}

static void test_get_variable_no_name(void)
{
    uint8_t *ptr;
    EFI_STATUS status;
    dstring *empty = alloc_dstring("");

    reset_vars();

    /* An empty name should not be found. */
    call_get_variable(empty, nullguid, BSIZ, 0);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_NOT_FOUND);

    free_dstring(empty);
}

static void test_get_variable_long_name(void)
{
    uint8_t *ptr;
    EFI_STATUS status;
    dstring *bigname;

    reset_vars();
    bigname = alloc_dstring_unset(NAME_LIMIT / sizeof(uint16_t) + 1);
    memset(bigname->data, 42, dstring_data_size(bigname));

    /* Test the maximum variable name length. */
    call_get_variable(bigname, nullguid, BSIZ, 0);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_DEVICE_ERROR);
    free_dstring(bigname);
}

static void test_get_variable_not_found(void)
{
    uint8_t *ptr;
    EFI_STATUS status;

    reset_vars();
    sv_ok(tname1, tguid1, tdata1, sizeof(tdata1), ATTR_B);
    sv_ok(tname2, tguid2, tdata2, sizeof(tdata2), ATTR_B);
    sv_ok(tname3, tguid3, tdata3, sizeof(tdata3), ATTR_B);

    /* Name is correct, guid is wrong */
    call_get_variable(tname2, tguid4, BSIZ, 0);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_NOT_FOUND);

    /* Name is wrong, guid is correct */
    call_get_variable(tname4, tguid2, BSIZ, 0);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_NOT_FOUND);

    /* Boot service only variable cannot be found at runtime */
    call_get_variable(tname2, tguid2, BSIZ, 1);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_NOT_FOUND);
}

static void test_get_variable_found(void)
{
    uint8_t *ptr;
    uint8_t *data;
    UINTN data_len;
    UINT32 attr;
    EFI_STATUS status;

    reset_vars();
    sv_ok(tname1, tguid1, tdata1, sizeof(tdata1), ATTR_B);
    sv_ok(tname2, tguid2, tdata2, sizeof(tdata2), ATTR_BR);
    sv_ok(tname3, tguid3, tdata3, sizeof(tdata3), ATTR_B);

    /* Variable is correctly retrieved. */
    call_get_variable(tname1, tguid1, BSIZ, 0);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_SUCCESS);
    attr = unserialize_uint32(&ptr);
    g_assert_cmpuint(attr, ==, ATTR_B);
    data = unserialize_data(&ptr, &data_len, BSIZ);
    g_assert_cmpuint(data_len, ==, sizeof(tdata1));
    g_assert(!memcmp(tdata1, data, data_len));
    free(data);

    /* Runtime variable can be found at runtime */
    call_get_variable(tname2, tguid2, BSIZ, 1);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_SUCCESS);
    attr = unserialize_uint32(&ptr);
    g_assert_cmpuint(attr, ==, ATTR_BR);
    data = unserialize_data(&ptr, &data_len, BSIZ);
    g_assert_cmpuint(data_len, ==, sizeof(tdata2));
    g_assert(!memcmp(tdata2, data, data_len));
    free(data);

    /* Variable is correctly retrieved. */
    call_get_variable(tname3, tguid3, BSIZ, 0);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_SUCCESS);
    attr = unserialize_uint32(&ptr);
    g_assert_cmpuint(attr, ==, ATTR_B);
    data = unserialize_data(&ptr, &data_len, BSIZ);
    g_assert_cmpuint(data_len, ==, sizeof(tdata3));
    g_assert(!memcmp(tdata3, data, data_len));
    free(data);
}

static void test_get_variable_too_small(void)
{
    uint8_t *ptr;
    UINTN data_len;
    EFI_STATUS status;

    reset_vars();
    sv_ok(tname1, tguid1, tdata1, sizeof(tdata1), ATTR_B);

    /*
     * If the output buffer is too small, check that the correct size is
     * returned.
     */
    call_get_variable(tname1, tguid1, sizeof(tdata1) - 1, 0);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_BUFFER_TOO_SMALL);
    data_len = unserialize_uintn(&ptr);
    g_assert_cmpuint(data_len, ==, sizeof(tdata1));
}

static void test_query_variable_info(void)
{
    uint8_t *ptr;
    EFI_STATUS status;
    dstring *longname;

    reset_vars();

    /*
     * Use a long variable name to ensure the variable is larger than the
     * "overhead" size.
     */

    longname = alloc_dstring_unset(VARIABLE_SIZE_MIN / sizeof(uint16_t));
    memset(longname->data, 'a', dstring_data_size(longname));

    /* Check the defined limits with no variables. */
    call_query_variable_info();
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_SUCCESS);
    g_assert_cmpuint(TOTAL_LIMIT, ==, unserialize_uintn(&ptr));
    g_assert_cmpuint(TOTAL_LIMIT, ==, unserialize_uintn(&ptr));
    g_assert_cmpuint(DATA_LIMIT, ==, unserialize_uintn(&ptr));

    sv_ok(longname, tguid1, tdata1, sizeof(tdata1), ATTR_B);

    /* Inserting a variable updates the limits correctly. */
    call_query_variable_info();
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_SUCCESS);
    g_assert_cmpuint(TOTAL_LIMIT, ==, unserialize_uintn(&ptr));
    g_assert_cmpuint(TOTAL_LIMIT - dstring_data_size(longname) - sizeof(tdata1),
                     ==, unserialize_uintn(&ptr));
    g_assert_cmpuint(DATA_LIMIT, ==, unserialize_uintn(&ptr));

    /* Updating a variable updates the limits correctly. */
    sv_ok(longname, tguid1, tdata2, sizeof(tdata2), ATTR_B);
    call_query_variable_info();
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_SUCCESS);
    g_assert_cmpuint(TOTAL_LIMIT, ==, unserialize_uintn(&ptr));
    g_assert_cmpuint(TOTAL_LIMIT - dstring_data_size(longname) - sizeof(tdata2),
                     ==, unserialize_uintn(&ptr));
    g_assert_cmpuint(DATA_LIMIT, ==, unserialize_uintn(&ptr));

    /* Appending to a variable updates the limits correctly. */
    sv_ok(longname, tguid1, tdata1, sizeof(tdata1),
          ATTR_B|EFI_VARIABLE_APPEND_WRITE);
    call_query_variable_info();
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_SUCCESS);
    g_assert_cmpuint(TOTAL_LIMIT, ==, unserialize_uintn(&ptr));
    g_assert_cmpuint(TOTAL_LIMIT - dstring_data_size(longname) -
                     sizeof(tdata2) - sizeof(tdata1),
                     ==, unserialize_uintn(&ptr));
    g_assert_cmpuint(DATA_LIMIT, ==, unserialize_uintn(&ptr));

    /* Deleting a variable updates the limits correctly. */
    sv_ok(longname, tguid1, NULL, 0, ATTR_B);
    call_query_variable_info();
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_SUCCESS);
    g_assert_cmpuint(TOTAL_LIMIT, ==, unserialize_uintn(&ptr));
    g_assert_cmpuint(TOTAL_LIMIT, ==, unserialize_uintn(&ptr));
    g_assert_cmpuint(DATA_LIMIT, ==, unserialize_uintn(&ptr));
    free_dstring(longname);
}

static void test_get_next_variable_empty(void)
{
    uint8_t *ptr;
    EFI_STATUS status;

    reset_vars();

    /* No variables */
    call_get_next_variable(BSIZ, NULL, nullguid, 0);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_NOT_FOUND);
}

static void test_get_next_variable_long_name(void)
{
    uint8_t *ptr;
    EFI_STATUS status;
    dstring *tmp_name;

    reset_vars();
    tmp_name = alloc_dstring_unset(NAME_LIMIT / sizeof(uint16_t) + 1);
    memset(tmp_name->data, 42, dstring_data_size(tmp_name));

    /* Input name exceeds the limit */
    call_get_next_variable(BSIZ, tmp_name, nullguid, 0);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_DEVICE_ERROR);
    free_dstring(tmp_name);
}

static void test_get_next_variable_only_runtime(void)
{
    uint8_t *ptr, *data;
    UINTN data_len;
    EFI_STATUS status;
    char guid[GUID_LEN];

    /*
     * Insert a mixture of variables.
     * Only runtime variables should be returned at runtime.
     */

    reset_vars();
    sv_ok(tname5, tguid5, tdata5, sizeof(tdata5), ATTR_B);
    sv_ok(tname2, tguid2, tdata2, sizeof(tdata2), ATTR_BR);
    sv_ok(tname1, tguid1, tdata1, sizeof(tdata1), ATTR_B);
    sv_ok(tname4, tguid4, tdata4, sizeof(tdata4), ATTR_BR);
    sv_ok(tname3, tguid3, tdata3, sizeof(tdata3), ATTR_B);

    call_get_next_variable(BSIZ, NULL, nullguid, 1);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_SUCCESS);

    data = unserialize_data(&ptr, &data_len, BSIZ);
    g_assert_cmpuint(data_len, ==, dstring_data_size(tname4));
    g_assert(!memcmp(tname4->data, data, data_len));
    unserialize_guid(&ptr, guid);
    g_assert(!memcmp(guid, tguid4, GUID_LEN));
    free(data);

    call_get_next_variable(BSIZ, tname4, guid, 1);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_SUCCESS);
    data = unserialize_data(&ptr, &data_len, BSIZ);
    g_assert_cmpuint(data_len, ==, dstring_data_size(tname2));
    g_assert(!memcmp(tname2->data, data, data_len));
    unserialize_guid(&ptr, guid);
    g_assert(!memcmp(guid, tguid2, GUID_LEN));
    free(data);

    call_get_next_variable(BSIZ, tname2, guid, 1);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_NOT_FOUND);
}

static void test_get_next_variable_too_small(void)
{
    uint8_t *ptr;
    UINTN data_len;
    EFI_STATUS status;

    reset_vars();
    sv_ok(tname1, tguid1, tdata1, sizeof(tdata1), ATTR_B);

    /*
     * If the output buffer is too small, check that the correct size is
     * returned.
     */
    call_get_next_variable(0, NULL, nullguid, 0);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_BUFFER_TOO_SMALL);
    data_len = unserialize_uintn(&ptr);
    g_assert_cmpuint(data_len, ==, dstring_data_size(tname1) + sizeof(CHAR16));
}

static void test_get_next_variable_no_match(void)
{
    uint8_t *ptr, *data;
    UINTN data_len;
    EFI_STATUS status;
    char guid[GUID_LEN];

    reset_vars();
    sv_ok(tname1, tguid1, tdata1, sizeof(tdata1), ATTR_B);
    sv_ok(tname2, tguid2, tdata2, sizeof(tdata2), ATTR_B);

    /* First variable is retrieved successfully. */
    call_get_next_variable(BSIZ, NULL, nullguid, 0);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_SUCCESS);
    data = unserialize_data(&ptr, &data_len, BSIZ);
    g_assert_cmpuint(data_len, ==, dstring_data_size(tname2));
    g_assert(!memcmp(tname2->data, data, data_len));
    unserialize_guid(&ptr, guid);
    g_assert(!memcmp(guid, tguid2, GUID_LEN));

    /* Check when an incorrect name is passed in. */
    call_get_next_variable(BSIZ, tname4, guid, 0);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_INVALID_PARAMETER);

    /* Check when an incorrect guid is passed in. */
    call_get_next_variable(BSIZ, tname2, tguid4, 0);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_INVALID_PARAMETER);

    free(data);
}

static void test_get_next_variable_all(void)
{
    uint8_t *ptr, *data;
    UINTN data_len;
    EFI_STATUS status;
    char guid[GUID_LEN];

    /*
     * Insert a mixture of variables.
     * At boot time, all variables should be retrieved.
     */

    reset_vars();
    sv_ok(tname5, tguid5, tdata5, sizeof(tdata5), ATTR_B);
    sv_ok(tname2, tguid2, tdata2, sizeof(tdata2), ATTR_BR);
    sv_ok(tname1, tguid1, tdata1, sizeof(tdata1), ATTR_B);
    sv_ok(tname4, tguid4, tdata4, sizeof(tdata4), ATTR_BR);
    sv_ok(tname3, tguid3, tdata3, sizeof(tdata3), ATTR_B);

    call_get_next_variable(BSIZ, NULL, nullguid, 0);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_SUCCESS);
    data = unserialize_data(&ptr, &data_len, BSIZ);
    g_assert_cmpuint(data_len, ==, dstring_data_size(tname3));
    g_assert(!memcmp(tname3->data, data, data_len));
    unserialize_guid(&ptr, guid);
    g_assert(!memcmp(guid, tguid3, GUID_LEN));

    call_get_next_variable(BSIZ, tname3, guid, 0);
    free(data);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_SUCCESS);
    data = unserialize_data(&ptr, &data_len, BSIZ);
    g_assert_cmpuint(data_len, ==, dstring_data_size(tname4));
    g_assert(!memcmp(tname4->data, data, data_len));
    unserialize_guid(&ptr, guid);
    g_assert(!memcmp(guid, tguid4, GUID_LEN));
    free(data);

    call_get_next_variable(BSIZ, tname4, guid, 0);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_SUCCESS);
    data = unserialize_data(&ptr, &data_len, BSIZ);
    g_assert_cmpuint(data_len, ==, dstring_data_size(tname1));
    g_assert(!memcmp(tname1->data, data, data_len));
    unserialize_guid(&ptr, guid);
    g_assert(!memcmp(guid, tguid1, GUID_LEN));

    call_get_next_variable(BSIZ, tname1, guid, 0);

    free(data);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_SUCCESS);
    data = unserialize_data(&ptr, &data_len, BSIZ);
    g_assert_cmpuint(data_len, ==, dstring_data_size(tname2));
    g_assert(!memcmp(tname2->data, data, data_len));
    unserialize_guid(&ptr, guid);
    g_assert(!memcmp(guid, tguid2, GUID_LEN));
    free(data);

    call_get_next_variable(BSIZ, tname2, guid, 0);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_SUCCESS);
    data = unserialize_data(&ptr, &data_len, BSIZ);
    g_assert_cmpuint(data_len, ==, dstring_data_size(tname5));
    g_assert(!memcmp(tname5->data, data, data_len));
    unserialize_guid(&ptr, guid);
    g_assert(!memcmp(guid, tguid5, GUID_LEN));

    call_get_next_variable(BSIZ, tname5, guid, 0);
    free(data);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_NOT_FOUND);
}

static void test_set_variable_attr(void)
{
    uint8_t *ptr;
    EFI_STATUS status;

    reset_vars();
    setup_variables();

    /* hardware error record is not supported */
    call_set_variable(tname1, tguid1, tdata1, sizeof(tdata1),
                      ATTR_B|EFI_VARIABLE_HARDWARE_ERROR_RECORD, 0);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_INVALID_PARAMETER);

    /* authenticated write access is not supported */
    call_set_variable(tname1, tguid1, tdata1, sizeof(tdata1),
                      ATTR_B|EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS, 0);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_UNSUPPORTED);

    /* runtime without boottime access is invalid */
    call_set_variable(tname1, tguid1, tdata1, sizeof(tdata1),
                      ATTR_R, 0);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_INVALID_PARAMETER);

    /* Setting boottime variables at runtime is not supported */
    call_set_variable(tname1, tguid1, tdata1, sizeof(tdata1),
                      ATTR_B, 1);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_INVALID_PARAMETER);

    /* Set a volatile variable at runtime fails */
    call_set_variable(tname1, tguid1, tdata1, sizeof(tdata1),
                      ATTR_BR, 1);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_INVALID_PARAMETER);

    /* Set a variable at runtime without runtime access fails */
    call_set_variable(tname1, tguid1, tdata1, sizeof(tdata1),
                      ATTR_B, 1);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_INVALID_PARAMETER);
}

static void test_set_variable_set(void)
{
    uint8_t *ptr, *data;
    UINTN data_len;
    EFI_STATUS status;
    UINT32 attr;

    reset_vars();

    /* Basic SetVariable usage. */
    sv_ok(tname1, tguid1, tdata1, sizeof(tdata1), ATTR_B);
    sv_ok(tname2, tguid2, tdata2, sizeof(tdata2), ATTR_BR);

    /* Set an NV variable at runtime */
    call_set_variable(tname3, tguid3, tdata3, sizeof(tdata3), ATTR_BRNV, 1);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_SUCCESS);

    /* Set an NV variable at boottime */
    sv_ok(tname4, tguid4, tdata4, sizeof(tdata4), ATTR_BNV);

    /* Access boottime variable at boottime */
    call_get_variable(tname1, tguid1, BSIZ, 0);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_SUCCESS);
    attr = unserialize_uint32(&ptr);
    g_assert_cmpuint(attr, ==, ATTR_B);
    data = unserialize_data(&ptr, &data_len, BSIZ);
    g_assert_cmpuint(data_len, ==, sizeof(tdata1));
    g_assert(!memcmp(tdata1, data, data_len));
    free(data);

    /* Access BR variable at boottime */
    call_get_variable(tname2, tguid2, BSIZ, 0);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_SUCCESS);
    attr = unserialize_uint32(&ptr);
    g_assert_cmpuint(attr, ==, ATTR_BR);
    data = unserialize_data(&ptr, &data_len, BSIZ);
    g_assert_cmpuint(data_len, ==, sizeof(tdata2));
    g_assert(!memcmp(tdata2, data, data_len));
    free(data);

    /* Access runtime variable at runtime */
    call_get_variable(tname2, tguid2, BSIZ, 1);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_SUCCESS);
    attr = unserialize_uint32(&ptr);
    g_assert_cmpuint(attr, ==, ATTR_BR);
    data = unserialize_data(&ptr, &data_len, BSIZ);
    g_assert_cmpuint(data_len, ==, sizeof(tdata2));
    g_assert(!memcmp(tdata2, data, data_len));
    free(data);

    /* Access runtime variable at runtime */
    call_get_variable(tname3, tguid3, BSIZ, 1);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_SUCCESS);
    attr = unserialize_uint32(&ptr);
    g_assert_cmpuint(attr, ==, ATTR_BRNV);
    data = unserialize_data(&ptr, &data_len, BSIZ);
    g_assert_cmpuint(data_len, ==, sizeof(tdata3));
    g_assert(!memcmp(tdata3, data, data_len));
    free(data);

    /* Access NV runtime variable at runtime */
    call_get_variable(tname3, tguid3, BSIZ, 1);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_SUCCESS);
    attr = unserialize_uint32(&ptr);
    g_assert_cmpuint(attr, ==, ATTR_BRNV);
    data = unserialize_data(&ptr, &data_len, BSIZ);
    g_assert_cmpuint(data_len, ==, sizeof(tdata3));
    g_assert(!memcmp(tdata3, data, data_len));
    free(data);

    /* Access NV boottime variable at boottime */
    call_get_variable(tname4, tguid4, BSIZ, 0);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_SUCCESS);
    attr = unserialize_uint32(&ptr);
    g_assert_cmpuint(attr, ==, ATTR_BNV);
    data = unserialize_data(&ptr, &data_len, BSIZ);
    g_assert_cmpuint(data_len, ==, sizeof(tdata4));
    g_assert(!memcmp(tdata4, data, data_len));
    free(data);
}

static void test_set_variable_update(void)
{
    uint8_t *ptr, *data;
    UINTN data_len;
    EFI_STATUS status;
    UINT32 attr;

    reset_vars();

    /* Insert a variable... */
    sv_ok(tname1, tguid1, tdata1, sizeof(tdata1), ATTR_B);

    /* ... and check it can be updated */
    sv_ok(tname1, tguid1, tdata2, sizeof(tdata2), ATTR_B);
    sv_ok(tname3, tguid3, tdata3, sizeof(tdata3), ATTR_BR);
    sv_ok(tname4, tguid4, tdata4, sizeof(tdata4), ATTR_BNV);

    /* Check the update worked. */
    call_get_variable(tname1, tguid1, BSIZ, 0);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_SUCCESS);
    attr = unserialize_uint32(&ptr);
    g_assert_cmpuint(attr, ==, ATTR_B);
    data = unserialize_data(&ptr, &data_len, BSIZ);
    g_assert_cmpuint(data_len, ==, sizeof(tdata2));
    g_assert(!memcmp(tdata2, data, data_len));
    free(data);

    /* Cannot change attributes */
    call_set_variable(tname1, tguid1, tdata2, sizeof(tdata2), ATTR_BR, 0);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_INVALID_PARAMETER);

    /* Updating a volatile variable at runtime fails */
    call_set_variable(tname3, tguid3, tdata3, sizeof(tdata3), ATTR_BR, 1);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_WRITE_PROTECTED);

    /* Updating a variable at runtime without runtime access fails */
    call_set_variable(tname4, tguid4, tdata4, sizeof(tdata4), ATTR_BNV, 1);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_INVALID_PARAMETER);
}

static void test_set_variable_append(void)
{
    uint8_t *ptr, *data;
    UINTN data_len;
    EFI_STATUS status;
    UINT32 attr;

    reset_vars();

    /* Insert some variables */
    sv_ok(tname1, tguid1, tdata1, sizeof(tdata1), ATTR_B);
    sv_ok(tname3, tguid3, tdata3, sizeof(tdata3), ATTR_BR);
    sv_ok(tname4, tguid4, tdata4, sizeof(tdata4), ATTR_BNV);

    /* Append 0 bytes must not delete the variable */
    sv_ok(tname1, tguid1, NULL, 0, ATTR_B|EFI_VARIABLE_APPEND_WRITE);

    /* Append data to the variable */
    sv_ok(tname1, tguid1, tdata2, sizeof(tdata2),
          ATTR_B | EFI_VARIABLE_APPEND_WRITE);

    /* Verify the contents are a concatenation */
    call_get_variable(tname1, tguid1, BSIZ, 0);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_SUCCESS);
    attr = unserialize_uint32(&ptr);
    g_assert_cmpuint(attr, ==, ATTR_B);
    data = unserialize_data(&ptr, &data_len, BSIZ);
    g_assert_cmpuint(data_len, ==, sizeof(tdata1) + sizeof(tdata2));
    g_assert(!memcmp(data, tdata1, sizeof(tdata1)));
    g_assert(!memcmp(data + sizeof(tdata1), tdata2, sizeof(tdata2)));
    free(data);

    /* Appending to a volatile variable at runtime fails */
    call_set_variable(tname3, tguid3, tdata3, sizeof(tdata3),
                      ATTR_BR|EFI_VARIABLE_APPEND_WRITE, 1);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_WRITE_PROTECTED);

    /* Appending to a variable at runtime without runtime access fails */
    call_set_variable(tname4, tguid4, tdata4, sizeof(tdata4),
                      ATTR_BNV|EFI_VARIABLE_APPEND_WRITE, 1);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_INVALID_PARAMETER);
}

static void test_set_variable_delete(void)
{
    uint8_t *ptr;
    EFI_STATUS status;

    reset_vars();

    sv_ok(tname1, tguid1, tdata1, sizeof(tdata1), ATTR_B);
    sv_ok(tname2, tguid2, tdata2, sizeof(tdata2), ATTR_B);
    sv_ok(tname3, tguid3, tdata3, sizeof(tdata3), ATTR_BR);
    sv_ok(tname5, tguid5, tdata5, sizeof(tdata5), ATTR_BNV);

    /* Deleting a non-existent variable at boottime fails (by setting no data) */
    call_set_variable(tname4, tguid4, NULL, 0, ATTR_B, 0);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_NOT_FOUND);

    /*
     * Deleting a non-existent variable at boottime fails (by setting no
     * access attributes)
     */
    call_set_variable(tname4, tguid4, tdata4, sizeof(tdata4), 0, 0);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_NOT_FOUND);

    /* Deleting a non-existent variable at runtime fails (by setting no data) */
    call_set_variable(tname4, tguid4, NULL, 0, ATTR_BRNV, 0);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_NOT_FOUND);

    /*
     * Deleting a non-existent variable at runtime fails (by setting no access
     * attributes)
     */
    call_set_variable(tname4, tguid4, tdata4, sizeof(tdata4), 0, 0);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_NOT_FOUND);

    /* Delete by setting no data */
    sv_ok(tname1, tguid1, NULL, 0, ATTR_B);

    /* Verify it is gone */
    call_get_variable(tname1, tguid1, BSIZ, 0);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_NOT_FOUND);

    /* Delete by setting no access attributes */
    sv_ok(tname2, tguid2, tdata2, sizeof(tdata2), 0);

    /* Verify it is gone */
    call_get_variable(tname2, tguid2, BSIZ, 0);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_NOT_FOUND);

    /* Deleting a volatile variable at runtime fails */
    call_set_variable(tname3, tguid3, NULL, 0, ATTR_BR, 1);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_WRITE_PROTECTED);

    /* Deleting a variable at runtime without runtime access fails */
    call_set_variable(tname5, tguid5, NULL, 0, ATTR_B, 1);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_INVALID_PARAMETER);

    /* Deleting a variable at runtime by setting attributes to 0 succeeds */
    sv_ok(tname5, tguid5, NULL, 0, ATTR_BNV); /* Remove old variable */
    /* Insert it with different attr */
    sv_ok(tname5, tguid5, tdata5, sizeof(tdata5), ATTR_BRNV);
    /* Then delete it at runtime */
    call_set_variable(tname5, tguid5, tdata5, sizeof(tdata5), 0, 1);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_SUCCESS);
}

static void test_set_variable_resource_limit(void)
{
    uint8_t *ptr;
    EFI_STATUS status;
    UINTN remaining;
#define TMP_SIZE 65536
    uint8_t tmp[TMP_SIZE] = {0};

    reset_vars();

    /* Check per-variable limit */
    call_set_variable(tname1, tguid1, tmp, DATA_LIMIT + 1, ATTR_B, 0);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_OUT_OF_RESOURCES);

    sv_ok(tname1, tguid1, tmp, DATA_LIMIT, ATTR_B);

    /* Use all the remaining space */
    remaining = TMP_SIZE - DATA_LIMIT - dstring_data_size(tname1) -
                dstring_data_size(tname2);
    sv_ok(tname2, tguid2, tmp, remaining, ATTR_B);

    /* Cannot use any more space with a new variable */
    call_set_variable(tname3, tguid3, tmp, 1, ATTR_B, 0);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_OUT_OF_RESOURCES);

    /* Cannot use any more by appending */
    call_set_variable(tname1, tguid1, tmp, 1, ATTR_B|EFI_VARIABLE_APPEND_WRITE, 0);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_OUT_OF_RESOURCES);

    /* Cannot use any more by replacing */
    call_set_variable(tname2, tguid2, tmp, remaining + 1, ATTR_B, 0);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_OUT_OF_RESOURCES);

    /* Can update without exceeding the limit */
    sv_ok(tname1, tguid1, tmp, DATA_LIMIT, ATTR_B);
}

static void test_set_variable_many_vars(void)
{
    uint8_t *ptr;
    EFI_STATUS status;
    int i;
    uint8_t tmp = 0;
    dstring *dname = alloc_dstring_unset(5);
    char *name = (char *)dname->data;

    reset_vars();

    /* Set more variables than are allowed based on the variable "overhead". */
    for (i = 0; i < (TOTAL_LIMIT / VARIABLE_SIZE_MIN) + 1; i++) {
        sprintf(name, "%04d", i);
        call_set_variable(dname, tguid1, &tmp, 1, ATTR_B, 0);
        ptr = buf;
        status = unserialize_uintn(&ptr);
        if (i == (TOTAL_LIMIT / VARIABLE_SIZE_MIN))
            g_assert_cmpuint(status, ==, EFI_OUT_OF_RESOURCES);
        else
            g_assert_cmpuint(status, ==, EFI_SUCCESS);
    }
    free_dstring(dname);
}

static void test_set_variable_non_volatile(void)
{
    uint8_t *ptr, *data;
    EFI_STATUS status;
    UINTN data_len;
    UINT32 attr;

    remove(save_name);
    reset_vars();
    sv_ok(tname1, tguid1, tdata1, sizeof(tdata1), ATTR_BNV);
    sv_ok(tname2, tguid2, tdata2, sizeof(tdata2), ATTR_B);
    sv_ok(tname3, tguid3, tdata3, sizeof(tdata3), ATTR_BRNV);
    sv_ok(tname4, tguid4, tdata4, sizeof(tdata4), ATTR_BR);

    reset_vars();
    load_list();

    call_get_variable(tname1, tguid1, BSIZ, 0);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_SUCCESS);
    attr = unserialize_uint32(&ptr);
    g_assert_cmpuint(attr, ==, ATTR_BNV);
    data = unserialize_data(&ptr, &data_len, BSIZ);
    g_assert_cmpuint(data_len, ==, sizeof(tdata1));
    g_assert(!memcmp(tdata1, data, data_len));
    free(data);

    call_get_variable(tname3, tguid3, BSIZ, 0);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_SUCCESS);
    attr = unserialize_uint32(&ptr);
    g_assert_cmpuint(attr, ==, ATTR_BRNV);
    data = unserialize_data(&ptr, &data_len, BSIZ);
    g_assert_cmpuint(data_len, ==, sizeof(tdata3));
    g_assert(!memcmp(tdata3, data, data_len));
    free(data);

    call_get_variable(tname2, tguid2, BSIZ, 0);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_NOT_FOUND);

    call_get_variable(tname4, tguid4, BSIZ, 0);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_NOT_FOUND);

    /* Update, reload & check */
    sv_ok(tname1, tguid1, tdata2, sizeof(tdata2), ATTR_BNV);

    reset_vars();
    load_list();

    call_get_variable(tname1, tguid1, BSIZ, 0);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_SUCCESS);
    attr = unserialize_uint32(&ptr);
    g_assert_cmpuint(attr, ==, ATTR_BNV);
    data = unserialize_data(&ptr, &data_len, BSIZ);
    g_assert_cmpuint(data_len, ==, sizeof(tdata2));
    g_assert(!memcmp(tdata2, data, data_len));
    free(data);

    /* Append, reload & check */
    call_set_variable(tname3, tguid3, tdata4, sizeof(tdata4),
                      ATTR_BRNV|EFI_VARIABLE_APPEND_WRITE, 1);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_SUCCESS);

    reset_vars();
    load_list();

    call_get_variable(tname3, tguid3, BSIZ, 0);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_SUCCESS);
    attr = unserialize_uint32(&ptr);
    g_assert_cmpuint(attr, ==, ATTR_BRNV);
    data = unserialize_data(&ptr, &data_len, BSIZ);
    g_assert_cmpuint(data_len, ==, sizeof(tdata3) + sizeof(tdata4));
    g_assert(!memcmp(data, tdata3, sizeof(tdata3)));
    g_assert(!memcmp(data + sizeof(tdata3), tdata4, sizeof(tdata4)));
    free(data);

    /* Delete, reload & check */
    call_set_variable(tname3, tguid3, NULL, 0, ATTR_BRNV, 1);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_SUCCESS);

    reset_vars();
    load_list();

    call_get_variable(tname3, tguid3, BSIZ, 0);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_NOT_FOUND);
}

int main(int argc, char **argv)
{
    setup_globals();
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/test/get_variable/no_name",
                    test_get_variable_no_name);
    g_test_add_func("/test/get_variable/long_name",
                    test_get_variable_long_name);
    g_test_add_func("/test/get_variable/not_found",
                    test_get_variable_not_found);
    g_test_add_func("/test/get_variable/found",
                    test_get_variable_found);
    g_test_add_func("/test/get_variable/too_small",
                    test_get_variable_too_small);
    g_test_add_func("/test/query_variable_info",
                    test_query_variable_info);
    g_test_add_func("/test/get_next_variable/empty",
                    test_get_next_variable_empty);
    g_test_add_func("/test/get_next_variable/long_name",
                    test_get_next_variable_long_name);
    g_test_add_func("/test/get_next_variable/only_runtime",
                    test_get_next_variable_only_runtime);
    g_test_add_func("/test/get_next_variable/too_small",
                    test_get_next_variable_too_small);
    g_test_add_func("/test/get_next_variable/no_match",
                    test_get_next_variable_no_match);
    g_test_add_func("/test/get_next_variable/all",
                    test_get_next_variable_all);
    g_test_add_func("/test/set_variable/attr",
                    test_set_variable_attr);
    g_test_add_func("/test/set_variable/set",
                    test_set_variable_set);
    g_test_add_func("/test/set_variable/update",
                    test_set_variable_update);
    g_test_add_func("/test/set_variable/append",
                    test_set_variable_append);
    g_test_add_func("/test/set_variable/delete",
                    test_set_variable_delete);
    g_test_add_func("/test/set_variable/resource_limit",
                    test_set_variable_resource_limit);
    g_test_add_func("/test/set_variable/many_vars",
                    test_set_variable_many_vars);
    g_test_add_func("/test/set_variable/non_volatile",
                    test_set_variable_non_volatile);

    return g_test_run();
}
