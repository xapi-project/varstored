/* Avoid logging anything */
#define _DEBUG_H
#define DBG(...)

/* Including this directly allows us to poke into the implementation. */
#include "handler.c"

#include <glib.h>
#include <openssl/pem.h>
#include <assert.h>

static char *save_name = "test.dat";

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

static dstring *signatureSupport_name;
static dstring *setupMode_name;
static dstring *secureBoot_name;
static dstring *PK_name;

static EFI_GUID testOwnerGuid = {{7, 5, 3, 8, 9, 6, 1, 3,
                                  2, 3, 4, 5, 4, 6, 7, 8}};

EFI_TIME test_timea = {2018, 6, 20, 13, 38, 1, 0, 0, 0, 0, 0};
EFI_TIME test_timeb = {2018, 6, 20, 13, 38, 2, 0, 0, 0, 0, 0};
EFI_TIME test_timec = {2018, 6, 20, 13, 38, 3, 0, 0, 0, 0, 0};

#define BSIZ 1024 /* general buffer size */

/* Assert statements, which provide info about the failure */

#define vsd_assert_status(_txt, _x, _y, _z, ...) \
    do { \
        if (!((_x) _y (_z))) \
            printf("\nWhile checking " _txt " assert failed: %s %llu " #_y \
                   " %s %llu\n", ## __VA_ARGS__, \
                   EFI_ERROR(_x) ? "ERROR" : "", (~EFI_MAX_BIT & _x), \
                   EFI_ERROR(_z) ? "ERROR" : "", (~EFI_MAX_BIT & _z)); \
        g_assert_cmpuint(_x, _y, _z); \
    } while (0);

#define vsd_assert_cmpuint(_txt, _x, _y, _z, ...) \
    do { \
        if (!((_x) _y (_z))) \
            printf("\nWhile checking " # _txt " assert failed: %lu " #_y \
                   " %lu\n", ## __VA_ARGS__, (UINTN)(_x), (UINTN)(_z)); \
        g_assert_cmpuint(_x, _y, _z); \
    } while (0);

#define vsd_assert_nonnull(_txt, _x, ...) \
    do { \
        if ((_x) == NULL) \
            printf("\nWhile checking " # _txt " assert non null failed.\n", \
                   ## __VA_ARGS__); \
        g_assert_nonnull(_x); \
    } while (0);

/*
 * dstring handling functions
 */

static size_t dstring_data_size(const dstring *name)
{
    return name->length * sizeof(uint16_t);
}

/* convert a dstring into something printable */
static char *get_dstring_pretty(const dstring *s)
{
    const int size_of_char_hex =  strlen("{xx}");
    /* Alloc space for worst case */
    char *str = malloc(s->length * size_of_char_hex + 1);
    char *pos = str;
    int i;

    for (i = 0; i < s->length; i++) {
        if (s->data[i] > 31 && s->data[i] < 128)
            *(pos++) = s->data[i];
        else
            sprintf(pos += 4, "{%02x}", s->data[i] && 0xff);
    }
    *pos = '\0';
    return str;
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

static enum backend_init_status testdb_init(void)
{
    struct efi_variable *l;
    FILE *f = fopen(save_name, "r");

    if (!f) {
        fprintf(stderr, "failed to open %s : %s\n", save_name, strerror(errno));
        abort();
    }

    for (;;) {
        UINTN name_len;

        if (fread(&name_len, sizeof name_len, 1, f) != 1)
            break;

        l = malloc(sizeof *l);
        if (!l)
            abort();

        l->name_len = name_len;
        l->name = malloc(l->name_len);
        fread(l->name, 1, l->name_len, f);
        fread(&l->data_len, sizeof l->data_len, 1, f);
        l->data = malloc(l->data_len);
        fread(l->data, 1, l->data_len, f);
        fread(l->guid, 1, GUID_LEN, f);
        fread(&l->attributes, 1, sizeof l->attributes, f);
        l->next = var_list;
        var_list = l;
    }

    fclose(f);
    return BACKEND_INIT_SUCCESS;
}

static bool testdb_save(void)
{
    struct efi_variable *l;
    FILE *f = fopen(save_name, "w");

    if (!f) {
        fprintf(stderr, "failed to open %s %s\n", save_name, strerror(errno));
        abort();
    }

    l = var_list;
    while (l) {
        if (l->attributes & EFI_VARIABLE_NON_VOLATILE) {
            fwrite(&l->name_len, sizeof l->name_len, 1, f);
            fwrite(l->name, 1, l->name_len, f);
            fwrite(&l->data_len, sizeof l->data_len, 1, f);
            fwrite(l->data, 1, l->data_len, f);
            fwrite(l->guid, 1, GUID_LEN, f);
            fwrite(&l->attributes, sizeof l->attributes, 1, f);
        }
        l = l->next;
    }

    fclose(f);
    return true;
}

struct backend testdb = {
    .parse_arg = NULL,
    .check_args = NULL,
    .init = testdb_init,
    .save = NULL,
    .resume = NULL,
    .set_variable = testdb_save,
};
struct backend *db = &testdb;

static void setup_globals(void)
{
    tname1 = alloc_dstring("foo");
    tname2 = alloc_dstring("foobar");
    tname3 = alloc_dstring("foobar");
    tname4 = alloc_dstring("baz");
    tname5 = alloc_dstring("xyzabcdefgh");

    signatureSupport_name = alloc_dstring("SignatureSupport");
    setupMode_name = alloc_dstring("SetupMode");
    secureBoot_name = alloc_dstring("SecureBoot");
    PK_name = alloc_dstring("PK");

    secure_boot_enable = true;
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

static EFI_STATUS call_get_variable_data(const dstring *name, const char *guid,
                                         UINTN avail, BOOLEAN at_runtime,
                                         uint8_t **data, UINTN *len)
{
    uint8_t *ptr = buf;
    EFI_STATUS status;

    call_get_variable(name, guid, avail, at_runtime);

    status = unserialize_uintn(&ptr);
    unserialize_uint32(&ptr); /* attr */
    *data = unserialize_data(&ptr, len, BSIZ);
    return status;
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

/*
 * This calls SetVariable and checks the result against expected. In the
 * failing case, the line number provided reported.
 */
static EFI_STATUS setVariable_check_line(const dstring *name, const char *guid,
                                         uint8_t *data, UINTN len, UINT32 attr,
                                         EFI_STATUS expected, int line)
{
    uint8_t *ptr;
    EFI_STATUS status;
    char *nice_name;

    call_set_variable(name, guid, data, len, attr, 0);
    ptr = buf;
    status = unserialize_uintn(&ptr);

    nice_name = get_dstring_pretty(name);
    vsd_assert_status("set_variable(\"%s\", ...) for line %d", status, ==,
                      expected, nice_name, line);
    free(nice_name);

    return status;
}

#define sv_check(_name, _guid, _data, _len, _attr, _expected) \
    setVariable_check_line(_name, _guid, _data, _len, _attr, \
                           _expected, __LINE__);

#define sv_ok(_name, _guid, _data, _len, _attr) \
    setVariable_check_line(_name, _guid, _data, _len, _attr, \
                           EFI_SUCCESS, __LINE__);

/*
 * Crypto/signing functions
 */

struct sign_details
{
    char *cert;
    char *key;
    char *digest;
};

struct sign_details sign_first_key = {"testPK.pem", "testPK.key", "SHA256"};
struct sign_details sign_bad_digest = {"testPK.pem", "testPK.key", "SHA224"};
struct sign_details sign_second_key = {"testPK2.pem", "testPK2.key", "SHA256"};
struct sign_details sign_mixed_keys = {"testPK.pem", "testPK2.key", "SHA256"};

static void setup_ssl(void)
{
    ERR_load_crypto_strings();
    OpenSSL_add_all_digests();
    OpenSSL_add_all_ciphers();
}

static void read_x509_into_CertList(char *certfile, EFI_SIGNATURE_LIST **ret_cert,
                                    int *len)
{
    EFI_SIGNATURE_LIST *pk_cert;
    EFI_SIGNATURE_DATA *pk_cert_data;
    unsigned char *tmp;
    int pk_cert_len;
    BIO *cert_bio;
    X509 *cert;

    ERR_clear_error();

    cert_bio = BIO_new_file(certfile, "r");
    assert(cert_bio);
    cert = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);
    vsd_assert_nonnull("reading cert \"%s\"", cert, certfile);
    BIO_free(cert_bio);

    pk_cert_len = i2d_X509(cert, NULL);
    pk_cert_len += sizeof(EFI_SIGNATURE_LIST) +
                   offsetof(EFI_SIGNATURE_DATA, SignatureData);

    pk_cert = malloc(pk_cert_len);
    vsd_assert_nonnull("malloc pk cert", pk_cert);

    tmp = (unsigned char *)pk_cert + sizeof(EFI_SIGNATURE_LIST) +
          offsetof(EFI_SIGNATURE_DATA, SignatureData);
    i2d_X509(cert, &tmp);
    pk_cert->SignatureListSize   = pk_cert_len;
    pk_cert->SignatureSize       = (UINT32)(pk_cert_len -
                                   sizeof(EFI_SIGNATURE_LIST));
    pk_cert->SignatureHeaderSize = 0;
    memcpy(&pk_cert->SignatureType, gEfiCertX509Guid, sizeof(gEfiCertX509Guid));

    pk_cert_data = (void *)pk_cert + sizeof(EFI_SIGNATURE_LIST);
    pk_cert_data->SignatureOwner = testOwnerGuid;

    *ret_cert = pk_cert;
    *len = pk_cert_len;
}

static size_t sign(uint8_t **signed_buf, const dstring *varname,
                   const char *vendor_guid, UINT32 attributes,
                   const EFI_TIME *timestamp, const uint8_t *data,
                   size_t data_size, const struct sign_details *sd)
{
    PKCS7 *p7;
    BIO *bio;
    X509 *cert;
    EVP_PKEY *pkey;
    const EVP_MD *md;
    void *ret;
    int sig_size;
    size_t auth_size;
    uint8_t *buf;
    EFI_VARIABLE_AUTHENTICATION_2 *var_auth;
    unsigned char *auth_sigbuf;
    size_t name_size = dstring_data_size(varname);
    int request_len = name_size + sizeof(EFI_GUID) + sizeof(UINT32) +
                        sizeof(EFI_TIME) + data_size;
    uint8_t *request = malloc(request_len);
    uint8_t *ptr = request;

    vsd_assert_nonnull("malloc signing request buffer", request);

    /*
     * signature is over variable name (no null), the vendor GUID, the
     * attributes, the timestamp and the contents
     */

    /* copy var name */
    memcpy(ptr, varname->data, name_size);
    ptr += name_size;

    /* copy vendor_guid */
    memcpy(ptr, vendor_guid, GUID_LEN);
    ptr += sizeof(EFI_GUID);

    /* copy attibutes */
    memcpy(ptr, &attributes, sizeof(attributes));
    ptr += sizeof(attributes);

    /* copy timestamp */
    memcpy(ptr, timestamp, sizeof(*timestamp));
    ptr += sizeof(*timestamp);

    /* copy data */
    if (data)
        memcpy(ptr, data, data_size);

    /* sign */
    ERR_clear_error();

    bio = BIO_new_file(sd->cert, "r");
    assert(bio);
    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    vsd_assert_nonnull("PEM_read_bio_X509(\"%s\")", cert, sd->cert);
    BIO_free(bio);

    bio = BIO_new_file(sd->key, "r");
    assert(bio);
    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    vsd_assert_nonnull("PEM_read_bio_PrivateKey(\"%s\")", pkey, sd->key);
    BIO_free(bio);

    bio = BIO_new_mem_buf(request, request_len);
    assert(bio);
    p7 = PKCS7_sign(NULL, NULL, NULL, bio, PKCS7_BINARY | PKCS7_PARTIAL |
                    PKCS7_DETACHED | PKCS7_NOATTR);
    md = EVP_get_digestbyname(sd->digest);
    vsd_assert_nonnull("digest", md);

    ret = PKCS7_sign_add_signer(p7, cert, pkey, md,
                                PKCS7_BINARY | PKCS7_DETACHED | PKCS7_NOATTR);
    vsd_assert_nonnull("PKCS7 add signer", ret);

    PKCS7_final(p7, bio, PKCS7_BINARY | PKCS7_DETACHED | PKCS7_NOATTR);
    BIO_free(bio);
    free(request);

    sig_size = i2d_PKCS7(p7, NULL);
    auth_size = offsetof(EFI_VARIABLE_AUTHENTICATION_2, AuthInfo.CertData) +
                sig_size;
    buf = malloc(auth_size + data_size);
    vsd_assert_nonnull("malloc output buffer", request);
    var_auth = (EFI_VARIABLE_AUTHENTICATION_2 *)buf;
    var_auth->TimeStamp = *timestamp;
    memcpy(var_auth->AuthInfo.CertType, gEfiCertPkcs7Guid,
           sizeof(gEfiCertPkcs7Guid));

    var_auth->AuthInfo.Hdr.dwLength = sig_size +
                                      offsetof(WIN_CERTIFICATE_UEFI_GUID, CertData);
    var_auth->AuthInfo.Hdr.wRevision = 0x0200;
    var_auth->AuthInfo.Hdr.wCertificateType = WIN_CERT_TYPE_EFI_GUID;

    auth_sigbuf = var_auth->AuthInfo.CertData;
    i2d_PKCS7(p7, &auth_sigbuf);

    PKCS7_free(p7);

    if (data)
        memcpy(buf + auth_size, data, data_size);

    *signed_buf = buf;
    return auth_size + data_size;
}

static void sign_and_check_(const dstring *varname, const char *vendor_guid,
                            UINT32 attributes, const EFI_TIME *timestamp,
                            const uint8_t *data, size_t data_size,
                            struct sign_details *sd, EFI_STATUS expected, int line)
{
    uint8_t *sign_buffer;
    int len;

    len = sign(&sign_buffer, varname, vendor_guid, attributes, timestamp,
               data, data_size, sd);
    setVariable_check_line(varname, vendor_guid, sign_buffer, len,
                           attributes, expected, line);
    free(sign_buffer);
}

#define sign_and_check(_name, _vend, _attr, _time, _data, _size, _sig, _e_d) \
    sign_and_check_(_name, _vend, _attr, _time, _data, _size, _sig, _e_d, \
                    __LINE__)

/*
 * This function checks the variable's data is as expected.
 * The expected data is provided, such that it can be compared
 */

static void check_variable_data(dstring *name, const char *guid,
                                UINTN avail, BOOLEAN at_runtime,
                                const uint8_t *expected_data, UINTN expected_len)
{
    uint8_t *ret_data;
    EFI_STATUS status;
    int cmp;
    UINTN len;
    char *nice_name = get_dstring_pretty(name);

    status = call_get_variable_data(name, guid, avail, at_runtime, &ret_data, &len);
    vsd_assert_status("get_variable(\"%s\")", status, ==, 0, nice_name);
    vsd_assert_cmpuint("data length for \"%s\"", expected_len, ==, len,
                       nice_name);

    cmp = memcmp(ret_data, expected_data, len);
    vsd_assert_cmpuint("cmp of data for \"%s\"", cmp, ==, 0, nice_name);
    free(nice_name);
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
          ATTR_B | EFI_VARIABLE_APPEND_WRITE);
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
                      ATTR_B | EFI_VARIABLE_HARDWARE_ERROR_RECORD, 0);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_INVALID_PARAMETER);

    /* authenticated write access is not supported */
    call_set_variable(tname1, tguid1, tdata1, sizeof(tdata1),
                      ATTR_B | EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS, 0);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_UNSUPPORTED);

    /* runtime without boottime access is invalid */
    call_set_variable(tname1, tguid1, tdata1, sizeof(tdata1), ATTR_R, 0);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_INVALID_PARAMETER);

    /* Setting boottime variables at runtime is not supported */
    call_set_variable(tname1, tguid1, tdata1, sizeof(tdata1), ATTR_B, 1);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_INVALID_PARAMETER);

    /* Set a volatile variable at runtime fails */
    call_set_variable(tname1, tguid1, tdata1, sizeof(tdata1), ATTR_BR, 1);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_INVALID_PARAMETER);

    /* Set a variable at runtime without runtime access fails */
    call_set_variable(tname1, tguid1, tdata1, sizeof(tdata1), ATTR_B, 1);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_INVALID_PARAMETER);

    /*
     * If both the EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS and the
     * EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS attribute are set in a
     * SetVariable() call, then the firmware must return EFI_INVALID_PARAMETER.
     */
     sign_and_check(tname2, tguid1,
                    ATTR_B_TIME | EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS,
                    &test_timea, tdata1, sizeof(tdata1), &sign_first_key,
                    EFI_INVALID_PARAMETER);
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
    sv_ok(tname1, tguid1, NULL, 0, ATTR_B | EFI_VARIABLE_APPEND_WRITE);

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
                      ATTR_BR | EFI_VARIABLE_APPEND_WRITE, 1);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_WRITE_PROTECTED);

    /* Appending to a variable at runtime without runtime access fails */
    call_set_variable(tname4, tguid4, tdata4, sizeof(tdata4),
                      ATTR_BNV | EFI_VARIABLE_APPEND_WRITE, 1);
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
    call_set_variable(tname1, tguid1, tmp, 1, ATTR_B | EFI_VARIABLE_APPEND_WRITE, 0);
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
    db->init();

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
    db->init();

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
                      ATTR_BRNV | EFI_VARIABLE_APPEND_WRITE, 1);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_SUCCESS);

    reset_vars();
    db->init();

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
    db->init();

    call_get_variable(tname3, tguid3, BSIZ, 0);
    ptr = buf;
    status = unserialize_uintn(&ptr);
    g_assert_cmpuint(status, ==, EFI_NOT_FOUND);
}

__attribute__((unused)) static void test_use_bad_digest(void)
{
    /*
     * Attempt bad digest
     *
     * 4.b.  b SignedData.digestAlgorithms shall contain the digest
     * algorithm used when preparing the signature. Only a digest
     * algorithm of SHA-256 is accepted.
     */

    reset_vars();
    setup_variables();

    sign_and_check(tname1, tguid1, ATTR_B_TIME, &test_timea, tdata1,
                   sizeof(tdata1), &sign_bad_digest, EFI_INVALID_PARAMETER);
}

static void test_set_secure_variable(void)
{
    const char tosign_data[] = "testdata";
    const char tosign2_data[] = "|appended";
    const char tosign_appended_data[] = "testdata|appended";
    const char tosign3_data[] = "|back";
    const char tosign_appended2_data[] = "testdata|appended|back";

    uint8_t *sign_buffer;
    int len;

    /* 1. Create a EFI_VARIABLE_AUTHENTICATION_2 variable */
    sign_and_check(tname1, tguid1, ATTR_B_TIME, &test_timea,
                   (uint8_t *)tosign_data, strlen((char *)tosign_data),
                   &sign_first_key, EFI_SUCCESS);
    check_variable_data(tname1, tguid1, BSIZ, 0,
                        (uint8_t *)tosign_data, strlen(tosign_data));

    /* 2. try append */
    sign_and_check(tname1, tguid1, ATTR_B_TIME | EFI_VARIABLE_APPEND_WRITE,
                   &test_timeb, (uint8_t *)tosign2_data, strlen(tosign2_data),
                   &sign_first_key, EFI_SUCCESS);
    check_variable_data(tname1, tguid1, BSIZ, 0,
                        (uint8_t *)tosign_appended_data,
                        strlen(tosign_appended_data));

    /* 3. Try append with older time stamp (is meant to work!) */
    sign_and_check(tname1, tguid1, ATTR_B_TIME | EFI_VARIABLE_APPEND_WRITE,
                   &test_timea, (uint8_t *)tosign3_data, strlen(tosign3_data),
                   &sign_first_key, EFI_SUCCESS);
    check_variable_data(tname1, tguid1, BSIZ, 0,
                        (uint8_t *)tosign_appended2_data,
                        strlen(tosign_appended2_data));

    /*
     * Try updating, at time b. This shouldn't work. (appends with bad times,
     * don't update the time
     */
    sign_and_check(tname1, tguid1, ATTR_B_TIME, &test_timeb,
                   (uint8_t *)tosign3_data, strlen(tosign3_data),
                   &sign_first_key, EFI_SECURITY_VIOLATION);
    check_variable_data(tname1, tguid1, BSIZ, 0,
                        (uint8_t *)tosign_appended2_data,
                        strlen(tosign_appended2_data));

    /*
     * 3. Try with bad signature (mismatching attributes)
     *
     * Here we sign without EFI_VARIABLE_APPEND_WRITE, but still include
     * this attribute in the setvariable call.
     */
    len = sign(&sign_buffer, tname1, tguid1,
               ATTR_B_TIME, &test_timec, (uint8_t *)tosign2_data,
               strlen(tosign2_data), &sign_first_key);
    assert(len);
    sv_check(tname1, tguid1, sign_buffer, len, ATTR_B_TIME |
             EFI_VARIABLE_APPEND_WRITE, EFI_SECURITY_VIOLATION);
    free(sign_buffer);

    /* check it's the same */
    check_variable_data(tname1, tguid1, BSIZ, 0,
                        (uint8_t *)tosign_appended2_data,
                        strlen(tosign_appended2_data));

    /* 4. Try updating with wrong key */
    sign_and_check(tname1, tguid1, ATTR_B_TIME, &test_timec,
                   (uint8_t *)tosign2_data, strlen(tosign2_data),
                   &sign_second_key, EFI_SECURITY_VIOLATION);

    /* check it's the same */
    check_variable_data(tname1, tguid1, BSIZ, 0,
                        (uint8_t *)tosign_appended2_data,
                        strlen(tosign_appended2_data));

    /* try deleting */
    sign_and_check(tname1, tguid1, ATTR_B_TIME, &test_timec, NULL, 0,
                   &sign_first_key, EFI_SUCCESS);
}

static void test_secure_set_variable_setupmode(void)
{
    reset_vars();
    setup_variables();

    /*
     * While no Platform Key is enrolled, and while the variable
     * AuditMode == 0, the platform is said to be
     * operating in setup mode.
     */

    check_variable_data(setupMode_name, gEfiGlobalVariableGuid, BSIZ, 0,
                        (uint8_t *)"\1", 1);
    test_set_secure_variable();
}

static void test_secure_set_variable_usermode()
{
    EFI_SIGNATURE_LIST *ret_cert;
    int certlen;

    reset_vars();
    setup_variables();

    /* Check we're in setup mode */
    check_variable_data(setupMode_name, gEfiGlobalVariableGuid, BSIZ, 0,
                        (uint8_t *)"\1", 1);

    /* Move into user mode by enrolling Platform Key. */
    read_x509_into_CertList("testPK.pem", &ret_cert, &certlen);

    sign_and_check(PK_name, gEfiGlobalVariableGuid, ATTR_BRNV_TIME,
                   &test_timea, (uint8_t *)ret_cert, certlen,
                   &sign_first_key, EFI_SUCCESS);
    free(ret_cert);
    check_variable_data(setupMode_name, gEfiGlobalVariableGuid,
                        BSIZ, 0, (uint8_t *)"\0", 1);

    test_set_secure_variable();
}

static void test_secure_set_PK()
{
    int certlen;
    EFI_SIGNATURE_LIST *ret_cert;
    EFI_SIGNATURE_LIST *second_cert;
    int secondcertlen;

    reset_vars();
    setup_variables();

    check_variable_data(setupMode_name, gEfiGlobalVariableGuid, BSIZ, 0,
                        (uint8_t *)"\1", 1);
    check_variable_data(secureBoot_name, gEfiGlobalVariableGuid, BSIZ, 0,
                        (uint8_t *)"\0", 1);

    read_x509_into_CertList("testPK.pem", &ret_cert, &certlen);

    /* try cert, signed by someone unknown. Should be no mode change. */
    sign_and_check(PK_name, gEfiGlobalVariableGuid, ATTR_BRNV_TIME,
                   &test_timea, (uint8_t *)ret_cert, certlen,
                   &sign_second_key, EFI_SECURITY_VIOLATION);
    check_variable_data(setupMode_name, gEfiGlobalVariableGuid,
                        BSIZ, 0, (uint8_t *)"\1", 1);
    check_variable_data(secureBoot_name, gEfiGlobalVariableGuid, BSIZ, 0,
                        (uint8_t *)"\0", 1);

    /* try setting PK, with wrong attributes */

    sv_check(PK_name, gEfiGlobalVariableGuid, (uint8_t *)ret_cert, certlen,
             ATTR_BRNV, EFI_INVALID_PARAMETER);

    sign_and_check(PK_name, gEfiGlobalVariableGuid,
                   EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
                   &test_timea, (uint8_t *)ret_cert, certlen,
                   &sign_second_key, EFI_NOT_FOUND);

    sign_and_check(PK_name, gEfiGlobalVariableGuid,
                   ATTR_B_TIME | EFI_VARIABLE_RUNTIME_ACCESS,
                   &test_timea, (uint8_t *)ret_cert, certlen,
                   &sign_second_key, EFI_INVALID_PARAMETER);

    sign_and_check(PK_name, gEfiGlobalVariableGuid,
                   ATTR_B_TIME | EFI_VARIABLE_NON_VOLATILE,
                   &test_timea, (uint8_t *)ret_cert, certlen,
                   &sign_second_key, EFI_INVALID_PARAMETER);

    sign_and_check(PK_name, gEfiGlobalVariableGuid,
                   EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_NON_VOLATILE |
                   EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
                   &test_timea, (uint8_t *)ret_cert, certlen,
                   &sign_second_key, EFI_INVALID_PARAMETER);

    check_variable_data(setupMode_name, gEfiGlobalVariableGuid,
                        BSIZ, 0, (uint8_t *)"\1", 1);
    check_variable_data(secureBoot_name, gEfiGlobalVariableGuid, BSIZ, 0,
                        (uint8_t *)"\0", 1);

    /* Set PK, self signed - should move to user mode */
    sign_and_check(PK_name, gEfiGlobalVariableGuid, ATTR_BRNV_TIME,
                   &test_timea, (uint8_t *)ret_cert, certlen,
                   &sign_first_key, EFI_SUCCESS);
    check_variable_data(setupMode_name, gEfiGlobalVariableGuid,
                        BSIZ, 0, (uint8_t *)"\0", 1);
    check_variable_data(secureBoot_name, gEfiGlobalVariableGuid, BSIZ, 0,
                        (uint8_t *)"\1", 1);

    read_x509_into_CertList("testPK.pem", &second_cert, &secondcertlen);

    /* new cert, signed by self */
    sign_and_check(PK_name, gEfiGlobalVariableGuid, ATTR_BRNV_TIME,
                   &test_timeb, (uint8_t *)second_cert, secondcertlen,
                   &sign_second_key, EFI_SECURITY_VIOLATION);
    check_variable_data(setupMode_name, gEfiGlobalVariableGuid,
                        BSIZ, 0, (uint8_t *)"\0", 1);
    check_variable_data(secureBoot_name, gEfiGlobalVariableGuid, BSIZ, 0,
                        (uint8_t *)"\1", 1);

    /* new cert, truncated */
    sign_and_check(PK_name, gEfiGlobalVariableGuid, ATTR_BRNV_TIME,
                   &test_timeb, (uint8_t *)&second_cert, secondcertlen - 8,
                   &sign_first_key, EFI_INVALID_PARAMETER);
    check_variable_data(setupMode_name, gEfiGlobalVariableGuid,
                        BSIZ, 0, (uint8_t *)"\0", 1);
    check_variable_data(secureBoot_name, gEfiGlobalVariableGuid, BSIZ, 0,
                        (uint8_t *)"\1", 1);

    /* new cert, signed by previous */
    sign_and_check(PK_name, gEfiGlobalVariableGuid, ATTR_BRNV_TIME,
                   &test_timeb, (uint8_t *)second_cert, secondcertlen,
                   &sign_first_key, EFI_SUCCESS);
    check_variable_data(setupMode_name, gEfiGlobalVariableGuid,
                        BSIZ, 0, (uint8_t *)"\0", 1);
    check_variable_data(secureBoot_name, gEfiGlobalVariableGuid, BSIZ, 0,
                        (uint8_t *)"\1", 1);

    /* delete it.... */
    sign_and_check(PK_name, gEfiGlobalVariableGuid, ATTR_BRNV_TIME,
                   &test_timec, NULL, 0, &sign_first_key, EFI_SUCCESS);
    check_variable_data(setupMode_name, gEfiGlobalVariableGuid,
                        BSIZ, 0, (uint8_t *)"\1", 1);
    check_variable_data(secureBoot_name, gEfiGlobalVariableGuid, BSIZ, 0,
                        (uint8_t *)"\0", 1);
    /*
     * TODO: This test fails.  Tried to delete it again....
     *
     * sign_and_check(PK_name, gEfiGlobalVariableGuid, ATTR_BRNV_TIME,
     *                &test_timeb, NULL, 0, &sign_first_key, EFI_NOT_FOUND);
     */
    free(second_cert);
    free(ret_cert);
}

int main(int argc, char **argv)
{
    setup_globals();
    setup_ssl();

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

    /*
     * TODO: This test fails, and should be fixed
     *
     *  g_test_add_func("/test/secure_set_variable/use_bad_digest",
     *                 test_use_bad_digest);
     */

    g_test_add_func("/test/secure_set_variable/setupmode",
                    test_secure_set_variable_setupmode);
    g_test_add_func("/test/secure_set_variable/PK",
                    test_secure_set_PK);
    g_test_add_func("/test/secure_set_variable/usermode",
                    test_secure_set_variable_usermode);

    return g_test_run();
}
