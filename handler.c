/*
 * Copyright (c) Citrix Systems, Inc
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Portions derived from edk2 (https://github.com/tianocore/edk2)
 * with the following license:
 *
 * Copyright (c) 2004 - 2016, Intel Corporation. All rights reserved.
 * Copyright (c) 2008 - 2010, Apple Inc. All rights reserved.
 * Copyright (c) 2011 - 2015, ARM Limited. All rights reserved.
 * Copyright (c) 2014 - 2015, Linaro Limited. All rights reserved.
 * Copyright (c) 2013 - 2015, Red Hat, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>

#include <openssl/objects.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs7.h>
#include <openssl/err.h>

#include <backend.h>
#include <debug.h>
#include <efi.h>
#include <guid.h>
#include <serialize.h>
#include <handler.h>
#include <mor.h>
#include <ppi.h>

struct auth_info {
    const char *pretty_name;
    const uint8_t *name;
    UINTN name_len;
    const EFI_GUID *guid;
    const char *path;
    bool append;
    bool required;
    uint8_t *data;
    off_t data_len;
};

/* Some values from edk2. */
static const uint8_t mOidValue[9] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02};
static const uint8_t mSignatureSupport[] = {
    0x12,0xa5,0x6c,0x82,0x10,0xcf,0xc9,0x4a,0xb1,0x87,0xbe,0x01,0x49,0x66,0x31,0xbd, /* EFI_CERT_SHA1_GUID */
    0x26,0x16,0xc4,0xc1,0x4c,0x50,0x92,0x40,0xac,0xa9,0x41,0xf9,0x36,0x93,0x43,0x28, /* EFI_CERT_SHA256_GUID */
    0xe8,0x66,0x57,0x3c,0x9c,0x26,0x34,0x4e,0xaa,0x14,0xed,0x77,0x6e,0x85,0xb3,0xb6, /* EFI_CERT_RSA2048_GUID */
    0xa1,0x59,0xc0,0xa5,0xe4,0x94,0xa7,0x4a,0x87,0xb5,0xab,0x15,0x5c,0x2b,0xf0,0x72, /* EFI_CERT_X509_GUID */
};

static const uint8_t mSha256OidValue[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01};
static const EFI_SIGNATURE_ITEM mSupportSigItem[] = {
    {{{0x26, 0x16, 0xc4, 0xc1, 0x4c, 0x50, 0x92, 0x40, 0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93, 0x43, 0x28}}, 0, 32           }, /* EFI_CERT_SHA256_GUID */
    {{{0xe8, 0x66, 0x57, 0x3c, 0x9c, 0x26, 0x34, 0x4e, 0xaa, 0x14, 0xed, 0x77, 0x6e, 0x85, 0xb3, 0xb6}}, 0, 256          }, /* EFI_CERT_RSA2048_GUID */
    {{{0x90, 0x61, 0xb3, 0xe2, 0x9b, 0x87, 0x3d, 0x4a, 0xad, 0x8d, 0xf2, 0xe7, 0xbb, 0xa3, 0x27, 0x84}}, 0, 256          }, /* EFI_CERT_RSA2048_SHA256_GUID */
    {{{0x12, 0xa5, 0x6c, 0x82, 0x10, 0xcf, 0xc9, 0x4a, 0xb1, 0x87, 0xbe, 0x01, 0x49, 0x66, 0x31, 0xbd}}, 0, 20           }, /* EFI_CERT_SHA1_GUID */
    {{{0x4f, 0x44, 0xf8, 0x67, 0x43, 0x87, 0xf1, 0x48, 0xa3, 0x28, 0x1e, 0xaa, 0xb8, 0x73, 0x60, 0x80}}, 0, 256          }, /* EFI_CERT_RSA2048_SHA1_GUID */
    {{{0xa1, 0x59, 0xc0, 0xa5, 0xe4, 0x94, 0xa7, 0x4a, 0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72}}, 0, ((UINT32) ~0)}, /* EFI_CERT_X509_GUID */
    {{{0x33, 0x52, 0x6e, 0x0b, 0x5c, 0xa6, 0xc9, 0x44, 0x94, 0x07, 0xd9, 0xab, 0x83, 0xbf, 0xc8, 0xbd}}, 0, 28           }, /* EFI_CERT_SHA224_GUID */
    {{{0x07, 0x53, 0x3e, 0xff, 0xd0, 0x9f, 0xc9, 0x48, 0x85, 0xf1, 0x8a, 0xd5, 0x6c, 0x70, 0x1e, 0x01}}, 0, 48           }, /* EFI_CERT_SHA384_GUID */
    {{{0xae, 0x0f, 0x3e, 0x09, 0xc4, 0xa6, 0x50, 0x4f, 0x9f, 0x1b, 0xd4, 0x1e, 0x2b, 0x89, 0xc1, 0x9a}}, 0, 64           }, /* EFI_CERT_SHA512_GUID */
    {{{0x92, 0xa4, 0xd2, 0x3b, 0xc0, 0x96, 0x79, 0x40, 0xb4, 0x20, 0xfc, 0xf9, 0x8e, 0xf1, 0x03, 0xed}}, 0, 48           }, /* EFI_CERT_X509_SHA256_GUID */
    {{{0x6e, 0x87, 0x76, 0x70, 0xc2, 0x80, 0xe6, 0x4e, 0xaa, 0xd2, 0x28, 0xb3, 0x49, 0xa6, 0x86, 0x5b}}, 0, 64           }, /* EFI_CERT_X509_SHA384_GUID */
    {{{0x63, 0xbf, 0x6d, 0x44, 0x02, 0x25, 0xda, 0x4c, 0xbc, 0xfa, 0x24, 0x65, 0xd2, 0xb0, 0xfe, 0x9d}}, 0, 80           } /* EFI_CERT_X509_SHA512_GUID */
};

#define NUM_OF_SUPPORTED_SIG_ITEMS    (sizeof(mSupportSigItem) / sizeof(EFI_SIGNATURE_ITEM))

static const uint8_t EFI_SETUP_MODE_NAME[] = {'S',0,'e',0,'t',0,'u',0,'p',0,'M',0,'o',0,'d',0,'e',0};
static const uint8_t EFI_AUDIT_MODE_NAME[] = {'A',0,'u',0,'d',0,'i',0,'t',0,'M',0,'o',0,'d',0,'e',0};
static const uint8_t EFI_DEPLOYED_MODE_NAME[] = {'D',0,'e',0,'p',0,'l',0,'o',0,'y',0,'e',0,'d',0,'M',0,'o',0,'d',0,'e',0};
static const uint8_t EFI_PLATFORM_KEY_NAME[] = {'P',0,'K',0};
static const uint8_t EFI_KEY_EXCHANGE_KEY_NAME[] = {'K',0,'E',0,'K',0};
static const uint8_t EFI_SECURE_BOOT_MODE_NAME[] = {'S',0,'e',0,'c',0,'u',0,'r',0,'e',0,'B',0,'o',0,'o',0,'t',0};
static const uint8_t EFI_SIGNATURE_SUPPORT_NAME[] = {'S',0,'i',0,'g',0,'n',0,'a',0,'t',0,'u',0,'r',0,'e',0,'S',0,'u',0,'p',0,'p',0,'o',0,'r',0,'t',0};

const uint8_t TCG2_PHYSICAL_PRESENCEFLAGSLOCK_NAME[] = {
    'T', 0, 'c', 0, 'g', 0, '2', 0, 'P', 0, 'h', 0, 'y', 0, 's', 0, 'i', 0, 'c', 0, 'a', 0, 'l', 0, 'P', 0, 'r', 0, 'e', 0,
    's', 0, 'e', 0, 'n', 0, 'c', 0, 'e', 0, 'F', 0, 'l', 0, 'a', 0, 'g', 0, 's', 0, 'L', 0, 'o', 0, 'c', 0,'k', 0
};
const size_t TCG2_PHYSICAL_PRESENCEFLAGSLOCK_NAME_SIZE = sizeof(TCG2_PHYSICAL_PRESENCEFLAGSLOCK_NAME);

static const uint8_t TCG2_PHYSICAL_PRESENCEFLAGS_NAME[] = {
     'T', 0, 'c', 0, 'g', 0, '2', 0, 'P', 0, 'h', 0, 'y', 0, 's', 0, 'i', 0, 'c', 0, 'a', 0, 'l', 0, 'P', 0, 'r', 0, 'e', 0,
     's', 0, 'e', 0, 'n', 0, 'c', 0, 'e', 0, 'F', 0, 'l', 0, 'a', 0, 'g', 0, 's', 0
};

static const uint8_t EFI_IMAGE_SECURITY_DATABASE[] = {'d',0,'b',0};
static const uint8_t EFI_IMAGE_SECURITY_DATABASE1[] = {'d',0,'b',0,'x',0};
static const uint8_t EFI_IMAGE_SECURITY_DATABASE2[] = {'d',0,'b',0,'t',0};

#define AUTH_PATH_PREFIX "/var/lib/varstored"

/*
 * The macro AUTH_ONLY_PK_REQUIRED makes KEK and DB files optional, allowing
 * varstored and varstore-sb-state to copy only the PK file (which is always
 * present) and switch the VM to user mode. This will prevent the VM to boot
 * if it has SecureBoot enabled by the user but UEFI certificates are missing.
 */
#ifdef AUTH_ONLY_PK_REQUIRED
#define AUTH_DB_REQUIRED false
#define AUTH_KEK_REQUIRED false
#else
#define AUTH_DB_REQUIRED true
#define AUTH_KEK_REQUIRED true
#endif

/*
 * Array of auth_info structs containing the information about the keys
 * we need. Avoid switching to user mode before importing other keys by
 * importing PK key last, otherwise this would require signing other keys
 * in Dom0.
 */
static struct auth_info auth_info[] = {
    {"dbx", EFI_IMAGE_SECURITY_DATABASE1, sizeof(EFI_IMAGE_SECURITY_DATABASE1),
     &gEfiImageSecurityDatabaseGuid, AUTH_PATH_PREFIX "/dbx.auth", true, false},
    {"db", EFI_IMAGE_SECURITY_DATABASE, sizeof(EFI_IMAGE_SECURITY_DATABASE),
     &gEfiImageSecurityDatabaseGuid, AUTH_PATH_PREFIX "/db.auth", false, AUTH_DB_REQUIRED},
    {"KEK", EFI_KEY_EXCHANGE_KEY_NAME, sizeof(EFI_KEY_EXCHANGE_KEY_NAME),
     &gEfiGlobalVariableGuid, AUTH_PATH_PREFIX "/KEK.auth", false, AUTH_KEK_REQUIRED},
    {"PK", EFI_PLATFORM_KEY_NAME, sizeof(EFI_PLATFORM_KEY_NAME),
     &gEfiGlobalVariableGuid, AUTH_PATH_PREFIX "/PK.auth", false, true},
};

struct efi_variable *var_list;
bool secure_boot_enable;
bool auth_enforce = true;
bool persistent = true;

static uint64_t
get_space_usage(void)
{
    struct efi_variable *l;
    uint64_t total = 0;

    l = var_list;
    while (l) {
        total += l->name_len + l->data_len + VARIABLE_SIZE_OVERHEAD;
        l = l->next;
    }

    return total;
}

/* A limited version of SetVariable for internal use. */
EFI_STATUS
internal_set_variable(const uint8_t *name, UINTN name_len, const EFI_GUID *guid,
                      const uint8_t *data, UINTN data_len, UINT32 attr)
{
    struct efi_variable *l;
    uint8_t *new_data;

    new_data = malloc(data_len);
    if (!new_data)
        return EFI_DEVICE_ERROR;
    memcpy(new_data, data, data_len);

    l = var_list;
    while (l) {
        if (l->name_len == name_len &&
                !memcmp(l->name, name, name_len) &&
                !memcmp(&l->guid, guid, GUID_LEN)) {
            free(l->data);
            l->data = new_data;
            l->data_len = data_len;
            return EFI_SUCCESS;
        }
        l = l->next;
    }

    l = calloc(1, sizeof *l);
    if (!l) {
        free(new_data);
        return EFI_DEVICE_ERROR;
    }
    l->name = malloc(name_len);
    if (!l->name) {
        free(l);
        free(new_data);
        return EFI_DEVICE_ERROR;
    }
    memcpy(l->name, name, name_len);
    l->name_len = name_len;
    memcpy(&l->guid, guid, GUID_LEN);
    l->data = new_data;
    l->data_len = data_len;
    l->attributes = attr;
    l->next = var_list;
    var_list = l;

    return EFI_SUCCESS;
}

/* A limited version of GetVariable for internal use. */
EFI_STATUS
internal_get_variable(const uint8_t *name, UINTN name_len, const EFI_GUID *guid,
                      uint8_t **data, UINTN *data_len)
{
    struct efi_variable *l;

    l = var_list;
    while (l) {
        if (l->name_len == name_len &&
                !memcmp(l->name, name, name_len) &&
                !memcmp(&l->guid, guid, GUID_LEN)) {

            *data = malloc(l->data_len);
            if (!*data)
                return EFI_DEVICE_ERROR;
            memcpy(*data, l->data, l->data_len);
            *data_len = l->data_len;
            return EFI_SUCCESS;
        }
        l = l->next;
    }

    return EFI_NOT_FOUND;
}

static void
do_get_variable(uint8_t *comm_buf)
{
    uint8_t *ptr, *name;
    EFI_GUID guid;
    UINTN name_len, data_len;
    BOOLEAN at_runtime;
    struct efi_variable *l;

    ptr = comm_buf;
    unserialize_uint32(&ptr); /* version */
    unserialize_command(&ptr);
    name = unserialize_data(&ptr, &name_len, NAME_LIMIT);
    if (!name) {
        serialize_result(&comm_buf, name_len == 0 ? EFI_NOT_FOUND : EFI_DEVICE_ERROR);
        return;
    }
    unserialize_guid(&ptr, &guid);
    data_len = unserialize_uintn(&ptr);
    at_runtime = unserialize_boolean(&ptr);

    ptr = comm_buf;
    l = var_list;
    while (l) {
        if (l->name_len == name_len &&
                !memcmp(l->name, name, name_len) &&
                !memcmp(&l->guid, &guid, GUID_LEN)) {
            if (at_runtime && !(l->attributes & EFI_VARIABLE_RUNTIME_ACCESS)) {
                l = l->next;
                continue;
            }
            if (data_len < l->data_len) {
                serialize_result(&ptr, EFI_BUFFER_TOO_SMALL);
                serialize_uintn(&ptr, l->data_len);
            } else {
                serialize_result(&ptr, EFI_SUCCESS);
                serialize_uint32(&ptr, l->attributes);
                serialize_data(&ptr, l->data, l->data_len);
            }
            goto out;
        }
        l = l->next;
    }

    serialize_result(&ptr, EFI_NOT_FOUND);

out:
    free(name);
}

static X509 *
X509_from_buf(const uint8_t *buf, long len)
{
    const uint8_t *ptr = buf;

    return d2i_X509(NULL, &ptr, len);
}

static uint8_t *
X509_to_buf(X509 *cert, int *len)
{
    uint8_t *ptr, *buf;

    *len = i2d_X509(cert, NULL);
    buf = malloc(*len);
    if (!buf)
        return NULL;
    ptr = buf;
    i2d_X509(cert, &ptr);

    return buf;
}

/*
 * Get the TBS certificate from an X509 certificate.
 * Adapted from edk2.
 *
 * tbs_cert should be freed by the caller.
 */
static EFI_STATUS
X509_get_tbs_cert(X509 *cert, uint8_t **tbs_cert, UINTN *tbs_len)
{
    int asn1_tag, obj_class, len, ret;
    long tmp_len;
    uint8_t *buf, *ptr, *tbs_ptr;

    buf = X509_to_buf(cert, &len);
    if (!buf)
        return EFI_DEVICE_ERROR;

    ptr = buf;
    tmp_len = 0;
    ret = ASN1_get_object((const unsigned char **)&ptr, &tmp_len, &asn1_tag,
                          &obj_class, len);
    if (ret == 0x80 || asn1_tag != V_ASN1_SEQUENCE) {
        free(buf);
        return EFI_SECURITY_VIOLATION;
    }

    tbs_ptr = ptr;
    ret = ASN1_get_object((const unsigned char **)&ptr, &tmp_len, &asn1_tag,
                          &obj_class, tmp_len);
    if (ret == 0x80 || asn1_tag != V_ASN1_SEQUENCE) {
        free(buf);
        return EFI_SECURITY_VIOLATION;
    }

    *tbs_len = tmp_len + (ptr - tbs_ptr);
    *tbs_cert = malloc(*tbs_len);
    if (!*tbs_cert) {
        free(buf);
        return EFI_DEVICE_ERROR;
    }
    memcpy(*tbs_cert, tbs_ptr, *tbs_len);
    free(buf);

    return EFI_SUCCESS;
}

/*
 * Calculate SHA256 digest of:
 *   SignerCert CommonName + ToplevelCert tbsCertificate
 * Adapted from edk2.
 */
static EFI_STATUS
sha256_sig(STACK_OF(X509) *certs, X509 *top_level_cert, uint8_t *digest)
{
    SHA256_CTX ctx;
    char name[128];
    X509_NAME *x509_name;
    uint8_t *tbs_cert;
    UINTN tbs_cert_len;
    EFI_STATUS status;
    int name_len;

    x509_name = X509_get_subject_name(sk_X509_value(certs, 0));
    if (!x509_name)
        return EFI_SECURITY_VIOLATION;

    name_len = X509_NAME_get_text_by_NID(x509_name, NID_commonName,
                                         name, sizeof(name));
    if (name_len < 0)
        return EFI_SECURITY_VIOLATION;
    name_len++; /* Include trailing NUL character */

    status = X509_get_tbs_cert(top_level_cert, &tbs_cert, &tbs_cert_len);
    if (status != EFI_SUCCESS)
        return status;

    status = EFI_DEVICE_ERROR;
    if (!SHA256_Init(&ctx))
        goto out;

    if (!SHA256_Update(&ctx, name, strlen(name)))
        goto out;

    if (!SHA256_Update(&ctx, tbs_cert, tbs_cert_len))
        goto out;

    if (!SHA256_Final(digest, &ctx))
        goto out;

    status = EFI_SUCCESS;
out:
    free(tbs_cert);
    return status;
}

#ifndef X509_V_FLAG_NO_CHECK_TIME
#define OPENSSL_NO_CHECK_TIME 0

/*
 * Verification callback function to override the existing callbacks in
 * OpenSSL.  This is required due to the lack of X509_V_FLAG_NO_CHECK_TIME in
 * OpenSSL 1.0.2.  This function has been taken directly from an older version
 * of edk2 and been to use X509_V_ERR_CERT_HAS_EXPIRED and
 * X509_V_ERR_CERT_NOT_YET_VALID since verification of the timestamps in
 * certificates is not typically done in firmware due to untrustworthy system
 * time. This part was taken from a patch sent to the edk2 mailing list by
 * David Woodhouse entitled "CryptoPkg: Remove OpenSSL hack and manually ignore
 * validity time range".
 */
static int
X509_verify_cb(int status, X509_STORE_CTX *context)
{
    X509_OBJECT *obj = NULL;
    int error;
    int index;
    int count;

    error = X509_STORE_CTX_get_error(context);

    if ((error == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT) ||
            (error == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY)) {
        obj = malloc(sizeof(*obj));
        if (!obj)
            return 0;

        obj->type = X509_LU_X509;
        obj->data.x509 = context->current_cert;

        CRYPTO_w_lock (CRYPTO_LOCK_X509_STORE);

        if (X509_OBJECT_retrieve_match(context->ctx->objs, obj)) {
            status = 1;
        } else {
            if (error == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY) {
                count = sk_X509_num(context->chain);
                for (index = 0; index < count; index++) {
                    obj->data.x509 = sk_X509_value(context->chain, index);
                    if (X509_OBJECT_retrieve_match(context->ctx->objs, obj)) {
                        status = 1;
                        break;
                    }
                }
            }
        }

        CRYPTO_w_unlock (CRYPTO_LOCK_X509_STORE);
    }

    if ((error == X509_V_ERR_CERT_UNTRUSTED) ||
            (error == X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE) ||
            (error == X509_V_ERR_CERT_HAS_EXPIRED) ||
            (error == X509_V_ERR_CERT_NOT_YET_VALID))
        status = 1;

    free(obj);

    return status;
}
#else
#define OPENSSL_NO_CHECK_TIME X509_V_FLAG_NO_CHECK_TIME
#endif

/*
 * Check whether input p7data is a wrapped ContentInfo structure or not. Wrap
 * it if needed. While the specification seems to indicate that it should not
 * be wrapped (i.e. it should just be signed data), edk2 accepts either and at
 * least one existing tool signs SetVariable updates with a wrapped structure.
 * Adapted from edk2. This function contains several magic numbers since it is
 * parsing DER-encoded PKCS #7 ASN.1 object by hand. The caller must free
 * wrap_data on success.
 */
static EFI_STATUS
wrap_pkcs7_data(const uint8_t *p7data, UINTN p7_len,
                uint8_t **wrap_data, UINTN *wrap_len)
{
    uint8_t *sig_data;

    /*
     * We need to look at the first 17 bytes to determine whether the input
     * data is wrapped or not. The length needs to be at least this long in
     * either case so check and bail early if needed.
     */
    if (p7_len < 17) {
        return EFI_SECURITY_VIOLATION;
    }

    if ((p7data[4] == 0x06) && (p7data[5] == 0x09) &&
            !memcmp(p7data + 6, mOidValue, sizeof(mOidValue)) &&
            (p7data[15] == 0xa0) && (p7data[16] == 0x82)) {
        *wrap_data = malloc(p7_len);
        if (!*wrap_data)
            return EFI_DEVICE_ERROR;
        memcpy(*wrap_data, p7data, p7_len);
        *wrap_len = p7_len;
        return EFI_SUCCESS;
    }

    *wrap_len = p7_len + 19;
    *wrap_data = malloc(*wrap_len);
    if (!*wrap_data)
        return EFI_DEVICE_ERROR;

    sig_data = *wrap_data;
    sig_data[0] = 0x30;
    sig_data[1] = 0x82;
    sig_data[2] = ((uint16_t)(*wrap_len - 4)) >> 8;
    sig_data[3] = ((uint16_t)(*wrap_len - 4)) & 0xff;
    sig_data[4] = 0x06;
    sig_data[5] = 0x09;
    memcpy(sig_data + 6, mOidValue, sizeof(mOidValue));
    sig_data[15] = 0xA0;
    sig_data[16] = 0x82;
    sig_data[17] = ((uint16_t)p7_len) >> 8;
    sig_data[18] = ((uint16_t)p7_len) & 0xff;
    memcpy(sig_data + 19, p7data, p7_len);

    return EFI_SUCCESS;
}

/*
 * Verify the validity of PKCS#7 data.
 * Adapted from edk2.
 */
static EFI_STATUS
pkcs7_verify(const uint8_t *p7data, UINTN p7_len, X509 *trusted_cert,
             uint8_t *verify_buf, UINTN verify_len)
{
    EFI_STATUS status;
    const uint8_t *ptr;
    PKCS7 *pkcs7 = NULL;
    BIO *data_bio = NULL;
    X509_STORE *cert_store = NULL;

    ptr = p7data;
    pkcs7 = d2i_PKCS7(NULL, &ptr, (int)p7_len);
    if (!pkcs7) {
        status = EFI_SECURITY_VIOLATION;
        goto out;
    }

    if (!PKCS7_type_is_signed(pkcs7)) {
        status = EFI_SECURITY_VIOLATION;
        goto out;
    }

    cert_store = X509_STORE_new();
    if (!cert_store) {
        status = EFI_DEVICE_ERROR;
        goto out;
    }

#ifndef X509_V_FLAG_NO_CHECK_TIME
    cert_store->verify_cb = X509_verify_cb;
#endif

    if (!(X509_STORE_add_cert(cert_store, trusted_cert))) {
        status = EFI_SECURITY_VIOLATION;
        goto out;
    }

    data_bio = BIO_new(BIO_s_mem());
    if (!data_bio) {
        status = EFI_DEVICE_ERROR;
        goto out;
    }

    if (BIO_write(data_bio, verify_buf, (int)verify_len) != verify_len) {
        status = EFI_SECURITY_VIOLATION;
        goto out;
    }

    X509_STORE_set_flags(cert_store,
                         X509_V_FLAG_PARTIAL_CHAIN | OPENSSL_NO_CHECK_TIME);
    X509_STORE_set_purpose(cert_store, X509_PURPOSE_ANY);

    if (PKCS7_verify(pkcs7, NULL, cert_store, data_bio, NULL, PKCS7_BINARY))
        status = EFI_SUCCESS;
    else {
        if (log_level >= LOG_LVL_DEBUG) {
            ERR_load_crypto_strings();
            DBG("verify_error : %s\n", ERR_error_string(ERR_get_error(), NULL));
            ERR_free_strings();
        }
        status = EFI_SECURITY_VIOLATION;
    }

out:
    BIO_free(data_bio);
    X509_STORE_free(cert_store);
    PKCS7_free(pkcs7);
    return status;
}

/*
 * Get the signer's certificates from PKCS#7 signed data.
 * Adapted from edk2.
 *
 * The caller is responsible for free the pkcs7 context and the stack of certs
 * (but not the certs themselves). The certs should not be used after the
 * context is freed.
 */
static EFI_STATUS
pkcs7_get_signers(const uint8_t *p7data, UINTN p7_len,
                  PKCS7 **pkcs7, STACK_OF(X509) **certs)
{
    const uint8_t *ptr;

    ptr = p7data;
    *pkcs7 = d2i_PKCS7(NULL, &ptr, (int)p7_len);
    if (!*pkcs7)
        return EFI_SECURITY_VIOLATION;

    if (!PKCS7_type_is_signed(*pkcs7)) {
        PKCS7_free(*pkcs7);
        *pkcs7 = NULL;
        return EFI_SECURITY_VIOLATION;
    }

    *certs = PKCS7_get0_signers(*pkcs7, NULL, PKCS7_BINARY);
    if (!*certs) {
        PKCS7_free(*pkcs7);
        *pkcs7 = NULL;
        return EFI_SECURITY_VIOLATION;
    }

    return EFI_SUCCESS;
}

/* Returns true iff b is later than a */
static bool time_later(EFI_TIME *a, EFI_TIME *b)
{
    if (a->Year != b->Year)
        return b->Year > a->Year;
    else if (a->Month != b->Month)
        return b->Month > a->Month;
    else if (a->Day != b->Day)
        return b->Day > a->Day;
    else if (a->Hour != b->Hour)
        return b->Hour > a->Hour;
    else if (a->Minute != b->Minute)
        return b->Minute > a->Minute;
    else
        return b->Second > a->Second;
}

enum auth_type {
    AUTH_TYPE_PK,
    AUTH_TYPE_KEK,
    AUTH_TYPE_PAYLOAD,
    AUTH_TYPE_PRIVATE,
    AUTH_TYPE_NONE,
};

static EFI_STATUS
check_signature_list_format(uint8_t *data, UINTN data_len, bool is_pk)
{
    EFI_SIGNATURE_LIST *sig_list;
    int count;
    UINTN remaining, list_items;
    int i;
    size_t list_body_size;

    if (data_len == 0)
        return EFI_SUCCESS;

    count = 0;
    sig_list  = (EFI_SIGNATURE_LIST *)data;
    remaining = data_len;

    while ((remaining >= sizeof(*sig_list)) &&
           (remaining >= sig_list->SignatureListSize)) {
        for (i = 0; i < NUM_OF_SUPPORTED_SIG_ITEMS; i++) {
            if (!memcmp(&sig_list->SignatureType, &mSupportSigItem[i].SigType,
                        GUID_LEN)) {
                if (mSupportSigItem[i].SigDataSize != (UINT32)~0 &&
                        (sig_list->SignatureSize - GUID_LEN) != mSupportSigItem[i].SigDataSize)
                    return EFI_INVALID_PARAMETER;
                if (mSupportSigItem[i].SigHeaderSize != ((UINT32) ~0) &&
                        sig_list->SignatureHeaderSize != mSupportSigItem[i].SigHeaderSize)
                    return EFI_INVALID_PARAMETER;
                break;
            }
        }

        if (i == NUM_OF_SUPPORTED_SIG_ITEMS)
            return EFI_INVALID_PARAMETER;

        /*
         * Check SignatureHeaderSize since its size may be undefined in
         * mSupportSigItem.
         */
        if (sig_list->SignatureHeaderSize >
                (sig_list->SignatureListSize - sizeof(EFI_SIGNATURE_LIST)))
            return EFI_INVALID_PARAMETER;

        /*
         * Check SignatureSize since its size may be undefined in
         * mSupportSigItem.
         */
        if (sig_list->SignatureSize == 0)
            return EFI_INVALID_PARAMETER;

        list_body_size = sig_list->SignatureListSize - sizeof(EFI_SIGNATURE_LIST) -
                         sig_list->SignatureHeaderSize;

        if (list_body_size % sig_list->SignatureSize != 0)
            return EFI_INVALID_PARAMETER;

        list_items = list_body_size / sig_list->SignatureSize;

        /* Don't allow signature lists with no items in it. */
        if (list_items == 0)
            return EFI_INVALID_PARAMETER;

        if (!memcmp(&sig_list->SignatureType, &gEfiCertX509Guid, GUID_LEN)) {
            UINTN cert_len;
            X509 *cert;
            EVP_PKEY *pkey;
            RSA *ctx;
            bool fail;
            EFI_SIGNATURE_DATA *cert_data =
                    (EFI_SIGNATURE_DATA *)((uint8_t *)sig_list +
                    sizeof(EFI_SIGNATURE_LIST) + sig_list->SignatureHeaderSize);
            void *end = (void *)cert_data + sig_list->SignatureSize * list_items;

            if (sig_list->SignatureSize < EFI_SIG_DATA_SIZE)
                return EFI_INVALID_PARAMETER;
            cert_len = sig_list->SignatureSize - EFI_SIG_DATA_SIZE;

            while (cert_data != end) {
                cert = X509_from_buf(cert_data->SignatureData, cert_len);
                if (!cert)
                    return EFI_INVALID_PARAMETER;
                pkey = X509_get_pubkey(cert);
                if (!pkey || EVP_PKEY_id(pkey) != EVP_PKEY_RSA) {
                    X509_free(cert);
                    return EFI_INVALID_PARAMETER;
                }
                ctx = EVP_PKEY_get1_RSA(pkey);
                fail = ctx == NULL;
                RSA_free(ctx);
                EVP_PKEY_free(pkey);
                X509_free(cert);
                if (fail)
                    return EFI_INVALID_PARAMETER;
                cert_data = (void *)cert_data + sig_list->SignatureSize;
            }
        }

        count += list_items;
        remaining -= sig_list->SignatureListSize;
        sig_list = (EFI_SIGNATURE_LIST *)((uint8_t *)sig_list +
                   sig_list->SignatureListSize);
    }

    if (((uint8_t *)sig_list - data) != data_len)
        return EFI_INVALID_PARAMETER;

    if (is_pk && count > 1)
        return EFI_INVALID_PARAMETER;

    return EFI_SUCCESS;
}

/*
 * Verify the authentication descriptor for a time based authentication
 * variable.
 *
 * On success, payload_out and payload_len_out refer to the actual payload.
 * The caller is responsible for freeing.
 * digest is the digest of the signer's certificates.
 * timestamp is the associated with the descriptor.
 */
static EFI_STATUS
verify_auth_var_type(uint8_t *name, UINTN name_len,
                     uint8_t *data, UINTN data_len,
                     EFI_GUID *guid, UINT32 attr, bool append,
                     struct efi_variable *cur, enum auth_type auth_type,
                     uint8_t **payload_out, UINTN *payload_len_out,
                     uint8_t *digest, EFI_TIME *timestamp)
{
    uint8_t *ptr, *sig = NULL, *payload, *verify_buf = NULL, *tlc_buf = NULL;
    uint8_t *var_data = NULL;
    EFI_VARIABLE_AUTHENTICATION_2 *d;
    UINTN sig_len, verify_len, payload_len, var_len;
    STACK_OF(X509) *certs = NULL;
    X509 *top_level_cert;
    PKCS7 *pkcs7 = NULL;
    EFI_STATUS status;

    if (data_len < offsetof(EFI_VARIABLE_AUTHENTICATION_2, AuthInfo.CertData))
        return EFI_SECURITY_VIOLATION;

    d = (EFI_VARIABLE_AUTHENTICATION_2 *)data;

    *timestamp = d->TimeStamp;
    if ((timestamp->Pad1 != 0) ||
            (timestamp->Nanosecond != 0) ||
            (timestamp->TimeZone != 0) ||
            (timestamp->Daylight != 0) ||
            (timestamp->Pad2 != 0))
        return EFI_SECURITY_VIOLATION;

    if (auth_enforce && auth_type != AUTH_TYPE_NONE && !append && cur &&
            !time_later(&cur->timestamp, timestamp))
        return EFI_SECURITY_VIOLATION;

    if ((d->AuthInfo.Hdr.wCertificateType != WIN_CERT_TYPE_EFI_GUID) ||
            memcmp(&d->AuthInfo.CertType, &gEfiCertPkcs7Guid, GUID_LEN))
        return EFI_SECURITY_VIOLATION;

    sig_len = d->AuthInfo.Hdr.dwLength - offsetof(WIN_CERTIFICATE_UEFI_GUID, CertData);
    if (sig_len > (data_len - offsetof(EFI_VARIABLE_AUTHENTICATION_2, AuthInfo.CertData)))
        return EFI_SECURITY_VIOLATION;

    payload = d->AuthInfo.CertData + sig_len;
    payload_len = data_len - offsetof(EFI_VARIABLE_AUTHENTICATION_2, AuthInfo) - d->AuthInfo.Hdr.dwLength;

    if (auth_type == AUTH_TYPE_NONE) {
        sig = malloc(sig_len);
        if (!sig)
            return EFI_DEVICE_ERROR;
        memcpy(sig, d->AuthInfo.CertData, sig_len);
    } else {
        status = wrap_pkcs7_data(d->AuthInfo.CertData, sig_len, &sig, &sig_len);
        if (status != EFI_SUCCESS)
            goto out;

        /*
         * Verify that the signature uses a digest algorithm of SHA-256 as
         * required by the specification.  Assumes that two-byte length
         * encoding has been used. Adapted from edk2.
         */
        if (sig_len >= (32 + sizeof(mSha256OidValue)) &&
                ((sig[20] != 0x82) ||
                 memcmp(sig + 32, &mSha256OidValue, sizeof(mSha256OidValue)))) {
            status = EFI_SECURITY_VIOLATION;
            goto out;
        }
    }

    /* VariableName, VendorGuid, Attributes, TimeStamp, Data */
    verify_len = name_len + GUID_LEN + sizeof(UINT32) + sizeof(EFI_TIME) +
                 payload_len;
    verify_buf = malloc(verify_len);
    if (!verify_buf) {
        status = EFI_DEVICE_ERROR;
        goto out;
    }

    ptr = verify_buf;
    memcpy(ptr, name, name_len);
    ptr += name_len;
    memcpy(ptr, guid, GUID_LEN);
    ptr += GUID_LEN;
    if (append)
        attr |= EFI_VARIABLE_APPEND_WRITE;
    memcpy(ptr, &attr, sizeof attr);
    ptr += sizeof attr;
    memcpy(ptr, &d->TimeStamp, sizeof d->TimeStamp);
    ptr += sizeof d->TimeStamp;
    memcpy(ptr, payload, payload_len);

    if (auth_type == AUTH_TYPE_PK) {
        EFI_SIGNATURE_LIST *cert_list;
        EFI_SIGNATURE_DATA *cert;
        int tlc_len;

        status = pkcs7_get_signers(sig, sig_len, &pkcs7, &certs);
        if (status != EFI_SUCCESS)
            goto out;
        if (sk_X509_num(certs) == 0) {
            status = EFI_SECURITY_VIOLATION;
            goto out;
        }
        top_level_cert = sk_X509_value(certs, sk_X509_num(certs) - 1);

        tlc_buf = X509_to_buf(top_level_cert, &tlc_len);
        if (!tlc_buf) {
            status = EFI_DEVICE_ERROR;
            goto out;
        }

        status = internal_get_variable(EFI_PLATFORM_KEY_NAME,
                                       sizeof(EFI_PLATFORM_KEY_NAME),
                                       &gEfiGlobalVariableGuid,
                                       &var_data, &var_len);
        if (status != EFI_SUCCESS) {
            status = EFI_SECURITY_VIOLATION;
            goto out;
        }

        cert_list = (EFI_SIGNATURE_LIST *)var_data;
        cert = (EFI_SIGNATURE_DATA *)((uint8_t *)cert_list +
               sizeof(EFI_SIGNATURE_LIST) + cert_list->SignatureHeaderSize);
        if ((tlc_len != (cert_list->SignatureSize - EFI_SIG_DATA_SIZE)) ||
                memcmp(cert->SignatureData, tlc_buf, tlc_len)) {
            status = EFI_SECURITY_VIOLATION;
            goto out;
        }

        status = pkcs7_verify(sig, sig_len, top_level_cert,
                              verify_buf, verify_len);
        if (status == EFI_SUCCESS) {
            *payload_len_out = payload_len;
            *payload_out = malloc(payload_len);
            if (*payload_out)
                memcpy(*payload_out, payload, payload_len);
            else
                status = EFI_DEVICE_ERROR;
        }
    } else if (auth_type == AUTH_TYPE_KEK) {
        EFI_SIGNATURE_LIST *cert_list;
        EFI_SIGNATURE_DATA *cert;
        int remaining, i, count;
        X509 *trusted_cert;

        status = internal_get_variable(EFI_KEY_EXCHANGE_KEY_NAME,
                                       sizeof(EFI_KEY_EXCHANGE_KEY_NAME),
                                       &gEfiGlobalVariableGuid,
                                       &var_data, &var_len);
        if (status != EFI_SUCCESS) {
            status = EFI_SECURITY_VIOLATION;
            goto out;
        }

        remaining = (UINT32)var_len;
        /*
         * cert_list (i.e. the contents of KEK) was verified to be valid when
         * it was written. Therefore no checking of validity is needed here.
         */
        cert_list = (EFI_SIGNATURE_LIST *)var_data;
        while (remaining > 0) {
            if (!memcmp(&cert_list->SignatureType, &gEfiCertX509Guid, GUID_LEN)) {
                cert = (EFI_SIGNATURE_DATA *)((uint8_t *)cert_list +
                       sizeof(EFI_SIGNATURE_LIST) + cert_list->SignatureHeaderSize);
                count  = (cert_list->SignatureListSize - sizeof(EFI_SIGNATURE_LIST) -
                          cert_list->SignatureHeaderSize) / cert_list->SignatureSize;

                for (i = 0; i < count; i++) {
                    trusted_cert = X509_from_buf(cert->SignatureData,
                        cert_list->SignatureSize - EFI_SIG_DATA_SIZE);
                    if (trusted_cert) {
                        status = pkcs7_verify(sig, sig_len, trusted_cert,
                                              verify_buf, verify_len);
                        X509_free(trusted_cert);
                        if (status == EFI_SUCCESS) {
                            *payload_len_out = payload_len;
                            *payload_out = malloc(payload_len);
                            if (*payload_out)
                                memcpy(*payload_out, payload, payload_len);
                            else
                                status = EFI_DEVICE_ERROR;
                            goto out;
                        }
                    }
                    cert = (EFI_SIGNATURE_DATA *)((uint8_t *)cert +
                           cert_list->SignatureSize);
                }
            }
            remaining -= cert_list->SignatureListSize;
            cert_list = (EFI_SIGNATURE_LIST *)((uint8_t *)cert_list +
                        cert_list->SignatureListSize);
        }
        status = EFI_SECURITY_VIOLATION;
    } else if (auth_type == AUTH_TYPE_PAYLOAD) {
        EFI_SIGNATURE_LIST *cert_list;
        EFI_SIGNATURE_DATA *cert;
        X509 *trusted_cert;

        if (payload_len == 0) {
            /* There is no payload therefore the variable will be deleted. */
            *payload_len_out = payload_len;
            *payload_out = NULL;
            status = EFI_SUCCESS;
            goto out;
        } else if (payload_len < sizeof(*cert_list)) {
            status = EFI_SECURITY_VIOLATION;
            goto out;
        }

        cert_list = (EFI_SIGNATURE_LIST *)payload;
        if (payload_len < (sizeof(*cert_list) + cert_list->SignatureHeaderSize +
                           cert_list->SignatureSize) ||
                cert_list->SignatureSize < EFI_SIG_DATA_SIZE) {
            status = EFI_SECURITY_VIOLATION;
            goto out;
        }
        cert = (EFI_SIGNATURE_DATA *)((uint8_t *)cert_list +
               sizeof(EFI_SIGNATURE_LIST) + cert_list->SignatureHeaderSize);
        trusted_cert = X509_from_buf(cert->SignatureData,
                                     cert_list->SignatureSize - EFI_SIG_DATA_SIZE);
        if (!trusted_cert) {
            status = EFI_SECURITY_VIOLATION;
            goto out;
        }

        status = pkcs7_verify(sig, sig_len, trusted_cert,
                              verify_buf, verify_len);
        X509_free(trusted_cert);
        if (status == EFI_SUCCESS) {
            *payload_len_out = payload_len;
            *payload_out = malloc(payload_len);
            if (*payload_out)
                memcpy(*payload_out, payload, payload_len);
            else
                status = EFI_DEVICE_ERROR;
        }
    } else if (auth_type == AUTH_TYPE_PRIVATE) {
        status = pkcs7_get_signers(sig, sig_len, &pkcs7, &certs);
        if (status != EFI_SUCCESS)
            goto out;
        if (sk_X509_num(certs) == 0) {
            status = EFI_SECURITY_VIOLATION;
            goto out;
        }
        top_level_cert = sk_X509_value(certs, sk_X509_num(certs) - 1);

        status = sha256_sig(certs, top_level_cert, digest);
        if (status != EFI_SUCCESS)
            goto out;

        /*
         * For private authenticated variables, permissive mode means that the
         * certificate used to sign the data does not need to match the
         * previous one. However, it still needs to exist and sign the data
         * correctly since it is used for verifying subsequent updates.
         */
        if (auth_enforce && cur &&
                memcmp(digest, cur->cert, SHA256_DIGEST_SIZE)) {
            status = EFI_SECURITY_VIOLATION;
            goto out;
        }

        status = pkcs7_verify(sig, sig_len, top_level_cert,
                              verify_buf, verify_len);
        if (status == EFI_SUCCESS) {
            *payload_len_out = payload_len;
            *payload_out = malloc(payload_len);
            if (*payload_out)
                memcpy(*payload_out, payload, payload_len);
            else
                status = EFI_DEVICE_ERROR;
        }
    } else if (auth_type == AUTH_TYPE_NONE) {
        status = EFI_SUCCESS;
        *payload_len_out = payload_len;
        *payload_out = malloc(payload_len);
        if (*payload_out)
            memcpy(*payload_out, payload, payload_len);
        else
            status = EFI_DEVICE_ERROR;
    } else {
        status = EFI_DEVICE_ERROR;
    }

out:
    free(sig);
    free(var_data);
    free(tlc_buf);
    free(verify_buf);
    sk_X509_free(certs);
    PKCS7_free(pkcs7);
    return status;
}

static EFI_STATUS verify_auth_var(uint8_t *name, UINTN name_len,
                                  uint8_t *data, UINTN data_len,
                                  EFI_GUID *guid, UINT32 attr, bool append,
                                  struct efi_variable *cur,
                                  uint8_t **payload_out, UINTN *payload_len_out,
                                  uint8_t *digest, EFI_TIME *timestamp)
{
    EFI_STATUS status;
    uint8_t *var;
    uint8_t setup_mode, secure_boot;
    UINTN var_len;

    *payload_out = NULL;

    status = internal_get_variable(EFI_SETUP_MODE_NAME,
                                   sizeof(EFI_SETUP_MODE_NAME),
                                   &gEfiGlobalVariableGuid, &var, &var_len);
    if (status != EFI_SUCCESS)
        return status;
    setup_mode = var[0];
    free(var);

    if (name_len == sizeof(EFI_PLATFORM_KEY_NAME) &&
            !memcmp(name, EFI_PLATFORM_KEY_NAME, name_len) &&
            !memcmp(guid, &gEfiGlobalVariableGuid, GUID_LEN)) {
        enum auth_type type = AUTH_TYPE_PK;

        /*
         * For the PK, the spec states:
         * "The variable has the format of a signature database as described in
         * “Signature Database” below, with exactly one entry."
         * Enforce this, as to be consistent with check_signature_list_format
         */
        if (append && cur) {
            status = EFI_INVALID_PARAMETER;
            goto out;
        }

        if (!auth_enforce)
            type = AUTH_TYPE_NONE;
        else if (setup_mode == 1)
            type = AUTH_TYPE_PAYLOAD;

        status = verify_auth_var_type(name, name_len,
                                      data, data_len,
                                      guid, attr, append,
                                      cur, type,
                                      payload_out, payload_len_out,
                                      digest, timestamp);
        if (status != EFI_SUCCESS)
            goto out;

        status = check_signature_list_format(*payload_out, *payload_len_out,
                                             true);
        if (status != EFI_SUCCESS)
            goto out;

        if (setup_mode == 1 && *payload_len_out != 0) {
            EFI_STATUS saved_status;
            uint8_t deployed_mode = 1;

            /*
             * Always try to update all the internal variables but return an
             * error if any fail.
             */
            status = EFI_SUCCESS;
            setup_mode = 0;
            saved_status = internal_set_variable(EFI_SETUP_MODE_NAME,
                                                 sizeof(EFI_SETUP_MODE_NAME),
                                                 &gEfiGlobalVariableGuid,
                                                 &setup_mode,
                                                 sizeof(setup_mode),
                                                 ATTR_BR);
            if (saved_status != EFI_SUCCESS)
                status = saved_status;

            saved_status = internal_set_variable(EFI_DEPLOYED_MODE_NAME,
                                                 sizeof(EFI_DEPLOYED_MODE_NAME),
                                                 &gEfiGlobalVariableGuid,
                                                 &deployed_mode,
                                                 sizeof(deployed_mode),
                                                 ATTR_BR);
            if (saved_status != EFI_SUCCESS)
                status = saved_status;

            secure_boot = secure_boot_enable;
            saved_status = internal_set_variable(EFI_SECURE_BOOT_MODE_NAME,
                                                 sizeof(EFI_SECURE_BOOT_MODE_NAME),
                                                 &gEfiGlobalVariableGuid,
                                                 &secure_boot,
                                                 sizeof(secure_boot),
                                                 ATTR_BR);
            if (saved_status != EFI_SUCCESS)
                status = saved_status;
        } else if (setup_mode == 0 && *payload_len_out == 0) {
            EFI_STATUS saved_status;
            uint8_t deployed_mode = 0;

            /*
             * Always try to update all the internal variables but return an
             * error if any fail.
             */
            status = EFI_SUCCESS;
            setup_mode = 1;
            saved_status = internal_set_variable(EFI_SETUP_MODE_NAME,
                                                 sizeof(EFI_SETUP_MODE_NAME),
                                                 &gEfiGlobalVariableGuid,
                                                 &setup_mode,
                                                 sizeof(setup_mode),
                                                 ATTR_BR);
            if (saved_status != EFI_SUCCESS)
                status = saved_status;

            saved_status = internal_set_variable(EFI_DEPLOYED_MODE_NAME,
                                                 sizeof(EFI_DEPLOYED_MODE_NAME),
                                                 &gEfiGlobalVariableGuid,
                                                 &deployed_mode,
                                                 sizeof(deployed_mode),
                                                 ATTR_BR);
            if (saved_status != EFI_SUCCESS)
                status = saved_status;

            secure_boot = 0;
            saved_status = internal_set_variable(EFI_SECURE_BOOT_MODE_NAME,
                                                 sizeof(EFI_SECURE_BOOT_MODE_NAME),
                                                 &gEfiGlobalVariableGuid,
                                                 &secure_boot,
                                                 sizeof(secure_boot),
                                                 ATTR_BR);
            if (saved_status != EFI_SUCCESS)
                status = saved_status;
        }
    } else if (name_len == sizeof(EFI_KEY_EXCHANGE_KEY_NAME) &&
               !memcmp(name, EFI_KEY_EXCHANGE_KEY_NAME, name_len) &&
               !memcmp(guid, &gEfiGlobalVariableGuid, GUID_LEN)) {
        enum auth_type type = AUTH_TYPE_PK;

        if (setup_mode == 1 || !auth_enforce)
            type = AUTH_TYPE_NONE;

        status = verify_auth_var_type(name, name_len,
                                      data, data_len,
                                      guid, attr, append,
                                      cur, type,
                                      payload_out, payload_len_out,
                                      digest, timestamp);
        if (status == EFI_SUCCESS)
            status = check_signature_list_format(*payload_out, *payload_len_out,
                                                 false);
    } else if (!memcmp(guid, &gEfiImageSecurityDatabaseGuid, GUID_LEN) &&
               ((name_len == sizeof(EFI_IMAGE_SECURITY_DATABASE) &&
                 !memcmp(name, EFI_IMAGE_SECURITY_DATABASE, name_len)) ||
                (name_len == sizeof(EFI_IMAGE_SECURITY_DATABASE1) &&
                 !memcmp(name, EFI_IMAGE_SECURITY_DATABASE1, name_len)) ||
                (name_len == sizeof(EFI_IMAGE_SECURITY_DATABASE2) &&
                 !memcmp(name, EFI_IMAGE_SECURITY_DATABASE2, name_len)))) {
        if (setup_mode == 1 || !auth_enforce) {
            status = verify_auth_var_type(name, name_len,
                                          data, data_len,
                                          guid, attr, append,
                                          cur, AUTH_TYPE_NONE,
                                          payload_out, payload_len_out,
                                          digest, timestamp);
        } else {
            status = verify_auth_var_type(name, name_len,
                                          data, data_len,
                                          guid, attr, append,
                                          cur, AUTH_TYPE_PK,
                                          payload_out, payload_len_out,
                                          digest, timestamp);
            if (status != EFI_SUCCESS)
                status = verify_auth_var_type(name, name_len,
                                              data, data_len,
                                              guid, attr, append,
                                              cur, AUTH_TYPE_KEK,
                                              payload_out, payload_len_out,
                                              digest, timestamp);
        }

        if (status == EFI_SUCCESS)
            status = check_signature_list_format(*payload_out, *payload_len_out,
                                                 false);
    } else {
        status = verify_auth_var_type(name, name_len,
                                      data, data_len,
                                      guid, attr, append,
                                      cur, AUTH_TYPE_PRIVATE,
                                      payload_out, payload_len_out,
                                      digest, timestamp);
    }

out:
    if (status != EFI_SUCCESS)
        free(*payload_out);
    return status;
}

static EFI_STATUS
check_ppi_variables(uint8_t *name, UINTN name_len, EFI_GUID *guid, uint8_t *data, UINTN data_len)
{
    if (name_len == sizeof(TCG2_PHYSICAL_PRESENCEFLAGSLOCK_NAME) &&
            !memcmp(name, TCG2_PHYSICAL_PRESENCEFLAGSLOCK_NAME, name_len) &&
            !memcmp(guid, &gEfiTcg2PpiXenGuid, GUID_LEN)) {
       if (data_len != sizeof (uint8_t)) {
           DBG("Bad PPI lock write. size=%lu\n", data_len);
           return EFI_INVALID_PARAMETER;
       }
       if (*data != 1) {
           DBG("Bad PPI lock write. data=%hu\n", *data);
           return EFI_INVALID_PARAMETER;
       }
       DBG("PPI lock set!\n");
       return EFI_SUCCESS;
    }

    if ((name_len == sizeof(TCG2_PHYSICAL_PRESENCEFLAGS_NAME) &&
            !memcmp(name, TCG2_PHYSICAL_PRESENCEFLAGS_NAME, name_len)) &&
            !memcmp(guid, &gEfiTcg2PpiXenGuid, GUID_LEN)) {

        EFI_STATUS status;
        UINTN lock_len;
        uint8_t *lock_data;

        status = internal_get_variable(TCG2_PHYSICAL_PRESENCEFLAGSLOCK_NAME,
                                       sizeof(TCG2_PHYSICAL_PRESENCEFLAGSLOCK_NAME),
                                       &gEfiTcg2PpiXenGuid, &lock_data, &lock_len);
        if (status == EFI_SUCCESS) {

            if (lock_len != sizeof(uint8_t) ||
                *lock_data != 0) {
                DBG("Attempt to set PPI flags while locked! Lock length %lu, value: %hu \n", lock_len, lock_len ? *lock_data : 0xff);
                free(lock_data);
                return EFI_WRITE_PROTECTED;
            }
            free(lock_data);
        } else {
           DBG("Attempt to set PPI flags while, but getting lock returned 0x%016lx\n", status);
           return status;
        }
    }
    return EFI_SUCCESS;
}

static bool
check_ro_variable(uint8_t *name, UINTN name_len, EFI_GUID *guid)
{
    if ((name_len == sizeof(EFI_AUDIT_MODE_NAME) &&
            !memcmp(name, EFI_AUDIT_MODE_NAME, name_len) &&
            !memcmp(guid, &gEfiGlobalVariableGuid, GUID_LEN)) ||
        (name_len == sizeof(EFI_DEPLOYED_MODE_NAME) &&
            !memcmp(name, EFI_DEPLOYED_MODE_NAME, name_len) &&
            !memcmp(guid, &gEfiGlobalVariableGuid, GUID_LEN)) ||
        (name_len == sizeof(EFI_SECURE_BOOT_MODE_NAME) &&
            !memcmp(name, EFI_SECURE_BOOT_MODE_NAME, name_len) &&
            !memcmp(guid, &gEfiGlobalVariableGuid, GUID_LEN)) ||
        (name_len == sizeof(EFI_SETUP_MODE_NAME) &&
            !memcmp(name, EFI_SETUP_MODE_NAME, name_len) &&
            !memcmp(guid, &gEfiGlobalVariableGuid, GUID_LEN)) ||
        (name_len == sizeof(EFI_SIGNATURE_SUPPORT_NAME) &&
            !memcmp(name, EFI_SIGNATURE_SUPPORT_NAME, name_len) &&
            !memcmp(guid, &gEfiGlobalVariableGuid, GUID_LEN)))
        return true;
    return false;
}

static bool
check_attr(uint8_t *name, UINTN name_len, EFI_GUID *guid, UINT32 attr)
{
    if ((name_len == sizeof(EFI_PLATFORM_KEY_NAME) &&
            !memcmp(name, EFI_PLATFORM_KEY_NAME, name_len) &&
            !memcmp(guid, &gEfiGlobalVariableGuid, GUID_LEN)) ||
        (name_len == sizeof(EFI_KEY_EXCHANGE_KEY_NAME) &&
            !memcmp(name, EFI_KEY_EXCHANGE_KEY_NAME, name_len) &&
            !memcmp(guid, &gEfiGlobalVariableGuid, GUID_LEN))) {
        if (attr != (ATTR_BRNV | EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS))
            return true;
    } else if (!memcmp(guid, &gEfiImageSecurityDatabaseGuid, GUID_LEN) &&
               ((name_len == sizeof(EFI_IMAGE_SECURITY_DATABASE) &&
                 !memcmp(name, EFI_IMAGE_SECURITY_DATABASE, name_len)) ||
                (name_len == sizeof(EFI_IMAGE_SECURITY_DATABASE1) &&
                 !memcmp(name, EFI_IMAGE_SECURITY_DATABASE1, name_len)) ||
                (name_len == sizeof(EFI_IMAGE_SECURITY_DATABASE2) &&
                 !memcmp(name, EFI_IMAGE_SECURITY_DATABASE2, name_len)))) {
        if (attr != (ATTR_BRNV | EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS))
            return true;
    }

    return false;
}

/*
 * Append a signature list, new_data, to an existing signature list, data,
 * while removing duplicates. This function must only be called with valid
 * signature lists (i.e. check_signature_list_format has already been called
 * on the signature list).
 */
static EFI_STATUS
filter_signature_list(uint8_t *data, UINTN data_len,
                      uint8_t *new_data, UINTN *new_data_len)
{
    EFI_SIGNATURE_LIST *cert_list, *new_cert_list, *old_cert_list;
    EFI_SIGNATURE_DATA *new_cert, *old_cert;
    UINTN new_rem, old_rem;
    uint8_t *buf, *ptr;
    int i, j, new_cert_count, old_cert_count;

    buf = malloc(*new_data_len);
    if (!buf)
        return EFI_DEVICE_ERROR;
    ptr = buf;

    new_cert_list = (EFI_SIGNATURE_LIST *)new_data;
    new_rem = *new_data_len;

    while ((new_rem > 0) && (new_rem >= new_cert_list->SignatureListSize)) {
        int copied = 0;

        new_cert = (EFI_SIGNATURE_DATA *)((uint8_t *)new_cert_list +
                   sizeof(EFI_SIGNATURE_LIST) + new_cert_list->SignatureHeaderSize);
        new_cert_count = (new_cert_list->SignatureListSize - sizeof(EFI_SIGNATURE_LIST) -
                          new_cert_list->SignatureHeaderSize) / new_cert_list->SignatureSize;

        for (i = 0; i < new_cert_count; i++) {
            bool is_new_cert = true;

            old_rem = data_len;
            old_cert_list = (EFI_SIGNATURE_LIST *)data;
            while ((old_rem > 0) && (old_rem >= old_cert_list->SignatureListSize)) {
                if (!memcmp(&old_cert_list->SignatureType, &new_cert_list->SignatureType, GUID_LEN) &&
                        (old_cert_list->SignatureSize == new_cert_list->SignatureSize)) {
                    old_cert = (EFI_SIGNATURE_DATA *)((uint8_t *)old_cert_list +
                               sizeof(EFI_SIGNATURE_LIST) + old_cert_list->SignatureHeaderSize);
                    old_cert_count = (old_cert_list->SignatureListSize - sizeof(EFI_SIGNATURE_LIST) -
                                      old_cert_list->SignatureHeaderSize) / old_cert_list->SignatureSize;

                    for (j = 0; j < old_cert_count; j++) {
                        if (!memcmp(new_cert, old_cert, old_cert_list->SignatureSize)) {
                            is_new_cert = false;
                            break;
                        }
                        old_cert = (EFI_SIGNATURE_DATA *)((uint8_t *)old_cert + old_cert_list->SignatureSize);
                    }
                }
                if (!is_new_cert)
                    break;

                old_rem -= old_cert_list->SignatureListSize;
                old_cert_list = (EFI_SIGNATURE_LIST *)((uint8_t *)old_cert_list +
                                old_cert_list->SignatureListSize);
            }

            if (is_new_cert) {
                if (copied == 0) {
                    memcpy(ptr, new_cert_list,
                           sizeof(EFI_SIGNATURE_LIST) + new_cert_list->SignatureHeaderSize);
                    ptr += sizeof(EFI_SIGNATURE_LIST) + new_cert_list->SignatureHeaderSize;
                }

                memcpy(ptr, new_cert, new_cert_list->SignatureSize);
                ptr += new_cert_list->SignatureSize;
                copied++;
            }

            new_cert = (EFI_SIGNATURE_DATA *)((uint8_t *)new_cert +
                       new_cert_list->SignatureSize);
        }

        if (copied != 0) {
            int size = sizeof(EFI_SIGNATURE_LIST) + new_cert_list->SignatureHeaderSize +
                       (copied * new_cert_list->SignatureSize);
            cert_list = (EFI_SIGNATURE_LIST *)(ptr - size);
            cert_list->SignatureListSize = size;
        }

        new_rem -= new_cert_list->SignatureListSize;
        new_cert_list = (EFI_SIGNATURE_LIST *)((uint8_t *)new_cert_list +
                        new_cert_list->SignatureListSize);
    }

    *new_data_len = ptr - buf;
    memcpy(new_data, buf, *new_data_len);
    free(buf);

    return EFI_SUCCESS;
}

static struct efi_variable *
copy_efi_variable(struct efi_variable *efi_var)
{
    struct efi_variable *new_efi_var;

    if (efi_var == NULL)
        return NULL;

    new_efi_var = malloc(sizeof *new_efi_var);
    if (!new_efi_var)
        return NULL;

    *new_efi_var = *efi_var;
    new_efi_var->next = NULL;

    new_efi_var->name = malloc(efi_var->name_len);
    if (!new_efi_var->name) {
        free(new_efi_var);
        return NULL;
    }
    memcpy(new_efi_var->name, efi_var->name, efi_var->name_len);

    new_efi_var->data = malloc(efi_var->data_len);
    if (!new_efi_var->data) {
        free(new_efi_var->name);
        free(new_efi_var);
        return NULL;
    }
    memcpy(new_efi_var->data, efi_var->data, efi_var->data_len);

    return new_efi_var;
}

static void
free_efi_variable(struct efi_variable *efi_var)
{
    if (efi_var == NULL)
        return;

    free(efi_var->name);
    free(efi_var->data);
    free(efi_var);
}

/* Returns true if two EFI variables are equivalent, false otherwise. */
static bool
cmp_efi_variable(struct efi_variable *a, struct efi_variable *b)
{
    if (a->name_len != b->name_len)
        return false;
    if (a->data_len != b->data_len)
        return false;
    if (a->attributes != b->attributes)
        return false;
    if (memcmp(&a->guid, &b->guid, GUID_LEN))
        return false;
    if (memcmp(&a->timestamp, &b->timestamp, sizeof(a->timestamp)))
        return false;
    if (memcmp(a->cert, b->cert, sizeof(a->cert)))
        return false;
    if (memcmp(a->name, b->name, a->name_len))
        return false;
    if (memcmp(a->data, b->data, a->data_len))
        return false;

    return true;
}

#if 0
static void
debug_all_variables(const struct efi_variable *l)
{
    if (log_level < LOG_LVL_DEBUG)
        return;
    fprintf(stderr, "Listing UEFI variables\n");
    for(; l; l = l->next) {
        for (int i = 0; i < l->name_len; i += 2) {
            if (isprint(l->name[i]))
                fprintf(stderr, "%c", (char)l->name[i]);
        }
        fprintf(stderr, "\n");
    }
}
#endif

static void
do_set_variable(uint8_t *comm_buf)
{
    UINTN name_len, data_len;
    struct efi_variable *l, *prev = NULL;
    uint8_t *ptr, *name, *data;
    EFI_GUID guid;
    UINT32 attr;
    BOOLEAN at_runtime, append;
    EFI_STATUS status;
    uint8_t digest[SHA256_DIGEST_SIZE] = {0};
    EFI_TIME timestamp;

    ptr = comm_buf;
    unserialize_uint32(&ptr); /* version */
    unserialize_command(&ptr);
    name = unserialize_data(&ptr, &name_len, NAME_LIMIT);
    if (!name) {
        serialize_result(&comm_buf, name_len == 0 ? EFI_INVALID_PARAMETER : EFI_DEVICE_ERROR);
        return;
    }
    unserialize_guid(&ptr, &guid);
    data = unserialize_data(&ptr, &data_len, DATA_LIMIT);
    if (!data && data_len) {
        serialize_result(&comm_buf, data_len > DATA_LIMIT ? EFI_OUT_OF_RESOURCES : EFI_DEVICE_ERROR);
        free(name);
        return;
    }
    attr = unserialize_uint32(&ptr);
    at_runtime = unserialize_boolean(&ptr);
    ptr = comm_buf;

    append = !!(attr & EFI_VARIABLE_APPEND_WRITE);
    attr &= ~EFI_VARIABLE_APPEND_WRITE;

    /* The hardware error record is not supported for now. */
    if (attr & EFI_VARIABLE_HARDWARE_ERROR_RECORD) {
        serialize_result(&ptr, EFI_INVALID_PARAMETER);
        goto err;
    }

    /* Authenticated write access is deprecated and is not supported. */
    if (attr & EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS) {
        serialize_result(&ptr, EFI_UNSUPPORTED);
        goto err;
    }

    if ((attr & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS) &&
            (attr & EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS)) {
        serialize_result(&ptr, EFI_INVALID_PARAMETER);
        goto err;
    }

    /* Enhanced authenticated access is not yet implemented. */
    if (attr & EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS) {
        serialize_result(&ptr, EFI_UNSUPPORTED);
        goto err;
    }

    /* If runtime access is set, bootservice access must also be set. */
    if ((attr & (EFI_VARIABLE_RUNTIME_ACCESS |
               EFI_VARIABLE_BOOTSERVICE_ACCESS)) == EFI_VARIABLE_RUNTIME_ACCESS) {
        serialize_result(&ptr, EFI_INVALID_PARAMETER);
        goto err;
    }

    if (is_mor_control(name, name_len, &guid)) {
        serialize_result(&ptr, do_set_mor_control(data, data_len, attr, append));
        goto err;
    }

    if (is_mor_control_lock(name, name_len, &guid)) {
        serialize_result(&ptr, do_set_mor_control_lock(data, data_len, attr, append));
        goto err;
    }

    l = var_list;
    while (l) {
        if (l->name_len == name_len &&
                !memcmp(l->name, name, name_len) &&
                !memcmp(&l->guid, &guid, GUID_LEN)) {
            struct efi_variable *rollback_var = NULL;
            bool should_save = !!(l->attributes & EFI_VARIABLE_NON_VOLATILE);

            /* Only runtime variables can be updated/deleted at runtime. */
            if (at_runtime && !(l->attributes & EFI_VARIABLE_RUNTIME_ACCESS)) {
                serialize_result(&ptr, EFI_INVALID_PARAMETER);
                goto err;
            }

            /* Only NV variables can be update/deleted at runtime. */
            if (at_runtime && !(l->attributes & EFI_VARIABLE_NON_VOLATILE)) {
                serialize_result(&ptr, EFI_WRITE_PROTECTED);
                goto err;
            }

            if (check_ro_variable(name, name_len, &guid)) {
                serialize_result(&ptr, EFI_WRITE_PROTECTED);
                goto err;
            }

            status = check_ppi_variables(name, name_len, &guid, data, data_len);
            if (status != EFI_SUCCESS) {
                serialize_result(&ptr, status);
                goto err;
            }
            if (attr & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS) {
                uint8_t *payload;
                UINTN payload_len;

                /*
                 * Authenticated variables cannot be deleted by setting no
                 * access bits so ensure the bits are unchanged early.
                 */
                if (l->attributes != attr) {
                    serialize_result(&ptr, EFI_INVALID_PARAMETER);
                    goto err;
                }

                status = verify_auth_var(name, name_len,
                                         data, data_len,
                                         &guid, attr, append,
                                         l,
                                         &payload, &payload_len,
                                         digest, &timestamp);
                if (status != EFI_SUCCESS) {
                    serialize_result(&ptr, status);
                    goto err;
                }
                free(data);
                data = payload;
                data_len = payload_len;
            }

            if ((data_len == 0 && !append) || !(attr & ATTR_BR)) {
                /*
                 * Authenticated variables cannot be deleted by unsetting
                 * attributes. (2.7A page 248)
                 */
                if ((l->attributes & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS) &&
                    (l->attributes != attr)) {
                    serialize_result(&ptr, EFI_INVALID_PARAMETER);
                    goto err;
                }

                if (prev)
                    prev->next = l->next;
                else
                    var_list = l->next;
                rollback_var = l;
                free(data);
            } else {
                if (l->attributes != attr) {
                    serialize_result(&ptr, EFI_INVALID_PARAMETER);
                    goto err;
                }
                if (append) {
                    uint8_t *new_data;

                    if ((attr & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS) &&
                            !memcmp(&guid, &gEfiImageSecurityDatabaseGuid, GUID_LEN) &&
                            ((name_len == sizeof(EFI_IMAGE_SECURITY_DATABASE) &&
                              !memcmp(name, EFI_IMAGE_SECURITY_DATABASE, name_len)) ||
                             (name_len == sizeof(EFI_IMAGE_SECURITY_DATABASE1) &&
                              !memcmp(name, EFI_IMAGE_SECURITY_DATABASE1, name_len)) ||
                             (name_len == sizeof(EFI_IMAGE_SECURITY_DATABASE2) &&
                              !memcmp(name, EFI_IMAGE_SECURITY_DATABASE2, name_len)))) {
                        status = filter_signature_list(l->data, l->data_len, data, &data_len);
                        if (status != EFI_SUCCESS) {
                            serialize_result(&ptr, status);
                            goto err;
                        }
                    }

                    if (get_space_usage() + data_len > TOTAL_LIMIT) {
                        serialize_result(&ptr, EFI_OUT_OF_RESOURCES);
                        goto err;
                    }

                    rollback_var = copy_efi_variable(l);
                    if (!rollback_var) {
                        serialize_result(&ptr, EFI_OUT_OF_RESOURCES);
                        goto err;
                    }

                    new_data = realloc(l->data, l->data_len + data_len);
                    if (!new_data) {
                        serialize_result(&ptr, EFI_DEVICE_ERROR);
                        free_efi_variable(rollback_var);
                        goto err;
                    }
                    if ((attr & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS) &&
                            time_later(&l->timestamp, &timestamp))
                        l->timestamp = timestamp;
                    l->data = new_data;
                    memcpy(l->data + l->data_len, data, data_len);
                    free(data);
                    l->data_len += data_len;
                } else {
                    if (get_space_usage() - l->data_len + data_len > TOTAL_LIMIT) {
                        serialize_result(&ptr, EFI_OUT_OF_RESOURCES);
                        goto err;
                    }

                    rollback_var = copy_efi_variable(l);
                    if (!rollback_var) {
                        serialize_result(&ptr, EFI_OUT_OF_RESOURCES);
                        goto err;
                    }

                    if (attr & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS)
                        l->timestamp = timestamp;
                    free(l->data);
                    l->data = data;
                    l->data_len = data_len;
                }

                /* Skip saving if nothing changed. */
                if (cmp_efi_variable(l, rollback_var))
                    should_save = false;
            }
            free(name);
            if (should_save && persistent) {
                if (!db->set_variable()) {
                    /* efivar delete and append/update case */
                    rollback_var->next = l->next;
                    if (prev)
                        prev->next = rollback_var;
                    else
                        var_list = rollback_var;

                    /* Free the changed var in the append/update case */
                    if (rollback_var != l)
                        free_efi_variable(l);
                    serialize_result(&ptr, EFI_DEVICE_ERROR);
                    return;
                }
            }
            free_efi_variable(rollback_var);
            serialize_result(&ptr, EFI_SUCCESS);
            return;
        }
        prev = l;
        l = l->next;
    }

    if (data_len == 0 || !(attr & ATTR_BR)) {
        serialize_result(&ptr, EFI_NOT_FOUND);
        goto err;
    } else {
        if (at_runtime && (!(attr & EFI_VARIABLE_RUNTIME_ACCESS) ||
                           !(attr & EFI_VARIABLE_NON_VOLATILE))) {
            serialize_result(&ptr, EFI_INVALID_PARAMETER);
            goto err;
        }

        if (check_attr(name, name_len, &guid, attr)) {
            serialize_result(&ptr, EFI_INVALID_PARAMETER);
            goto err;
        }

        if (attr & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS) {
            uint8_t *payload;
            UINTN payload_len;

            status = verify_auth_var(name, name_len,
                                     data, data_len,
                                     &guid, attr, append,
                                     NULL,
                                     &payload, &payload_len,
                                     digest, &timestamp);
            if (status != EFI_SUCCESS) {
                serialize_result(&ptr, status);
                goto err;
            }
            free(data);
            data = payload;
            data_len = payload_len;
        }

        if (data_len == 0) {
            serialize_result(&ptr, EFI_NOT_FOUND);
            goto err;
        }

        if (get_space_usage() + name_len + data_len +
                VARIABLE_SIZE_OVERHEAD > TOTAL_LIMIT) {
            serialize_result(&ptr, EFI_OUT_OF_RESOURCES);
            goto err;
        }

        l = calloc(1, sizeof(*l));
        if (!l) {
            serialize_result(&ptr, EFI_DEVICE_ERROR);
            goto err;
        }

        l->name = name;
        l->name_len = name_len;
        memcpy(&l->guid, &guid, GUID_LEN);
        l->data = data;
        l->data_len = data_len;
        l->attributes = attr;
        if (attr & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS) {
            l->timestamp = timestamp;
            memcpy(l->cert, digest, SHA256_DIGEST_SIZE);
        }
        l->next = var_list;
        var_list = l;
        if ((attr & EFI_VARIABLE_NON_VOLATILE) && persistent) {
            if (!db->set_variable()) {
                /* remove var inserted to head */
                var_list = l->next;

                free_efi_variable(l);
                serialize_result(&ptr, EFI_DEVICE_ERROR);
                return;
            }
        }
        serialize_result(&ptr, EFI_SUCCESS);
    }

    return;

err:
    free(name);
    free(data);
}

static void
do_get_next_variable(uint8_t *comm_buf)
{
    UINTN name_len, avail_len;
    uint8_t *ptr, *name;
    struct efi_variable *l;
    EFI_GUID guid;
    BOOLEAN at_runtime;

    ptr = comm_buf;
    unserialize_uint32(&ptr); /* version */
    unserialize_command(&ptr);
    avail_len = unserialize_uintn(&ptr);
    name = unserialize_data(&ptr, &name_len, NAME_LIMIT);
    if (!name && name_len) {
        serialize_result(&comm_buf, EFI_DEVICE_ERROR);
        return;
    }
    unserialize_guid(&ptr, &guid);
    at_runtime = unserialize_boolean(&ptr);

    ptr = comm_buf;
    l = var_list;

    if (name_len) {
        while (l) {
            if (l->name_len == name_len &&
                    !memcmp(l->name, name, name_len) &&
                    !memcmp(&l->guid, &guid, GUID_LEN) &&
                    (!at_runtime || (l->attributes & EFI_VARIABLE_RUNTIME_ACCESS)))
                break;
            l = l->next;
        }
        if (!l) {
            /* Given name & guid didn't match an existing variable */
            serialize_result(&ptr, EFI_INVALID_PARAMETER);
            goto out;
        }
        l = l->next;
    }

    /* Find the next valid variable, if any. */
    while (at_runtime && l && !(l->attributes & EFI_VARIABLE_RUNTIME_ACCESS))
        l = l->next;

    if (l) {
        if (avail_len < l->name_len + sizeof(CHAR16)) {
            serialize_result(&ptr, EFI_BUFFER_TOO_SMALL);
            serialize_uintn(&ptr, l->name_len + sizeof(CHAR16));
        } else {
            serialize_result(&ptr, EFI_SUCCESS);
            serialize_data(&ptr, l->name, l->name_len);
            serialize_guid(&ptr, &l->guid);
        }
    } else {
        serialize_result(&ptr, EFI_NOT_FOUND);
    }

out:
    free(name);
}

static void
do_query_variable_info(uint8_t *comm_buf)
{
    uint8_t *ptr;
    UINT32 attr;

    ptr = comm_buf;
    unserialize_uint32(&ptr); /* version */
    unserialize_command(&ptr);
    attr = unserialize_uint32(&ptr);

    ptr = comm_buf;

    if ((attr & EFI_VARIABLE_HARDWARE_ERROR_RECORD)) {
        serialize_result(&ptr, EFI_UNSUPPORTED);
        return;
    }

    /*
     * In this implementation, all variables share a common storage area, so
     * there is no need to check the attributes further.
     */
    serialize_result(&ptr, EFI_SUCCESS);
    serialize_uint64(&ptr, TOTAL_LIMIT);
    serialize_uint64(&ptr, TOTAL_LIMIT - get_space_usage());
    serialize_uint64(&ptr, DATA_LIMIT);
}

static void
do_notify_sb_failure(uint8_t *comm_buf)
{
    uint8_t *ptr;
    bool ret;
    static bool called;

    /*
     * Emit only one alert per VM start (actually per varstored instance, but
     * this is sufficient) to avoid the VM creating a flood of messages (either
     * maliciously or by accident).
     */
    if (called) {
        ptr = comm_buf;
        serialize_result(&ptr, EFI_ACCESS_DENIED);
        return;
    }
    called = true;

    ptr = comm_buf;
    unserialize_uint32(&ptr); /* version */
    unserialize_command(&ptr);

    ret = db->sb_notify();

    ptr = comm_buf;
    serialize_result(&ptr, ret ? EFI_SUCCESS : EFI_DEVICE_ERROR);
}

void dispatch_command(uint8_t *comm_buf)
{
    enum command_t command;
    UINT32 version;
    uint8_t *ptr = comm_buf;

    version = unserialize_uint32(&ptr);
    if (version != 1) {
        DBG("Unknown version: %u\n", version);
        return;
    }

    command = unserialize_command(&ptr);
    switch (command) {
    case COMMAND_GET_VARIABLE:
        DBG("COMMAND_GET_VARIABLE\n");
        do_get_variable(comm_buf);
        break;
    case COMMAND_SET_VARIABLE:
        DBG("COMMAND_SET_VARIABLE\n");
        do_set_variable(comm_buf);
        break;
    case COMMAND_GET_NEXT_VARIABLE:
        DBG("COMMAND_GET_NEXT_VARIABLE\n");
        do_get_next_variable(comm_buf);
        break;
    case COMMAND_QUERY_VARIABLE_INFO:
        DBG("COMMAND_QUERY_VARIABLE_INFO\n");
        do_query_variable_info(comm_buf);
        break;
    case COMMAND_NOTIFY_SB_FAILURE:
        DBG("COMMAND_NOTIFY_SB_FAILURE\n");
        do_notify_sb_failure(comm_buf);
        break;
    default:
        DBG("Unknown command\n");
        break;
    };
}

bool
setup_crypto(void)
{
    return !!EVP_add_digest(EVP_sha256());
}

bool
setup_variables(void)
{
    EFI_STATUS status;
    UINTN data_len;
    uint8_t setup_mode = 0;
    uint8_t *data;
    uint8_t secure_boot = 0, deployed_mode = 1, audit_mode = 0;

    status = internal_set_variable(EFI_SIGNATURE_SUPPORT_NAME,
                                   sizeof(EFI_SIGNATURE_SUPPORT_NAME),
                                   &gEfiGlobalVariableGuid,
                                   mSignatureSupport,
                                   sizeof(mSignatureSupport),
                                   ATTR_BR);
    if (status != EFI_SUCCESS)
        return false;

    status = internal_get_variable(EFI_PLATFORM_KEY_NAME,
                                   sizeof(EFI_PLATFORM_KEY_NAME),
                                   &gEfiGlobalVariableGuid, &data, &data_len);
    if (status == EFI_NOT_FOUND) {
        setup_mode = 1;
        deployed_mode = 0;
    } else if (status == EFI_SUCCESS) {
        free(data);
        secure_boot = secure_boot_enable;
    } else {
        return false;
    }

    status = internal_set_variable(EFI_SETUP_MODE_NAME,
                                   sizeof(EFI_SETUP_MODE_NAME),
                                   &gEfiGlobalVariableGuid,
                                   &setup_mode,
                                   sizeof(setup_mode),
                                   ATTR_BR);
    if (status != EFI_SUCCESS)
        return false;

    status = internal_set_variable(EFI_AUDIT_MODE_NAME,
                                   sizeof(EFI_AUDIT_MODE_NAME),
                                   &gEfiGlobalVariableGuid,
                                   &audit_mode,
                                   sizeof(audit_mode),
                                   ATTR_BR);
    if (status != EFI_SUCCESS)
        return false;

    status = internal_set_variable(EFI_DEPLOYED_MODE_NAME,
                                   sizeof(EFI_DEPLOYED_MODE_NAME),
                                   &gEfiGlobalVariableGuid,
                                   &deployed_mode,
                                   sizeof(deployed_mode),
                                   ATTR_BR);
    if (status != EFI_SUCCESS)
        return false;

    status = internal_set_variable(EFI_SECURE_BOOT_MODE_NAME,
                                   sizeof(EFI_SECURE_BOOT_MODE_NAME),
                                   &gEfiGlobalVariableGuid,
                                   &secure_boot,
                                   sizeof(secure_boot),
                                   ATTR_BR);
    if (status != EFI_SUCCESS)
        return false;

    return true;
}

static bool
set_variable_from_auth(const uint8_t *name, UINTN name_len, const EFI_GUID *guid,
                       const uint8_t *data, off_t data_len, bool append)
{
    uint8_t buf[SHMEM_SIZE];
    uint8_t *ptr;
    EFI_STATUS status;
    UINT32 attr = ATTR_BRNV_TIME;

    if (append)
        attr |= EFI_VARIABLE_APPEND_WRITE;

    ptr = buf;
    serialize_uint32(&ptr, 1); /* version */
    serialize_uint32(&ptr, COMMAND_SET_VARIABLE);
    serialize_data(&ptr, name, name_len);
    serialize_guid(&ptr, guid);
    serialize_data(&ptr, data, data_len);
    serialize_uint32(&ptr, attr);
    *ptr = 0; /* at_runtime */
    dispatch_command(buf);

    ptr = buf;
    status = unserialize_uintn(&ptr);
    if (status != EFI_SUCCESS) {
        ERR("Failed to execute auth data: 0x%lx\n", status);
        return false;
    }

    return true;
}

bool
setup_keys(void)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(auth_info); i++) {
        if (!auth_info[i].data) {
            WARN("Cannot setup %s because auth data is missing!\n",
                 auth_info[i].pretty_name);

            if (!auth_info[i].required) {
                INFO("Continuing keys setup despite missing optional %s\n",
                    auth_info[i].pretty_name);
                continue;
            }

            /*
             * Skip setting the rest of the keys (in particular, PK).
             * Otherwise the platform may be in user mode without
             * KEK/db set which will cause in-guest dbx updates to fail.
             */
            WARN("Aborting keys setup\n");
            return true;
        }

        INFO("Setting %s...\n", auth_info[i].pretty_name);
        if (!set_variable_from_auth(auth_info[i].name,
                                    auth_info[i].name_len,
                                    auth_info[i].guid,
                                    auth_info[i].data,
                                    auth_info[i].data_len,
                                    auth_info[i].append))
            return false;
    }

    return true;
}

static bool
load_one_auth_data(const char *path, uint8_t **data_out, off_t *len)
{
    struct stat st;
    FILE *f;
    uint8_t *data;

    f = fopen(path, "r");
    if (!f) {
        if (errno == ENOENT) {
            WARN("Auth file '%s' is missing!\n", path);
            return true;
        } else {
            ERR("Failed to open '%s': %d, %s\n", path, errno, strerror(errno));
            return true;
        }
    }

    if (fstat(fileno(f), &st) == -1) {
        ERR("Failed to stat '%s'\n", path);
        fclose(f);
        return false;
    }

    /*
     * This will be checked later during SetVariable but check it now to avoid
     * reading a malicously large file into memory.
     */
    if (st.st_size > DATA_LIMIT) {
        ERR("Auth file '%s' is too large: %ld\n", path, st.st_size);
        fclose(f);
        return false;
    }

    data = malloc(st.st_size);
    if (!data) {
        ERR("Out of memory!\n");
        fclose(f);
        return false;
    }
    if (fread(data, 1, st.st_size, f) != st.st_size) {
        ERR("Failed to read '%s'\n", path);
        fclose(f);
        free(data);
        return false;
    }
    fclose(f);

    *data_out = data;
    *len = st.st_size;

    return true;
}

bool
load_auth_data(void)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(auth_info); i++) {
        if (!load_one_auth_data(auth_info[i].path,
                                &auth_info[i].data,
                                &auth_info[i].data_len))
            return false;
    }

    return true;
}

void
free_auth_data(void)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(auth_info); i++) {
        free(auth_info[i].data);
        auth_info[i].data = NULL;
    }
}
