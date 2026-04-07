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
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>

#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs7.h>
#include <openssl/err.h>

#include <efi.h>
#include <guid.h>

/*
 * This utility prepares an "auth". An auth file contains an authentication
 * descriptor, a signature, and some data and is used for updating a secure
 * variable. It is used at build time to prepare authentication descriptors
 * that are used to set up PK, KEK, db, etc. if needed during VM start. It
 * needs to be done at build time because the private key used to sign the data
 * is ephemeral.
 */

static const EFI_GUID citrix_guid =
    {{0x35, 0xc5, 0xac, 0xc0, 0xc8, 0x25, 0x46, 0x64, 0x92, 0x5b, 0x5d, 0xd7, 0xd0, 0xb2, 0xf5, 0xaa}};
static const EFI_GUID microsoft_guid =
    {{0xbd, 0x9a, 0xfa, 0x77, 0x59, 0x03, 0x32, 0x4d, 0xbd, 0x60, 0x28, 0xf4, 0xe7, 0x8f, 0x78, 0x4b}};

/*
 * Converts an array of X509 certificates into a list of EFI_SIGNATURE_LISTs,
 * each container a single certificate. data_len is set to the total output
 * length.
 */
static uint8_t *
certs_to_sig_list(X509 **cert, int count, UINTN *data_len,
                  const EFI_GUID *vendor_guid)
{
    int i, len;
    size_t offset = 0;
    uint8_t *data = NULL, *ptr;
    EFI_SIGNATURE_LIST *sig_list;
    EFI_SIGNATURE_DATA *sig_data;

    *data_len = 0;
    for (i = 0; i < count; i++) {
        len = i2d_X509(cert[i], NULL);
        if (len < 0) {
            printf("i2d_X509 failed\n");
            exit(1);
        }
        *data_len += sizeof(EFI_SIGNATURE_LIST) + offsetof(EFI_SIGNATURE_DATA, SignatureData) + len;

        data = realloc(data, *data_len);
        if (!data) {
            printf("Out of memory!\n");
            exit(1);
        }

        /* Write SignatureList header */
        sig_list = (EFI_SIGNATURE_LIST *)(data + offset);
        sig_list->SignatureHeaderSize = 0;
        sig_list->SignatureSize = offsetof(EFI_SIGNATURE_DATA, SignatureData) + len;
        sig_list->SignatureListSize = sizeof(EFI_SIGNATURE_LIST) + sig_list->SignatureSize;
        memcpy(&sig_list->SignatureType, &gEfiCertX509Guid, GUID_LEN);
        offset += sizeof(EFI_SIGNATURE_LIST);

        /* Write first and only SignatureData header */
        sig_data = (EFI_SIGNATURE_DATA *)(data + offset);
        memcpy(&sig_data->SignatureOwner, vendor_guid, GUID_LEN);
        offset += offsetof(EFI_SIGNATURE_DATA, SignatureData);

        /* Write certificate */
        ptr = data + offset;
        if (i2d_X509(cert[i], &ptr) < 0) {
            printf("i2d_X509 failed\n");
            exit(1);
        }
        offset += len;
    }

    return data;
}

/* Returns data ready for signing. */
static uint8_t *
create_signable_data(const uint8_t *name, UINTN name_len,
                     const EFI_GUID *guid, UINT32 attr, EFI_TIME *timestamp,
                     const uint8_t *data, UINTN data_len, UINTN *signable_len)
{
    UINTN len;
    uint8_t *buf, *ptr;

    len = name_len + GUID_LEN + sizeof(attr) + sizeof(*timestamp) + data_len;
    buf = malloc(len);
    if (!buf) {
        printf("Out of memory!\n");
        exit(1);
    }

    ptr = buf;
    memcpy(ptr, name, name_len);
    ptr += name_len;
    memcpy(ptr, guid, GUID_LEN);
    ptr += GUID_LEN;
    memcpy(ptr, &attr, sizeof(attr));
    ptr += sizeof(attr);
    memcpy(ptr, timestamp, sizeof(*timestamp));
    ptr += sizeof(*timestamp);
    memcpy(ptr, data, data_len);

    *signable_len = len;

    return buf;
}

/* Returns a signature suitable for a time-based authenticated write. */
static uint8_t *
sign_data(X509 *cert, EVP_PKEY *key, const uint8_t *data, UINTN data_len, UINTN *sig_len)
{
    int p7_len;
    uint8_t *sig, *ptr;
    PKCS7 *p7;
    BIO *bio;
    const EVP_MD *md;

    if (!key) {
        printf("No key provided to sign with\n");
        exit(1);
    }

    bio = BIO_new_mem_buf(data, data_len);
    if (!bio) {
        printf("Failed to create bio\n");
        exit(1);
    }

    p7 = PKCS7_sign(NULL, NULL, NULL, bio,
                    PKCS7_BINARY | PKCS7_PARTIAL | PKCS7_DETACHED | PKCS7_NOATTR);
    if (!p7) {
        printf("PKCS7_sign failed\n");
        exit(1);
    }
    md = EVP_get_digestbyname("SHA256");
    if (!md) {
        printf("EVP_get_digestbyname failed\n");
        exit(1);
    }
    if (!PKCS7_sign_add_signer(p7, cert, key, md,
                               PKCS7_BINARY | PKCS7_DETACHED | PKCS7_NOATTR)) {
        printf("PKCS7_sign_add_signer failed\n");
        exit(1);
    }
    if (!PKCS7_final(p7, bio, PKCS7_BINARY | PKCS7_DETACHED | PKCS7_NOATTR)) {
        printf("PKCS7_final failed\n");
        exit(1);
    }

    p7_len = i2d_PKCS7(p7, NULL);
    if (p7_len < 0) {
        printf("i2d_PKCS7 failed\n");
        exit(1);
    }

    sig = malloc(p7_len);
    if (!sig) {
        printf("Out of memory!\n");
        exit(1);
    }
    ptr = sig;
    if (i2d_PKCS7(p7, &ptr) < 0) {
        printf("i2d_PKCS7 failed\n");
        exit(1);
    }
    *sig_len = p7_len;

    PKCS7_free(p7);
    BIO_free(bio);

    return sig;
}

static EFI_VARIABLE_AUTHENTICATION_2 *
create_descriptor(UINTN sig_len, EFI_TIME *timestamp, UINTN *descriptor_len)
{
    EFI_VARIABLE_AUTHENTICATION_2 *d;

    d = malloc(sizeof(*d));
    if (!d) {
        printf("Out of memory!\n");
        exit(1);
    }

    d->TimeStamp = *timestamp;
    memcpy(&d->AuthInfo.CertType, &gEfiCertPkcs7Guid, GUID_LEN);
    d->AuthInfo.Hdr.dwLength = sig_len + offsetof(WIN_CERTIFICATE_UEFI_GUID, CertData);
    d->AuthInfo.Hdr.wRevision = 0x0200;
    d->AuthInfo.Hdr.wCertificateType = WIN_CERT_TYPE_EFI_GUID;

    *descriptor_len = offsetof(EFI_VARIABLE_AUTHENTICATION_2, AuthInfo.CertData);

    return d;
}

/*
 * Parse a GUID string in RFC-4122 format (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
 * into an EFI_GUID. The EFI_GUID uses mixed-endian encoding:
 *   Data1 (4 bytes) little-endian
 *   Data2 (2 bytes) little-endian
 *   Data3 (2 bytes) little-endian
 *   Data4 (8 bytes) big-endian
 *   https://uefi.org/specs/UEFI/2.10/Apx_A_GUID_and_Time_Formats.html
 * Returns true on success, false on failure.
 */
static bool
parse_guid(const char *str, EFI_GUID *guid)
{
    unsigned int data1, data2, data3;
    unsigned int data4[8];
    unsigned int i;
    int ret;

    if (strlen(str) != 36)
        return false;

    ret = sscanf(str, "%8x-%4x-%4x-%2x%2x-%2x%2x%2x%2x%2x%2x",
                 &data1, &data2, &data3,
                 &data4[0], &data4[1], &data4[2], &data4[3],
                 &data4[4], &data4[5], &data4[6], &data4[7]);
    if (ret != 11)
        return false;

    /* Data1: 4 bytes, little-endian */
    guid->data[0] = data1 & 0xff;
    guid->data[1] = (data1 >> 8) & 0xff;
    guid->data[2] = (data1 >> 16) & 0xff;
    guid->data[3] = (data1 >> 24) & 0xff;

    /* Data2: 2 bytes, little-endian */
    guid->data[4] = data2 & 0xff;
    guid->data[5] = (data2 >> 8) & 0xff;

    /* Data3: 2 bytes, little-endian */
    guid->data[6] = data3 & 0xff;
    guid->data[7] = (data3 >> 8) & 0xff;

    /* Data4: 8 bytes, big-endian */
    for (i = 0; i < 8; i++)
        guid->data[8 + i] = data4[i];

    return true;
}

static void
usage(const char *progname)
{
    printf("usage: %s [-o] [-t <seconds>] [-k <key>] [-c cert] [-s signature]\n"
           "       [-g <guid>] name output cert [cert...]\n",
           progname);
}

int main(int argc, char **argv)
{
    X509 **cert;
    UINTN name_len, data_len, signable_len, sig_len, descriptor_len;
    uint8_t *name, *data, *signable_data, *sig, *descriptor;
    const EFI_GUID *guid, *vendor_guid;
    EFI_GUID custom_vendor_guid;
    char *out_file;
    EFI_TIME timestamp;
    UINT32 attr = ATTR_BRNV | EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS;
    EVP_PKEY *sign_key = NULL;
    X509 *sign_cert = NULL;
    BIO *bio;
    FILE *out, *signature = NULL;
    time_t t;
    struct tm *tm;
    int i, count;
    bool timestamp_provided = false;
    bool output_signable = false;
    bool custom_guid_provided = false;

    ERR_load_crypto_strings();
    OpenSSL_add_all_digests();
    OpenSSL_add_all_ciphers();
    ERR_clear_error();

    for (;;) {
        int c = getopt(argc, argv, "c:g:k:hot:s:");

        if (c == -1)
            break;

        switch (c) {
        case 'c':
            bio = BIO_new_file(optarg, "r");
            if (!bio) {
                printf("Failed to open %s\n", optarg);
                exit(1);
            }
            sign_cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
            if (!sign_cert) {
                printf("Failed to parse %s\n", optarg);
                exit(1);
            }
            BIO_free_all(bio);
            break;
        case 'k':
            bio = BIO_new_file(optarg, "r");
            if (!bio) {
                printf("Failed to open %s\n", optarg);
                exit(1);
            }
            sign_key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
            if (!sign_key) {
                printf("Failed to parse %s\n", optarg);
                exit(1);
            }
            BIO_free_all(bio);
            break;
        case 'g':
            if (!parse_guid(optarg, &custom_vendor_guid)) {
                printf("Failed to parse GUID: %s\n", optarg);
                exit(1);
            }
            custom_guid_provided = true;
            break;
        case 'h':
            usage(argv[0]);
            exit(0);
        case 'o':
            output_signable = true;
            break;
        case 't':
            timestamp_provided = true;
            t = (time_t)atol(optarg);
            break;
        case 's':
            signature = fopen(optarg, "r");
            if (!signature) {
                printf("Failed to open '%s'\n", optarg);
                exit(1);
            }
            break;
        default:
            usage(argv[0]);
            exit(1);
        }
    }

    if ((sign_key && !sign_cert) || (sign_cert && !(sign_key || output_signable || (signature != NULL))) ||
            argc - optind < 3) {
        usage(argv[0]);
        exit(1);
    }

    if (!strcmp(argv[optind], "PK") || !strcmp(argv[optind], "KEK"))
        guid = &gEfiGlobalVariableGuid;
    else if (!strcmp(argv[optind], "db") || !strcmp(argv[optind], "dbx"))
        guid = &gEfiImageSecurityDatabaseGuid;
    else {
        printf("Unsupported variable name\n");
        exit(1);
    }

    if (custom_guid_provided)
        vendor_guid = &custom_vendor_guid;
    else if (!strcmp(argv[optind], "PK"))
        vendor_guid = &citrix_guid;
    else
        vendor_guid = &microsoft_guid;

    /* Handle "name" argument */
    name_len = strlen(argv[optind]);
    name = malloc(name_len * 2);
    if (!name) {
        printf("Out of memory!\n");
        exit(1);
    }
    for (i = 0; i < name_len; i++) {
        name[i * 2] = argv[optind][i];
        name[i * 2 + 1] = '\0';
    }
    name_len *= 2;
    optind++;

    /* Handle "output" argument */
    out_file = argv[optind];
    optind++;

    /* Handle certificate arguments */
    count = argc - optind;
    cert = calloc(count, sizeof(*cert));
    if (!cert) {
        printf("Out of memory!\n");
        exit(1);
    }

    for (i = optind; i < argc; i++) {
        bio = BIO_new_file(argv[i], "r");
        if (!bio) {
            printf("Failed to open %s\n", argv[i]);
            exit(1);
        }
        cert[i - optind] = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        if (!cert[i - optind]) {
            printf("Failed to parse %s\n", argv[i]);
            exit(1);
        }
        BIO_free_all(bio);
    }

    /* Initialize timestamp to current time (in UTC). */
    if (!timestamp_provided)
        time(&t);
    tm = gmtime(&t);
    if (!tm) {
         printf("gmtime() failed: %d, %s\n", errno, strerror(errno));
         exit(1);
    }
    timestamp.Year = tm->tm_year + 1900;
    timestamp.Month = tm->tm_mon + 1;
    timestamp.Day = tm->tm_mday;
    timestamp.Hour = tm->tm_hour;
    timestamp.Minute = tm->tm_min;
    timestamp.Second = tm->tm_sec;
    timestamp.Pad1 = 0;
    timestamp.Nanosecond = 0;
    timestamp.TimeZone = 0;
    timestamp.Daylight = 0;
    timestamp.Pad2 = 0;

    data = certs_to_sig_list(cert, count, &data_len, vendor_guid);
    signable_data = create_signable_data(name, name_len, guid, attr, &timestamp,
                                         data, data_len, &signable_len);

    out = fopen(out_file, "w");
    if (!out) {
        printf("Failed to open '%s'\n", out_file);
        exit(1);
    }

    if (output_signable) {
        if (fwrite(signable_data, 1, signable_len, out) != signable_len) {
            printf("Failed to write!\n");
            exit(1);
        }
    } else {
        if (signature != NULL) {
            fseek(signature, 0L, SEEK_END);
            sig_len = ftell(signature);
            fseek(signature, 0L, SEEK_SET);
            sig = malloc(sig_len);
            if (!sig) {
                printf("Out of memory!\n");
                exit(1);
            }
            if (fread(sig, 1, sig_len, signature) != sig_len) {
                printf("Failed to read!\n");
                exit(1);
            }
            fclose(signature);
        } else
            sig = sign_data(sign_cert, sign_key, signable_data, signable_len, &sig_len);

        descriptor = (uint8_t *)create_descriptor(sig_len, &timestamp, &descriptor_len);

        if (fwrite(descriptor, 1, descriptor_len, out) != descriptor_len) {
            printf("Failed to write!\n");
            exit(1);
        }
        if (fwrite(sig, 1, sig_len, out) != sig_len) {
            printf("Failed to write!\n");
            exit(1);
        }
        if (fwrite(data, 1, data_len, out) != data_len) {
            printf("Failed to write!\n");
            exit(1);
        }

        free(sig);
        free(descriptor);
    }
    fclose(out);

    free(signable_data);
    free(data);

    for (i = 0; i < count; i++)
        X509_free(cert[i]);
    free(cert);
    X509_free(sign_cert);
    EVP_PKEY_free(sign_key);
    free(name);

    return 0;
}
