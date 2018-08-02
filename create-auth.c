#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs7.h>
#include <openssl/err.h>

#include "efi.h"
#include "guid.h"

/*
 * This utility prepares an "auth". An auth file contains an authentication
 * descriptor, a signature, and some data and is used for updating a secure
 * variable. It is used at build time to prepare authentication descriptors
 * that are used to set up PK, KEK, db, etc. if needed during VM start. It
 * needs to be done at build time because the private key used to sign the data
 * is ephemeral.
 */

static EFI_GUID citrix_guid =
    {{0x35, 0xc5, 0xac, 0xc0, 0xc8, 0x25, 0x46, 0x64, 0x92, 0x5b, 0x5d, 0xd7, 0xd0, 0xb2, 0xf5, 0xaa}};

/* Converts an array of X509 certificates into an EFI_SIGNATURE_LIST */
static EFI_SIGNATURE_LIST *
certs_to_sig_list(X509 **cert, int count, UINTN *data_len)
{
    int i, len;
    uint8_t *ptr;
    EFI_SIGNATURE_LIST *data;
    EFI_SIGNATURE_DATA *sig_data;
    UINT32 signature_size = 0;

    for (i = 0; i < count; i++) {
        len = i2d_X509(cert[i], NULL);
        if (len < 0) {
            printf("i2d_X509 failed\n");
            exit(1);
        }
        if (len > signature_size)
            signature_size = len;
    }
    signature_size += offsetof(EFI_SIGNATURE_DATA, SignatureData);

    *data_len = sizeof(EFI_SIGNATURE_LIST) + count * signature_size;
    data = malloc(*data_len);
    if (!data) {
        printf("Out of memory!\n");
        exit(1);
    }

    data->SignatureListSize = *data_len;
    data->SignatureSize = signature_size;
    data->SignatureHeaderSize = 0;
    memcpy(&data->SignatureType, &gEfiCertX509Guid, GUID_LEN);

    for (i = 0; i < count; i++) {
        ptr = (uint8_t *)data + sizeof(EFI_SIGNATURE_LIST) +
            i * signature_size + offsetof(EFI_SIGNATURE_DATA, SignatureData);
        if (i2d_X509(cert[i], &ptr) < 0) {
            printf("i2d_X509 failed\n");
            exit(1);
        }

        sig_data = (EFI_SIGNATURE_DATA *)((uint8_t *)data +
                   sizeof(EFI_SIGNATURE_LIST) + i * signature_size);
        memcpy(&sig_data->SignatureOwner, &citrix_guid, GUID_LEN);
    }

    return data;
}

/* Returns a signature suitable for a time-based authenticated write. */
static uint8_t *
sign_data(X509 *cert, EVP_PKEY *key, uint8_t *name, UINTN name_len,
          EFI_GUID *guid, UINT32 attr, EFI_TIME *timestamp, uint8_t *data,
          UINTN data_len, UINTN *sig_len)
{
    UINTN len;
    int p7_len;
    uint8_t *sig, *buf, *ptr;
    PKCS7 *p7;
    BIO *bio;
    const EVP_MD *md;

    if (!key) {
        *sig_len = 0;
        return NULL;
    }

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

    bio = BIO_new_mem_buf(buf, len);
    if (!buf) {
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

static void
usage(const char *progname)
{
    printf("usage: %s [-k <key>] [-c cert] name output cert [cert...]\n",
           progname);
}

int main(int argc, char **argv)
{
    X509 **cert;
    UINTN name_len, data_len, sig_len, descriptor_len;
    uint8_t *name, *data, *sig, *descriptor;
    EFI_GUID *guid;
    char *out_file;
    EFI_TIME timestamp;
    UINT32 attr = ATTR_BRNV | EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS;
    EVP_PKEY *sign_key = NULL;
    X509 *sign_cert = NULL;
    BIO *bio;
    FILE *out;
    time_t t;
    struct tm *tm;
    int i, count;

    ERR_load_crypto_strings();
    OpenSSL_add_all_digests();
    OpenSSL_add_all_ciphers();
    ERR_clear_error();

    for (;;) {
        int c = getopt(argc, argv, "c:k:h");

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
        case 'h':
            usage(argv[0]);
            exit(0);
        default:
            usage(argv[0]);
            exit(1);
        }
    }

    if ((sign_key && !sign_cert) || (!sign_key && sign_cert) ||
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

    /* Hanlde certificate arguments */
    count = argc - optind;
    cert = calloc(count, sizeof(*cert));
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
    time(&t);
    tm = gmtime(&t);
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

    data = (uint8_t *)certs_to_sig_list(cert, count, &data_len);
    sig = sign_data(sign_cert, sign_key, name, name_len, guid, attr,
                    &timestamp, data, data_len, &sig_len);
    descriptor = (uint8_t *)create_descriptor(sig_len, &timestamp, &descriptor_len);

    out = fopen(out_file, "w");
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
    fclose(out);

    free(data);
    free(sig);
    free(descriptor);

    for (i = 0; i < count; i++)
        X509_free(cert[i]);
    free(cert);
    X509_free(sign_cert);
    EVP_PKEY_free(sign_key);
    free(name);

    return 0;
}
