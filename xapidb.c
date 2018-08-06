#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#include "backend.h"
#include "debug.h"
#include "efi.h"
#include "handler.h"
#include "option.h"
#include "pci.h"
#include "serialize.h"

#define DB_MAGIC "VARS"
#define DB_VERSION 1
/* magic, version, count, data length */
#define DB_HEADER_LEN \
    (strlen(DB_MAGIC) + sizeof(UINT32) + sizeof(UINTN) + sizeof(UINTN))

#define MAX_FILE_SIZE (1024 * 1024)

/* Path to the file containing the initial data from XAPI. */
static char *arg_init;
/* Path to the file used for resuming. */
static char *arg_resume;
/* Path to the file used for saving. */
static char *arg_save;
/* The VM's uuid. Used for saving to the XAPI db. */
static char *arg_uuid;

static bool
xapidb_parse_arg(const char *name, const char *val)
{
    if (!strcmp(name, "init"))
        arg_init = strdup(val);
    else if (!strcmp(name, "resume"))
        arg_resume = strdup(val);
    else if (!strcmp(name, "save"))
        arg_save = strdup(val);
    else if (!strcmp(name, "uuid"))
        arg_uuid = strdup(val);
    else
        return false;

    return true;
}

static bool
xapidb_check_args(void)
{
    if (opt_resume && arg_init) {
        fprintf(stderr, "Backend arg 'init' is invalid when resuming\n");
        return false;
    }
    if (!opt_resume && arg_resume) {
        fprintf(stderr, "Backend arg 'resume' is invalid when not resuming\n");
        return false;
    }

    return true;
}

/*
 * Serializes the list of variables into a buffer. The buffer must be freed by
 * the caller. Returns the length of the buffer on success otherwise 0.
 */
static size_t
serialize_variables(uint8_t **out, bool only_nv)
{
    struct efi_variable *l;
    uint8_t *buf, *ptr;
    size_t data_len = 0, count = 0;

    l = var_list;
    while (l) {
        if (only_nv && !(l->attributes & EFI_VARIABLE_NON_VOLATILE)) {
            l = l->next;
            continue;
        }

        data_len += sizeof(l->name_len) + l->name_len;
        data_len += sizeof(l->data_len) + l->data_len;
        data_len += GUID_LEN;
        data_len += sizeof(l->attributes);
        data_len += sizeof(l->timestamp);
        data_len += sizeof(l->cert);
        count++;
        l = l->next;
    }

    buf = malloc(data_len + DB_HEADER_LEN);
    if (!buf) {
        DBG("Failed to allocate memory\n");
        return 0;
    }

    ptr = buf;
    l = var_list;

    memcpy(ptr, DB_MAGIC, strlen(DB_MAGIC));
    ptr += strlen(DB_MAGIC);
    serialize_uint32(&ptr, DB_VERSION);
    serialize_uintn(&ptr, count);
    serialize_uintn(&ptr, data_len);

    while (l) {
        if (only_nv && !(l->attributes & EFI_VARIABLE_NON_VOLATILE)) {
            l = l->next;
            continue;
        }

        serialize_data(&ptr, l->name, l->name_len);
        serialize_data(&ptr, l->data, l->data_len);
        serialize_guid(&ptr, &l->guid);
        serialize_uint32(&ptr, l->attributes);
        serialize_timestamp(&ptr, &l->timestamp);
        memcpy(ptr, l->cert, sizeof(l->cert));
        ptr += sizeof(l->cert);
        l = l->next;
    }

    *out = buf;
    return data_len + DB_HEADER_LEN;
}

static bool
unserialize_variables(uint8_t **buf, size_t count)
{
    struct efi_variable *l;
    size_t i;

    for (i = 0; i < count; i++) {
        l = malloc(sizeof(*l));
        if (!l) {
            DBG("Failed to allocate memory\n");
            return false;
        }

        l->name = unserialize_data(buf, &l->name_len, NAME_LIMIT);
        if (!l->name) {
            DBG("Failed to allocate memory\n");
            free(l);
            return false;
        }
        l->data = unserialize_data(buf, &l->data_len, DATA_LIMIT);
        if (!l->data) {
            DBG("Failed to allocate memory\n");
            free(l->name);
            free(l);
            return false;
        }
        unserialize_guid(buf, &l->guid);
        l->attributes = unserialize_uint32(buf);
        unserialize_timestamp(buf, &l->timestamp);
        memcpy(l->cert, buf, sizeof(l->cert));
        *buf += sizeof(l->cert);

        l->next = var_list;
        var_list = l;
    }

    return true;
}

static enum backend_init_status
xapidb_init(void)
{
    FILE *f;
    BIO *bio, *b64;
    struct stat st;
    uint8_t *buf, *ptr;
    uint32_t version;
    size_t count;
    bool ret;
    int max_len, n, total = 0;

    if (!arg_init)
        return BACKEND_INIT_FIRSTBOOT;

    f = fopen(arg_init, "r");
    if (!f) {
        DBG("Failed to open '%s'\n", arg_init);
        return BACKEND_INIT_FAILURE;
    }

    if (fstat(fileno(f), &st) == -1 || st.st_size > MAX_FILE_SIZE) {
        DBG("Init file size is invalid\n");
        fclose(f);
        return BACKEND_INIT_FAILURE;
    }
    max_len = st.st_size * 3 / 4;

    buf = malloc(max_len + 1);
    if (!buf) {
        DBG("Failed to allocate memory\n");
        fclose(f);
        return BACKEND_INIT_FAILURE;
    }

    bio = BIO_new_fp(f, BIO_CLOSE);
    if (!bio) {
        DBG("Failed to create BIO\n");
        free(buf);
        fclose(f);
        return BACKEND_INIT_FAILURE;
    }
    b64 = BIO_new(BIO_f_base64());
    if (!b64) {
        DBG("Failed to create BIO\n");
        BIO_free_all(bio);
        return BACKEND_INIT_FAILURE;
    }
    BIO_push(b64, bio);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    for (;;) {
        n = BIO_read(b64, buf + total, max_len - total);
        if (n <= 0)
            break;
        total += n;
    }
    buf[total] = '\0';

    BIO_free_all(b64);

    if (total < DB_HEADER_LEN) {
        DBG("Init file size is invalid\n");
        free(buf);
        return BACKEND_INIT_FAILURE;
    }

    ptr = buf;
    if (memcmp(ptr, DB_MAGIC, strlen(DB_MAGIC))) {
        DBG("Invalid init magic\n");
        free(buf);
        return BACKEND_INIT_FAILURE;
    }
    ptr += strlen(DB_MAGIC);

    version = unserialize_uint32(&ptr);
    if (version != DB_VERSION) {
        DBG("Unsupported init version\n");
        free(buf);
        return BACKEND_INIT_FAILURE;
    }

    count = unserialize_uintn(&ptr);
    unserialize_uintn(&ptr); /* data_len */

    ret = unserialize_variables(&ptr, count);
    free(buf);

    return ret ? BACKEND_INIT_SUCCESS : BACKEND_INIT_FAILURE;
}

static bool
xapidb_save(void)
{
    FILE *f;
    uint8_t *buf;
    size_t len;

    if (!arg_save)
        return true;

    len = serialize_variables(&buf, false);
    if (len == 0)
        return false;

    f = fopen(arg_save, "w");
    if (!f) {
        DBG("Failed to open '%s'\n", arg_save);
        return false;
    }
    if (fwrite(buf, 1, len, f) != len) {
        DBG("Failed to write to '%s': %s\n", arg_save, strerror(errno));
        fclose(f);
        free(buf);
        return false;
    }
    free(buf);

    if (fwrite(pci_config_ptr(), 1, PCI_CONFIG_SIZE, f) != PCI_CONFIG_SIZE) {
        DBG("Failed to write to '%s': %s\n", arg_save, strerror(errno));
        fclose(f);
        return false;
    }

    fclose(f);
    return true;
}

static bool
xapidb_resume(void)
{
    FILE *f;
    struct stat st;
    uint8_t *buf, *ptr;
    uint32_t version;
    size_t count;

    if (!arg_resume)
        return true;

    f = fopen(arg_resume, "r");
    if (!f) {
        DBG("Failed to open '%s'\n", arg_resume);
        return false;
    }

    if (fstat(fileno(f), &st) == -1 || st.st_size < DB_HEADER_LEN ||
            st.st_size > MAX_FILE_SIZE) {
        DBG("Save file size is invalid\n");
        fclose(f);
        return false;
    }

    buf = malloc(st.st_size);
    if (!buf) {
        DBG("Failed to allocate memory\n");
        fclose(f);
        return false;
    }
    if (fread(buf, 1, st.st_size, f) != st.st_size) {
        DBG("Failed to read from '%s'\n", arg_resume);
        free(buf);
        fclose(f);
        return false;
    }
    fclose(f);

    ptr = buf;
    if (memcmp(ptr, DB_MAGIC, strlen(DB_MAGIC))) {
        DBG("Invalid db magic\n");
        free(buf);
        return false;
    }
    ptr += strlen(DB_MAGIC);

    version = unserialize_uint32(&ptr);
    if (version != DB_VERSION) {
        DBG("Unsupported save version\n");
        free(buf);
        return false;
    }

    count = unserialize_uintn(&ptr);
    unserialize_uintn(&ptr); /* data_len */
    if (!unserialize_variables(&ptr, count)) {
        free(buf);
        return false;
    }

    pci_config_resume(ptr);
    free(buf);

    return true;
}

static bool
base64_encode(const uint8_t *buf, size_t len, char **out)
{
    BIO *b64, *bio;
    char *ptr;
    int n;
    long out_len;
    size_t total = 0;

    bio = BIO_new(BIO_s_mem());
    if (!bio) {
        /* DBG("Failed to create BIO\n"); */
        return false;
    }
    b64 = BIO_new(BIO_f_base64());
    if (!b64) {
        /* DBG("Failed to create BIO\n"); */
        BIO_free_all(bio);
        return false;
    }
    BIO_push(b64, bio);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_set_close(bio, BIO_CLOSE);

    while ((len - total) > 0) {
        n = BIO_write(b64, buf + total, (int)(len - total));
        if (n <= 0)
            break;
        total += n;
    }

    BIO_flush(b64);
    out_len = BIO_get_mem_data(b64, &ptr);
    *out = malloc(out_len + 1);
    if (!*out) {
        BIO_free_all(b64);
        return false;
    }
    memcpy(*out, ptr, out_len);
    (*out)[out_len] = '\0';

    BIO_free_all(b64);

    return total == len ? true : false;
}

#define XAPI_SOCKET "/var/lib/xcp/xapi"

#define HTTP_STATUS_OK 200

#define HTTP_POST \
    "POST / HTTP/1.1\r\n" \
    "Host: _var_lib_xcp_xapi\r\n" \
    "Accept-Encoding: identity\r\n" \
    "User-Agent: varstored/0.1\r\n" \
    "Connection: close\r\n" \
    "Content-Type: text/xml\r\n" \
    "Content-Length: %lu\r\n" \
    "\r\n" \
    "%s"

#define LOGIN_CALL \
    "<?xml version='1.0'?>" \
    "<methodCall>" \
      "<methodName>session.login_with_password</methodName>" \
      "<params>" \
        "<param><value><string>root</string></value></param>" \
        "<param><value><string></string></value></param>" \
        "<param><value><string></string></value></param>" \
        "<param><value><string></string></value></param>" \
      "</params>" \
    "</methodCall>"

#define VM_GET_BY_UUID_CALL \
    "<?xml version='1.0'?>" \
    "<methodCall>" \
      "<methodName>VM.get_by_uuid</methodName>" \
      "<params>" \
        "<param><value><string>%s</string></value></param>" \
        "<param><value><string>%s</string></value></param>" \
      "</params>" \
    "</methodCall>"

#define VM_REMOVE_FROM_PLATFORM_CALL \
    "<?xml version='1.0'?>" \
    "<methodCall>" \
      "<methodName>VM.remove_from_NVRAM</methodName>" \
      "<params>" \
        "<param><value><string>%s</string></value></param>" \
        "<param><value><string>%s</string></value></param>" \
        "<param><value><string>EFI-variables</string></value></param>" \
      "</params>" \
    "</methodCall>"

#define VM_ADD_TO_PLATFORM_CALL \
    "<?xml version='1.0'?>" \
    "<methodCall>" \
      "<methodName>VM.add_to_NVRAM</methodName>" \
      "<params>" \
        "<param><value><string>%s</string></value></param>" \
        "<param><value><string>%s</string></value></param>" \
        "<param><value><string>EFI-variables</string></value></param>" \
        "<param><value><string>%s</string></value></param>" \
      "</params>" \
    "</methodCall>"

#define LOGOUT_CALL \
    "<?xml version='1.0'?>" \
    "<methodCall>" \
      "<methodName>session.logout</methodName>" \
      "<params>" \
        "<param><value><string>%s</string></value></param>" \
      "</params>" \
    "</methodCall>"

static bool
write_all(int fd, const char *buf, size_t remaining)
{
    ssize_t ret;

    while (remaining > 0) {
        ret = write(fd, buf, remaining < BUFSIZ ? remaining : BUFSIZ);
        if (ret < 0)
            return false;
        if (ret == 0)
            break;
        remaining -= ret;
        buf += ret;
    }

    return true;
}

static size_t read_all(int fd, char *buf, size_t limit)
{
    ssize_t ret;
    size_t total = 0, remaining;

    for (;;) {
        remaining = limit - total - 1;
        ret = read(fd, buf, remaining < BUFSIZ ? remaining : BUFSIZ);
        if (ret <= 0)
            break;
        total += ret;
        buf += ret;
    }

    *buf = '\0';

    return total;
}

static int
xmlrpc_call(char **response, const char *fmt, ...)
{
    va_list ap;
    struct sockaddr_un addr;
    int fd, status;
    size_t n;
    char *ptr, *request, *content;
    char buf[1024];

    va_start(ap, fmt);
    if (vasprintf(&content, fmt, ap) == -1) {
        va_end(ap);
        return -1;
    }
    va_end(ap);

    if (asprintf(&request, HTTP_POST, strlen(content), content) == -1) {
        free(content);
        return -1;
    }
    free(content);

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, XAPI_SOCKET, sizeof(addr.sun_path) - 1);

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1) {
        free(request);
        return -1;
    }
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        free(request);
        close(fd);
        return -1;
    }

    if (!write_all(fd, request, strlen(request))) {
        free(request);
        close(fd);
        return -1;
    }
    free(request);

    n = read_all(fd, buf, sizeof(buf));
    close(fd);
    if (n == 0)
        return -1;

    ptr = strchr(buf, ' ');
    if (!ptr)
        return -1;
    status = atoi(ptr);

    ptr = strstr(buf, "\r\n\r\n");
    if (!ptr)
        return -1;

    *response = strdup(ptr + strlen("\r\n\r\n"));

    return status;
}

static bool
xmlrpc_process(char *response, char **result)
{
    xmlDocPtr doc = NULL;
    xmlNodePtr node = NULL;
    xmlXPathContextPtr xpath_ctx = NULL;
    xmlXPathObjectPtr xpath_obj = NULL;
    xmlChar *content = NULL;
    bool ret = false;

    doc = xmlReadMemory(response, strlen(response), "noname.xml", NULL, 0);
    if (!doc)
        goto out;
    xpath_ctx = xmlXPathNewContext(doc);
    if (!xpath_ctx)
        goto out;

    xpath_obj = xmlXPathEvalExpression(
        BAD_CAST "/methodResponse/params/param/value/struct/member[1]/value",
        xpath_ctx);
    if (!xpath_obj || !xpath_obj->nodesetval || xpath_obj->nodesetval->nodeNr == 0)
        goto out;
    node = xpath_obj->nodesetval->nodeTab[0];
    content = xmlNodeGetContent(node);
    if (strcmp((char *)content, "Success"))
        goto out;

    if (result) {
        xmlFree(content);
        content = NULL;
        xmlXPathFreeObject(xpath_obj);
        xpath_obj = xmlXPathEvalExpression(
            BAD_CAST "/methodResponse/params/param/value/struct/member[2]/value",
            xpath_ctx);
        if (!xpath_obj || !xpath_obj->nodesetval || xpath_obj->nodesetval->nodeNr == 0)
            goto out;
        node = xpath_obj->nodesetval->nodeTab[0];
        content = xmlNodeGetContent(node);
        *result = strdup((char *)content);
    }

    ret = true;

out:
    xmlFree(content);
    xmlXPathFreeObject(xpath_obj);
    xmlXPathFreeContext(xpath_ctx);
    xmlFreeDoc(doc);
    return ret;
}

static bool
send_to_xapi(char *uuid, char *data)
{
    int status;
    bool ret = false;
    char *session_ref = NULL, *vm_ref = NULL, *response = NULL;

    status = xmlrpc_call(&response, LOGIN_CALL);
    if (status != HTTP_STATUS_OK)
        goto out;
    if (!xmlrpc_process(response, &session_ref))
        goto out;
    free(response);
    response = NULL;

    status = xmlrpc_call(&response, VM_GET_BY_UUID_CALL, session_ref, uuid);
    if (status != HTTP_STATUS_OK)
        goto out;
    if (!xmlrpc_process(response, &vm_ref))
        goto out;
    free(response);
    response = NULL;

    status = xmlrpc_call(&response, VM_REMOVE_FROM_PLATFORM_CALL, session_ref, vm_ref);
    if (status != HTTP_STATUS_OK)
        goto out;
    if (!xmlrpc_process(response, NULL))
        goto out;
    free(response);
    response = NULL;

    status = xmlrpc_call(&response, VM_ADD_TO_PLATFORM_CALL, session_ref, vm_ref, data);
    if (status != HTTP_STATUS_OK)
        goto out;
    if (!xmlrpc_process(response, NULL))
        goto out;
    free(response);
    response = NULL;

    status = xmlrpc_call(&response, LOGOUT_CALL, session_ref);
    if (status != HTTP_STATUS_OK)
        goto out;
    if (!xmlrpc_process(response, NULL))
        goto out;
    free(response);
    response = NULL;

    ret = true;

out:
    free(session_ref);
    free(vm_ref);
    free(response);
    return ret;
}

static bool
xapidb_set_variable(void)
{
    uint8_t *buf;
    char *encoded;
    size_t len;
    bool ret;

    if (!arg_uuid)
        return true;

    len = serialize_variables(&buf, true);
    if (len == 0)
        return false;

    if (!base64_encode(buf, len, &encoded)) {
        free(buf);
        return false;
    }
    free(buf);

    ret = send_to_xapi(arg_uuid, encoded);
    free(encoded);

    return ret;
}

struct backend xapidb = {
    .parse_arg = xapidb_parse_arg,
    .check_args = xapidb_check_args,
    .init = xapidb_init,
    .save = xapidb_save,
    .resume = xapidb_resume,
    .set_variable = xapidb_set_variable,
};
