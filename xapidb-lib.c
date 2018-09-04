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

#include <debug.h>
#include <efi.h>
#include <serialize.h>
#include <xapidb.h>

#define XAPI_SOCKET "/var/lib/xcp/xapi"

#define MAX_HTTP_SIZE (128 * 1024)

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

#define VM_SET_NVRAM_EFI_VARIABLES_CALL \
    "<?xml version='1.0'?>" \
    "<methodCall>" \
      "<methodName>VM.set_NVRAM_EFI_variables</methodName>" \
      "<params>" \
        "<param><value><string>%s</string></value></param>" \
        "<param><value><string>%s</string></value></param>" \
        "<param><value><string>%s</string></value></param>" \
      "</params>" \
    "</methodCall>"

#define VM_GET_NVRAM_CALL \
    "<?xml version='1.0'?>" \
    "<methodCall>" \
      "<methodName>VM.get_NVRAM</methodName>" \
      "<params>" \
        "<param><value><string>%s</string></value></param>" \
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

/* Path to the file containing the initial data from XAPI. */
char *xapidb_arg_init;
/* The VM's uuid. Used for saving to the XAPI db. */
char *xapidb_arg_uuid;

/*
 * Serializes the list of variables into a buffer. The buffer must be freed by
 * the caller. Returns the length of the buffer on success otherwise 0.
 */
size_t
xapidb_serialize_variables(uint8_t **out, bool only_nv)
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

static size_t
read_all(int fd, char *buf, size_t limit)
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
    char buf[MAX_HTTP_SIZE];

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

    status = xmlrpc_call(&response, VM_SET_NVRAM_EFI_VARIABLES_CALL, session_ref, vm_ref, data);
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

bool
xapidb_set_variable(void)
{
    uint8_t *buf;
    char *encoded;
    size_t len;
    bool ret;

    if (!xapidb_arg_uuid)
        return true;

    len = xapidb_serialize_variables(&buf, true);
    if (len == 0)
        return false;

    if (!base64_encode(buf, len, &encoded)) {
        free(buf);
        return false;
    }
    free(buf);

    ret = send_to_xapi(xapidb_arg_uuid, encoded);
    free(encoded);

    return ret;
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

bool
xapidb_parse_blob(uint8_t **buf, int len)
{
    uint32_t version;
    size_t count;

    if (len < DB_HEADER_LEN) {
        ERR("Init file size is invalid\n");
        return false;
    }

    if (memcmp(*buf, DB_MAGIC, strlen(DB_MAGIC))) {
        ERR("Invalid init magic\n");
        return false;
    }
    *buf += strlen(DB_MAGIC);

    version = unserialize_uint32(buf);
    if (version != DB_VERSION) {
        ERR("Unsupported init version\n");
        return false;
    }

    count = unserialize_uintn(buf);
    unserialize_uintn(buf); /* data_len */

    return unserialize_variables(buf, count);
}

static bool
parse_get_nvram_call(const char *response, char **result)
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

#define RESPONSE_XPATH "/methodResponse/params/param/value/struct"

    xpath_obj = xmlXPathEvalExpression(
        BAD_CAST RESPONSE_XPATH "/member[1]/value",
        xpath_ctx);
    if (!xpath_obj || !xpath_obj->nodesetval || xpath_obj->nodesetval->nodeNr == 0)
        goto out;
    node = xpath_obj->nodesetval->nodeTab[0];
    content = xmlNodeGetContent(node);
    if (strcmp((char *)content, "Success"))
        goto out;

    xmlFree(content);
    content = NULL;
    xmlXPathFreeObject(xpath_obj);

    ret = true;
    *result = NULL;
    xpath_obj = xmlXPathEvalExpression(BAD_CAST
        RESPONSE_XPATH "/member/value/struct/member[name=\"EFI-variables\"]/value",
        xpath_ctx);
    if (!xpath_obj || !xpath_obj->nodesetval || xpath_obj->nodesetval->nodeNr == 0)
        goto out;
    node = xpath_obj->nodesetval->nodeTab[0];
    content = xmlNodeGetContent(node);
    *result = strdup((char *)content);

#undef RESPONSE_XPATH

out:
    xmlFree(content);
    xmlXPathFreeObject(xpath_obj);
    xmlXPathFreeContext(xpath_ctx);
    xmlFreeDoc(doc);
    return ret;
}

static bool
get_from_xapi(const char *uuid, char **out)
{
    int status;
    bool ret = false;
    char *session_ref = NULL, *vm_ref = NULL, *response = NULL;

    status = xmlrpc_call(&response, LOGIN_CALL);
    if (status != HTTP_STATUS_OK) {
        ERR("Failed to communicate with XAPI\n");
        goto out;
    }
    if (!xmlrpc_process(response, &session_ref)) {
        ERR("Failed to communicate with XAPI\n");
        goto out;
    }
    free(response);
    response = NULL;

    status = xmlrpc_call(&response, VM_GET_BY_UUID_CALL, session_ref, uuid);
    if (status != HTTP_STATUS_OK) {
        ERR("Failed to communicate with XAPI\n");
        goto out;
    }
    if (!xmlrpc_process(response, &vm_ref)) {
        ERR("Failed to lookup VM\n");
        goto out;
    }
    free(response);
    response = NULL;

    status = xmlrpc_call(&response, VM_GET_NVRAM_CALL, session_ref, vm_ref);
    if (status != HTTP_STATUS_OK) {
        ERR("Failed to get EFI variables\n");
        goto out;
    }
    if (!parse_get_nvram_call(response, out)) {
        ERR("Failed to get EFI variables\n");
        goto out;
    }
    free(response);
    response = NULL;

    status = xmlrpc_call(&response, LOGOUT_CALL, session_ref);
    if (status != HTTP_STATUS_OK) {
        ERR("Failed to logout\n");
        goto out;
    }
    if (!xmlrpc_process(response, NULL)) {
        ERR("Failed to logout\n");
        goto out;
    }
    free(response);
    response = NULL;

    ret = true;

out:
    free(session_ref);
    free(vm_ref);
    free(response);
    return ret;
}

enum backend_init_status
xapidb_init(void)
{
    char *encoded;
    uint8_t *buf, *ptr;
    BIO *bio, *b64;
    bool ret;
    int max_len, n, total = 0;

    ret = get_from_xapi(xapidb_arg_uuid, &encoded);
    if (!ret)
        return BACKEND_INIT_FAILURE;
    if (!encoded)
        return BACKEND_INIT_FIRSTBOOT;

    max_len = strlen(encoded) * 3 / 4;

    buf = malloc(max_len);
    if (!buf) {
        ERR("Failed to allocate memory\n");
        free(encoded);
        return BACKEND_INIT_FAILURE;
    }

    bio = BIO_new_mem_buf(encoded, -1);
    if (!bio) {
        ERR("Failed to create BIO\n");
        free(encoded);
        free(buf);
        return 1;
    }
    b64 = BIO_new(BIO_f_base64());
    if (!b64) {
        ERR("Failed to create BIO\n");
        free(encoded);
        free(buf);
        BIO_free_all(bio);
        return 1;
    }
    BIO_push(b64, bio);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    for (;;) {
        n = BIO_read(b64, buf + total, max_len - total);
        if (n <= 0)
            break;
        total += n;
    }
    BIO_free_all(b64);
    free(encoded);

    ptr = buf;
    ret = xapidb_parse_blob(&ptr, total);
    free(buf);

    return ret ? BACKEND_INIT_SUCCESS : BACKEND_INIT_FAILURE;
}
