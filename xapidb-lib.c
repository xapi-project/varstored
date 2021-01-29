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
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
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
#include <handler.h>
#include <serialize.h>
#include <xapidb.h>

#define MAX_HTTP_SIZE (256 * 1024)

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

#define VM_MESSAGE_CREATE_CALL \
    "<?xml version='1.0'?>" \
    "<methodCall>" \
      "<methodName>message.create</methodName>" \
      "<params>" \
        "<param><value><string>%s</string></value></param>" \
        "<param><value><string>%s</string></value></param>" \
        "<param><value><int>%d</int></value></param>" \
        "<param><value><string>%s</string></value></param>" \
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
/* Path to the XAPI socket. */
char *xapidb_arg_socket = "/var/lib/xcp/xapi";

/*
 * The VM's opaqueref: cached for the lifetime of varstored.
 * This only changes during storage migration, but then we start a new varstored on
 * the destination, so for the lifetime of a particular varstored instance this
 * does not change.
 */
static char *xapidb_vm_ref;

#define MAX_CREDIT        100
#define CREDIT_PER_SECOND 2
#define NS_PER_CREDIT (1000000000 / CREDIT_PER_SECOND)
static time_t last_time; /* Time of the last send. */
static unsigned int send_credit = MAX_CREDIT; /* Number of allowed fast sends. */

/*
 * Serializes the list of variables into a buffer. The buffer must be freed by
 * the caller. Returns the length of the buffer on success otherwise 0.
 */
bool
xapidb_serialize_variables(uint8_t **out, size_t *out_len, bool only_nv)
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
        return false;
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
    *out_len = data_len + DB_HEADER_LEN;
    return true;
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
    strncpy(addr.sun_path, xapidb_arg_socket, sizeof(addr.sun_path) - 1);

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
    char *session_ref = NULL, *response = NULL;

    status = xmlrpc_call(&response, LOGIN_CALL);
    if (status != HTTP_STATUS_OK)
        goto out;
    if (!xmlrpc_process(response, &session_ref))
        goto out;
    free(response);
    response = NULL;

    if (!xapidb_vm_ref) {
        status = xmlrpc_call(&response, VM_GET_BY_UUID_CALL, session_ref, uuid);
        if (status != HTTP_STATUS_OK) {
            ERR("Failed to communicate with XAPI\n");
            goto out;
        }
        if (!xmlrpc_process(response, &xapidb_vm_ref)) {
            ERR("Failed to lookup VM\n");
            goto out;
        }
        free(response);
        response = NULL;
    }

    status = xmlrpc_call(&response, VM_SET_NVRAM_EFI_VARIABLES_CALL, session_ref, xapidb_vm_ref, data);
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
    if (!bio)
        return false;
    b64 = BIO_new(BIO_f_base64());
    if (!b64) {
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

    if (total != len) {
        BIO_free_all(b64);
        return false;
    }

    out_len = BIO_get_mem_data(b64, &ptr);
    *out = malloc(out_len + 1);
    if (!*out) {
        BIO_free_all(b64);
        return false;
    }
    memcpy(*out, ptr, out_len);
    (*out)[out_len] = '\0';

    BIO_free_all(b64);

    return true;
}

bool
xapidb_set_variable(void)
{
    uint8_t *buf;
    char *encoded;
    size_t len;
    bool ret;
    time_t cur_time, diff_time;

    if (!xapidb_arg_uuid)
        return true;

    if (!xapidb_serialize_variables(&buf, &len, true))
        return false;

    if (!base64_encode(buf, len, &encoded)) {
        free(buf);
        return false;
    }
    free(buf);

    /*
     * To avoid a DoS on XAPI by the VM, rate limit sends to XAPI.
     * Normal usage should never hit this.
     */
    cur_time = time(NULL);
    diff_time = cur_time - last_time;
    last_time = cur_time;
    send_credit += diff_time * CREDIT_PER_SECOND;
    if (send_credit > MAX_CREDIT)
        send_credit = MAX_CREDIT;

    if (send_credit > 0) {
        send_credit--;
    } else {
        /* If no credit, wait the correct amount of time to get a credit. */
        struct timespec ts = {0, NS_PER_CREDIT};

        nanosleep(&ts, NULL);
        last_time = time(NULL);
    }

    ret = send_to_xapi(xapidb_arg_uuid, encoded);
    free(encoded);

    return ret;
}

static bool
unserialize_variables(uint8_t **buf, size_t count, size_t rem)
{
#define VARIABLE_SIZE \
    (sizeof(l->name_len) + sizeof(l->data_len) + sizeof(l->guid) + \
     sizeof(l->attributes) + sizeof(l->timestamp) + sizeof(l->cert))
    struct efi_variable *l;
    size_t i;

    for (i = 0; i < count; i++) {
        l = calloc(1, sizeof(*l));
        if (!l) {
            ERR("Failed to allocate memory\n");
            return false;
        }

        if (rem < VARIABLE_SIZE)
            goto invalid;
        rem -= VARIABLE_SIZE;

        l->name = unserialize_data(buf, &l->name_len,
                                   rem < NAME_LIMIT ? rem : NAME_LIMIT);
        if (!l->name)
            goto invalid;
        rem -= l->name_len;

        l->data = unserialize_data(buf, &l->data_len,
                                   rem < DATA_LIMIT ? rem : DATA_LIMIT);
        if (!l->data)
            goto invalid;
        rem -= l->data_len;

        unserialize_guid(buf, &l->guid);
        l->attributes = unserialize_uint32(buf);
        unserialize_timestamp(buf, &l->timestamp);
        memcpy(l->cert, *buf, sizeof(l->cert));
        *buf += sizeof(l->cert);

        l->next = var_list;
        var_list = l;
    }

    if (rem) {
        ERR("More data than expected: %lu\n", rem);
        return false;
    }

    return true;

invalid:
    ERR("Failed to unserialize variable!\n");
    free(l->name);
    free(l->data);
    free(l);

    return false;
#undef VARIABLE_SIZE
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
    if (count > MAX_VARIABLE_COUNT) {
        ERR("Invalid variable count %ld > %u\n", count, MAX_VARIABLE_COUNT);
        return false;
    }
    unserialize_uintn(buf); /* data_len */

    return unserialize_variables(buf, count, len - DB_HEADER_LEN);
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
    char *session_ref = NULL, *response = NULL;

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
    if (!xmlrpc_process(response, &xapidb_vm_ref)) {
        ERR("Failed to lookup VM\n");
        goto out;
    }
    free(response);
    response = NULL;

    status = xmlrpc_call(&response, VM_GET_NVRAM_CALL, session_ref, xapidb_vm_ref);
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
    if (status != HTTP_STATUS_OK || !xmlrpc_process(response, NULL)) {
        ERR("Failed to logout\n");
        free(*out);
        *out = NULL;
        goto out;
    }
    free(response);
    response = NULL;

    ret = true;

out:
    free(session_ref);
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

bool
xapidb_sb_notify(void)
{
    int status;
    bool ret = false;
    char *session_ref = NULL, *response = NULL;

    status = xmlrpc_call(&response, LOGIN_CALL);
    if (status != HTTP_STATUS_OK)
        goto out;
    if (!xmlrpc_process(response, &session_ref))
        goto out;
    free(response);
    response = NULL;

    status = xmlrpc_call(&response, VM_MESSAGE_CREATE_CALL,
                         session_ref,
                         "VM_SECURE_BOOT_FAILED",
                         5, /* priority */
                         "VM", /* class */
                         xapidb_arg_uuid,
                         "The VM failed to pass Secure Boot verification.");
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
    free(response);
    return ret;
}
