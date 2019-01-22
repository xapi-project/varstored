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

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <netinet/in.h>
#include <pwd.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <assert.h>

#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/prctl.h>

#include <locale.h>

#include <xenctrl.h>
#include <xen/hvm/ioreq.h>
#include <xenstore.h>
#include <xenevtchn.h>
#include <xendevicemodel.h>
#include <xenforeignmemory.h>
#include <xentoolcore.h>

#include <debug.h>
#include <depriv.h>
#include <handler.h>
#include <backend.h>

#include "io_port.h"
#include "option.h"

#define mb() asm volatile ("" : : : "memory")

#define XS_VARSTORED_PID_PATH "/local/domain/%u/varstored-pid"

enum {
    VARSTORED_OPT_DOMAIN,
    VARSTORED_OPT_RESUME,
    VARSTORED_OPT_NONPERSISTENT,
    VARSTORED_OPT_DEPRIV,
    VARSTORED_OPT_UID,
    VARSTORED_OPT_GID,
    VARSTORED_OPT_CHROOT,
    VARSTORED_OPT_PIDFILE,
    VARSTORED_OPT_BACKEND,
    VARSTORED_OPT_ARG,
    VARSTORED_NR_OPTS
    };

static struct option varstored_option[] = {
    {"domain", 1, NULL, 0},
    {"resume", 0, NULL, 0},
    {"nonpersistent", 0, NULL, 0},
    {"depriv", 0, NULL, 0},
    {"uid", 1, NULL, 0},
    {"gid", 1, NULL, 0},
    {"chroot", 1, NULL, 0},
    {"pidfile", 1, NULL, 0},
    {"backend", 1, NULL, 0},
    {"arg", 1, NULL, 0},
    {NULL, 0, NULL, 0}
};

static const char *varstored_option_text[] = {
    "<domid>",
    NULL,
    NULL,
    NULL,
    "<uid>",
    "<gid>",
    "<chroot>",
    "<pidfile>",
    "<backend>",
    "<name>:<val>",
};

static sig_atomic_t run_main_loop = 1;

static const char *prog;
const struct backend *db;
bool opt_resume;
static bool opt_depriv;
static uid_t opt_uid;
static gid_t opt_gid;
static char *opt_chroot;
const enum log_level log_level = LOG_LVL_INFO;

static void __attribute__((noreturn))
usage(void)
{
    int i;

    fprintf(stderr, "Usage: %s <options>\n\n", prog);

    for (i = 0; i < VARSTORED_NR_OPTS; i++) {
        if (varstored_option[i].has_arg) {
            fprintf(stderr, "\t--%s %s\n",
                    varstored_option[i].name,
                    varstored_option_text[i]);
        } else {
            fprintf(stderr, "\t--%s\n", varstored_option[i].name);
        }
    }

    fprintf(stderr, "\n");

    exit(2);
}

typedef struct varstored_state {
    xendevicemodel_handle *dmod;
    xenforeignmemory_handle *fmem;
    xenevtchn_handle *evth;
    domid_t domid;
    unsigned int vcpus;
    ioservid_t ioservid;
    bool ioserv_created;
    shared_iopage_t *iopage;
    xc_evtchn_port_or_error_t *ioreq_local_port;
    buffered_iopage_t *buffered_iopage;
    xc_evtchn_port_or_error_t buf_ioreq_port;
    xc_evtchn_port_or_error_t buf_ioreq_local_port;
} varstored_state_t;

static varstored_state_t varstored_state;

/*
 * Initialize various settings from xenstore.
 */
static void
initialize_settings(struct xs_handle *xsh, domid_t domid)
{
    char path[64];
    char *s = NULL;
    int flag;
    FILE *f;

    // read secureboot option from xenstore
    snprintf(path, sizeof(path), "/local/domain/%u/platform/secureboot", domid);
    s = xs_read(xsh, XBT_NULL, path, NULL);
    secure_boot_enable = s && !strcmp(s, "true");

    if(secure_boot_enable) {
        f = fopen("/etc/xenserver/feature.d/guefi-secureboot", "r");
        if (!f) {
            INFO(stderr, "Failed to open secureboot feature flag\n");
        } else {
            INFO("SECUREBOOT FEATURE FLAG EXISTS\n");
            flag = fgetc(f);
            if (flag == EOF || flag == '0')
                secure_boot_enable = 0;
            fclose(f);
         }
    }

    if (secure_boot_enable)
        INFO("SECURE_BOOT_ON\n");
    else
        INFO("SECURE_BOOT_OFF\n");
    free(s);

    snprintf(path, sizeof(path),
             "/local/domain/%u/platform/auth-enforce", domid);
    s = xs_read(xsh, XBT_NULL, path, NULL);

    auth_enforce = !s || strcmp(s, "false");
    free(s);

    INFO("Authenticated variables: %s\n",
         auth_enforce ? "enforcing" : "permissive");
}

static bool
xs_write_pid(struct xs_handle *xsh)
{
    char *varstore_pid = NULL;
    char *key = NULL;
    bool ret = false;
    pid_t pid = getpid();

    /* pid needs to be written to /local/domain/<domid>/varstored-pid */
    if (asprintf(&varstore_pid, "%u", pid) != -1)
        if (asprintf(&key, XS_VARSTORED_PID_PATH, varstored_state.domid) != -1)
            ret = xs_write(xsh, 0, key, varstore_pid, strlen(varstore_pid));

    free(key);
    free(varstore_pid);
    return ret;
}

static bool
create_pidfile(const char *path)
{
    int fd, len;
    char *pid;

    fd = open(path, O_WRONLY | O_TRUNC | O_CREAT | O_CLOEXEC, 0600);
    if (fd == -1) {
        ERR("Could not open pidfile '%s': %d, %s\n",
            path, errno, strerror(errno));
        return false;
    }

    if (lockf(fd, F_TLOCK, 0) == -1) {
        ERR("Failed to lock pidfile\n");
        close(fd);
        return false;
    }

    len = asprintf(&pid, "%u\n", getpid());
    if (len == -1) {
        ERR("Out of memory\n");
        close(fd);
        return false;
    }

    if (write(fd, pid, len) != len) {
        ERR("Failed to write to pidfile\n");
        free(pid);
        close(fd);
        return false;
    }
    free(pid);

    /* Leave pid file open and locked. */
    return true;
}

static void
handle_pio(ioreq_t *ioreq)
{
    if (ioreq->dir == IOREQ_READ) {
        DBG("IO request not WRITE. Doing nothing.\n");
    } else if (ioreq->dir == IOREQ_WRITE) {
        if (!ioreq->data_is_ptr) {
            io_port_write(ioreq->addr, ioreq->size, (uint32_t)ioreq->data);
        } else {
            assert(0);
        }
    }
}

static void
handle_ioreq(ioreq_t *ioreq)
{
    switch (ioreq->type) {
    case IOREQ_TYPE_PIO:
        handle_pio(ioreq);
        break;

    case IOREQ_TYPE_COPY:
        break;

    case IOREQ_TYPE_PCI_CONFIG:
        break;

    case IOREQ_TYPE_TIMEOFFSET:
        break;

    case IOREQ_TYPE_INVALIDATE:
        break;

    default:
        ERR("UNKNOWN (%02x)", ioreq->type);
        break;
    }
}

static void
varstored_teardown(void)
{
    int i;

    io_port_deregister();

    if (varstored_state.buf_ioreq_local_port >= 0)
        xenevtchn_unbind(varstored_state.evth,
                         varstored_state.buf_ioreq_local_port);

    if (varstored_state.ioreq_local_port) {
        for (i = 0; i < varstored_state.vcpus; i++) {
            if (varstored_state.ioreq_local_port[i] >= 0)
                xenevtchn_unbind(varstored_state.evth,
                                 varstored_state.ioreq_local_port[i]);
        }
        free(varstored_state.ioreq_local_port);
    }

    if (varstored_state.ioserv_created)
        xendevicemodel_set_ioreq_server_state(varstored_state.dmod,
                                              varstored_state.domid,
                                              varstored_state.ioservid,
                                              0);

    if (varstored_state.buffered_iopage)
        xenforeignmemory_unmap(varstored_state.fmem,
                               varstored_state.buffered_iopage, 1);

    if (varstored_state.iopage)
        xenforeignmemory_unmap(varstored_state.fmem, varstored_state.iopage, 1);

    if (varstored_state.ioserv_created)
        xendevicemodel_destroy_ioreq_server(varstored_state.dmod,
                                            varstored_state.domid,
                                            varstored_state.ioservid);

    xendevicemodel_close(varstored_state.dmod);
    xenforeignmemory_close(varstored_state.fmem);
    xenevtchn_close(varstored_state.evth);
}

static void
varstored_sigterm(int num)
{
    INFO("%s\n", strsignal(num));

    varstored_teardown();

    if (num == SIGTERM)
        run_main_loop = 0;
    else
        exit(0);
}

static bool
varstored_initialize(domid_t domid)
{
    int rc, i, subcount = 0, first = 1;
    uint64_t number = 0;
    xc_dominfo_t dominfo;
    xen_pfn_t pfn;
    xen_pfn_t buf_pfn;
    evtchn_port_t port;
    evtchn_port_t buf_port;
    struct xs_handle *xsh = NULL;
    xc_interface *xch = NULL;

    varstored_state.buf_ioreq_local_port = -1;
    varstored_state.domid = domid;

    xch = xc_interface_open(NULL, NULL, 0);
    if (!xch) {
        ERR("Failed to open xc_interface handle: %d, %s\n",
            errno, strerror(errno));
        goto err;
    }

    rc = xc_domain_getinfo(xch, domid, 1, &dominfo);
    if (rc < 0) {
        ERR("Failed to get domain info: %d, %s\n", errno, strerror(errno));
        goto err;
    }
    if (dominfo.domid != domid) {
        ERR("Domid %u does not match expected %u\n", dominfo.domid, domid);
        goto err;
    }

    varstored_state.vcpus = dominfo.max_vcpu_id + 1;

    INFO("%d vCPU(s)\n", varstored_state.vcpus);

    do {
        rc = xc_hvm_param_get(xch, varstored_state.domid,
                              HVM_PARAM_NR_IOREQ_SERVER_PAGES, &number);

        if (rc < 0) {
            ERR("xc_hvm_param_get failed: %d, %s", errno, strerror(errno));
            goto err;
        }

        if (first || number > 0)
            INFO("HVM_PARAM_NR_IOREQ_SERVER_PAGES = %ld\n", number);
        first = 0;

        if (number == 0) {
            if (!subcount)
                INFO("Waiting for ioreq server");
            usleep(100000);
            subcount++;
            if (subcount > 10)
                subcount = 0;
        }
    } while (number == 0);

    xc_interface_close(xch);
    xch = NULL;

    varstored_state.dmod = xendevicemodel_open(NULL, 0);
    if (!varstored_state.dmod) {
        ERR("Failed to open xendevicemodel handle: %d, %s\n",
            errno, strerror(errno));
        goto err;
    }

    varstored_state.fmem = xenforeignmemory_open(NULL, 0);
    if (!varstored_state.fmem) {
        ERR("Failed to open xenforeignmemory handle: %d, %s\n",
            errno, strerror(errno));
        goto err;
    }

    varstored_state.evth = xenevtchn_open(NULL, 0);
    if (!varstored_state.evth) {
        ERR("Failed to open evtchn handle: %d, %s\n",
            errno, strerror(errno));
        goto err;
    }

    rc = xentoolcore_restrict_all(domid);
    if (rc < 0) {
        ERR("Failed to restrict Xen handles: %d, %s\n", errno, strerror(errno));
        goto err;
    }

    rc = xendevicemodel_create_ioreq_server(varstored_state.dmod,
                                            varstored_state.domid, 1,
                                            &varstored_state.ioservid);
    if (rc < 0) {
        ERR("Failed to create ioreq server: %d, %s\n", errno, strerror(errno));
        goto err;
    }
    varstored_state.ioserv_created = true;

    rc = xendevicemodel_get_ioreq_server_info(varstored_state.dmod,
                                              varstored_state.domid,
                                              varstored_state.ioservid,
                                              &pfn, &buf_pfn, &buf_port);
    if (rc < 0) {
        ERR("Failed to get ioreq server info: %d, %s\n", errno, strerror(errno));
        goto err;
    }
    INFO("ioservid = %u\n", varstored_state.ioservid);

    varstored_state.iopage = xenforeignmemory_map(varstored_state.fmem,
                                                  varstored_state.domid,
                                                  PROT_READ | PROT_WRITE,
                                                  1, &pfn, NULL);
    if (!varstored_state.iopage) {
        ERR("Failed to map iopage: %d, %s\n", errno, strerror(errno));
        goto err;
    }
    INFO("iopage = %p\n", varstored_state.iopage);

    varstored_state.buffered_iopage = xenforeignmemory_map(
                                          varstored_state.fmem,
                                          varstored_state.domid,
                                          PROT_READ | PROT_WRITE,
                                          1, &buf_pfn, NULL);
    if (!varstored_state.buffered_iopage) {
        ERR("Failed to map buffered iopage: %d, %s\n", errno, strerror(errno));
        goto err;
    }
    INFO("buffered_iopage = %p\n", varstored_state.buffered_iopage);

    rc = xendevicemodel_set_ioreq_server_state(varstored_state.dmod,
                                               varstored_state.domid,
                                               varstored_state.ioservid,
                                               1);
    if (rc != 0) {
        ERR("Failed to set ioreq server state: %d, %s\n", errno, strerror(errno));
        goto err;
    }

    varstored_state.ioreq_local_port = malloc(sizeof (xc_evtchn_port_or_error_t) *
                                         varstored_state.vcpus);
    if (!varstored_state.ioreq_local_port) {
        ERR("Failed to alloc port array: %d, %s\n", errno, strerror(errno));
        goto err;
    }

    for (i = 0; i < varstored_state.vcpus; i++)
        varstored_state.ioreq_local_port[i] = -1;

    for (i = 0; i < varstored_state.vcpus; i++) {
        port = varstored_state.iopage->vcpu_ioreq[i].vp_eport;

        rc = xenevtchn_bind_interdomain(varstored_state.evth, varstored_state.domid,
                                        port);
        if (rc < 0) {
            ERR("Failed to failed to bind port: %d, %s\n", errno, strerror(errno));
            goto err;
        }
        varstored_state.ioreq_local_port[i] = rc;
    }

    for (i = 0; i < varstored_state.vcpus; i++)
        INFO("VCPU%d: %u -> %u\n", i,
            varstored_state.iopage->vcpu_ioreq[i].vp_eport,
            varstored_state.ioreq_local_port[i]);

    rc = xenevtchn_bind_interdomain(varstored_state.evth, varstored_state.domid,
                                    buf_port);
    if (rc < 0) {
        ERR("Failed to failed to bind buffered port: %d, %s\n",
            errno, strerror(errno));
        goto err;
    }
    varstored_state.buf_ioreq_local_port = rc;

    INFO("%u -> %u\n",
        varstored_state.buf_ioreq_port,
        varstored_state.buf_ioreq_local_port);

    rc = io_port_initialize(varstored_state.dmod, varstored_state.fmem,
                            varstored_state.domid, varstored_state.ioservid);
    if (rc < 0)
        goto err;

    /* Load auth data _before_ chrooting. */
    if (!load_auth_data())
        goto err;

    xsh = xs_open(0);
    if (!xsh) {
        ERR("Couldn't open xenstore: %d, %s", errno, strerror(errno));
        goto err;
    }

    initialize_settings(xsh, varstored_state.domid);

    if (!xs_write_pid(xsh)) {
        ERR("Failed to write pid to xenstore: %d, %s\n", errno, strerror(errno));
        goto err;
    }

    xs_close(xsh);
    xsh = NULL;

    if (!drop_privileges(opt_chroot, opt_depriv, opt_gid, opt_uid))
        goto err;

    /* Guest data should not be accessed before this point. */

    if (opt_resume) {
        if (!db->resume()) {
            ERR("Failed to resume!\n");
            goto err;
        }
    } else {
        enum backend_init_status status = db->init();

        if (status == BACKEND_INIT_FAILURE) {
            ERR("Failed to initialize backend!\n");
            goto err;
        }

        if (!setup_variables()) {
            ERR("Failed to setup variables\n");
            goto err;
        }

        if (status == BACKEND_INIT_FIRSTBOOT) {
            if (!setup_keys()) {
                ERR("Failed to setup keys\n");
                goto err;
            }
        }
    }

    free_auth_data();
    return true;

err:
    xc_interface_close(xch);
    xs_close(xsh);
    free_auth_data();
    return false;
}

static void
varstored_poll_buffered_iopage(void)
{
    for (;;) {
        unsigned int    read_pointer;
        unsigned int    write_pointer;

        read_pointer = varstored_state.buffered_iopage->read_pointer;
        write_pointer = varstored_state.buffered_iopage->write_pointer;

        if (read_pointer == write_pointer)
            break;

        while (read_pointer != write_pointer) {
            unsigned int    slot;
            buf_ioreq_t     *buf_ioreq;
            ioreq_t         ioreq;

            slot = read_pointer % IOREQ_BUFFER_SLOT_NUM;

            buf_ioreq = &varstored_state.buffered_iopage->buf_ioreq[slot];

            ioreq.size = 1UL << buf_ioreq->size;
            ioreq.count = 1;
            ioreq.addr = buf_ioreq->addr;
            ioreq.data = buf_ioreq->data;
            ioreq.state = STATE_IOREQ_READY;
            ioreq.dir = buf_ioreq->dir;
            ioreq.df = 1;
            ioreq.type = buf_ioreq->type;
            ioreq.data_is_ptr = 0;

            read_pointer++;

            if (ioreq.size == 8) {
                slot = read_pointer % IOREQ_BUFFER_SLOT_NUM;
                buf_ioreq = &varstored_state.buffered_iopage->buf_ioreq[slot];

                ioreq.data |= ((uint64_t)buf_ioreq->data) << 32;

                read_pointer++;
            }

            handle_ioreq(&ioreq);
            mb();
        }

        varstored_state.buffered_iopage->read_pointer = read_pointer;
        mb();
    }
}

static void
varstored_poll_iopage(unsigned int i)
{
    ioreq_t         *ioreq;

    ioreq = &varstored_state.iopage->vcpu_ioreq[i];
    if (ioreq->state != STATE_IOREQ_READY) {
        fprintf(stderr, "IO request not ready\n");
        return;
    }
    mb();

    ioreq->state = STATE_IOREQ_INPROCESS;

    handle_ioreq(ioreq);
    mb();

    ioreq->state = STATE_IORESP_READY;
    mb();

    xenevtchn_notify(varstored_state.evth, varstored_state.ioreq_local_port[i]);
}

static void
varstored_poll_iopages(void)
{
    xc_evtchn_port_or_error_t port;
    int i;

    port = xenevtchn_pending(varstored_state.evth);
    if (port < 0)
        return;

    if (port == varstored_state.buf_ioreq_local_port) {
        xenevtchn_unmask(varstored_state.evth, port);
        varstored_poll_buffered_iopage();
    } else {
        for (i = 0; i < varstored_state.vcpus; i++) {
            if (port == varstored_state.ioreq_local_port[i]) {
                xenevtchn_unmask(varstored_state.evth, port);
                varstored_poll_iopage(i);
            }
        }
    }
}

int
main(int argc, char **argv)
{
    struct sigaction sigterm_handler;
    char            *domain_str;
    char            *ptr;
    int             index;
    char            *end;
    domid_t         domid;
    sigset_t        block;
    struct pollfd   pfd;
    int             rc;

    prog = basename(argv[0]);

    domain_str = NULL;

    for (;;) {
        char    c;

        c = getopt_long(argc, argv, "", varstored_option, &index);
        if (c == -1)
            break;

        if (c != 0) {
            usage();
            /*NOTREACHED*/
        }

        INFO("--%s = '%s'\n", varstored_option[index].name, optarg);

        switch (index) {
        case VARSTORED_OPT_DOMAIN:
            domain_str = optarg;
            break;

        case VARSTORED_OPT_RESUME:
            opt_resume = true;
            break;

        case VARSTORED_OPT_NONPERSISTENT:
            persistent = false;
            break;

        case VARSTORED_OPT_DEPRIV:
            opt_depriv = true;
            break;

        case VARSTORED_OPT_UID:
            opt_uid = (uid_t)strtol(optarg, &end, 0);
            if (*end != '\0') {
                fprintf(stderr, "invalid uid '%s'\n", optarg);
                exit(1);
            }
            break;

        case VARSTORED_OPT_GID:
            opt_gid = (gid_t)strtol(optarg, &end, 0);
            if (*end != '\0') {
                fprintf(stderr, "invalid uid '%s'\n", optarg);
                exit(1);
            }
            break;

        case VARSTORED_OPT_CHROOT:
            opt_chroot = strdup(optarg);
            break;

        case VARSTORED_OPT_PIDFILE:
            if (!create_pidfile(optarg))
                exit(1);
            break;

        case VARSTORED_OPT_BACKEND:
            if (!strcmp(optarg, "xapidb")) {
                db = &xapidb;
            } else {
                fprintf(stderr, "Invalid backend '%s'\n", optarg);
                usage();
            }
            break;

        case VARSTORED_OPT_ARG:
            if (!db) {
                fprintf(stderr, "Must set backend before backend args\n");
                usage();
            }
            ptr = strchr(optarg, ':');
            if (!ptr) {
                fprintf(stderr, "Invalid argument '%s'\n", optarg);
                usage();
            }
            *ptr = '\0';
            ptr++;
            if (!db->parse_arg(optarg, ptr)) {
                fprintf(stderr, "Invalid argument '%s:%s'\n", optarg, ptr);
                usage();
            }
            break;

        default:
            assert(0);
            break;
        }
    }

    if (domain_str == NULL ||
        db == NULL ||
        !db->check_args()) {
        usage();
        /*NOTREACHED*/
    }

    domid = (domid_t)strtol(domain_str, &end, 0);
    if (*end != '\0') {
        fprintf(stderr, "invalid domain '%s'\n", domain_str);
        exit(1);
    }

    sigfillset(&block);

    memset(&sigterm_handler, 0, sizeof (struct sigaction));
    sigterm_handler.sa_handler = varstored_sigterm;

    sigaction(SIGTERM, &sigterm_handler, NULL);
    sigdelset(&block, SIGTERM);

    sigaction(SIGINT, &sigterm_handler, NULL);
    sigdelset(&block, SIGINT);

    sigaction(SIGHUP, &sigterm_handler, NULL);
    sigdelset(&block, SIGHUP);

    sigaction(SIGABRT, &sigterm_handler, NULL);
    sigdelset(&block, SIGABRT);

    sigprocmask(SIG_BLOCK, &block, NULL);

    if (!varstored_initialize(domid)) {
        varstored_teardown();
        exit(1);
    }

    pfd.fd = xenevtchn_fd(varstored_state.evth);
    pfd.events = POLLIN | POLLERR | POLLHUP;
    pfd.revents = 0;

    while (run_main_loop) {
        rc = poll(&pfd, 1, -1);

        if (!run_main_loop)
            break;

        if (rc > 0 && pfd.revents & POLLIN)
            varstored_poll_iopages();

        if (rc < 0 && errno != EINTR)
            break;
    }

    if (!db->save())
        return 1;

    return 0;
}
