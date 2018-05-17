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
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sched.h>
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

#include "debug.h"
#include "device.h"
#include "pci.h"

#define mb() asm volatile ("" : : : "memory")

enum {
    VARSTORED_OPT_DOMAIN,
    VARSTORED_OPT_DEVICE,
    VARSTORED_OPT_FUNCTION,
    VARSTORED_NR_OPTS
    };

static struct option varstored_option[] = {
    {"domain", 1, NULL, 0},
    {"device", 1, NULL, 0},
    {"function", 1, NULL, 0},
    {NULL, 0, NULL, 0}
};

static const char *varstored_option_text[] = {
    "<domid>",
    "<device>",
    "<function>",
    NULL
};

static const char *prog;

static void
usage(void)
{
    int i;

    fprintf(stderr, "Usage: %s <options>\n\n", prog);

    for (i = 0; i < VARSTORED_NR_OPTS; i++)
        fprintf(stderr, "\t--%s %s\n",
                varstored_option[i].name,
                varstored_option_text[i]);

    fprintf(stderr, "\n");

    exit(2);
}

typedef enum {
    VARSTORED_SEQ_UNINITIALIZED = 0,
    VARSTORED_SEQ_INTERFACE_OPEN,
    VARSTORED_SEQ_SERVER_REGISTERED,
    VARSTORED_SEQ_SHARED_IOPAGE_MAPPED,
    VARSTORED_SEQ_BUFFERED_IOPAGE_MAPPED,
    VARSTORED_SEQ_SERVER_ENABLED,
    VARSTORED_SEQ_PORT_ARRAY_ALLOCATED,
    VARSTORED_SEQ_EVTCHN_OPEN,
    VARSTORED_SEQ_PORTS_BOUND,
    VARSTORED_SEQ_BUF_PORT_BOUND,
    VARSTORED_SEQ_DEVICE_INITIALIZED,
    VARSTORED_SEQ_INITIALIZED,
    VARSTORED_NR_SEQS
} varstored_seq_t;

typedef struct varstored_state {
    varstored_seq_t     seq;
    xc_interface        *xch;
    xc_evtchn           *xceh;
    domid_t             domid;
    unsigned int        vcpus;
    ioservid_t          ioservid;
    shared_iopage_t     *iopage;
    evtchn_port_t       *ioreq_local_port;
    buffered_iopage_t   *buffered_iopage;
    evtchn_port_t       buf_ioreq_port;
    evtchn_port_t       buf_ioreq_local_port;
} varstored_state_t;

static varstored_state_t varstored_state;

static void
handle_pio(ioreq_t *ioreq)
{
    if (ioreq->dir == IOREQ_READ) {
        if (!ioreq->data_is_ptr) {
            ioreq->data = (uint64_t)pci_bar_read(0, ioreq->addr, ioreq->size);
        } else {
            assert(0);
        }
    } else if (ioreq->dir == IOREQ_WRITE) {
        if (!ioreq->data_is_ptr) {
            pci_bar_write(0, ioreq->addr, ioreq->size, (uint32_t)ioreq->data);
        } else {
            assert(0);
        }
    }
}

static void
handle_copy(ioreq_t *ioreq)
{
    if (ioreq->dir == IOREQ_READ) {
        if (!ioreq->data_is_ptr) {
            ioreq->data = (uint64_t)pci_bar_read(1, ioreq->addr, ioreq->size);
        } else {
            assert(0);
        }
    } else if (ioreq->dir == IOREQ_WRITE) {
        if (!ioreq->data_is_ptr) {
            pci_bar_write(1, ioreq->addr, ioreq->size, (uint32_t)ioreq->data);
        } else {
            assert(0);
        }
    }
}

static void
handle_pci_config(ioreq_t *ioreq)
{
    if (ioreq->dir == IOREQ_READ) {
        if (!ioreq->data_is_ptr) {
            ioreq->data = (uint32_t)pci_config_read(ioreq->addr, ioreq->size);
        } else {
            assert(0);
        }
    } else if (ioreq->dir == IOREQ_WRITE) {
        if (!ioreq->data_is_ptr) {
            pci_config_write(ioreq->addr, ioreq->size, (uint32_t)ioreq->data);
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
        handle_copy(ioreq);
        break;

    case IOREQ_TYPE_PCI_CONFIG:
        handle_pci_config(ioreq);
        break;

    case IOREQ_TYPE_TIMEOFFSET:
        break;

    case IOREQ_TYPE_INVALIDATE:
        break;

    default:
        DBG("UNKNOWN (%02x)", ioreq->type);
        break;
    }
}

static void
varstored_seq_next(void)
{
    assert(varstored_state.seq < VARSTORED_SEQ_INITIALIZED);

    switch (++varstored_state.seq) {
    case VARSTORED_SEQ_INTERFACE_OPEN:
        DBG(">INTERFACE_OPEN\n");
        break;

    case VARSTORED_SEQ_SERVER_REGISTERED:
        DBG(">SERVER_REGISTERED\n");
        DBG("ioservid = %u\n", varstored_state.ioservid);
        break;

    case VARSTORED_SEQ_SHARED_IOPAGE_MAPPED:
        DBG(">SHARED_IOPAGE_MAPPED\n");
        DBG("iopage = %p\n", varstored_state.iopage);
        break;

    case VARSTORED_SEQ_BUFFERED_IOPAGE_MAPPED:
        DBG(">BUFFERED_IOPAGE_MAPPED\n");
        DBG("buffered_iopage = %p\n", varstored_state.buffered_iopage);
        break;

    case VARSTORED_SEQ_SERVER_ENABLED:
        DBG(">SERVER_ENABLED\n");
        break;

    case VARSTORED_SEQ_PORT_ARRAY_ALLOCATED:
        DBG(">PORT_ARRAY_ALLOCATED\n");
        break;

    case VARSTORED_SEQ_EVTCHN_OPEN:
        DBG(">EVTCHN_OPEN\n");
        break;

    case VARSTORED_SEQ_PORTS_BOUND: {
        int i;

        DBG(">EVTCHN_PORTS_BOUND\n");

        for (i = 0; i < varstored_state.vcpus; i++)
            DBG("VCPU%d: %u -> %u\n", i,
                varstored_state.iopage->vcpu_ioreq[i].vp_eport,
                varstored_state.ioreq_local_port[i]);

        break;
    }

    case VARSTORED_SEQ_BUF_PORT_BOUND:
        DBG(">EVTCHN_BUF_PORT_BOUND\n");

        DBG("%u -> %u\n",
            varstored_state.buf_ioreq_port,
            varstored_state.buf_ioreq_local_port);
        break;

    case VARSTORED_SEQ_DEVICE_INITIALIZED:
        DBG(">DEVICE_INITIALIZED\n");
        break;

    case VARSTORED_SEQ_INITIALIZED:
        DBG(">INITIALIZED\n");
        break;

    default:
        assert(0);
        break;
    }
}

static void
varstored_teardown(void)
{
    if (varstored_state.seq == VARSTORED_SEQ_INITIALIZED) {
        DBG("<INITIALIZED\n");

        varstored_state.seq = VARSTORED_SEQ_DEVICE_INITIALIZED;
    }

    if (varstored_state.seq == VARSTORED_SEQ_DEVICE_INITIALIZED) {
        DBG("<DEVICE_INITIALIZED\n");
        device_teardown();

        varstored_state.seq = VARSTORED_SEQ_PORTS_BOUND;
    }

    if (varstored_state.seq >= VARSTORED_SEQ_PORTS_BOUND) {
        DBG("<EVTCHN_BUF_PORT_BOUND\n");
        evtchn_port_t   port;

        port = varstored_state.buf_ioreq_local_port;

        DBG("%u\n", port);
        (void) xc_evtchn_unbind(varstored_state.xceh, port);

        varstored_state.seq = VARSTORED_SEQ_PORTS_BOUND;
    }

    if (varstored_state.seq >= VARSTORED_SEQ_PORTS_BOUND) {
        DBG("<EVTCHN_PORTS_BOUND\n");

        varstored_state.seq = VARSTORED_SEQ_EVTCHN_OPEN;
    }

    if (varstored_state.seq >= VARSTORED_SEQ_EVTCHN_OPEN) {
        int i;

        DBG("<EVTCHN_OPEN\n");

        for (i = 0; i < varstored_state.vcpus; i++) {
            evtchn_port_t   port;

            port = varstored_state.ioreq_local_port[i];

            if (port >= 0) {
                DBG("VCPU%d: %u\n", i, port);
                (void) xc_evtchn_unbind(varstored_state.xceh, port);
            }
        }

        xc_evtchn_close(varstored_state.xceh);

        varstored_state.seq = VARSTORED_SEQ_PORT_ARRAY_ALLOCATED;
    }

    if (varstored_state.seq >= VARSTORED_SEQ_PORT_ARRAY_ALLOCATED) {
        DBG("<PORT_ARRAY_ALLOCATED\n");

        free(varstored_state.ioreq_local_port);

        varstored_state.seq = VARSTORED_SEQ_SERVER_ENABLED;
    }

    if (varstored_state.seq == VARSTORED_SEQ_SERVER_ENABLED) {
        DBG("<SERVER_ENABLED\n");
        (void) xc_hvm_set_ioreq_server_state(varstored_state.xch,
                                             varstored_state.domid,
                                             varstored_state.ioservid,
                                             0);

        varstored_state.seq = VARSTORED_SEQ_BUFFERED_IOPAGE_MAPPED;
    }

    if (varstored_state.seq >= VARSTORED_SEQ_BUFFERED_IOPAGE_MAPPED) {
        DBG("<BUFFERED_IOPAGE_MAPPED\n");

        munmap(varstored_state.buffered_iopage, XC_PAGE_SIZE);

        varstored_state.seq = VARSTORED_SEQ_SHARED_IOPAGE_MAPPED;
    }

    if (varstored_state.seq >= VARSTORED_SEQ_SHARED_IOPAGE_MAPPED) {
        DBG("<SHARED_IOPAGE_MAPPED\n");

        munmap(varstored_state.iopage, XC_PAGE_SIZE);

        varstored_state.seq = VARSTORED_SEQ_SERVER_REGISTERED;
    }

    if (varstored_state.seq >= VARSTORED_SEQ_SERVER_REGISTERED) {
        DBG("<SERVER_REGISTERED\n");

        (void) xc_hvm_destroy_ioreq_server(varstored_state.xch,
                                           varstored_state.domid,
                                           varstored_state.ioservid);
        varstored_state.seq = VARSTORED_SEQ_INTERFACE_OPEN;
    }

    if (varstored_state.seq >= VARSTORED_SEQ_INTERFACE_OPEN) {
        DBG("<INTERFACE_OPEN\n");

        xc_interface_close(varstored_state.xch);

        varstored_state.seq = VARSTORED_SEQ_UNINITIALIZED;
    }
}

static struct sigaction sigterm_handler;

static void
varstored_sigterm(int num)
{
    DBG("%s\n", strsignal(num));

    varstored_teardown();

    exit(0);
}

static struct sigaction sigusr1_handler;

static void
varstored_sigusr1(int num)
{
    DBG("%s\n", strsignal(num));

    sigaction(SIGHUP, &sigusr1_handler, NULL);

    pci_config_dump();
}

static int
varstored_initialize(domid_t domid, unsigned int device, unsigned int function)
{
    int             rc;
    xc_dominfo_t    dominfo;
    unsigned long   pfn;
    unsigned long   buf_pfn;
    evtchn_port_t   port;
    evtchn_port_t   buf_port;
    int             i;

    varstored_state.domid = domid;

    varstored_state.xch = xc_interface_open(NULL, NULL, 0);
    if (varstored_state.xch == NULL)
        goto fail1;

    varstored_seq_next();

    rc = xc_domain_getinfo(varstored_state.xch, varstored_state.domid, 1, &dominfo);
    if (rc < 0 || dominfo.domid != varstored_state.domid)
        goto fail2;

    varstored_state.vcpus = dominfo.max_vcpu_id + 1;

    DBG("%d vCPU(s)\n", varstored_state.vcpus);

    rc = xc_hvm_create_ioreq_server(varstored_state.xch, varstored_state.domid, 1,
                                    &varstored_state.ioservid);
    if (rc < 0)
        goto fail3;
    
    varstored_seq_next();

    rc = xc_hvm_get_ioreq_server_info(varstored_state.xch, varstored_state.domid,
                                      varstored_state.ioservid, &pfn, &buf_pfn, &buf_port);
    if (rc < 0)
        goto fail4;

    varstored_state.iopage = xc_map_foreign_range(varstored_state.xch,
                                             varstored_state.domid,
                                             XC_PAGE_SIZE,
                                             PROT_READ | PROT_WRITE,
                                             pfn);
    if (varstored_state.iopage == NULL)
        goto fail5;

    varstored_seq_next();

    varstored_state.buffered_iopage = xc_map_foreign_range(varstored_state.xch,
                                                      varstored_state.domid,
                                                      XC_PAGE_SIZE,
                                                      PROT_READ | PROT_WRITE,
                                                      buf_pfn);
    if (varstored_state.buffered_iopage == NULL)
        goto fail6;

    varstored_seq_next();

    rc = xc_hvm_set_ioreq_server_state(varstored_state.xch,
                                       varstored_state.domid,
                                       varstored_state.ioservid,
                                       1);
    if (rc != 0)
        goto fail7;

    varstored_seq_next();

    varstored_state.ioreq_local_port = malloc(sizeof (evtchn_port_t) *
                                         varstored_state.vcpus);
    if (varstored_state.ioreq_local_port == NULL)
        goto fail8;

    for (i = 0; i < varstored_state.vcpus; i++)
        varstored_state.ioreq_local_port[i] = -1;

    varstored_seq_next();

    varstored_state.xceh = xc_evtchn_open(NULL, 0);
    if (varstored_state.xceh == NULL)
        goto fail9;

    varstored_seq_next();

    for (i = 0; i < varstored_state.vcpus; i++) {
        port = varstored_state.iopage->vcpu_ioreq[i].vp_eport;

        rc = xc_evtchn_bind_interdomain(varstored_state.xceh, varstored_state.domid,
                                        port);
        if (rc < 0)
            goto fail10;

        varstored_state.ioreq_local_port[i] = rc;
    }

    varstored_seq_next();

    rc = xc_evtchn_bind_interdomain(varstored_state.xceh, varstored_state.domid,
                                    buf_port);
    if (rc < 0)
        goto fail11;

    varstored_state.buf_ioreq_local_port = rc;

    varstored_seq_next();

    rc = device_initialize(varstored_state.xch, varstored_state.domid,
                           varstored_state.ioservid, 0, device, function);
    if (rc < 0)
        goto fail12;

    varstored_seq_next();

    varstored_seq_next();

    assert(varstored_state.seq == VARSTORED_SEQ_INITIALIZED);
    return 0;

fail12:
    DBG("fail12\n");

fail11:
    DBG("fail11\n");

fail10:
    DBG("fail10\n");

fail9:
    DBG("fail9\n");

fail8:
    DBG("fail8\n");

fail7:
    DBG("fail7\n");

fail6:
    DBG("fail6\n");

fail5:
    DBG("fail5\n");

fail4:
    DBG("fail4\n");

fail3:
    DBG("fail3\n");

fail2:
    DBG("fail2\n");

fail1:
    DBG("fail1\n");

    warn("fail");
    return -1;
}

static void
varstored_poll_buffered_iopage(void)
{
    if (varstored_state.seq != VARSTORED_SEQ_INITIALIZED)
        return;

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

    if (varstored_state.seq != VARSTORED_SEQ_INITIALIZED)
        return;

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

    xc_evtchn_notify(varstored_state.xceh, varstored_state.ioreq_local_port[i]);
}

static void
varstored_poll_iopages(void)
{
    evtchn_port_t   port;
    int             i;

    if (varstored_state.seq != VARSTORED_SEQ_INITIALIZED)
        return;

    port = xc_evtchn_pending(varstored_state.xceh);
    if (port < 0)
        return;

    if (port == varstored_state.buf_ioreq_local_port) {
        xc_evtchn_unmask(varstored_state.xceh, port);
        varstored_poll_buffered_iopage();
    } else {
        for (i = 0; i < varstored_state.vcpus; i++) {
            if (port == varstored_state.ioreq_local_port[i]) {
                xc_evtchn_unmask(varstored_state.xceh, port);
                varstored_poll_iopage(i);
            }
        }
    }
}

int
main(int argc, char **argv, char **envp)
{
    char            *domain_str;
    char            *device_str;
    char            *function_str;
    int             index;
    char            *end;
    domid_t         domid;
    unsigned int    device;
    unsigned int    function;
    sigset_t        block;
    struct pollfd   pfd;
    int             rc;

    prog = basename(argv[0]);

    domain_str = NULL;
    device_str = NULL;
    function_str = NULL;

    for (;;) {
        char    c;

        c = getopt_long(argc, argv, "", varstored_option, &index);
        if (c == -1)
            break;

        if (c != 0) {
            usage();
            /*NOTREACHED*/
        }

        DBG("--%s = '%s'\n", varstored_option[index].name, optarg);

        switch (index) {
        case VARSTORED_OPT_DOMAIN:
            domain_str = optarg;
            break;

        case VARSTORED_OPT_DEVICE:
            device_str = optarg;
            break;

        case VARSTORED_OPT_FUNCTION:
            function_str = optarg;
            break;

        default:
            assert(0);
            break;
        }
    }

    if (domain_str == NULL ||
        device_str == NULL) {
        usage();
        /*NOTREACHED*/
    }

    domid = (domid_t)strtol(domain_str, &end, 0);
    if (*end != '\0') {
        fprintf(stderr, "invalid domain '%s'\n", domain_str);
        exit(1);
    }

    device = (unsigned int)strtol(device_str, &end, 0);
    if (*end != '\0') {
        fprintf(stderr, "invalid device number '%s'\n", device_str);
        exit(1);
    }

    if (function_str != NULL) {
        function = (unsigned int)strtol(function_str, &end, 0);
        if (*end != '\0') {
            fprintf(stderr, "invalid function number '%s'\n", function_str);
            exit(1);
        }
    } else {
        function = 0;
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

    memset(&sigusr1_handler, 0, sizeof (struct sigaction));
    sigusr1_handler.sa_handler = varstored_sigusr1;

    sigaction(SIGUSR1, &sigusr1_handler, NULL);
    sigdelset(&block, SIGUSR1);

    sigprocmask(SIG_BLOCK, &block, NULL);

    rc = varstored_initialize(domid, device, function);
    if (rc < 0) {
        varstored_teardown();
        exit(1);
    }

    pfd.fd = xc_evtchn_fd(varstored_state.xceh);
    pfd.events = POLLIN | POLLERR | POLLHUP;
    pfd.revents = 0;

    for (;;) {
        rc = poll(&pfd, 1, 5000);

        if (rc > 0 && pfd.revents & POLLIN)
            varstored_poll_iopages();

        if (rc < 0 && errno != EINTR)
            break;
    }

    return 0;
}
