#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <grp.h>
#include <sched.h>
#include <sys/resource.h>

#include <seccomp.h>

#include <debug.h>
#include <depriv.h>
#include <handler.h>

/* This blacklist is based on the one used by QEMU. */
static const int seccomp_blacklist[] = {
    SCMP_SYS(reboot),
    SCMP_SYS(swapon),
    SCMP_SYS(swapoff),
    SCMP_SYS(syslog),
    SCMP_SYS(mount),
    SCMP_SYS(umount),
    SCMP_SYS(kexec_load),
    SCMP_SYS(afs_syscall),
    SCMP_SYS(break),
    SCMP_SYS(ftime),
    SCMP_SYS(getpmsg),
    SCMP_SYS(gtty),
    SCMP_SYS(lock),
    SCMP_SYS(mpx),
    SCMP_SYS(prof),
    SCMP_SYS(profil),
    SCMP_SYS(putpmsg),
    SCMP_SYS(security),
    SCMP_SYS(stty),
    SCMP_SYS(tuxcall),
    SCMP_SYS(ulimit),
    SCMP_SYS(vserver),
    SCMP_SYS(readdir),
    SCMP_SYS(_sysctl),
    SCMP_SYS(bdflush),
    SCMP_SYS(unshare),
    SCMP_SYS(create_module),
    SCMP_SYS(get_kernel_syms),
    SCMP_SYS(query_module),
    SCMP_SYS(sgetmask),
    SCMP_SYS(ssetmask),
    SCMP_SYS(sysfs),
    SCMP_SYS(uselib),
    SCMP_SYS(ustat),
    SCMP_SYS(setuid),
    SCMP_SYS(setgid),
    SCMP_SYS(setpgid),
    SCMP_SYS(setsid),
    SCMP_SYS(setreuid),
    SCMP_SYS(setregid),
    SCMP_SYS(setresuid),
    SCMP_SYS(setresgid),
    SCMP_SYS(setfsuid),
    SCMP_SYS(setfsgid),
    SCMP_SYS(clone),
    SCMP_SYS(fork),
    SCMP_SYS(vfork),
    SCMP_SYS(execve),
    SCMP_SYS(getpriority),
    SCMP_SYS(setpriority),
    SCMP_SYS(sched_setparam),
    SCMP_SYS(sched_getparam),
    SCMP_SYS(sched_setscheduler),
    SCMP_SYS(sched_getscheduler),
    SCMP_SYS(sched_setaffinity),
    SCMP_SYS(sched_getaffinity),
    SCMP_SYS(sched_get_priority_max),
    SCMP_SYS(sched_get_priority_min),
};

bool
drop_privileges(const char *opt_chroot, bool opt_depriv, gid_t opt_gid,
                uid_t opt_uid)
{
    if (opt_chroot) {
        if (chroot(opt_chroot) < 0) {
            ERR("Failed to chroot to %s: %d, %s\n", opt_chroot,
                errno, strerror(errno));
            return false;
        }
    }

    if (opt_depriv) {
        if (unshare(CLONE_NEWNS | CLONE_NEWIPC |
                    CLONE_NEWNET | CLONE_NEWUTS) < 0) {
            ERR("Failed to unshare namespaces: %d, %s\n", errno, strerror(errno));
            return false;
        }
    }

    if (opt_gid) {
        if (setgid(opt_gid) < 0) {
            ERR("Failed to set gid to %u: %d, %s\n", opt_gid,
                errno, strerror(errno));
            return false;
        }
        if (setgroups(1, &opt_gid) < 0) {
            ERR("Failed to set supplementary groups to %u: %d, %s\n", opt_gid,
                errno, strerror(errno));
            return false;
        }
    }

    if (opt_uid) {
        if (setuid(opt_uid) < 0) {
            ERR("Failed to set uid to %u: %d, %s\n", opt_uid,
                errno, strerror(errno));
            return false;
        }
        if (setuid(0) != -1) {
            ERR("Dropping privileges failed\n");
            return false;
        }
    }

    if (opt_depriv) {
        struct rlimit limit;
        scmp_filter_ctx ctx;
        int rc, i;

        /* Set the max writable file size to 256 KiB. */
        limit.rlim_cur = 256 * 1024;
        limit.rlim_max = 256 * 1024;
        setrlimit(RLIMIT_FSIZE, &limit);

        /* Set the maximum number of threads/processes to 1. */
        limit.rlim_cur = 1;
        limit.rlim_max = 1;
        setrlimit(RLIMIT_NPROC, &limit);

        ctx = seccomp_init(SCMP_ACT_ALLOW);
        if (!ctx) {
            ERR("Failed to initialize seccomp\n");
            return false;
        }

        for (i = 0; i < ARRAY_SIZE(seccomp_blacklist); i++) {
            rc = seccomp_rule_add(ctx, SCMP_ACT_KILL, seccomp_blacklist[i], 0);
            if (rc < 0) {
                ERR("seccomp_rule_add failed: %d, %s\n", -rc, strerror(-rc));
                seccomp_release(ctx);
                return false;
            }
        }

        rc = seccomp_load(ctx);
        seccomp_release(ctx);
        if (rc < 0) {
            ERR("seccomp_load failed: %d, %s\n", -rc, strerror(-rc));
            return false;
        }
    }

    return true;
}
