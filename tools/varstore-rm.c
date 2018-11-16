/*
 * Copyright (C) Citrix Systems, Inc
 */

#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>

#include <backend.h>
#include <debug.h>
#include <depriv.h>
#include <guid.h>
#include <serialize.h>

#include "tool-lib.h"

#define CLONE_RM_DIR "/etc/xapi.d/efi-clone"

const struct backend *db = &xapidb_cmdline;
const enum log_level log_level = LOG_LVL_INFO;

static void
usage(const char *progname)
{
    printf("usage: %s [-c] [-h] [depriv options] <vm-uuid> [<guid> <name>]\n\n",
           progname);
    printf("Removes an EFI variable (either normal or authenticated).\n"
           "Alternatively, if -c is given then guid and name should not given\n"
           "and it will remove all remove-on-clone variables configured in\n"
           CLONE_RM_DIR ".\n");
    print_depriv_options();
}

static bool
clone_rm_one_file(const char *path)
{
    FILE *f;
    EFI_GUID guid;
    /* GUID string length + maximum length of a name + some whitespace */
    char line[GUID_STR_LEN + NAME_MAX + 16];
    char *ptr, *end;

    f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "Could not open '%s': %d, %s\n",
                path, errno, strerror(errno));
        return false;
    }

    while (fgets(line, sizeof(line), f)) {
        /* Strip newline */
        ptr = line + strlen(line) - 1;
        while (ptr >= line && (*ptr == '\r' || *ptr == '\n'))
            *ptr-- = '\0';

        /* Ignore comments and blank lines */
        if (strlen(line) == 0)
            continue;
        if (*line == '#')
            continue;

        /* Split GUID and name separated by some whitespace */
        end = line + strlen(line);
        ptr = line + GUID_STR_LEN;
        while (ptr < end) {
            if (isblank(*ptr))
                *ptr++ = '\0';
            else
                break;
        }

        if (ptr >= end || !parse_guid(&guid, line)) {
            fprintf(stderr, "Invalid format\n");
            fclose(f);
            return false;
        } else {
            printf("Removing: GUID: '%s' Name: '%s'\n", line, ptr);
            do_rm(&guid, ptr);
        }
    }
    fclose(f);

    return true;
}

static bool
do_clone_rm(void)
{
    DIR *dir;
    struct dirent *d;
    char path[PATH_MAX];
    bool ret = true;

    dir = opendir(CLONE_RM_DIR);
    if (!dir)
        return true;

    for (;;) {
        d = readdir(dir);

        if (!d)
            break;
        if (!strcmp(d->d_name, ".") || !strcmp(d->d_name, ".."))
            continue;

        if (snprintf(path, sizeof(path),
                     CLONE_RM_DIR "/%s", d->d_name) >= sizeof(path)) {
            fprintf(stderr, "Path too long\n");
            ret = false;
            goto out;
        }

        ret = clone_rm_one_file(path);
        if (!ret)
            goto out;
    }

out:
    closedir(dir);
    return ret;
}

int main(int argc, char **argv)
{
    bool clone_rm = false;
    DEPRIV_VARS

    for (;;) {
        int c = getopt(argc, argv, "ch" DEPRIV_OPTS);

        if (c == -1)
            break;

        switch (c) {
        DEPRIV_CASES
        case 'c':
            clone_rm = true;
            break;
        case 'h':
            usage(argv[0]);
            exit(0);
        default:
            usage(argv[0]);
            exit(1);
        }
    }

    if ((clone_rm && argc - optind != 1) || (!clone_rm && argc - optind != 3)) {
        usage(argv[0]);
        exit(1);
    }

    db->parse_arg("uuid", argv[optind]);

    if (opt_socket)
        db->parse_arg("socket", opt_socket);

    if (!drop_privileges(opt_chroot, opt_depriv, opt_gid, opt_uid))
        exit(1);

    if (!tool_init())
        exit(1);

    if (clone_rm) {
        return !do_clone_rm();
    } else {
        EFI_GUID guid;

        if (!parse_guid(&guid, argv[optind + 1])) {
            ERR("Failed to parse GUID\n");
            return 1;
        }

        return !do_rm(&guid, argv[optind + 2]);
    }
}
