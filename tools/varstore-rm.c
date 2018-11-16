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

struct clone_variable
{
    EFI_GUID guid;
    char *guid_str;
    char *name;
    struct clone_variable *next;
};

static struct clone_variable *clone_vars;

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
parse_one_clone_file(const char *path)
{
    FILE *f;
    /* GUID string length + maximum length of a name + some whitespace */
    char line[GUID_STR_LEN + NAME_MAX + 16];
    char *ptr, *end;
    struct clone_variable *v;
    int lineno = 0;

    f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "Could not open '%s': %d, %s\n",
                path, errno, strerror(errno));
        return false;
    }

    while (fgets(line, sizeof(line), f)) {
        lineno++;
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

        v = malloc(sizeof(*v));
        if (!v) {
            ERR("Out of memory\n");
            fclose(f);
            return false;
        }

        if (ptr >= end || !parse_guid(&v->guid, line)) {
            fprintf(stderr, "Failed to parse line %d in '%s'.\n", lineno, path);
            fclose(f);
            return false;
        } else {
            v->guid_str = strdup(line);
            v->name = strdup(ptr);
            if (!v->guid_str || !v->name) {
                ERR("Out of memory\n");
                fclose(f);
                return false;
            }
            v->next = clone_vars;
            clone_vars = v;
        }
    }
    fclose(f);

    return true;
}

static bool
parse_clone_files(void)
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

        ret = parse_one_clone_file(path);
        if (!ret)
            goto out;
    }

out:
    closedir(dir);
    return ret;
}

static void
do_rm_clone(void)
{
    struct clone_variable *v = clone_vars;

    while (v) {
        printf("Removing: GUID: '%s' Name: '%s'\n", v->guid_str, v->name);
        do_rm(&v->guid, v->name);
        v = v->next;
    }
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

    if (clone_rm && !parse_clone_files())
        return 1;

    if (!drop_privileges(opt_chroot, opt_depriv, opt_gid, opt_uid))
        exit(1);

    if (!tool_init())
        exit(1);

    if (clone_rm) {
        do_rm_clone();
        return 0;
    } else {
        EFI_GUID guid;

        if (!parse_guid(&guid, argv[optind + 1])) {
            ERR("Failed to parse GUID\n");
            return 1;
        }

        return !do_rm(&guid, argv[optind + 2]);
    }
}
