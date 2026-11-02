#!/usr/bin/env python3
"""Make every kernel-identity surface report the same string.

SUSFS's CONFIG_KSU_SUSFS_SPOOF_UNAME rewrites only the reply of newuname(2):
it memcpy()s utsname() into a stack copy, calls susfs_spoof_uname() on that
copy, and copy_to_user()s it back.  init_uts_ns is never written, so the
paths that serialize the namespace directly kept printing the real build
string to any unprivileged reader:

  fs/proc/version.c                 /proc/version
  kernel/utsname_sysctl.c           /proc/sys/kernel/{osrelease,version}

That is a mismatch tell as loud as an unspoofed string: uname(2) says one
release, /proc/version says another.

This script patches both to derive from the same susfs_spoof_uname()
buffer, gated on the same static branch the syscall path uses.  Both states
are therefore self-consistent:

  spoof disarmed (ksud pushed no string)  -> every surface reports the real value
  spoof armed                             -> every surface reports the fake value

It is written against the android13-5.15 GKI tree and asserts each anchor,
so a source drift fails the build instead of silently shipping half a patch.
Idempotent: re-running on a patched tree is a no-op.
"""
import os
import sys

MARK = "susfs_spoof_uname"
GUARD = "#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME"

INCLUDES = """#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
#include <linux/jump_label.h>
#include <linux/string.h>
extern struct static_key_false susfs_is_uname_spoof_buffer_set;
extern void susfs_spoof_uname(struct new_utsname *tmp);
#endif"""

# utsname_sysctl.c already pulls <linux/utsname.h>; it still needs the two
# externs or the call is an implicit declaration (-Werror on 5.15 GKI clang).
UTS_INCLUDES = """
#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
#include <linux/jump_label.h>
#include <linux/string.h>
extern struct static_key_false susfs_is_uname_spoof_buffer_set;
extern void susfs_spoof_uname(struct new_utsname *tmp);
#endif"""

VER_OLD = """static int version_proc_show(struct seq_file *m, void *v)
{
\tseq_printf(m, linux_proc_banner,
\t\tutsname()->sysname,
\t\tutsname()->release,
\t\tutsname()->version);
\treturn 0;
}"""

VER_NEW = INCLUDES + """

static int version_proc_show(struct seq_file *m, void *v)
{
#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
\tif (static_branch_likely(&susfs_is_uname_spoof_buffer_set)) {
\t\tstruct new_utsname tmp;

\t\tmemcpy(&tmp, utsname(), sizeof(tmp));
\t\tsusfs_spoof_uname(&tmp);
\t\tseq_printf(m, linux_proc_banner,
\t\t\ttmp.sysname, tmp.release, tmp.version);
\t\treturn 0;
\t}
#endif
\tseq_printf(m, linux_proc_banner,
\t\tutsname()->sysname,
\t\tutsname()->release,
\t\tutsname()->version);
\treturn 0;
}"""

UTS_OLD = """\tdown_read(&uts_sem);
\tmemcpy(tmp_data, get_uts(table), sizeof(tmp_data));
\tup_read(&uts_sem);
"""

UTS_NEW = UTS_OLD + """#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
\t/*
\t * The sysctl entries read the uts namespace directly. Mirror the same
\t * buffer the newuname(2) hook uses, so /proc/sys/kernel/osrelease and
\t * /proc/sys/kernel/version cannot disagree with uname(2).
\t */
\tif (!write && static_branch_likely(&susfs_is_uname_spoof_buffer_set) &&
\t    table->procname &&
\t    (!strcmp(table->procname, "osrelease") ||
\t     !strcmp(table->procname, "version"))) {
\t\tstruct new_utsname tmp;

\t\tdown_read(&uts_sem);
\t\tmemcpy(&tmp, utsname(), sizeof(tmp));
\t\tup_read(&uts_sem);
\t\tsusfs_spoof_uname(&tmp);
\t\tstrscpy(tmp_data,
\t\t\t!strcmp(table->procname, "osrelease") ? tmp.release
\t\t\t\t\t\t\t      : tmp.version,
\t\t\tsizeof(tmp_data));
\t}
#endif
"""


def patch(path, old, new, include_anchor=None, uts_includes=""):
    """Apply one edit; return human-readable status, or raise on drift."""
    with open(path, "r", encoding="utf-8") as f:
        src = f.read()

    if MARK in src:
        return f"[=] {path}: already patched"

    if old not in src:
        raise SystemExit(
            f"ERROR: anchor not found verbatim in {path}.\n"
            f"The tree drifted from android13-5.15; refusing to ship a half patch."
        )

    src = src.replace(old, new, 1)

    if include_anchor is not None:
        if include_anchor not in src:
            raise SystemExit(f"ERROR: include anchor {include_anchor!r} missing in {path}")
        if "susfs_is_uname_spoof_buffer_set" not in src.split(include_anchor, 1)[1][:900]:
            src = src.replace(include_anchor, include_anchor + uts_includes, 1)

    with open(path, "w", encoding="utf-8") as f:
        f.write(src)
    return f"[+] {path}: patched"


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    ver = os.path.join(root, "fs", "proc", "version.c")
    uts = os.path.join(root, "kernel", "utsname_sysctl.c")

    for p in (ver, uts):
        if not os.path.isfile(p):
            raise SystemExit(f"ERROR: {p} not found (root={root!r})")

    print(patch(ver, VER_OLD, VER_NEW, include_anchor="#include <linux/utsname.h>"))
    print(patch(uts, UTS_OLD, UTS_NEW, include_anchor="#include <linux/rwsem.h>",
                uts_includes=UTS_INCLUDES))

    # Post-conditions: the guards must be present in both files.
    for p in (ver, uts):
        with open(p, "r", encoding="utf-8") as f:
            s = f.read()
        if GUARD not in s or MARK not in s:
            raise SystemExit(f"ERROR: post-check failed for {p}")
    print("[ok] both surfaces now derive from susfs_spoof_uname()")


if __name__ == "__main__":
    main()
