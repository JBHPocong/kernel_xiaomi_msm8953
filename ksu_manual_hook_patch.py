#!/usr/bin/env python3
"""
KernelSU Manual Hook + BakaSU SELinux Static Symbol Export patcher.

Manual Hook:
    fs/exec.c
    fs/open.c
    kernel/reboot.c
    fs/stat.c

BakaSU SELinux:
    security/selinux/selinuxfs.c
    security/selinux/ss/status.c
    security/selinux/ss/services.c
    security/selinux/hooks.c

Features:
    - Automatic patching
    - Timestamped backups
    - Multiple declaration support
    - Optional symbols are skipped
    - Required symbols are validated
    - All patches are prepared before writing
    - Rollback on write failure
    - Already patched symbols are detected
    - Pre-existing (foreign-format) hooks are detected
      and skipped instead of aborting
"""

import argparse
import re
import shutil
import sys
from datetime import datetime
from pathlib import Path


# ============================================================
# MANUAL HOOK DECLARATIONS
# ============================================================

EXEC_DECLS = r'''
#ifdef CONFIG_KSU_MANUAL_HOOK
__attribute__((hot))
extern int ksu_handle_execveat(int *fd, struct filename **filename_ptr,
        void *argv, void *envp, int *flags);
__attribute__((hot))
extern int ksu_handle_post_execveat(int *fd, struct filename **filename_ptr,
        void *argv, void *envp, int *flags, int *retval);
#endif
'''

OPEN_DECLS = r'''
#ifdef CONFIG_KSU_MANUAL_HOOK
__attribute__((hot))
extern int ksu_handle_faccessat(int *dfd, const char __user **filename_user,
                                int *mode, int *flags);
#endif
'''

STAT_DECLS = r'''
#ifdef CONFIG_KSU_MANUAL_HOOK
__attribute__((hot))
extern int ksu_handle_stat(int *dfd, const char __user **filename_user,
                           int *flags);

extern void ksu_handle_newfstat_ret(unsigned int *fd,
                                    struct stat __user **statbuf_ptr);

#if defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_COMPAT_STAT64)
extern void ksu_handle_fstat64_ret(unsigned long *fd,
                                   struct stat64 __user **statbuf_ptr);
#endif
#endif
'''

REBOOT_DECLS = r'''
#ifdef CONFIG_KSU_MANUAL_HOOK
extern int ksu_handle_sys_reboot(int magic1, int magic2,
                                 unsigned int cmd, void __user **arg);
#endif
'''


# ============================================================
# UTILITIES
# ============================================================

def abort(message):
    raise RuntimeError(message)


def insert_before_once(text, anchor, addition, label):
    count = text.count(anchor)

    if count != 1:
        abort(
            f"{label}: expected one insertion point, "
            f"found {count}"
        )

    return text.replace(anchor, addition + "\n" + anchor, 1)


def replace_once(text, old, new, label):
    count = text.count(old)

    if count != 1:
        abort(
            f"{label}: expected one matching block, "
            f"found {count}"
        )

    return text.replace(old, new, 1)


def function_bounds(text, signature):
    start = text.find(signature)

    if start < 0:
        abort(f"Function not found: {signature}")

    brace = text.find("{", start)

    if brace < 0:
        abort(f"Opening brace not found: {signature}")

    depth = 0

    for pos in range(brace, len(text)):
        if text[pos] == "{":
            depth += 1

        elif text[pos] == "}":
            depth -= 1

            if depth == 0:
                return start, pos + 1

    abort(f"Unclosed function: {signature}")


def function_body(text, signature):
    """Return the body of the function (without the trailing brace)."""
    start, end = function_bounds(text, signature)
    return text[start:end]


def patch_function(text, signature, old, new, hook_name):
    start, end = function_bounds(text, signature)

    block = text[start:end]

    if hook_name in block:
        # The hook is already present in *some* form. Two cases:
        #   1. Our exact patched text is present -> idempotent skip.
        #   2. A different (e.g. vendor) variant is present ->
        #      that's fine too, don't double-inject, just skip.
        if new.strip() in block:
            print(f"[SKIP] {signature}: hook already present")
        else:
            print(
                f"[SKIP] {signature}: pre-existing "
                f"'{hook_name}' hook detected, leaving untouched"
            )
        return text

    block = replace_once(block, old, new, signature)

    print(f"[PATCH] {signature}")

    return text[:start] + block + text[end:]


# ============================================================
# MANUAL HOOK PATCHES
# ============================================================

def apply_manual_hook_patch(text, relative_path):

    # --------------------------------------------------------
    # fs/exec.c
    # --------------------------------------------------------

    if relative_path == "fs/exec.c":

        native_old = (
            "\treturn do_execveat_common("
            "AT_FDCWD, filename, argv, envp, 0);"
        )

        native_new = r'''
#ifdef CONFIG_KSU_MANUAL_HOOK
	int retval;

	ksu_handle_execveat(
		(int *)AT_FDCWD,
		&filename,
		&argv,
		&envp,
		0
	);

	retval = do_execveat_common(
		AT_FDCWD,
		filename,
		argv,
		envp,
		0
	);

	ksu_handle_post_execveat(
		(int *)AT_FDCWD,
		&filename,
		&argv,
		&envp,
		0,
		&retval
	);

	return retval;
#else
	return do_execveat_common(
		AT_FDCWD,
		filename,
		argv,
		envp,
		0
	);
#endif
'''

        if "ksu_handle_execveat" not in text:
            text = insert_before_once(
                text,
                "int do_execve(struct filename *filename,",
                EXEC_DECLS,
                "exec declarations"
            )

        text = patch_function(
            text,
            "int do_execve(struct filename *filename,",
            native_old,
            native_new,
            "ksu_handle_execveat("
        )

        return text

    # --------------------------------------------------------
    # fs/open.c
    # --------------------------------------------------------

    if relative_path == "fs/open.c":

        signature = (
            "SYSCALL_DEFINE3(faccessat, int, dfd, "
            "const char __user *, filename, int, mode)"
        )

        # Pre-existing hook check. Many Android 10–13 trees ship
        # with a vendor-format `ksu_handle_faccessat(...)` call
        # already inside the function body. Detect that up front
        # and skip cleanly, instead of letting patch_function()
        # trip on the "partial or different hook" guard.
        body = function_body(text, signature)

        if "ksu_handle_faccessat(" in body:
            print(
                f"[SKIP] {signature}: pre-existing "
                f"'ksu_handle_faccessat' hook detected, "
                f"leaving untouched"
            )
            return text

        if "ksu_handle_faccessat" not in text:
            text = insert_before_once(
                text,
                "/*\n * access() needs to use the real uid/gid",
                OPEN_DECLS,
                "open declarations"
            )

        text = patch_function(
            text,
            signature,
            "\tif (mode & ~S_IRWXO)",
            "\tksu_handle_faccessat(&dfd, &filename, "
            "&mode, NULL);\n"
            "\tif (mode & ~S_IRWXO)",
            "ksu_handle_faccessat("
        )

        return text

    # --------------------------------------------------------
    # kernel/reboot.c
    # --------------------------------------------------------

    if relative_path == "kernel/reboot.c":

        if "ksu_handle_sys_reboot" not in text:
            text = insert_before_once(
                text,
                "SYSCALL_DEFINE4(reboot, int, magic1, "
                "int, magic2, unsigned int, cmd,",
                REBOOT_DECLS,
                "reboot declarations"
            )

        text = patch_function(
            text,
            "SYSCALL_DEFINE4(reboot, int, magic1, "
            "int, magic2, unsigned int, cmd,",
            "\tint ret = 0;",
            "\tint ret = 0;\n\n"
            "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
            "\tksu_handle_sys_reboot("
            "magic1, magic2, cmd, &arg);\n"
            "#endif",
            "ksu_handle_sys_reboot("
        )

        return text

    # --------------------------------------------------------
    # fs/stat.c
    # --------------------------------------------------------

    if relative_path == "fs/stat.c":

        if "ksu_handle_stat" not in text:
            text = insert_before_once(
                text,
                "#if !defined(__ARCH_WANT_STAT64) "
                "|| defined(__ARCH_WANT_SYS_NEWFSTATAT)",
                STAT_DECLS,
                "stat declarations"
            )

        text = patch_function(
            text,
            "SYSCALL_DEFINE4(newfstatat, int, dfd, "
            "const char __user *, filename,",
            "\terror = vfs_fstatat(dfd, filename, "
            "&stat, flag);",
            "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
            "\tksu_handle_stat(&dfd, &filename, &flag);\n"
            "#endif\n"
            "\terror = vfs_fstatat(dfd, filename, "
            "&stat, flag);",
            "ksu_handle_stat("
        )

        text = patch_function(
            text,
            "SYSCALL_DEFINE2(newfstat, unsigned int, fd, "
            "struct stat __user *, statbuf)",
            "\treturn error;",
            "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
            "\tksu_handle_newfstat_ret(&fd, &statbuf);\n"
            "#endif\n"
            "\treturn error;",
            "ksu_handle_newfstat_ret("
        )

        # Optional fstat64

        signature_fstat64 = (
            "SYSCALL_DEFINE2(fstat64, unsigned long, fd, "
            "struct stat64 __user *, statbuf)"
        )

        if signature_fstat64 in text:
            text = patch_function(
                text,
                signature_fstat64,
                "\treturn error;",
                "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
                "\tksu_handle_fstat64_ret(&fd, &statbuf);\n"
                "#endif\n"
                "\treturn error;",
                "ksu_handle_fstat64_ret("
            )

        # Optional fstatat64

        signature_fstatat64 = (
            "SYSCALL_DEFINE4(fstatat64, int, dfd, "
            "const char __user *, filename,"
        )

        if signature_fstatat64 in text:
            text = patch_function(
                text,
                signature_fstatat64,
                "\terror = vfs_fstatat(dfd, filename, "
                "&stat, flag);",
                "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
                "\tksu_handle_stat(&dfd, &filename, &flag);\n"
                "#endif\n"
                "\terror = vfs_fstatat(dfd, filename, "
                "&stat, flag);",
                "ksu_handle_stat("
            )

        return text

    abort(f"Unsupported Manual Hook target: {relative_path}")


# ============================================================
# BAKASU SELINUX STATIC SYMBOL PATCHES
# ============================================================

SELINUX_SYMBOL_PATCHES = {

    "security/selinux/selinuxfs.c": [
        {
            "name": "write_op",
            "pattern": (
                r"\bstatic\s+"
                r"(?=ssize_t\s*\(\s*\*\s*write_op\s*\[\s*\]\s*\))"
            ),
            "required": True,
        },
        {
            "name": "sel_handle_status_ops",
            "pattern": (
                r"\bstatic\s+"
                r"(?=const\s+struct\s+file_operations\s+"
                r"sel_handle_status_ops\s*=)"
            ),
            "required": True,
        },
        {
            "name": "sel_mutex",
            "pattern": (
                r"\bstatic\s+"
                r"(?=DEFINE_MUTEX\s*\(\s*sel_mutex\s*\))"
            ),
            "required": False,
        },
    ],

    "security/selinux/ss/status.c": [
        {
            "name": "selinux_status_page",
            "pattern": (
                r"\bstatic\s+"
                r"(?=struct\s+page\s*\*\s*selinux_status_page\s*;)"
            ),
            "required": False,
        },
        {
            "name": "selinux_status_lock",
            "pattern": (
                r"\bstatic\s+"
                r"(?=DEFINE_MUTEX\s*\(\s*selinux_status_lock\s*\))"
            ),
            "required": False,
        },
    ],

    "security/selinux/ss/services.c": [
        {
            "name": "security_dump_masked_av",
            "pattern": (
                r"\bstatic\s+"
                r"(?=void\s+security_dump_masked_av\s*\()"
            ),
            "required": True,
        },
        {
            "name": "context_struct_compute_av",
            "pattern": (
                r"\bstatic\s+"
                r"(?=void\s+context_struct_compute_av\s*\()"
            ),
            "required": True,
        },
        {
            "name": "latest_granting",
            "pattern": (
                r"\bstatic\s+"
                r"(?=u32\s+latest_granting\s*;)"
            ),
            "required": False,
        },
        {
            "name": "policy_rwlock",
            "pattern": (
                r"\bstatic\s+"
                r"(?=DEFINE_RWLOCK\s*\(\s*policy_rwlock\s*\))"
            ),
            "required": False,
        },
    ],

    "security/selinux/hooks.c": [
        {
            "name": "inode_doinit_with_dentry",
            "pattern": (
                r"\bstatic\s+"
                r"(?=int\s+inode_doinit_with_dentry\s*\()"
            ),
            "required": True,
        },
        {
            "name": "selinux_inode_setxattr",
            "pattern": (
                r"\bstatic\s+"
                r"(?=int\s+selinux_inode_setxattr\s*\()"
            ),
            "required": True,
        },
    ],
}


# ============================================================
# SELINUX PATCH ENGINE
# ============================================================

def apply_selinux_symbol_patch(text, symbol, pattern, required):
    matches = list(re.finditer(pattern, text))

    if matches:
        text, count = re.subn(pattern, "", text)

        if count != len(matches):
            abort(
                f"SELinux symbol {symbol}: "
                "match count changed during replacement"
            )

        print(
            f"[PATCH] SELinux symbol: {symbol} "
            f"({count} occurrence(s))"
        )

        return text

    symbol_pattern = re.compile(
        r"\b" + re.escape(symbol) + r"\b"
    )

    if symbol_pattern.search(text):
        print(
            f"[SKIP] SELinux symbol already exported: "
            f"{symbol}"
        )
        return text

    if required:
        abort(f"Required SELinux symbol not found: {symbol}")

    print(
        f"[SKIP] Optional SELinux symbol not found: "
        f"{symbol}"
    )
    return text


def apply_selinux_patch(text, relative_path):
    patches = SELINUX_SYMBOL_PATCHES.get(relative_path)

    if patches is None:
        return text

    for patch in patches:
        text = apply_selinux_symbol_patch(
            text,
            patch["name"],
            patch["pattern"],
            patch["required"],
        )

    return text


# ============================================================
# PATCH DISPATCHER
# ============================================================

def apply_patch(text, relative_path):

    if relative_path in (
        "fs/exec.c",
        "fs/open.c",
        "kernel/reboot.c",
        "fs/stat.c",
    ):
        text = apply_manual_hook_patch(text, relative_path)

    if relative_path in SELINUX_SYMBOL_PATCHES:
        text = apply_selinux_patch(text, relative_path)

    return text


# ============================================================
# MAIN
# ============================================================

def main():

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "kernel",
        nargs="?",
        default=".",
        help="Kernel source directory",
    )
    args = parser.parse_args()

    root = Path(args.kernel).expanduser().resolve()

    targets = [
        "fs/exec.c",
        "fs/open.c",
        "kernel/reboot.c",
        "fs/stat.c",
        "security/selinux/selinuxfs.c",
        "security/selinux/ss/status.c",
        "security/selinux/ss/services.c",
        "security/selinux/hooks.c",
    ]

    originals = {}
    patched = {}

    try:
        for name in targets:
            file_path = root / name

            if not file_path.is_file():
                if name == "security/selinux/ss/status.c":
                    print(f"[SKIP] Optional file missing: {name}")
                    continue
                abort(f"Missing target file: {file_path}")

            originals[name] = file_path.read_text()

        print("\n[INFO] Preparing patches...\n")

        for name in originals:
            patched[name] = apply_patch(originals[name], name)

        changed = [
            name
            for name in originals
            if patched[name] != originals[name]
        ]

        if not changed:
            print(
                "\n[OK] All requested patches "
                "already appear to be applied."
            )
            return

        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        backups = {}

        print("\n[INFO] Creating backups...\n")

        for name in changed:
            source = root / name
            backup = source.with_name(
                source.name + f".bak.ksu_patch.{timestamp}"
            )
            shutil.copy2(source, backup)
            backups[name] = backup
            print(f"[BACKUP] {backup}")

        written = []

        try:
            print("\n[INFO] Writing patches...\n")

            for name in changed:
                file_path = root / name
                file_path.write_text(patched[name])
                written.append(name)
                print(f"[OK] Patched {name}")

        except Exception:
            print("\n[ROLLBACK] Restoring modified files...")

            for name in written:
                shutil.copy2(backups[name], root / name)

            raise

        print("\n" + "=" * 60)
        print("PATCH COMPLETED SUCCESSFULLY")
        print("=" * 60)
        print("\nModified files:")

        for name in changed:
            print(f"  - {name}")

        print("\nNext steps:")
        print("  1. git diff --check")
        print("  2. git diff")
        print("  3. Review the changes before compiling")
        print("\n[NOTE] CONFIG_KALLSYMS_ALL was not modified.")
        print("[NOTE] Missing optional SELinux symbols are skipped.")
        print("[NOTE] Required symbols must exist in the kernel source.")

    except (OSError, RuntimeError) as exc:
        print(f"\n[ERROR] {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
