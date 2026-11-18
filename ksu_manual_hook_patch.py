
#!/usr/bin/env python3
"""
KernelSU Manual Hook patcher for legacy Android kernels.

Targets:
    fs/exec.c
    fs/open.c
    kernel/reboot.c
    fs/stat.c

Only adds the hooks shown in the supplied reference diff.
Creates backups and refuses ambiguous or partially applied patches.
"""

import argparse
import re
import shutil
import sys
from datetime import datetime
from pathlib import Path


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

extern void ksu_handle_newfstat_ret(unsigned int *fd, struct stat __user **statbuf_ptr);
#if defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_COMPAT_STAT64)
extern void ksu_handle_fstat64_ret(unsigned long *fd, struct stat64 __user **statbuf_ptr);
#endif
#endif
'''

REBOOT_DECLS = r'''
#ifdef CONFIG_KSU_MANUAL_HOOK
extern int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user **arg);
#endif
'''


def abort(message):
    raise RuntimeError(message)


def insert_before_once(text, anchor, addition, label):
    count = text.count(anchor)
    if count != 1:
        abort(f"{label}: expected one insertion point, found {count}")
    return text.replace(anchor, addition + "\n" + anchor, 1)


def replace_once(text, old, new, label):
    count = text.count(old)
    if count != 1:
        abort(f"{label}: expected one matching block, found {count}")
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


def patch_function(text, signature, old, new, hook_name):
    start, end = function_bounds(text, signature)
    block = text[start:end]

    if hook_name in block:
        if new.strip() in block:
            print(f"[SKIP] {signature}: hook already present")
            return text
        abort(f"{signature}: partial or different hook already present")

    block = replace_once(block, old, new, signature)
    print(f"[PATCH] {signature}")
    return text[:start] + block + text[end:]


def apply_patch(text, relative_path):
    if relative_path == "fs/exec.c":
        native_old = (
            "\treturn do_execveat_common(AT_FDCWD, filename, argv, envp, 0);"
        )
        native_new = r'''
#ifdef CONFIG_KSU_MANUAL_HOOK
  int retval;
  ksu_handle_execveat((int *)AT_FDCWD, &filename, &argv, &envp, 0);
  retval = do_execveat_common(AT_FDCWD, filename, argv, envp, 0);
  ksu_handle_post_execveat((int *)AT_FDCWD, &filename, &argv, &envp, 0, &retval);
  return retval;
#else
        return do_execveat_common(AT_FDCWD, filename, argv, envp, 0);
#endif'''
        if "ksu_handle_execveat" not in text:
            text = insert_before_once(
                text,
                "int do_execve(struct filename *filename,",
                EXEC_DECLS,
                "exec declarations",
            )

        text = patch_function(
            text,
            "int do_execve(struct filename *filename,",
            native_old,
            native_new,
            "ksu_handle_execveat(",
        )

        # The supplied reference diff does not include compat_do_execve().
        # Do not invent or add extra compat hooks.
        return text

    if relative_path == "fs/open.c":
        if "ksu_handle_faccessat" not in text:
            text = insert_before_once(
                text,
                "/*\n * access() needs to use the real uid/gid",
                OPEN_DECLS,
                "open declarations",
            )

        text = patch_function(
            text,
            "SYSCALL_DEFINE3(faccessat, int, dfd, const char __user *, filename, int, mode)",
            "\tif (mode & ~S_IRWXO)",
            "\tksu_handle_faccessat(&dfd, &filename, &mode, NULL);\n"
            "\tif (mode & ~S_IRWXO)",
            "ksu_handle_faccessat(",
        )
        return text

    if relative_path == "kernel/reboot.c":
        if "ksu_handle_sys_reboot" not in text:
            text = insert_before_once(
                text,
                "SYSCALL_DEFINE4(reboot, int, magic1, int, magic2, unsigned int, cmd,",
                REBOOT_DECLS,
                "reboot declarations",
            )

        text = patch_function(
            text,
            "SYSCALL_DEFINE4(reboot, int, magic1, int, magic2, unsigned int, cmd,",
            "\tint ret = 0;",
            "\tint ret = 0;\n\n#ifdef CONFIG_KSU_MANUAL_HOOK\n"
            "\tksu_handle_sys_reboot(magic1, magic2, cmd, &arg);\n#endif",
            "ksu_handle_sys_reboot(",
        )
        return text

    if relative_path == "fs/stat.c":
        if "ksu_handle_stat" not in text:
            text = insert_before_once(
                text,
                "#if !defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_SYS_NEWFSTATAT)",
                STAT_DECLS,
                "stat declarations",
            )

        text = patch_function(
            text,
            "SYSCALL_DEFINE4(newfstatat, int, dfd, const char __user *, filename,",
            "\terror = vfs_fstatat(dfd, filename, &stat, flag);",
            "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
            "\tksu_handle_stat(&dfd, &filename, &flag);\n"
            "#endif\n"
            "\terror = vfs_fstatat(dfd, filename, &stat, flag);",
            "ksu_handle_stat(",
        )

        text = patch_function(
            text,
            "SYSCALL_DEFINE2(newfstat, unsigned int, fd, struct stat __user *, statbuf)",
            "\treturn error;",
            "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
            "\tksu_handle_newfstat_ret(&fd, &statbuf);\n"
            "#endif\n"
            "\treturn error;",
            "ksu_handle_newfstat_ret(",
        )

        # fstat64 exists only on source trees that provide this syscall.
        if "SYSCALL_DEFINE2(fstat64, unsigned long, fd, struct stat64 __user *, statbuf)" in text:
            text = patch_function(
                text,
                "SYSCALL_DEFINE2(fstat64, unsigned long, fd, struct stat64 __user *, statbuf)",
                "\treturn error;",
                "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
                "\tksu_handle_fstat64_ret(&fd, &statbuf);\n"
                "#endif\n"
                "\treturn error;",
                "ksu_handle_fstat64_ret(",
            )

        # fstatat64 exists only on compatible source configurations.
        if "SYSCALL_DEFINE4(fstatat64, int, dfd, const char __user *, filename," in text:
            text = patch_function(
                text,
                "SYSCALL_DEFINE4(fstatat64, int, dfd, const char __user *, filename,",
                "\terror = vfs_fstatat(dfd, filename, &stat, flag);",
                "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
                "\tksu_handle_stat(&dfd, &filename, &flag);\n"
                "#endif\n"
                "\terror = vfs_fstatat(dfd, filename, &stat, flag);",
                "ksu_handle_stat(",
            )

        return text

    abort(f"Unsupported target: {relative_path}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kernel", nargs="?", default=".",
                        help="Kernel source directory")
    args = parser.parse_args()

    root = Path(args.kernel).expanduser().resolve()
    targets = [
        "fs/exec.c",
        "fs/open.c",
        "kernel/reboot.c",
        "fs/stat.c",
    ]

    originals = {}
    patched = {}

    try:
        for name in targets:
            file_path = root / name
            if not file_path.is_file():
                abort(f"Missing target file: {file_path}")
            originals[name] = file_path.read_text()

        # Prepare every patch in memory first. No file is changed unless
        # all four target transformations succeed.
        for name in targets:
            patched[name] = apply_patch(originals[name], name)

        changed = [name for name in targets
                   if patched[name] != originals[name]]

        if not changed:
            print("[OK] All requested hooks already appear to be applied.")
            return

        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        backups = {}

        for name in changed:
            source = root / name
            backup = source.with_name(
                source.name + f".bak.manual-hook.{timestamp}"
            )
            shutil.copy2(source, backup)
            backups[name] = backup

        written = []
        try:
            for name in changed:
                (root / name).write_text(patched[name])
                written.append(name)
        except Exception:
            for name in written:
                shutil.copy2(backups[name], root / name)
            raise

        for name in changed:
            print(f"[OK] Patched {name}")
            print(f"[BACKUP] {backups[name]}")

        print("\n[VERIFY] Run git diff --check and inspect git diff.")
        print("[NOTE] This script does not modify Kconfig or hook implementations.")

    except (OSError, RuntimeError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
