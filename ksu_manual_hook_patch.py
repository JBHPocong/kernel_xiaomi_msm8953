
#!/usr/bin/env python3
"""
KernelSU Manual Hook + BakaSU SELinux Static Symbol Export patcher
for Linux Kernel 4.9.x.

Manual Hooks:
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
    - Kernel 4.9.x targeted
    - Adaptive declaration detection
    - Per-symbol declaration validation
    - Automatic patching
    - Timestamped backups
    - Optional syscall support
    - Required symbols validated
    - All patches prepared before writing
    - Rollback on write failure
    - Already patched symbols detected
    - Partial patch detection
    - No duplicate hook insertion

Usage:
    python3 ksu_manual_hook_patch.py
    python3 ksu_manual_hook_patch.py /path/to/kernel
"""

import argparse
import re
import shutil
import sys
from datetime import datetime
from pathlib import Path


# ============================================================
# UTILITIES
# ============================================================

def abort(message):
    raise RuntimeError(message)


def print_info(message):
    print(f"[INFO] {message}")


def print_patch(message):
    print(f"[PATCH] {message}")


def print_skip(message):
    print(f"[SKIP] {message}")


def print_ok(message):
    print(f"[OK] {message}")


def normalize_whitespace(text):
    return re.sub(r"\s+", " ", text).strip()


def insert_before_once(text, anchor, addition, label):

    count = text.count(anchor)

    if count != 1:
        abort(
            f"{label}: expected exactly one insertion point, "
            f"found {count}"
        )

    return text.replace(
        anchor,
        addition.rstrip() + "\n\n" + anchor,
        1
    )


def insert_declarations(
    text,
    declarations,
    anchor,
    label
):
    """
    Insert only missing declarations.

    Declaration detection is performed independently
    for every symbol.

    A function call does not count as a declaration.
    """

    missing = []

    for symbol, declaration in declarations:

        declaration_pattern = re.compile(
            r"(?m)^[ \t]*(?:extern\s+)?"
            r"[^;\n]*\b"
            + re.escape(symbol)
            + r"\s*\([^;]*\)\s*;"
        )

        if declaration_pattern.search(text):

            print_skip(
                f"{label}: declaration already exists "
                f"for {symbol}"
            )

        else:

            missing.append(declaration)

    if not missing:
        return text

    addition = (
        "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
        + "\n".join(missing)
        + "\n#endif"
    )

    text = insert_before_once(
        text,
        anchor,
        addition,
        label
    )

    for declaration in missing:
        print_patch(
            f"{label}: inserted declaration"
        )

    return text


def function_bounds(text, signature):

    start = text.find(signature)

    if start < 0:
        abort(
            f"Function not found: {signature}"
        )

    brace = text.find("{", start)

    if brace < 0:
        abort(
            f"Opening brace not found: {signature}"
        )

    depth = 0

    for pos in range(brace, len(text)):

        char = text[pos]

        if char == "{":
            depth += 1

        elif char == "}":
            depth -= 1

            if depth == 0:
                return start, pos + 1

    abort(
        f"Unclosed function: {signature}"
    )


def patch_function(
    text,
    signature,
    old,
    new,
    hook_name
):

    start, end = function_bounds(
        text,
        signature
    )

    block = text[start:end]

    # --------------------------------------------------------
    # ALREADY PATCHED
    # --------------------------------------------------------

    if hook_name in block:

        if new.strip() in block:

            print_skip(
                f"{signature}: hook already present"
            )

            return text

        abort(
            f"{signature}: hook symbol exists but "
            "expected patch block is missing. "
            "Possible partial patch."
        )

    # --------------------------------------------------------
    # PATCH
    # --------------------------------------------------------

    count = block.count(old)

    if count != 1:

        abort(
            f"{signature}: expected exactly one matching "
            f"block, found {count}"
        )

    block = block.replace(
        old,
        new,
        1
    )

    print_patch(
        f"{signature}: {hook_name}"
    )

    return (
        text[:start]
        + block
        + text[end:]
    )


def symbol_declaration_exists(
    text,
    symbol
):

    pattern = re.compile(
        r"(?m)^[ \t]*"
        r"(?:extern\s+)?"
        r"[^;\n]*\b"
        + re.escape(symbol)
        + r"\s*\([^;]*\)\s*;"
    )

    return bool(
        pattern.search(text)
    )


# ============================================================
# MANUAL HOOK DECLARATIONS
# ============================================================

EXEC_DECLS = [

    (
        "ksu_handle_execveat",
        "__attribute__((hot))\n"
        "extern int ksu_handle_execveat(\n"
        "    int *fd,\n"
        "    struct filename **filename_ptr,\n"
        "    void *argv,\n"
        "    void *envp,\n"
        "    int *flags\n"
        ");"
    ),

    (
        "ksu_handle_post_execveat",
        "__attribute__((hot))\n"
        "extern int ksu_handle_post_execveat(\n"
        "    int *fd,\n"
        "    struct filename **filename_ptr,\n"
        "    void *argv,\n"
        "    void *envp,\n"
        "    int *flags,\n"
        "    int *retval\n"
        ");"
    ),
]


OPEN_DECLS = [

    (
        "ksu_handle_faccessat",
        "__attribute__((hot))\n"
        "extern int ksu_handle_faccessat(\n"
        "    int *dfd,\n"
        "    const char __user **filename_user,\n"
        "    int *mode,\n"
        "    int *flags\n"
        ");"
    ),
]


STAT_DECLS = [

    (
        "ksu_handle_stat",
        "__attribute__((hot))\n"
        "extern int ksu_handle_stat(\n"
        "    int *dfd,\n"
        "    const char __user **filename_user,\n"
        "    int *flags\n"
        ");"
    ),

    (
        "ksu_handle_newfstat_ret",
        "extern void ksu_handle_newfstat_ret(\n"
        "    unsigned int *fd,\n"
        "    struct stat __user **statbuf_ptr\n"
        ");"
    ),

    (
        "ksu_handle_fstat64_ret",
        "extern void ksu_handle_fstat64_ret(\n"
        "    unsigned long *fd,\n"
        "    struct stat64 __user **statbuf_ptr\n"
        ");"
    ),
]


REBOOT_DECLS = [

    (
        "ksu_handle_sys_reboot",
        "extern int ksu_handle_sys_reboot(\n"
        "    int magic1,\n"
        "    int magic2,\n"
        "    unsigned int cmd,\n"
        "    void __user **arg\n"
        ");"
    ),
]


# ============================================================
# MANUAL HOOK PATCHES
# ============================================================

def apply_manual_hook_patch(
    text,
    relative_path
):

    # ========================================================
    # fs/exec.c
    # ========================================================

    if relative_path == "fs/exec.c":

        declaration_anchor = (
            "int do_execve(struct filename *filename,"
        )

        text = insert_declarations(
            text,
            EXEC_DECLS,
            declaration_anchor,
            "exec declarations"
        )

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

        text = patch_function(
            text,
            "int do_execve(struct filename *filename,",
            native_old,
            native_new,
            "ksu_handle_execveat("
        )

        return text

    # ========================================================
    # fs/open.c
    # ========================================================

    if relative_path == "fs/open.c":

        declaration_anchor = (
            "/*\n"
            " * access() needs to use the real uid/gid"
        )

        text = insert_declarations(
            text,
            OPEN_DECLS,
            declaration_anchor,
            "open declarations"
        )

        signature = (
            "SYSCALL_DEFINE3(faccessat, int, dfd, "
            "const char __user *, filename, int, mode)"
        )

        old = (
            "\tif (mode & ~S_IRWXO)"
        )

        new = (
            "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
            "\tksu_handle_faccessat("
            "&dfd, &filename, &mode, NULL);\n"
            "#endif\n"
            "\tif (mode & ~S_IRWXO)"
        )

        text = patch_function(
            text,
            signature,
            old,
            new,
            "ksu_handle_faccessat("
        )

        return text

    # ========================================================
    # kernel/reboot.c
    # ========================================================

    if relative_path == "kernel/reboot.c":

        declaration_anchor = (
            "SYSCALL_DEFINE4(reboot, int, magic1, "
            "int, magic2, unsigned int, cmd,"
        )

        text = insert_declarations(
            text,
            REBOOT_DECLS,
            declaration_anchor,
            "reboot declarations"
        )

        signature = (
            "SYSCALL_DEFINE4(reboot, int, magic1, "
            "int, magic2, unsigned int, cmd,"
        )

        old = "\tint ret = 0;"

        new = (
            "\tint ret = 0;\n\n"
            "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
            "\tksu_handle_sys_reboot("
            "magic1, magic2, cmd, &arg);\n"
            "#endif"
        )

        text = patch_function(
            text,
            signature,
            old,
            new,
            "ksu_handle_sys_reboot("
        )

        return text

    # ========================================================
    # fs/stat.c
    # ========================================================

    if relative_path == "fs/stat.c":

        declaration_anchor = (
            "#if !defined(__ARCH_WANT_STAT64) "
            "|| defined(__ARCH_WANT_SYS_NEWFSTATAT)"
        )

        text = insert_declarations(
            text,
            STAT_DECLS,
            declaration_anchor,
            "stat declarations"
        )

        # ----------------------------------------------------
        # newfstatat
        # ----------------------------------------------------

        signature_newfstatat = (
            "SYSCALL_DEFINE4(newfstatat, int, dfd, "
            "const char __user *, filename,"
        )

        old_newfstatat = (
            "\terror = vfs_fstatat(dfd, filename, "
            "&stat, flag);"
        )

        new_newfstatat = (
            "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
            "\tksu_handle_stat("
            "&dfd, &filename, &flag);\n"
            "#endif\n"
            "\terror = vfs_fstatat(dfd, filename, "
            "&stat, flag);"
        )

        text = patch_function(
            text,
            signature_newfstatat,
            old_newfstatat,
            new_newfstatat,
            "ksu_handle_stat("
        )

        # ----------------------------------------------------
        # newfstat
        # ----------------------------------------------------

        signature_newfstat = (
            "SYSCALL_DEFINE2(newfstat, unsigned int, fd, "
            "struct stat __user *, statbuf)"
        )

        old_newfstat = "\treturn error;"

        new_newfstat = (
            "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
            "\tksu_handle_newfstat_ret("
            "&fd, &statbuf);\n"
            "#endif\n"
            "\treturn error;"
        )

        text = patch_function(
            text,
            signature_newfstat,
            old_newfstat,
            new_newfstat,
            "ksu_handle_newfstat_ret("
        )

        # ----------------------------------------------------
        # OPTIONAL fstat64
        # ----------------------------------------------------

        signature_fstat64 = (
            "SYSCALL_DEFINE2(fstat64, unsigned long, fd, "
            "struct stat64 __user *, statbuf)"
        )

        if signature_fstat64 in text:

            old_fstat64 = "\treturn error;"

            new_fstat64 = (
                "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
                "\tksu_handle_fstat64_ret("
                "&fd, &statbuf);\n"
                "#endif\n"
                "\treturn error;"
            )

            text = patch_function(
                text,
                signature_fstat64,
                old_fstat64,
                new_fstat64,
                "ksu_handle_fstat64_ret("
            )

        else:

            print_skip(
                "fs/stat.c: fstat64 syscall not present"
            )

        # ----------------------------------------------------
        # OPTIONAL fstatat64
        # ----------------------------------------------------

        signature_fstatat64 = (
            "SYSCALL_DEFINE4(fstatat64, int, dfd, "
            "const char __user *, filename,"
        )

        if signature_fstatat64 in text:

            old_fstatat64 = (
                "\terror = vfs_fstatat(dfd, filename, "
                "&stat, flag);"
            )

            new_fstatat64 = (
                "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
                "\tksu_handle_stat("
                "&dfd, &filename, &flag);\n"
                "#endif\n"
                "\terror = vfs_fstatat(dfd, filename, "
                "&stat, flag);"
            )

            text = patch_function(
                text,
                signature_fstatat64,
                old_fstatat64,
                new_fstatat64,
                "ksu_handle_stat("
            )

        else:

            print_skip(
                "fs/stat.c: fstatat64 syscall not present"
            )

        return text

    abort(
        f"Unsupported Manual Hook target: "
        f"{relative_path}"
    )


# ============================================================
# BAKASU SELINUX STATIC SYMBOL PATCHES
# ============================================================

SELINUX_SYMBOL_PATCHES = {

    # --------------------------------------------------------
    # security/selinux/selinuxfs.c
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # security/selinux/ss/status.c
    # --------------------------------------------------------

    "security/selinux/ss/status.c": [

        {
            "name": "selinux_status_page",
            "pattern": (
                r"\bstatic\s+"
                r"(?=struct\s+page\s*\*\s*"
                r"selinux_status_page\s*;)"
            ),
            "required": False,
        },

        {
            "name": "selinux_status_lock",
            "pattern": (
                r"\bstatic\s+"
                r"(?=DEFINE_MUTEX\s*\(\s*"
                r"selinux_status_lock\s*\))"
            ),
            "required": False,
        },
    ],

    # --------------------------------------------------------
    # security/selinux/ss/services.c
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # security/selinux/hooks.c
    # --------------------------------------------------------

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

        # Legacy selinux_ops intentionally excluded.
        #
        # Kernel 4.9 vendor sources may use:
        #
        #   struct security_hook_list selinux_hooks[]
        #   security_add_hooks()
        #
        # instead of legacy security_operations.
    ],
}


# ============================================================
# SELINUX PATCH ENGINE
# ============================================================

def apply_selinux_symbol_patch(
    text,
    symbol,
    pattern,
    required
):

    matches = list(
        re.finditer(
            pattern,
            text
        )
    )

    # --------------------------------------------------------
    # STATIC MATCHES FOUND
    # --------------------------------------------------------

    if matches:

        text, count = re.subn(
            pattern,
            "",
            text
        )

        if count != len(matches):

            abort(
                f"SELinux symbol {symbol}: "
                "match count changed during replacement"
            )

        print_patch(
            f"SELinux symbol: {symbol} "
            f"({count} occurrence(s))"
        )

        return text

    # --------------------------------------------------------
    # NO STATIC MATCH
    # --------------------------------------------------------

    symbol_pattern = re.compile(
        r"\b"
        + re.escape(symbol)
        + r"\b"
    )

    symbol_matches = list(
        symbol_pattern.finditer(text)
    )

    # Symbol exists, but is already non-static.

    if symbol_matches:

        print_skip(
            f"SELinux symbol already exported: "
            f"{symbol}"
        )

        return text

    # --------------------------------------------------------
    # SYMBOL NOT FOUND
    # --------------------------------------------------------

    if required:

        abort(
            f"Required SELinux symbol not found: "
            f"{symbol}"
        )

    print_skip(
        f"Optional SELinux symbol not found: "
        f"{symbol}"
    )

    return text


def apply_selinux_patch(
    text,
    relative_path
):

    patches = SELINUX_SYMBOL_PATCHES.get(
        relative_path
    )

    if patches is None:
        return text

    for patch in patches:

        text = apply_selinux_symbol_patch(
            text,
            patch["name"],
            patch["pattern"],
            patch["required"]
        )

    return text


# ============================================================
# PATCH DISPATCHER
# ============================================================

def apply_patch(
    text,
    relative_path
):

    # --------------------------------------------------------
    # MANUAL HOOKS
    # --------------------------------------------------------

    if relative_path in (

        "fs/exec.c",
        "fs/open.c",
        "kernel/reboot.c",
        "fs/stat.c",

    ):

        text = apply_manual_hook_patch(
            text,
            relative_path
        )

    # --------------------------------------------------------
    # BAKASU SELINUX
    # --------------------------------------------------------

    if relative_path in SELINUX_SYMBOL_PATCHES:

        text = apply_selinux_patch(
            text,
            relative_path
        )

    return text


# ============================================================
# TARGET FILES
# ============================================================

TARGETS = [

    # Manual Hooks

    "fs/exec.c",
    "fs/open.c",
    "kernel/reboot.c",
    "fs/stat.c",

    # BakaSU SELinux

    "security/selinux/selinuxfs.c",
    "security/selinux/ss/status.c",
    "security/selinux/ss/services.c",
    "security/selinux/hooks.c",
]


# ============================================================
# MAIN
# ============================================================

def main():

    parser = argparse.ArgumentParser(
        description=__doc__
    )

    parser.add_argument(
        "kernel",
        nargs="?",
        default=".",
        help="Kernel source directory"
    )

    args = parser.parse_args()

    root = Path(
        args.kernel
    ).expanduser().resolve()

    if not root.is_dir():

        abort(
            f"Kernel source directory not found: "
            f"{root}"
        )

    originals = {}
    patched = {}

    # ========================================================
    # READ FILES
    # ========================================================

    print_info(
        f"Kernel source: {root}"
    )

    print_info(
        "Target: Linux kernel 4.9.x"
    )

    for name in TARGETS:

        file_path = root / name

        if not file_path.is_file():

            # ------------------------------------------------
            # OPTIONAL FILE
            # ------------------------------------------------

            if name == (
                "security/selinux/ss/status.c"
            ):

                print_skip(
                    f"Optional file missing: {name}"
                )

                continue

            abort(
                f"Missing target file: {file_path}"
            )

        try:

            originals[name] = (
                file_path.read_text(
                    encoding="utf-8"
                )
            )

        except UnicodeDecodeError:

            abort(
                f"Cannot read source as UTF-8: "
                f"{file_path}"
            )

    # ========================================================
    # PREPARE PATCHES
    # ========================================================

    print(
        "\n[INFO] Preparing patches...\n"
    )

    for name, original in originals.items():

        patched[name] = apply_patch(
            original,
            name
        )

    # ========================================================
    # DETERMINE CHANGES
    # ========================================================

    changed = [

        name

        for name in originals

        if patched[name] != originals[name]

    ]

    # ========================================================
    # NOTHING TO PATCH
    # ========================================================

    if not changed:

        print(
            "\n[OK] All requested patches "
            "already appear to be applied."
        )

        return

    # ========================================================
    # CREATE BACKUPS
    # ========================================================

    timestamp = datetime.now().strftime(
        "%Y%m%d-%H%M%S"
    )

    backups = {}

    print(
        "\n[INFO] Creating backups...\n"
    )

    for name in changed:

        source = root / name

        backup = source.with_name(
            source.name
            + f".bak.ksu_patch.{timestamp}"
        )

        shutil.copy2(
            source,
            backup
        )

        backups[name] = backup

        print(
            f"[BACKUP] {backup}"
        )

    # ========================================================
    # WRITE PATCHES
    # ========================================================

    written = []

    try:

        print(
            "\n[INFO] Writing patches...\n"
        )

        for name in changed:

            file_path = root / name

            file_path.write_text(
                patched[name],
                encoding="utf-8"
            )

            written.append(name)

            print(
                f"[OK] Patched {name}"
            )

    except Exception as exc:

        print(
            "\n[ROLLBACK] Restoring modified files..."
        )

        rollback_errors = []

        for name in written:

            try:

                shutil.copy2(
                    backups[name],
                    root / name
                )

                print(
                    f"[ROLLBACK] Restored {name}"
                )

            except Exception as rollback_error:

                rollback_errors.append(
                    f"{name}: {rollback_error}"
                )

        if rollback_errors:

            print(
                "\n[ROLLBACK ERROR]"
            )

            for error in rollback_errors:

                print(
                    f"  {error}"
                )

        raise RuntimeError(
            f"Patch write failed: {exc}"
        )

    # ========================================================
    # SUMMARY
    # ========================================================

    print(
        "\n"
        + "=" * 60
    )

    print(
        "PATCH COMPLETED SUCCESSFULLY"
    )

    print(
        "=" * 60
    )

    print(
        "\nModified files:"
    )

    for name in changed:

        print(
            f"  - {name}"
        )

    print(
        "\nNext steps:"
    )

    print(
        "  1. git diff --check"
    )

    print(
        "  2. git diff"
    )

    print(
        "  3. Review all changes"
    )

    print(
        "  4. Compile the kernel"
    )

    print(
        "\n[NOTE] CONFIG_KALLSYMS_ALL "
        "was not modified."
    )

    print(
        "[NOTE] Optional SELinux symbols "
        "are skipped when unavailable."
    )

    print(
        "[NOTE] Required SELinux symbols "
        "must exist in the source."
    )

    print(
        "[NOTE] This script targets "
        "Linux 4.9.x source structures."
    )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    try:

        main()

    except (
        OSError,
        RuntimeError
    ) as exc:

        print(
            f"\n[ERROR] {exc}",
            file=sys.stderr
        )

        sys.exit(1)
