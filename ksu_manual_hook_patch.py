
#!/usr/bin/env python3
"""
Adaptive KernelSU Manual Hook + BakaSU SELinux Patcher

Features:
- Adaptive source matching
- Similarity scoring
- Reference-based matching
- Function signature matching with whitespace tolerance
- Automatic Manual Hook integration
- Legacy vfs_read hook removal
- BakaSU SELinux static symbol export
- Idempotent
- Timestamped backups
- Transactional patching
- Rollback on failure
- Dry-run mode
- Detailed patch report

Usage:
    python3 ksu_manual_hook_patch.py .
    python3 ksu_manual_hook_patch.py /path/to/kernel
    python3 ksu_manual_hook_patch.py . --dry-run
    python3 ksu_manual_hook_patch.py . --threshold 0.85
"""

import argparse
import difflib
import re
import shutil
import sys
from datetime import datetime
from pathlib import Path


# ============================================================
# CONFIGURATION
# ============================================================

DEFAULT_THRESHOLD = 0.85

REFERENCE_THRESHOLD = 0.90
PARTIAL_THRESHOLD = 0.75
MINIMUM_THRESHOLD = 0.50

REPORT = []

# ============================================================
# LOGGING
# ============================================================

def log(level, message):
    print(f"[{level}] {message}")
    REPORT.append((level, message))


def abort(message):
    raise RuntimeError(message)


# ============================================================
# NORMALIZATION
# ============================================================

def normalize_code(code):
    """
    Normalize source code for similarity comparison.

    Removes:
    - whitespace differences
    - comments
    - unnecessary formatting differences

    Does NOT remove:
    - identifiers
    - operators
    - function names
    - structural tokens
    """

    code = re.sub(
        r"/\*.*?\*/",
        "",
        code,
        flags=re.DOTALL
    )

    code = re.sub(
        r"//[^\n]*",
        "",
        code
    )

    code = re.sub(
        r"\s+",
        "",
        code
    )

    return code


def similarity(a, b):
    """
    Return similarity ratio between two code fragments.
    """

    a = normalize_code(a)
    b = normalize_code(b)

    if not a or not b:
        return 0.0

    return difflib.SequenceMatcher(
        None,
        a,
        b
    ).ratio()


def compare_reference(
    source,
    reference,
    threshold=DEFAULT_THRESHOLD,
    label="reference"
):
    """
    Compare source against a reference implementation.

    High similarity:
        Accept reference.

    Medium similarity:
        Candidate only.

    Low similarity:
        Reject reference.
    """

    score = similarity(
        source,
        reference
    )

    if score >= REFERENCE_THRESHOLD:

        log(
            "REFERENCE",
            f"{label}: similarity={score:.2%}, "
            "strong match"
        )

        return "strong", score

    if score >= PARTIAL_THRESHOLD:

        log(
            "REFERENCE",
            f"{label}: similarity={score:.2%}, "
            "partial match"
        )

        return "partial", score

    if score >= MINIMUM_THRESHOLD:

        log(
            "REFERENCE",
            f"{label}: similarity={score:.2%}, "
            "weak match"
        )

        return "weak", score

    log(
        "REFERENCE",
        f"{label}: similarity={score:.2%}, "
        "ignored"
    )

    return "ignored", score


# ============================================================
# STRUCTURAL MATCHING
# ============================================================

def find_function(
    text,
    signature_pattern,
    label=None
):
    """
    Find function using regex signature.

    Whitespace and line breaks are ignored.
    """

    match = re.search(
        signature_pattern,
        text,
        re.MULTILINE | re.DOTALL
    )

    if not match:

        if label:
            log(
                "SKIP",
                f"Function not found: {label}"
            )

        return None

    start = match.start()

    brace = text.find(
        "{",
        match.end()
    )

    if brace < 0:
        return None

    depth = 0

    for pos in range(
        brace,
        len(text)
    ):

        char = text[pos]

        if char == "{":
            depth += 1

        elif char == "}":
            depth -= 1

            if depth == 0:

                return (
                    start,
                    pos + 1,
                    text[start:pos + 1]
                )

    return None


def find_function_by_name(
    text,
    function_name
):
    """
    Generic function finder.

    Allows:
        static int foo(...)
        int foo(...)
        __attribute__((...)) int foo(...)
    """

    pattern = (
        r"\b"
        + re.escape(function_name)
        + r"\s*\([^;]*?\)\s*\{"
    )

    return find_function(
        text,
        pattern,
        function_name
    )


def replace_function(
    text,
    bounds,
    new_block
):

    start, end, old_block = bounds

    return (
        text[:start]
        + new_block
        + text[end:]
    )


# ============================================================
# ADAPTIVE ANCHOR MATCHER
# ============================================================

def find_anchor(
    block,
    reference,
    threshold=DEFAULT_THRESHOLD,
    label="anchor"
):
    """
    Find a source line matching the reference.

    Exact match:
        accepted

    Similarity >= threshold:
        accepted

    Similarity between 0.75 and threshold:
        candidate, not automatically accepted

    Similarity below 0.75:
        rejected
    """

    lines = block.splitlines()

    reference_normalized = normalize_code(
        reference
    )

    candidates = []

    for index, line in enumerate(lines):

        normalized = normalize_code(
            line
        )

        if not normalized:
            continue

        score = difflib.SequenceMatcher(
            None,
            normalized,
            reference_normalized
        ).ratio()

        candidates.append(
            (
                score,
                index,
                line
            )
        )

    candidates.sort(
        reverse=True
    )

    if not candidates:

        log(
            "SKIP",
            f"No candidate anchor: {label}"
        )

        return None

    best_score, best_index, best_line = (
        candidates[0]
    )

    if best_score >= threshold:

        log(
            "MATCH",
            f"{label}: {best_score:.2%}"
        )

        return best_index

    if best_score >= PARTIAL_THRESHOLD:

        log(
            "REVIEW",
            f"{label}: {best_score:.2%}; "
            "not automatically patched"
        )

        return None

    log(
        "SKIP",
        f"{label}: similarity too low "
        f"({best_score:.2%})"
    )

    return None


# ============================================================
# SAFE INSERTION
# ============================================================

def insert_before_anchor(
    block,
    anchor,
    addition,
    label,
    threshold=DEFAULT_THRESHOLD
):

    lines = block.splitlines()

    index = find_anchor(
        block,
        anchor,
        threshold,
        label
    )

    if index is None:
        return block, False

    lines.insert(
        index,
        addition
    )

    return (
        "\n".join(lines),
        True
    )


def replace_anchor(
    block,
    anchor,
    replacement,
    label,
    threshold=DEFAULT_THRESHOLD
):

    lines = block.splitlines()

    index = find_anchor(
        block,
        anchor,
        threshold,
        label
    )

    if index is None:
        return block, False

    lines[index] = replacement

    return (
        "\n".join(lines),
        True
    )


# ============================================================
# DECLARATIONS
# ============================================================

EXEC_DECLS = r"""
#ifdef CONFIG_KSU_MANUAL_HOOK
__attribute__((hot))
extern int ksu_handle_execveat(
    int *fd,
    struct filename **filename_ptr,
    void *argv,
    void *envp,
    int *flags
);

__attribute__((hot))
extern int ksu_handle_post_execveat(
    int *fd,
    struct filename **filename_ptr,
    void *argv,
    void *envp,
    int *flags,
    int *retval
);
#endif
"""

OPEN_DECLS = r"""
#ifdef CONFIG_KSU_MANUAL_HOOK
__attribute__((hot))
extern int ksu_handle_faccessat(
    int *dfd,
    const char __user **filename_user,
    int *mode,
    int *flags
);
#endif
"""

STAT_DECLS = r"""
#ifdef CONFIG_KSU_MANUAL_HOOK
__attribute__((hot))
extern int ksu_handle_stat(
    int *dfd,
    const char __user **filename_user,
    int *flags
);

extern void ksu_handle_newfstat_ret(
    unsigned int *fd,
    struct stat __user **statbuf_ptr
);

#if defined(__ARCH_WANT_STAT64) || \
    defined(__ARCH_WANT_COMPAT_STAT64)

extern void ksu_handle_fstat64_ret(
    unsigned long *fd,
    struct stat64 __user **statbuf_ptr
);

#endif
#endif
"""

REBOOT_DECLS = r"""
#ifdef CONFIG_KSU_MANUAL_HOOK
extern int ksu_handle_sys_reboot(
    int magic1,
    int magic2,
    unsigned int cmd,
    void __user **arg
);
#endif
"""


# ============================================================
# DECLARATION INSERTION
# ============================================================

def insert_declaration(
    text,
    declaration,
    anchor_pattern,
    label
):

    if declaration.splitlines()[1] in text:

        log(
            "SKIP",
            f"{label}: declaration already present"
        )

        return text

    match = re.search(
        anchor_pattern,
        text,
        re.MULTILINE
    )

    if not match:

        log(
            "SKIP",
            f"{label}: insertion anchor not found"
        )

        return text

    return (
        text[:match.start()]
        + declaration
        + "\n"
        + text[match.start():]
    )


# ============================================================
# PATCH FUNCTION
# ============================================================

def patch_function_adaptive(
    text,
    signature_pattern,
    reference_anchor,
    replacement,
    hook_name,
    label,
    threshold=DEFAULT_THRESHOLD
):

    # Already patched?

    if hook_name in text:

        log(
            "SKIP",
            f"{label}: hook already exists"
        )

        return text

    bounds = find_function(
        text,
        signature_pattern,
        label
    )

    if bounds is None:

        log(
            "SKIP",
            f"{label}: function not found"
        )

        return text

    start, end, block = bounds

    # Find matching anchor

    index = find_anchor(
        block,
        reference_anchor,
        threshold,
        label
    )

    if index is None:

        log(
            "SKIP",
            f"{label}: no safe insertion point"
        )

        return text

    lines = block.splitlines()

    lines.insert(
        index,
        replacement
    )

    new_block = "\n".join(
        lines
    )

    log(
        "PATCH",
        label
    )

    return (
        text[:start]
        + new_block
        + text[end:]
    )


# ============================================================
# FS/EXEC.C
# ============================================================

def patch_exec(text):

    signature = (
        r"int\s+do_execve\s*"
        r"\(\s*struct\s+filename\s*\*filename,"
    )

    reference = (
        "return do_execveat_common("
        "AT_FDCWD, filename, argv, envp, 0);"
    )

    replacement = r"""
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
"""

    if "ksu_handle_execveat" not in text:

        text = insert_declaration(
            text,
            EXEC_DECLS,
            r"int\s+do_execve\s*\(",
            "exec declarations"
        )

    return patch_function_adaptive(
        text,
        signature,
        reference,
        replacement,
        "ksu_handle_execveat",
        "do_execve"
    )


# ============================================================
# FS/OPEN.C
# ============================================================

def patch_open(text):

    if "ksu_handle_faccessat" not in text:

        text = insert_declaration(
            text,
            OPEN_DECLS,
            r"/\*\s*\n\s*\*\s*access\(\)",
            "open declarations"
        )

    signature = (
        r"SYSCALL_DEFINE3\s*\(\s*faccessat\s*,"
        r"\s*int\s*,\s*dfd\s*,"
        r"\s*const\s+char\s+__user\s*\*,"
        r"\s*filename\s*,"
        r"\s*int\s*,\s*mode\s*\)"
    )

    return patch_function_adaptive(
        text,
        signature,
        "if (mode & ~S_IRWXO)",
        "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
        "\tksu_handle_faccessat("
        "&dfd, &filename, &mode, NULL);\n"
        "#endif",
        "ksu_handle_faccessat",
        "faccessat"
    )


# ============================================================
# KERNEL/REBOOT.C
# ============================================================

def patch_reboot(text):

    signature = (
        r"SYSCALL_DEFINE4\s*\(\s*reboot\s*,"
        r"\s*int\s*,\s*magic1\s*,"
        r"\s*int\s*,\s*magic2\s*,"
        r"\s*unsigned\s+int\s*,\s*cmd\s*,"
    )

    if "ksu_handle_sys_reboot" not in text:

        text = insert_declaration(
            text,
            REBOOT_DECLS,
            r"SYSCALL_DEFINE4\s*\(\s*reboot",
            "reboot declarations"
        )

    return patch_function_adaptive(
        text,
        signature,
        "int ret = 0;",
        "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
        "\tksu_handle_sys_reboot("
        "magic1, magic2, cmd, &arg);\n"
        "#endif",
        "ksu_handle_sys_reboot",
        "sys_reboot"
    )


# ============================================================
# FS/STAT.C
# ============================================================

def patch_stat(text):

    if "ksu_handle_stat" not in text:

        text = insert_declaration(
            text,
            STAT_DECLS,
            r"#if\s*!defined\(__ARCH_WANT_STAT64\)",
            "stat declarations"
        )

    # --------------------------------------------------------
    # newfstatat
    # --------------------------------------------------------

    signature_newfstatat = (
        r"SYSCALL_DEFINE4\s*\(\s*newfstatat\s*,"
        r"\s*int\s*,\s*dfd\s*,"
        r"\s*const\s+char\s+__user\s*\*,"
        r"\s*filename\s*,"
    )

    text = patch_function_adaptive(
        text,
        signature_newfstatat,
        "error = vfs_fstatat(dfd, filename, &stat, flag);",
        "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
        "\tksu_handle_stat("
        "&dfd, &filename, &flag);\n"
        "#endif",
        "ksu_handle_stat",
        "newfstatat"
    )

    # --------------------------------------------------------
    # newfstat
    # --------------------------------------------------------

    signature_newfstat = (
        r"SYSCALL_DEFINE2\s*\(\s*newfstat\s*,"
        r"\s*unsigned\s+int\s*,\s*fd\s*,"
        r"\s*struct\s+stat\s+__user\s*\*,"
        r"\s*statbuf\s*\)"
    )

    text = patch_function_adaptive(
        text,
        signature_newfstat,
        "return error;",
        "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
        "\tksu_handle_newfstat_ret("
        "&fd, &statbuf);\n"
        "#endif",
        "ksu_handle_newfstat_ret",
        "newfstat"
    )

    # --------------------------------------------------------
    # fstat64
    # --------------------------------------------------------

    signature_fstat64 = (
        r"SYSCALL_DEFINE2\s*\(\s*fstat64\s*,"
        r"\s*unsigned\s+long\s*,\s*fd\s*,"
        r"\s*struct\s+stat64\s+__user\s*\*,"
        r"\s*statbuf\s*\)"
    )

    if re.search(
        signature_fstat64,
        text,
        re.MULTILINE | re.DOTALL
    ):

        text = patch_function_adaptive(
            text,
            signature_fstat64,
            "return error;",
            "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
            "\tksu_handle_fstat64_ret("
            "&fd, &statbuf);\n"
            "#endif",
            "ksu_handle_fstat64_ret",
            "fstat64"
        )

    # --------------------------------------------------------
    # fstatat64
    # --------------------------------------------------------

    signature_fstatat64 = (
        r"SYSCALL_DEFINE4\s*\(\s*fstatat64\s*,"
        r"\s*int\s*,\s*dfd\s*,"
        r"\s*const\s+char\s+__user\s*\*,"
        r"\s*filename\s*,"
    )

    if re.search(
        signature_fstatat64,
        text,
        re.MULTILINE | re.DOTALL
    ):

        text = patch_function_adaptive(
            text,
            signature_fstatat64,
            "error = vfs_fstatat(dfd, filename, &stat, flag);",
            "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
            "\tksu_handle_stat("
            "&dfd, &filename, &flag);\n"
            "#endif",
            "ksu_handle_stat",
            "fstatat64"
        )

    return text


# ============================================================
# FS/READ_WRITE.C
# ============================================================

def patch_read_write(text):

    """
    Remove legacy KernelSU vfs_read hook.

    BakaSU Manual Hook checker rejects:
        ksu_vfs_read_hook
        ksu_handle_vfs_read

    The patcher removes the declaration and guarded call.
    """

    declaration_patterns = [

        r"^[ \t]*extern[ \t]+"
        r"bool[ \t]+ksu_vfs_read_hook"
        r"[ \t]*__read_mostly[ \t]*;",

        r"^[ \t]*extern[ \t]+"
        r"int[ \t]+ksu_handle_vfs_read"
        r"[ \t]*\([^;]*?\)[ \t]*;",
    ]

    call_pattern = (
        r"^[ \t]*if[ \t]*"
        r"\([ \t]*unlikely[ \t]*"
        r"\([ \t]*ksu_vfs_read_hook"
        r"[ \t]*\)[ \t]*\)[ \t]*\n"
        r"[ \t]*ksu_handle_vfs_read"
        r"[ \t]*\([^;]*?\)[ \t]*;"
    )

    changed = False

    for pattern in declaration_patterns:

        text, count = re.subn(
            pattern,
            "",
            text,
            flags=re.MULTILINE | re.DOTALL
        )

        if count:

            changed = True

            log(
                "PATCH",
                "Removed legacy vfs_read declaration"
            )

    text, count = re.subn(
        call_pattern,
        "",
        text,
        flags=re.MULTILINE | re.DOTALL
    )

    if count:

        changed = True

        log(
            "PATCH",
            "Removed legacy vfs_read hook call"
        )

    # --------------------------------------------------------
    # Validation
    # --------------------------------------------------------

    remaining = (
        "ksu_vfs_read_hook",
        "ksu_handle_vfs_read"
    )

    for symbol in remaining:

        if symbol in text:

            abort(
                f"Legacy hook remains in "
                f"fs/read_write.c: {symbol}"
            )

    if not changed:

        log(
            "SKIP",
            "fs/read_write.c: legacy hook absent"
        )

    return text


# ============================================================
# SELINUX SYMBOL EXPORT
# ============================================================

SELINUX_PATCHES = {

    "security/selinux/selinuxfs.c": [

        (
            "write_op",
            r"\bstatic\s+(?=ssize_t\s*\(\s*\*\s*write_op\s*\[\s*\]\s*\))",
            True
        ),

        (
            "sel_handle_status_ops",
            r"\bstatic\s+(?=const\s+struct\s+file_operations\s+sel_handle_status_ops\s*=)",
            True
        ),

        (
            "sel_mutex",
            r"\bstatic\s+(?=DEFINE_MUTEX\s*\(\s*sel_mutex\s*\))",
            False
        ),
    ],

    "security/selinux/ss/status.c": [

        (
            "selinux_status_page",
            r"\bstatic\s+(?=struct\s+page\s*\*\s*selinux_status_page\s*;)",
            False
        ),

        (
            "selinux_status_lock",
            r"\bstatic\s+(?=DEFINE_MUTEX\s*\(\s*selinux_status_lock\s*\))",
            False
        ),
    ],

    "security/selinux/ss/services.c": [

        (
            "security_dump_masked_av",
            r"\bstatic\s+(?=void\s+security_dump_masked_av\s*\()",
            True
        ),

        (
            "context_struct_compute_av",
            r"\bstatic\s+(?=void\s+context_struct_compute_av\s*\()",
            True
        ),

        (
            "latest_granting",
            r"\bstatic\s+(?=u32\s+latest_granting\s*;)",
            False
        ),

        (
            "policy_rwlock",
            r"\bstatic\s+(?=DEFINE_RWLOCK\s*\(\s*policy_rwlock\s*\))",
            False
        ),
    ],

    "security/selinux/hooks.c": [

        (
            "inode_doinit_with_dentry",
            r"\bstatic\s+(?=int\s+inode_doinit_with_dentry\s*\()",
            True
        ),

        (
            "selinux_inode_setxattr",
            r"\bstatic\s+(?=int\s+selinux_inode_setxattr\s*\()",
            True
        ),
    ],
}


def patch_selinux(text, relative_path):

    patches = SELINUX_PATCHES.get(
        relative_path,
        []
    )

    for symbol, pattern, required in patches:

        matches = list(
            re.finditer(
                pattern,
                text,
                re.MULTILINE
            )
        )

        if matches:

            text, count = re.subn(
                pattern,
                "",
                text,
                flags=re.MULTILINE
            )

            log(
                "PATCH",
                f"SELinux: {symbol}, "
                f"{count} occurrence(s)"
            )

            continue

        if re.search(
            r"\b" + re.escape(symbol) + r"\b",
            text
        ):

            log(
                "SKIP",
                f"SELinux symbol already exported: "
                f"{symbol}"
            )

            continue

        if required:

            abort(
                f"Required SELinux symbol not found: "
                f"{symbol}"
            )

        log(
            "SKIP",
            f"Optional SELinux symbol absent: "
            f"{symbol}"
        )

    return text


# ============================================================
# PATCH DISPATCHER
# ============================================================

PATCH_FUNCTIONS = {

    "fs/exec.c": patch_exec,

    "fs/open.c": patch_open,

    "kernel/reboot.c": patch_reboot,

    "fs/stat.c": patch_stat,

    "fs/read_write.c": patch_read_write,
}


def apply_patch(
    text,
    relative_path
):

    if relative_path in PATCH_FUNCTIONS:

        text = PATCH_FUNCTIONS[
            relative_path
        ](text)

    if relative_path in SELINUX_PATCHES:

        text = patch_selinux(
            text,
            relative_path
        )

    return text


# ============================================================
# VALIDATION
# ============================================================

def validate_patch(
    original,
    patched,
    relative_path
):

    if original == patched:

        return True

    # --------------------------------------------------------
    # Detect malformed patch
    # --------------------------------------------------------

    if patched.count("{") != patched.count("}"):

        abort(
            f"Brace count mismatch after patch: "
            f"{relative_path}"
        )

    # --------------------------------------------------------
    # Legacy read hook validation
    # --------------------------------------------------------

    if relative_path == "fs/read_write.c":

        forbidden = (
            "ksu_vfs_read_hook",
            "ksu_handle_vfs_read"
        )

        for symbol in forbidden:

            if symbol in patched:

                abort(
                    f"Legacy hook validation failed: "
                    f"{symbol}"
                )

    return True


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

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show changes without writing files"
    )

    parser.add_argument(
        "--threshold",
        type=float,
        default=DEFAULT_THRESHOLD,
        help="Minimum anchor similarity"
    )

    args = parser.parse_args()

    root = Path(
        args.kernel
    ).expanduser().resolve()

    targets = [

        "fs/exec.c",

        "fs/open.c",

        "kernel/reboot.c",

        "fs/stat.c",

        "fs/read_write.c",

        "security/selinux/selinuxfs.c",

        "security/selinux/ss/status.c",

        "security/selinux/ss/services.c",

        "security/selinux/hooks.c",
    ]

    originals = {}

    patched = {}

    # ========================================================
    # READ
    # ========================================================

    log(
        "INFO",
        f"Kernel source: {root}"
    )

    for name in targets:

        path = root / name

        if not path.is_file():

            if name == (
                "security/selinux/ss/status.c"
            ):

                log(
                    "SKIP",
                    f"Optional file missing: {name}"
                )

                continue

            abort(
                f"Missing target file: {name}"
            )

        originals[name] = path.read_text(
            encoding="utf-8"
        )

    # ========================================================
    # PREPARE
    # ========================================================

    log(
        "INFO",
        "Preparing patches"
    )

    for name, original in originals.items():

        result = apply_patch(
            original,
            name
        )

        validate_patch(
            original,
            result,
            name
        )

        patched[name] = result

    changed = [

        name

        for name in originals

        if originals[name] != patched[name]

    ]

    # ========================================================
    # DRY RUN
    # ========================================================

    if args.dry_run:

        log(
            "INFO",
            "Dry-run mode"
        )

        for name in changed:

            diff = difflib.unified_diff(

                originals[name].splitlines(),

                patched[name].splitlines(),

                fromfile=name,

                tofile=name + ".patched",

                lineterm=""
            )

            print(
                "\n".join(diff)
            )

        log(
            "DONE",
            f"Dry-run completed. "
            f"{len(changed)} file(s) would change."
        )

        return

    # ========================================================
    # NOTHING TO CHANGE
    # ========================================================

    if not changed:

        log(
            "DONE",
            "Everything already patched or "
            "no safe matches found."
        )

        return

    # ========================================================
    # BACKUP
    # ========================================================

    timestamp = datetime.now().strftime(
        "%Y%m%d-%H%M%S"
    )

    backups = {}

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

        log(
            "BACKUP",
            str(backup)
        )

    # ========================================================
    # WRITE
    # ========================================================

    written = []

    try:

        for name in changed:

            path = root / name

            path.write_text(
                patched[name],
                encoding="utf-8"
            )

            written.append(name)

            log(
                "OK",
                f"Patched {name}"
            )

    except Exception:

        log(
            "ROLLBACK",
            "Restoring original files"
        )

        for name in written:

            shutil.copy2(
                backups[name],
                root / name
            )

        raise

    # ========================================================
    # SUMMARY
    # ========================================================

    print()

    print("=" * 60)

    print(
        "PATCH COMPLETED"
    )

    print(
        "=" * 60
    )

    print()

    print(
        "Modified files:"
    )

    for name in changed:

        print(
            f"  - {name}"
        )

    print()

    print(
        "Next:"
    )

    print(
        "  git diff --check"
    )

    print(
        "  git diff"
    )

    print(
        "  Review all changes before compiling"
    )

    print()

    print(
        "CONFIG_KALLSYMS_ALL was not modified."
    )


if __name__ == "__main__":

    try:

        main()

    except (
        RuntimeError,
        OSError,
        ValueError
    ) as exc:

        print(
            f"\n[ERROR] {exc}",
            file=sys.stderr
        )

        sys.exit(1)
