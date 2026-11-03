import ctypes
import os
import subprocess
import sys

PTRACE_ATTACH = 16
PTRACE_DETACH = 17

RULES_OF_ENGAGEMENT = (
    "sim_privilege_escalation: runs as the user that started it and refuses root. "
    "Starts its own child (sleep 5), attaches to it with ptrace, detaches and kills it. "
    "Then asks for uid 0 with setuid(0), which the kernel refuses for a normal user. "
    "Then replaces itself with /bin/sh -c true. No other process is traced, no file "
    "is written and no privilege is gained."
)


def trace_own_child():
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    libc.ptrace.restype = ctypes.c_long
    libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p]

    child = subprocess.Popen(["sleep", "5"])
    try:
        if libc.ptrace(PTRACE_ATTACH, child.pid, None, None) == 0:
            os.waitpid(child.pid, 0)
            libc.ptrace(PTRACE_DETACH, child.pid, None, None)
            print("attached to own child", child.pid, "and detached")
        else:
            print("ptrace attach refused:", os.strerror(ctypes.get_errno()))
    finally:
        child.kill()
        child.wait(timeout=5)


def ask_for_root():
    try:
        os.setuid(0)
    except PermissionError as error:
        print("setuid(0) refused as expected:", error)
    return os.getuid() != 0 and os.geteuid() != 0


def main():
    print(RULES_OF_ENGAGEMENT, flush=True)
    if os.geteuid() == 0:
        print("refusing to run as root")
        return 1

    trace_own_child()
    if not ask_for_root():
        print("setuid(0) was not refused, stopping before the shell")
        return 1

    print("replacing this process with /bin/sh -c true", flush=True)
    os.execv("/bin/sh", ["sh", "-c", "true"])


if __name__ == "__main__":
    sys.exit(main())
