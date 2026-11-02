import ctypes
import os
import platform
import sys

FINIT_MODULE = {"x86_64": 313, "aarch64": 273}

RULES_OF_ENGAGEMENT = (
    "sim_rootkit: runs as the user that started it and refuses root. Opens /dev/null "
    "and asks the kernel to load it as a module with finit_module. A normal user has no "
    "CAP_SYS_MODULE, so the kernel refuses before it reads anything. No module is loaded."
)


def main():
    print(RULES_OF_ENGAGEMENT, flush=True)
    if os.geteuid() == 0:
        print("refusing to run as root")
        return 1

    number = FINIT_MODULE.get(platform.machine())
    if number is None:
        print("no finit_module number known for", platform.machine())
        return 1

    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    libc.syscall.restype = ctypes.c_long
    fd = os.open("/dev/null", os.O_RDONLY)
    try:
        result = libc.syscall(ctypes.c_long(number), ctypes.c_int(fd), ctypes.c_char_p(b""), ctypes.c_int(0))
        if result == 0:
            print("finit_module returned 0, which should not happen for /dev/null")
        else:
            print("finit_module refused as expected:", os.strerror(ctypes.get_errno()))
    finally:
        os.close(fd)

    print("sim_rootkit finished")
    return 0


if __name__ == "__main__":
    sys.exit(main())
