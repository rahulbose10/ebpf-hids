import os
import sys

TARGET = "/etc/shadow"

RULES_OF_ENGAGEMENT = (
    "sim_credaccess: runs as the user that started it and refuses root. Tries to open "
    "/etc/shadow read-only. A normal user is refused by the kernel, and if the open "
    "ever succeeded the file is closed without reading a single byte."
)


def main():
    print(RULES_OF_ENGAGEMENT, flush=True)
    if os.geteuid() == 0:
        print("refusing to run as root")
        return 1

    try:
        fd = os.open(TARGET, os.O_RDONLY)
    except OSError as error:
        print("open of /etc/shadow refused as expected:", error)
    else:
        os.close(fd)
        print("open of /etc/shadow succeeded, closed without reading")

    print("sim_credaccess finished")
    return 0


if __name__ == "__main__":
    sys.exit(main())
