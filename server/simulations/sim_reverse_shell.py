import os
import socket
import subprocess
import sys

RULES_OF_ENGAGEMENT = (
    "sim_reverse_shell: runs as the user that started it and refuses root. "
    "Makes one TCP connect to 127.0.0.1 port 9. Nothing listens there, so the "
    "kernel refuses it and no data moves. Then starts /bin/sh -c true as a child "
    "and waits for it. No files are written and no remote host is contacted."
)

TARGET = ("127.0.0.1", 9)


def main():
    print(RULES_OF_ENGAGEMENT, flush=True)
    if os.geteuid() == 0:
        print("refusing to run as root")
        return 1

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(2)
        try:
            sock.connect(TARGET)
            print("connected to 127.0.0.1:9 and closed at once")
        except OSError as error:
            print("connect to 127.0.0.1:9 failed as expected:", error)

    subprocess.run(["/bin/sh", "-c", "true"], timeout=10, check=False)
    print("sim_reverse_shell finished")
    return 0


if __name__ == "__main__":
    sys.exit(main())
