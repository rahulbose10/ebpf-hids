import os
import shutil
import socket
import sys
import tempfile
import time

RULES_OF_ENGAGEMENT = (
    "sim_backdoor: runs as the user that started it and refuses root. Opens a listening "
    "TCP socket on 127.0.0.1 on a port the kernel picks, keeps it for one second without "
    "accepting anyone, and closes it. Then copies /bin/true into a fresh folder under "
    "/tmp, sets the setuid bit on the copy and deletes the copy and the folder. The copy "
    "belongs to the user, so the bit gives nothing beyond the user's own rights."
)


def listen_briefly():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        print("listening on 127.0.0.1 port", server.getsockname()[1])
        time.sleep(1)


def setuid_copy():
    work = tempfile.mkdtemp(prefix="hids_sim_")
    try:
        copy = os.path.join(work, "true_copy")
        shutil.copyfile("/bin/true", copy)
        os.chmod(copy, 0o4755)
        print("set mode 4755 on", copy)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main():
    print(RULES_OF_ENGAGEMENT, flush=True)
    if os.geteuid() == 0:
        print("refusing to run as root")
        return 1

    listen_briefly()
    setuid_copy()
    print("sim_backdoor finished")
    return 0


if __name__ == "__main__":
    sys.exit(main())
