import os
import shutil
import subprocess
import sys
import tempfile

RULES_OF_ENGAGEMENT = (
    "sim_benign_exec_chain: the control case. Runs as the user that started it and "
    "refuses root. Starts /bin/sh, which runs ls, date and cat, writes one small file "
    "into a fresh folder under /tmp, reads it back, and the folder is deleted. No "
    "network and no privilege change. It should raise no rule alert."
)

SHELL_SCRIPT = 'ls / > /dev/null; date > "$1/note.txt"; cat "$1/note.txt" > /dev/null'


def main():
    print(RULES_OF_ENGAGEMENT, flush=True)
    if os.geteuid() == 0:
        print("refusing to run as root")
        return 1

    work = tempfile.mkdtemp(prefix="hids_sim_")
    try:
        subprocess.run(["/bin/sh", "-c", SHELL_SCRIPT, "sh", work], timeout=10, check=False)
    finally:
        shutil.rmtree(work, ignore_errors=True)

    print("sim_benign_exec_chain finished")
    return 0


if __name__ == "__main__":
    sys.exit(main())
