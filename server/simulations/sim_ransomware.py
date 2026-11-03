import os
import shutil
import sys
import tempfile

FILE_COUNT = 30

RULES_OF_ENGAGEMENT = (
    "sim_ransomware: runs as the user that started it and refuses root. Makes a fresh "
    "folder under /tmp, writes 30 small text files into it, renames each one to "
    ".locked, then deletes the files and the folder. It only touches files it created "
    "itself and nothing is encrypted."
)


def main():
    print(RULES_OF_ENGAGEMENT, flush=True)
    if os.geteuid() == 0:
        print("refusing to run as root")
        return 1

    work = tempfile.mkdtemp(prefix="hids_sim_")
    try:
        paths = []
        for number in range(FILE_COUNT):
            path = os.path.join(work, f"doc_{number:02d}.txt")
            with open(path, "w") as handle:
                handle.write("hids lab file\n")
            paths.append(path)

        for path in paths:
            os.rename(path, path + ".locked")
        print(f"renamed {len(paths)} files in {work}")
    finally:
        shutil.rmtree(work, ignore_errors=True)

    print("sim_ransomware finished")
    return 0


if __name__ == "__main__":
    sys.exit(main())
