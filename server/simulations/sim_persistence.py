import os
import pwd
import sys

MARKER_NAME = "hids_sim_marker.txt"

RULES_OF_ENGAGEMENT = (
    "sim_persistence: runs as the user that started it and refuses root. Writes one "
    "file named hids_sim_marker.txt into ~/.config/autostart and deletes it straight "
    "away. The name does not end in .desktop, so the desktop session never runs it. "
    "Any folder it had to create on the way is removed again."
)


def main():
    print(RULES_OF_ENGAGEMENT, flush=True)
    if os.geteuid() == 0:
        print("refusing to run as root")
        return 1

    home = pwd.getpwuid(os.getuid()).pw_dir
    config = os.path.join(home, ".config")
    folder = os.path.join(config, "autostart")
    created = [path for path in (config, folder) if not os.path.isdir(path)]
    os.makedirs(folder, exist_ok=True)
    marker = os.path.join(folder, MARKER_NAME)
    try:
        with open(marker, "w") as handle:
            handle.write("hids lab marker, safe to delete\n")
        print("wrote", marker)
    finally:
        if os.path.exists(marker):
            os.remove(marker)
        for path in reversed(created):
            try:
                os.rmdir(path)
            except OSError:
                pass

    print("sim_persistence finished")
    return 0


if __name__ == "__main__":
    sys.exit(main())
