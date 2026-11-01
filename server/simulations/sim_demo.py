import os
import tempfile
import time

path = os.path.join(tempfile.gettempdir(), "sim_demo_ran.txt")

with open(path, "a") as f:
    f.write("sim_demo ran at " + str(time.time()) + "\n")

print("sim_demo finished")
