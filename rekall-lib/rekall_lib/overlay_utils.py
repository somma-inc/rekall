# Rekall Memory Forensics
# Author: Taehong Kim <rlaxoghd91@gmail.com>


def TagOffset(x):
    if x.obj_profile.metadata("arch") == "AMD64":
        return x.obj_offset - 12
    return x.obj_offset - 4
