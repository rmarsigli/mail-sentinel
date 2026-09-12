"""Read only what was appended since the last cycle.

logrotate recreates the file (new inode) and may compress the old one; we do
not chase the old file. Losing at most one cycle of lines at rotation is the
documented trade-off for never reading a log twice.
"""
import os
from typing import List, Tuple


def read_new(path: str, record: dict) -> Tuple[List[str], bool]:
    st = os.stat(path)
    inode = st.st_ino
    offset = int(record.get("offset", 0))
    rotated = False
    if record.get("inode") != inode or st.st_size < offset:
        offset = 0
        rotated = "inode" in record  # a first-ever read is not a rotation
    with open(path, "rb") as fh:
        fh.seek(offset)
        data = fh.read()
    # Keep an unterminated last line for the next cycle; the writer is mid-line.
    cut = data.rfind(b"\n")
    if cut == -1:
        record.update(inode=inode, offset=offset)
        return [], rotated
    complete = data[: cut + 1]
    lines = complete.decode("utf-8", errors="replace").split("\n")[:-1]
    record.update(inode=inode, offset=offset + len(complete))
    return lines, rotated
