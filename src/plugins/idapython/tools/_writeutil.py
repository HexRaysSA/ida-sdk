"""Write-if-different helpers - keep dst mtimes stable when content matches
so ninja can short-circuit downstream consumers."""
import os
import shutil
from pathlib import Path


def write_if_different(path, content):
    p = Path(path)
    new = content.encode("utf-8") if isinstance(content, str) else content
    if p.exists() and p.read_bytes() == new:
        return
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = Path(str(p) + ".tmp")
    try:
        tmp.write_bytes(new)
        os.replace(str(tmp), str(p))
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def move_if_different(tmp, dst):
    # tmp may live on a different filesystem than dst (callers use
    # tempfile.NamedTemporaryFile which defaults to /tmp), so use
    # shutil.move which falls back to copy+delete across mounts.
    tp, dp = Path(tmp), Path(dst)
    try:
        if dp.exists() and dp.read_bytes() == tp.read_bytes():
            tp.unlink()
            return
        dp.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(tp), str(dp))
    except BaseException:
        tp.unlink(missing_ok=True)
        raise
