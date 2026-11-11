"""Actual same-descriptor regular-file and nonblocking FIFO admission for signed inputs. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: test_swapped_regular_file_is_not_silently_substituted — line 33
# parameter: monkeypatch — line 33
# parameter: tmp_path — line 33
# variable: selected — line 35
# variable: alternate — line 37
# variable: actual — line 39
# definition: replace — line 41
# parameter: flags — line 41
# parameter: path — line 41
# definition: test_opened_file_limit_is_enforced_before_allocating — line 51
# parameter: tmp_path — line 51
# variable: selected — line 53
# variable: linked — line 58
# definition: test_actual_no_writer_fifo_swap_refuses_under_a_child_deadline — line 67
# parameter: tmp_path — line 67
# variable: program — line 69
# variable: result — line 89
# END CODE MAP

import os
import subprocess
import sys
from pathlib import Path

import pytest

from drkit import bundle
from drkit.contracts import Rejected


def test_swapped_regular_file_is_not_silently_substituted(tmp_path, monkeypatch):
    """An actual replacement between admission and open must not select a different bundle or trust key."""
    selected = tmp_path / "selected"
    selected.write_bytes(b"original")
    alternate = tmp_path / "alternate"
    alternate.write_bytes(b"replacement")
    actual = os.open

    def replace(path, flags):
        """Interleave only one owned fixture replacement immediately before the real open."""
        alternate.replace(selected)
        return actual(path, flags)

    monkeypatch.setattr(bundle.os, "open", replace)
    with pytest.raises(Rejected, match="changed"):
        bundle.read_file(selected)


def test_opened_file_limit_is_enforced_before_allocating(tmp_path):
    """Exact caps and ordinary hardlinked read-only inputs keep the original CLI compatibility contract."""
    selected = tmp_path / "ordinary"
    selected.write_bytes(b"1234")
    assert bundle.read_file(selected, 4) == b"1234"
    with pytest.raises(Rejected, match="size cap"):
        bundle.read_file(selected, 3)
    linked = tmp_path / "explicit-hardlink"
    os.link(selected, linked)
    assert bundle.read_file(linked, 4) == b"1234"


@pytest.mark.skipif(
    os.name == "nt",
    reason="Actual POSIX no-writer FIFO swap; Windows descriptor identity tests remain active",
)
def test_actual_no_writer_fifo_swap_refuses_under_a_child_deadline(tmp_path):
    """Without O_NONBLOCK this actual filesystem race blocks; a strict child deadline makes that a failing regression."""
    program = r"""
import os,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from drkit import bundle
from drkit.contracts import Rejected
path=Path(sys.argv[2])/'input'
path.write_bytes(b'owned fixture')
actual=os.open
def swap(selected,flags):
    path.unlink()
    os.mkfifo(path)
    return actual(selected,flags)
bundle.os.open=swap
try:
    bundle.read_file(path)
except Rejected:
    raise SystemExit(0)
raise SystemExit(8)
"""
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            program,
            str(Path(__file__).resolve().parents[1]),
            str(tmp_path),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=2,
        check=False,
    )
    assert result.returncode == 0
