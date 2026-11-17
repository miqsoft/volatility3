"""SysV shared memory segment 0 has inode number 0 and must not be rejected."""

from types import SimpleNamespace

import pytest

from volatility3.framework.symbols.linux.extensions import linux, vm_area_struct, inode

SHM_SB = 0xFFFF888000001000
OTHER_SB = 0xFFFF888000002000


def make_inode(monkeypatch, i_ino, i_sb, i_count=1, has_shm_mnt=True):
    """Build a fake inode, on a kernel whose shm_mnt mount uses SHM_SB."""
    symbols = {"shm_mnt": SimpleNamespace(mnt_sb=SHM_SB)} if has_shm_mnt else {}
    vmlinux = SimpleNamespace(
        has_symbol=lambda name: name in symbols,
        object_from_symbol=lambda name: symbols[name],
    )
    monkeypatch.setattr(
        linux.LinuxUtilities,
        "get_module_from_volobj_type",
        lambda context, obj: vmlinux,
    )
    fake = SimpleNamespace(
        i_ino=i_ino,
        i_sb=i_sb,
        i_count=SimpleNamespace(counter=i_count),
        _context=None,
    )
    fake._is_sysv_shm_segment = lambda: inode._is_sysv_shm_segment(fake)
    return fake


@pytest.mark.parametrize(
    "i_ino, i_sb, i_count, has_shm_mnt, expected",
    [
        (0, SHM_SB, 1, True, True),  # SysV shm segment 0
        (0, OTHER_SB, 1, True, False),  # inode 0 on any other mount
        (0, SHM_SB, 1, False, False),  # kernel without shm_mnt
        (5, OTHER_SB, 1, True, True),  # ordinary inode
        (0, SHM_SB, -1, True, False),  # smeared reference count
    ],
    ids=["shm-ino-0", "other-mount-ino-0", "no-shm_mnt", "ordinary", "negative-count"],
)
def test_inode_is_valid(monkeypatch, i_ino, i_sb, i_count, has_shm_mnt, expected):
    fake = make_inode(monkeypatch, i_ino, i_sb, i_count, has_shm_mnt)
    assert inode.is_valid(fake) is expected


def make_vma(get_inode, page_offset=0):
    """Build a fake file-backed VMA covering one page."""
    layer = SimpleNamespace(page_size=4096)
    return SimpleNamespace(
        vm_start=0x7F0000000000,
        vm_end=0x7F0000001000,
        vm_file=SimpleNamespace(get_inode=get_inode),
        get_protection=lambda: "rw-",
        get_page_offset=lambda: page_offset,
        _context=SimpleNamespace(layers={"memory": layer}),
        vol=SimpleNamespace(layer_name="memory"),
    )


def test_vma_is_valid_without_inode():
    """get_inode() returns None when no valid inode is found."""
    assert vm_area_struct.is_valid(make_vma(lambda: None)) is True


@pytest.mark.parametrize("page_offset, expected", [(4096, True), (8192, False)])
def test_vma_is_valid_checks_inode_size(page_offset, expected):
    """A page offset beyond the end of the file's inode is rejected."""
    file_inode = SimpleNamespace(i_size=4096)
    vma = make_vma(lambda: file_inode, page_offset)
    assert vm_area_struct.is_valid(vma) is expected
