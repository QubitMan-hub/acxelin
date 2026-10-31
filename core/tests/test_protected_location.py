"""Code that runs with administrator rights must sit where an ordinary user cannot change it."""
import ntpath
import os

import pytest
from acxelin_core import files

posix = pytest.mark.skipif(os.name == "nt", reason="owner and mode bits are POSIX; Windows is checked by folder below")
ME = (os.getuid(),) if hasattr(os, "getuid") else ()


def made(tmp_path, mode=0o755, name="app", file_mode=0o644):
    folder = tmp_path / name
    folder.mkdir()
    folder.chmod(mode)
    target = folder / "run.py"
    target.write_text("print()\n")
    target.chmod(file_mode)
    return target


@posix
def test_a_file_and_its_folders_that_only_a_trusted_owner_can_write_are_protected(tmp_path):
    assert files.protected_location([made(tmp_path)], trusted_uids=ME, below=tmp_path) is None


@posix
@pytest.mark.parametrize("mode", [0o777, 0o757, 0o775, 0o722])
def test_a_folder_that_others_or_a_group_can_write_is_not_protected(tmp_path, mode):
    target = made(tmp_path, mode)
    why = files.protected_location([target], trusted_uids=ME, below=tmp_path)
    assert why and str(target.parent) in why and "can write" in why


@posix
def test_a_file_that_others_can_write_is_not_protected_even_in_a_protected_folder(tmp_path):
    target = made(tmp_path, file_mode=0o666)
    assert "can write" in files.protected_location([target], trusted_uids=ME, below=tmp_path)


@posix
def test_a_file_owned_by_someone_else_is_not_protected(tmp_path):
    target = made(tmp_path)
    why = files.protected_location([target], trusted_uids=(os.getuid() + 1,), below=tmp_path)
    assert why and "owned by" in why


@posix
def test_a_link_is_judged_by_where_it_leads(tmp_path):
    unsafe = made(tmp_path, 0o777, name="writable")
    safe = tmp_path / "safe"
    safe.mkdir()
    safe.chmod(0o755)
    (safe / "run.py").symlink_to(unsafe)
    assert files.protected_location([safe / "run.py"], trusted_uids=ME, below=tmp_path)


@posix
def test_every_path_is_checked_and_the_first_problem_is_named(tmp_path):
    good, bad = made(tmp_path, name="good"), made(tmp_path, 0o777, name="bad")
    why = files.protected_location([good, bad], trusted_uids=ME, below=tmp_path)
    assert str(bad.parent) in why and str(good.parent) not in why


@posix
def test_a_folder_that_is_gone_is_a_problem_not_a_pass(tmp_path):
    assert "not found" in files.protected_location([tmp_path / "missing" / "run.py"], trusted_uids=ME, below=tmp_path)


def test_on_windows_only_the_program_and_windows_folders_are_protected():
    roots = [r"C:\Program Files", r"C:\Program Files (x86)", r"C:\Windows"]
    ok = lambda p: files.windows_protected(p, roots, ntpath)
    assert ok(r"C:\Program Files\Acxelin VPN\acxelin-vpn.exe")
    assert ok(r"c:\program files (x86)\Acxelin VPN\acxelin-vpn.exe")
    assert not ok(r"C:\Users\ada\AppData\Local\Programs\Python\python.exe")
    assert not ok(r"C:\ProgramData\Acxelin\vpn\connect.cmd")
    assert not ok(r"C:\Program Files\..\Users\ada\run.py")
    assert not ok(r"C:\Program Files Evil\run.py")
