import json
import os
import stat
from datetime import datetime, timedelta

import pytest

from modules import fix_history as fh

POSIX = os.name != "nt"


def _write(path, text, mode=None):
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    if mode is not None:
        os.chmod(path, mode)


def _record(tmp_path, paths, fix_id="perms.fix_file", now=None):
    root = str(tmp_path / "backups")
    bdir = fh.backup_files(paths, root, fix_id, now=now)
    meta = fh.read_backup_meta(bdir)
    return fh.create_record(fix_id, {"file": "x"}, bdir, meta)


def test_backup_and_restore_roundtrip(tmp_path):
    f = tmp_path / "a.conf"
    _write(str(f), "original")
    rec = _record(tmp_path, [str(f)])
    assert os.path.isfile(os.path.join(rec["backup_dir"], "record.json"))
    _write(str(f), "changed")
    fh.restore_files(rec)
    assert f.read_text(encoding="utf-8") == "original"


def test_backup_dir_mode_700(tmp_path):
    f = tmp_path / "a.conf"
    _write(str(f), "x")
    bdir = fh.backup_files([str(f)], str(tmp_path / "backups"), "ntp.enable")
    assert os.path.isdir(bdir)
    if POSIX:
        assert stat.S_IMODE(os.stat(bdir).st_mode) == 0o700


def test_restore_removes_created_file(tmp_path):
    f = tmp_path / "new.conf"
    rec = _record(tmp_path, [str(f)])  # does not exist yet
    assert rec["created"] == [str(f)]
    _write(str(f), "made by fix")
    fh.restore_files(rec)
    assert not f.exists()
    fh.restore_files(rec)  # idempotent when already gone


def test_restore_preserves_mode(tmp_path):
    f = tmp_path / "secret"
    _write(str(f), "s", mode=0o600)
    rec = _record(tmp_path, [str(f)])
    os.chmod(str(f), 0o644)
    _write(str(f), "changed")
    fh.restore_files(rec)
    assert f.read_text(encoding="utf-8") == "s"
    if POSIX:
        assert stat.S_IMODE(os.stat(str(f)).st_mode) == 0o600
    assert rec["files"][0]["mode"] == stat.S_IMODE(os.stat(str(f)).st_mode) or not POSIX


def test_list_records_limited_and_ordered(tmp_path):
    f = tmp_path / "a.conf"
    _write(str(f), "x")
    root = str(tmp_path / "backups")
    base = datetime(2026, 11, 12, 10, 0, 0)
    for i in range(25):
        bdir = fh.backup_files([str(f)], root, "perms.fix_file",
                               now=base + timedelta(minutes=i))
        fh.create_record("perms.fix_file", {"i": i}, bdir,
                         fh.read_backup_meta(bdir))
    recs = fh.list_records(root)
    assert len(recs) == 20
    assert [r["params"]["i"] for r in recs] == list(range(24, 4, -1))
    assert len(fh.list_records(root, limit=3)) == 3
    assert fh.list_records(str(tmp_path / "missing")) == []


def test_same_second_backups_do_not_collide(tmp_path):
    f = tmp_path / "a.conf"
    _write(str(f), "x")
    root = str(tmp_path / "backups")
    now = datetime(2026, 11, 12, 10, 0, 0)
    d1 = fh.backup_files([str(f)], root, "ntp.enable", now=now)
    d2 = fh.backup_files([str(f)], root, "ntp.enable", now=now)
    assert d1 != d2


def test_create_record_extra_merged(tmp_path):
    f = tmp_path / "a.conf"
    _write(str(f), "x")
    bdir = fh.backup_files([str(f)], str(tmp_path / "b"), "ntp.enable")
    rec = fh.create_record("ntp.enable", {}, bdir, [], extra={"ntp_before": "no"})
    assert rec["ntp_before"] == "no"
    with open(os.path.join(bdir, "record.json"), encoding="utf-8") as fp:
        assert json.load(fp)["ntp_before"] == "no"


def test_append_log_one_json_line_each(tmp_path):
    log = str(tmp_path / "fixes.log")
    fh.append_log(log, {"fix_id": "a", "result": "applied"})
    fh.append_log(log, {"fix_id": "b", "result": "reverted"})
    with open(log, encoding="utf-8") as fp:
        lines = fp.read().splitlines()
    assert len(lines) == 2
    first, second = json.loads(lines[0]), json.loads(lines[1])
    assert first["fix_id"] == "a" and "time" in first
    assert second["result"] == "reverted"
    datetime.fromisoformat(first["time"])
