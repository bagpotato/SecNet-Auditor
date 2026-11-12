"""Backups, audit log and undo primitives for guided fixes."""
import json
import os
import shutil
import stat
from datetime import datetime

META_NAME = "files.json"
RECORD_NAME = "record.json"


def _safe_id(fix_id):
    return "".join(c if (c.isalnum() or c in "._-") else "_" for c in str(fix_id))


def _unique_dir(backup_root, fix_id, now):
    stamp = now.strftime("%Y%m%dT%H%M%S")
    base = os.path.join(backup_root, "{}-{}".format(stamp, _safe_id(fix_id)))
    path, n = base, 1
    while True:
        try:
            os.makedirs(path, mode=0o700)
            return path
        except FileExistsError:
            n += 1
            path = "{}-{}".format(base, n)


def backup_files(paths, backup_root, fix_id, now=None):
    """Copy every existing file in `paths` into a new backup dir (mode 700).

    Per-file metadata (path, existed, mode, backup name) is stored in
    `files.json`; read it back with read_backup_meta(). Returns the dir path.
    """
    now = now or datetime.now()
    os.makedirs(backup_root, exist_ok=True)
    backup_dir = _unique_dir(backup_root, fix_id, now)
    os.chmod(backup_dir, 0o700)

    meta = []
    for i, p in enumerate(paths):
        entry = {"path": p, "existed": False, "mode": None, "backup": None}
        if os.path.isfile(p):
            name = "{}_{}".format(i, os.path.basename(p))
            shutil.copy2(p, os.path.join(backup_dir, name))
            entry.update(existed=True, backup=name,
                         mode=stat.S_IMODE(os.stat(p).st_mode))
        meta.append(entry)

    with open(os.path.join(backup_dir, META_NAME), "w", encoding="utf-8") as f:
        json.dump(meta, f)
    return backup_dir


def read_backup_meta(backup_dir):
    with open(os.path.join(backup_dir, META_NAME), encoding="utf-8") as f:
        return json.load(f)


def create_record(fix_id, params, backup_dir, files, extra=None):
    """Build the record and write it to <backup_dir>/record.json."""
    files = list(files or [])
    record = {
        "id": os.path.basename(os.path.normpath(backup_dir)),
        "fix_id": fix_id,
        "params": params or {},
        "time": datetime.now().isoformat(),
        "backup_dir": backup_dir,
        "files": files,
        "created": [e["path"] for e in files if not e.get("existed")],
    }
    if extra:
        record.update(extra)
    with open(os.path.join(backup_dir, RECORD_NAME), "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2)
    return record


def save_record(record):
    """Rewrite <backup_dir>/record.json after a status change (e.g. undone)."""
    with open(os.path.join(record["backup_dir"], RECORD_NAME), "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2)


def append_log(log_path, entry):
    """Append one JSON line (with ISO time) to the audit log."""
    line = dict(entry)
    line.setdefault("time", datetime.now().isoformat())
    parent = os.path.dirname(log_path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(line, ensure_ascii=False) + "\n")


def list_records(backup_root, limit=20):
    """Newest-first records found under backup_root."""
    if not os.path.isdir(backup_root):
        return []
    records = []
    for name in os.listdir(backup_root):
        rec_path = os.path.join(backup_root, name, RECORD_NAME)
        try:
            with open(rec_path, encoding="utf-8") as f:
                records.append(json.load(f))
        except (OSError, ValueError):
            continue  # unreadable or in-progress backup: skip
    records.sort(key=lambda r: (r.get("time", ""), r.get("id", "")), reverse=True)
    return records[:limit]


def restore_files(record):
    """Restore contents and modes; delete files that did not exist before."""
    backup_dir = record["backup_dir"]
    for entry in record.get("files", []):
        path = entry["path"]
        if entry.get("existed"):
            src = os.path.join(backup_dir, entry["backup"])
            if os.path.lexists(path):
                try:  # a read-only target (e.g. after a chmod fix) must stay writable here
                    os.chmod(path, 0o600)
                except OSError:
                    pass
            shutil.copy2(src, path)
            if entry.get("mode") is not None:
                os.chmod(path, entry["mode"])
        elif os.path.lexists(path):
            os.remove(path)
