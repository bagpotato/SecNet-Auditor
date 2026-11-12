import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules import log_viewer as lv  # noqa: E402


def cfg_for(path, **extra):
    src = {"auth": {"type": "file", "path": str(path)}}
    src.update(extra)
    return {"logs": {"sources": src, "default_limit": 200}}


def write_lines(path, n):
    with open(path, "w", encoding="utf-8") as fh:
        for i in range(n):
            fh.write("Nov 12 10:01:%02d srv app[1]: line number %d\n" % (i % 60, i))


def test_parse_syslog_line():
    e = lv.parse_line("Nov 12 10:01:02 srv sshd[12]: Failed password for root from 10.0.0.5 port 22", 2026)
    assert e["process"] == "sshd"
    assert e["level"] == "WARN"
    assert e["ip"] == "10.0.0.5"
    assert e["host"] == "srv"
    assert e["time"] == "2026-11-12 10:01:02"


def test_parse_iso_line():
    e = lv.parse_line("2026-11-12T10:01:02+0100 srv sshd[12]: Accepted publickey for bob from 192.168.1.9")
    assert e["time"].startswith("2026-11-12 10:01:02")
    assert e["process"] == "sshd"
    assert e["ip"] == "192.168.1.9"
    assert e["level"] == "INFO"


def test_parse_ipv6():
    e = lv.parse_line("Nov 12 10:01:02 srv sshd[1]: Failed password from 2001:db8::1 port 22", 2026)
    assert e["ip"] == "2001:db8::1"
    e = lv.parse_line("Nov 12 10:01:02 srv sshd[1]: Failed password from ::ffff:10.1.2.3 port 22", 2026)
    assert e["ip"] == "::ffff:10.1.2.3"
    e = lv.parse_line("Nov 12 10:01:02 srv x[1]: nothing here at 10:01:02", 2026)
    assert e["ip"] is None


def test_level_inference():
    assert lv.parse_line("Nov 12 10:01:02 h p[1]: Accepted password for a")["level"] == "INFO"
    assert lv.parse_line("Nov 12 10:01:02 h p[1]: some error happened")["level"] == "ERROR"


def test_tail_lines_pagination(tmp_path):
    p = tmp_path / "big.log"
    write_lines(p, 5000)
    first, cur = lv.tail_lines(str(p), 200)
    assert len(first) == 200
    assert first[0].endswith("line number 4999")
    assert cur > 0
    second, cur2 = lv.tail_lines(str(p), 200, before=cur)
    assert second[0].endswith("line number 4799")
    assert not set(first) & set(second)
    # walk to the start of file
    total = len(first) + len(second)
    while cur2:
        more, cur2 = lv.tail_lines(str(p), 200, before=cur2)
        total += len(more)
    assert total == 5000


def test_tail_non_utf8_and_long_line(tmp_path):
    p = tmp_path / "bad.log"
    with open(p, "wb") as fh:
        fh.write(b"Nov 12 10:01:02 srv a[1]: bad \xff\xfe bytes\n")
        fh.write(b"Nov 12 10:01:03 srv a[1]: " + b"x" * 100000 + b"\n")
        fh.write(b"Nov 12 10:01:04 srv a[1]: end\n")
    lines, cur = lv.tail_lines(str(p), 10)
    assert len(lines) == 3
    assert "�" in lines[2]
    assert len(lines[1]) > 100000
    assert cur == 0


def test_tail_empty_file(tmp_path):
    p = tmp_path / "empty.log"
    p.write_text("")
    assert lv.tail_lines(str(p), 10) == ([], 0)
    assert lv.tail_lines(str(tmp_path / "missing.log"), 10) == ([], 0)
    r = lv.query_logs(cfg_for(p), "auth")
    assert r["entries"] == [] and r["message"]
    r = lv.query_logs(cfg_for(tmp_path / "missing.log"), "auth")
    assert r["entries"] == [] and r["message"]


def test_rotated_log_between_loads(tmp_path):
    p = tmp_path / "rot.log"
    write_lines(p, 300)
    r = lv.query_logs(cfg_for(p), "auth", limit=100)
    cur = r["cursor"]
    assert cur
    write_lines(p, 3)  # rotation: file is now tiny
    r2 = lv.query_logs(cfg_for(p), "auth", limit=100, before=cur)
    assert isinstance(r2["entries"], list) and r2["message"]


def test_query_unknown_source_rejected(tmp_path):
    p = tmp_path / "a.log"
    write_lines(p, 3)
    r = lv.query_logs(cfg_for(p), "../../etc/passwd")
    assert r["status"] == "ERROR"
    assert r["entries"] == []


def test_query_filters(tmp_path):
    p = tmp_path / "f.log"
    p.write_text(
        "Nov 12 10:01:01 srv sshd[1]: Failed password for root from 10.0.0.5 port 22\n"
        "Nov 12 10:01:02 srv sshd[1]: Failed password for bob from 10.0.0.6 port 22\n"
        "Nov 12 10:01:03 srv sshd[1]: Accepted password for root from 10.0.0.5 port 22\n"
        "Nov 12 10:01:04 srv sshd[1]: fatal error from 10.0.0.5\n", encoding="utf-8")
    c = cfg_for(p)
    assert len(lv.query_logs(c, "auth")["entries"]) == 4
    r = lv.query_logs(c, "auth", q="ROOT", level="WARN", ip="10.0.0.5")
    assert len(r["entries"]) == 1
    assert "Failed" in r["entries"][0]["message"]
    r = lv.query_logs(c, "auth", ip="10.0.0.5")
    assert len(r["entries"]) == 3
    assert r["entries"][0]["message"].startswith("fatal")  # newest first
    assert lv.query_logs(c, "auth", q="bob", level="INFO")["entries"] == []


def test_filtered_query_paginates(tmp_path):
    p = tmp_path / "pg.log"
    with open(p, "w", encoding="utf-8") as fh:
        for i in range(3000):
            fh.write("Nov 12 10:01:02 srv a[1]: %s %d\n" % ("needle" if i % 3 == 0 else "hay", i))
    c = cfg_for(p)
    r1 = lv.query_logs(c, "auth", q="needle", limit=100)
    r2 = lv.query_logs(c, "auth", q="needle", limit=100, before=r1["cursor"])
    m1 = {e["message"] for e in r1["entries"]}
    m2 = {e["message"] for e in r2["entries"]}
    assert len(r1["entries"]) == 100 and len(r2["entries"]) == 100
    assert not m1 & m2
    assert r1["entries"][0]["message"].endswith("2997")
    assert r2["entries"][0]["message"].endswith("2697")


def test_limit_clamped_to_1000(tmp_path):
    p = tmp_path / "l.log"
    write_lines(p, 1500)
    r = lv.query_logs(cfg_for(p), "auth", limit=99999)
    assert len(r["entries"]) == 1000
    r = lv.query_logs(cfg_for(p), "auth", limit=-5)
    assert len(r["entries"]) == 1


def test_journal_source_uses_runner():
    calls = []

    def fake(cmd, timeout=8):
        calls.append(cmd)
        return True, ("2026-11-12T10:00:01+0000 srv sshd[1]: Accepted key for a from 1.2.3.4\n"
                      "2026-11-12T10:00:02+0000 srv sshd[1]: Failed password for b from 1.2.3.5")
    cfg = {"logs": {"sources": {"ssh": {"type": "journal", "unit": "ssh"}}}}
    r = lv.query_logs(cfg, "ssh", limit=10, runner=fake)
    assert calls[0][:4] == ["journalctl", "-u", "ssh", "-n"]
    assert [e["ip"] for e in r["entries"]] == ["1.2.3.5", "1.2.3.4"]
    bad = lambda cmd, timeout=8: (False, "Command not found: journalctl")  # noqa: E731
    assert lv.query_logs(cfg, "ssh", runner=bad)["status"] == "ERROR"


def test_fixes_log_entries_parsed(tmp_path):
    import json as _json
    from modules import log_viewer as lv
    lines = [
        {"time": "2026-11-12T10:01:02.5", "action": "apply", "fix_id": "perms.fix_file",
         "title": "Restrict file permissions", "result": "applied", "message": "Applied"},
        {"time": "2026-11-12T10:02:00", "action": "apply", "fix_id": "ssh.x",
         "title": "T", "result": "reverted", "message": "Reverted"},
        {"time": "2026-11-12T10:03:00", "action": "apply", "fix_id": "ufw.block_ip",
         "title": "Block", "result": "error", "message": "bad", "params": {"ip": "2001:db8::1"}},
    ]
    p = tmp_path / "fixes.log"
    p.write_text("\n".join(_json.dumps(x) for x in lines) + "\n")
    e = lv.parse_line(_json.dumps(lines[0]))
    assert e["time"] == "2026-11-12 10:01:02" and e["process"] == "perms.fix_file"
    assert e["level"] == "INFO" and "Restrict file permissions" in e["message"]
    assert lv.parse_line(_json.dumps(lines[1]))["level"] == "WARN"
    cfg = {"logs": {"sources": {"fixes": {"type": "file", "path": str(p)}}}}
    res = lv.query_logs(cfg, "fixes")
    assert [x["level"] for x in res["entries"]] == ["ERROR", "WARN", "INFO"]
    assert res["entries"][0]["ip"] == "2001:db8::1"
    assert lv.query_logs(cfg, "fixes", level="WARN")["entries"][0]["process"] == "ssh.x"


def test_relative_source_path_resolves_to_repo_dir(tmp_path):
    from modules import log_viewer as lv
    cfg = {"logs": {"sources": {"fixes": {"type": "file", "path": "fixes.log"}}}}
    res = lv.query_logs(cfg, "fixes")
    assert lv.REPO_DIR in res["message"] or res["status"] in ("OK", "INFO", "WARN")
