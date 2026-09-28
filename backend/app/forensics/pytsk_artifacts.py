from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.core.config import settings

TARGET_BASENAMES = {
    ".bash_history",
    "activity.log",
    "meeting-notes.txt",
    "confidential-clients.txt",
}
TARGET_HINTS = ("orion", "transfer", "history", "activity", "meeting", "confidential", "zip")


def _decode_name(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value or "")


def _iso(value: Any) -> str | None:
    try:
        value = int(value or 0)
        if not value:
            return None
        return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def _read_entry(entry, max_bytes: int) -> bytes:
    meta = getattr(getattr(entry, "info", None), "meta", None)
    if meta is None:
        return b""
    size = int(getattr(meta, "size", 0) or 0)
    if size <= 0 or size > max_bytes:
        return b""
    try:
        return bytes(entry.read_random(0, size))
    except Exception:
        return b""


def _artifact_record(path: str, entry) -> dict[str, Any] | None:
    info = getattr(entry, "info", None)
    if not info:
        return None
    name_info = getattr(info, "name", None)
    meta = getattr(info, "meta", None)
    if not name_info or not meta:
        return None

    return {
        "path": path,
        "inode": int(getattr(meta, "addr", 0) or 0),
        "size": int(getattr(meta, "size", 0) or 0),
        "atime": _iso(getattr(meta, "atime", 0)),
        "mtime": _iso(getattr(meta, "mtime", 0)),
        "ctime": _iso(getattr(meta, "ctime", 0)),
        "dtime": _iso(getattr(meta, "dtime", 0)),
        "allocated": _meta_is_allocated(meta),
        "meta_type": int(getattr(meta, "type", 0) or 0),
    }


def _meta_is_allocated(meta) -> bool:
    try:
        import pytsk3
        unalloc = getattr(pytsk3, "TSK_FS_META_FLAG_UNALLOC", 0)
        return not bool(int(getattr(meta, "flags", 0) or 0) & int(unalloc))
    except Exception:
        return True


def walk_filesystem(fs, start_inode: int = 2, max_entries: int = 20000, max_depth: int = 20):
    """Yield (path, entry) pairs using the same directory/as_directory pattern as pytsk3's tests."""
    import pytsk3

    try:
        root = fs.open_dir(inode=start_inode)
    except Exception as exc:
        return [], f"Unable to open root inode {start_inode}: {exc}"

    rows: list[tuple[str, Any]] = []
    seen_dirs: set[int] = set()
    dir_type = getattr(pytsk3, "TSK_FS_META_TYPE_DIR", None)

    def recurse(directory, prefix: str, depth: int, active_dirs: set[int]):
        if len(rows) >= max_entries or depth > max_depth:
            return

        try:
            iterator = iter(directory)
        except Exception:
            return

        for entry in iterator:
            if len(rows) >= max_entries:
                return

            info = getattr(entry, "info", None)
            if not info:
                continue
            name_info = getattr(info, "name", None)
            meta = getattr(info, "meta", None)
            if not name_info or not meta:
                continue

            raw_name = getattr(name_info, "name", b"")
            name = _decode_name(raw_name)
            if not name or name in {".", "..", "$OrphanFiles"}:
                continue

            path = f"{prefix}/{name}" if prefix else f"/{name}"
            rows.append((path, entry))

            if dir_type is not None and getattr(meta, "type", None) == dir_type:
                inode = int(getattr(meta, "addr", 0) or 0)
                if inode and inode not in active_dirs and inode not in seen_dirs:
                    seen_dirs.add(inode)
                    try:
                        subdir = entry.as_directory()
                    except Exception:
                        continue
                    recurse(subdir, path, depth + 1, active_dirs | {inode})

    recurse(root, "", 0, {start_inode})
    return rows, None


def _interesting(path: str) -> bool:
    lower = path.lower()
    base = lower.rsplit("/", 1)[-1]
    return base in TARGET_BASENAMES or any(h in lower for h in TARGET_HINTS)


def _parse_kv(text: str) -> dict[str, str]:
    pairs = {}
    for match in re.finditer(r'(\w+)=((?:"[^"]*")|(?:[^\s]+))', text):
        pairs[match.group(1)] = match.group(2).strip('"')
    return pairs


def _normalize_activity_event(event: str, details: str) -> str:
    if event == "usb_device":
        kv = _parse_kv(details)
        action = kv.get("action", "").lower()
        if action == "connected":
            return "usb_connected"
        if action == "disconnected":
            return "usb_disconnected"
    if event == "archive_created":
        return "archive_created"
    if event == "file_open":
        return "file_open"
    if event == "delete":
        return "delete"
    if event == "shell" and "history -c" in details:
        return "history_clear"
    return event


def parse_activity_log(path: str, text: str) -> list[dict[str, Any]]:
    events = []
    for line_no, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        match = re.match(r"^(\d{4}-\d\d-\d\dT[^\s]+)\s+(\S+)\s*(.*)$", line)
        if not match:
            continue
        timestamp, raw_event, details = match.groups()
        events.append({
            "timestamp": timestamp,
            "local_time": timestamp,
            "source": path,
            "event": _normalize_activity_event(raw_event, details),
            "raw_event": raw_event,
            "details": details,
            "line_number": line_no,
            "classification": "fact",
        })
    return events


def parse_bash_history(path: str, text: str) -> list[dict[str, Any]]:
    events = []
    for index, line in enumerate(text.splitlines(), 1):
        command = line.strip()
        if not command:
            continue
        command_event = "shell_command"
        if command == "history -c":
            command_event = "history_clear_command"
        elif command.startswith("cp "):
            command_event = "copy_command"
        elif command.startswith("zip "):
            command_event = "archive_command"
        elif command.startswith("rm "):
            command_event = "delete_command"
        events.append({
            "timestamp": "",
            "local_time": None,
            "source": path,
            "event": command_event,
            "details": command,
            "sequence": index,
            "classification": "fact",
        })
    return events


def extract_artifacts(image_path: str | Path, fs_offset: int) -> dict[str, Any]:
    try:
        import pytsk3
        image = pytsk3.Img_Info(str(image_path))
        fs = pytsk3.FS_Info(image, offset=fs_offset)
    except Exception as exc:
        return {"status": "error", "message": str(exc), "files": [], "timeline": []}

    rows, error = walk_filesystem(fs)
    artifacts = []
    timeline = []
    errors = []

    for path, entry in rows:
        if not _interesting(path):
            continue
        record = _artifact_record(path, entry)
        if not record:
            continue
        if record["size"] > settings.text_artifact_max_bytes:
            continue
        data = _read_entry(entry, settings.text_artifact_max_bytes)
        if record["size"] and not data:
            errors.append(f"Could not read {path}")
            continue

        digest = hashlib.sha256(data).hexdigest()
        text = data.decode("utf-8", "replace")
        record.update({
            "type": "live_artifact",
            "content": text,
            "content_sha256": digest,
        })
        artifacts.append(record)

        base = path.rsplit("/", 1)[-1].lower()
        if base == "activity.log":
            timeline.extend(parse_activity_log(path, text))
        elif base == ".bash_history":
            timeline.extend(parse_bash_history(path, text))

    return {
        "status": "ok" if not error else "partial",
        "message": error or f"Walked {len(rows):,} filesystem entries; extracted {len(artifacts):,} targeted artifacts.",
        "files": artifacts,
        "timeline": timeline,
        "filesystem_entry_count": len(rows),
        "errors": errors,
    }
