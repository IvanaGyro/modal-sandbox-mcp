"""Choose a safe, bounded MCP response for a Sandbox filesystem path.

Inline only small UTF-8 text. Binary/large files and all directories are
downloaded over HTTPS instead of being returned through MCP JSON-RPC.
"""

from __future__ import annotations

INLINE_TEXT_LIMIT = 8192  # Bytes, not Unicode code points.


def inspect_path(filesystem, path: str) -> dict:
    """Return a small inline payload or metadata requiring a download link.

    A file that grows between stat() and read_bytes() is never returned inline
    if the bytes exceed the configured limit.
    """
    info = filesystem.stat(path)
    item_type = str(info.type).lower()
    if "directory" in item_type:
        return {"path": path, "kind": "directory", "delivery": "download",
                "format": "zip"}

    if "file" not in item_type:
        raise ValueError("Unsupported path type: " + item_type)

    size = int(info.size)
    if size < 0:
        raise ValueError("Invalid filesystem entry size")

    if size <= INLINE_TEXT_LIMIT:
        data = filesystem.read_bytes(path)
        if len(data) <= INLINE_TEXT_LIMIT:
            try:
                content = data.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                pass
            else:
                # Treat UTF-8-encoded binary/control data as binary, not as a
                # text prompt. Common whitespace remains valid in code files.
                if not any(ord(char) < 32 and char not in "\n\r\t\f"
                           for char in content):
                    return {
                        "path": path,
                        "kind": "file",
                        "delivery": "inline",
                        "encoding": "utf-8",
                        "size_bytes": len(data),
                        "content": content,
                    }
        # Re-stat in case the file grew while we were reading it.
        size = max(size, len(data))

    return {
        "path": path,
        "kind": "file",
        "delivery": "download",
        "size_bytes": size,
    }
