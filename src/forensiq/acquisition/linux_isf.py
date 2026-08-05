# FILE: src/forensiq/acquisition/linux_isf.py
"""Linux Volatility 3 ISF (Intermediate Symbol Format) generation and discovery.

Volatility 3 Linux plugins require a kernel ISF JSON that describes the exact
kernel struct layouts and symbol addresses.  For LiME dumps from the current
machine the ISF is generated from:

    1. BTF data — /sys/kernel/btf/vmlinux  (requires CONFIG_DEBUG_INFO_BTF=y)
    2. System.map — kernel symbol addresses  (/usr/lib/modules/<rel>/build/)

The BTF binary is parsed directly in Python — no external tools required.
BTF (BPF Type Format) is the compact kernel type description that linux-hardened
kernels include even when DWARF debug info is stripped.

Generated ISF is saved compressed to ~/.cache/volatility3/symbols/linux/ which
is one of Volatility 3's default search paths — no extra vol3 flags required.
"""

from __future__ import annotations

import base64
import gzip
import json
import os
import platform
import struct
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar

from forensiq.utils.logger import get_logger

log = get_logger(__name__)

# ─── BTF binary format constants ─────────────────────────────────────────────

_BTF_MAGIC = 0xEB9F

_KIND_INT = 1
_KIND_PTR = 2
_KIND_ARRAY = 3
_KIND_STRUCT = 4
_KIND_UNION = 5
_KIND_ENUM = 6
_KIND_FWD = 7
_KIND_TYPEDEF = 8
_KIND_VOLATILE = 9
_KIND_CONST = 10
_KIND_RESTRICT = 11
_KIND_FUNC = 12
_KIND_FUNC_PROTO = 13
_KIND_VAR = 14
_KIND_DATASEC = 15
_KIND_FLOAT = 16
_KIND_DECL_TAG = 17
_KIND_TYPE_TAG = 18
_KIND_ENUM64 = 19

_BTF_INT_SIGNED = 1 << 0
_BTF_INT_CHAR = 1 << 1

_TRANSPARENT_KINDS = {_KIND_TYPEDEF, _KIND_VOLATILE, _KIND_CONST, _KIND_RESTRICT, _KIND_TYPE_TAG}

# ─── Paths ────────────────────────────────────────────────────────────────────

_BTF_PATH = Path("/sys/kernel/btf/vmlinux")

_XDG_CACHE = Path(os.environ.get("XDG_CACHE_HOME") or (Path.home() / ".cache"))
_VOL3_CACHE_SYMBOLS_DIR = _XDG_CACHE / "volatility3" / "symbols" / "linux"
_FORENSIQ_SYMBOLS_DIR = Path.home() / ".forensiq" / "symbols" / "linux"

# ─── Known symbol → ISF type mappings ────────────────────────────────────────
# Volatility 3 plugins call vmlinux.object_from_symbol(symbol_name=X) which
# requires the symbol in the ISF to have a "type" field.  BTF VAR kinds only
# cover per-CPU / BPF variables, not the kernel globals used by vol3 plugins.
# This table provides the type references for all symbols accessed this way
# by the Linux plugins that ForensIQ uses.
_SYMBOL_TYPES: dict[str, dict] = {
    # linux.pslist / linux.psaux ─────────────────────────────────────
    "init_task": {"kind": "struct", "name": "task_struct"},
    # linux.sockstat ─────────────────────────────────────────────────
    "net_namespace_list": {"kind": "struct", "name": "list_head"},
    "socket_file_ops": {"kind": "struct", "name": "file_operations"},
    "sockfs_dentry_operations": {"kind": "struct", "name": "dentry_operations"},
    # linux.modules / linux.check_modules ────────────────────────────
    "modules": {"kind": "struct", "name": "list_head"},
    # linux.capabilities ─────────────────────────────────────────────
    "cap_last_cap": {"kind": "base", "name": "int"},
    # linux.dmesg ────────────────────────────────────────────────────
    "log_buf": {"kind": "pointer", "subtype": {"kind": "base", "name": "char"}},
    "log_buf_len": {"kind": "base", "name": "int"},
    "log_first_idx": {"kind": "base", "name": "unsigned int"},
    "log_next_idx": {"kind": "base", "name": "unsigned int"},
    # LinuxIntelStacker ASLR detection ───────────────────────────────
    "init_mm": {"kind": "struct", "name": "mm_struct"},
    "init_files": {"kind": "struct", "name": "files_struct"},
    "tasks": {"kind": "struct", "name": "list_head"},
}


# ─── BTF binary parser ────────────────────────────────────────────────────────


class _BTFParser:
    """Parse a raw BTF binary blob into a dict of type records keyed by type_id.

    https://www.kernel.org/doc/html/latest/bpf/btf.html
    """

    _HDR_FMT = "<HBBIIIII"
    _HDR_SIZE = struct.calcsize(_HDR_FMT)  # 24 bytes

    def __init__(self, data: bytes) -> None:
        if len(data) < self._HDR_SIZE:
            raise ValueError("BTF data too short")

        magic, _ver, _flags, hdr_len, type_off, type_len, str_off, str_len = struct.unpack_from(
            self._HDR_FMT, data
        )

        if magic != _BTF_MAGIC:
            raise ValueError(f"Invalid BTF magic 0x{magic:04X} (expected 0x{_BTF_MAGIC:04X})")

        self._type_data = data[hdr_len + type_off : hdr_len + type_off + type_len]
        self._str_data = data[hdr_len + str_off : hdr_len + str_off + str_len]
        self.types: dict[int, dict[str, Any]] = {}
        self._parse()

    def _str(self, off: int) -> str:
        if off == 0:
            return ""
        end = self._str_data.index(b"\x00", off)
        return self._str_data[off:end].decode("utf-8", errors="replace")

    def _parse(self) -> None:
        d = self._type_data
        n = len(d)
        pos = 0
        tid = 1

        while pos + 12 <= n:
            name_off, info, size_or_type = struct.unpack_from("<III", d, pos)
            pos += 12

            vlen = info & 0xFFFF
            kind = (info >> 24) & 0x1F
            kind_flag = bool((info >> 31) & 1)

            t: dict[str, Any] = {
                "id": tid,
                "kind": kind,
                "kind_flag": kind_flag,
                "vlen": vlen,
                "name": self._str(name_off),
                "size_or_type": size_or_type,
            }

            if kind == _KIND_INT:
                if pos + 4 > n:
                    break
                enc = struct.unpack_from("<I", d, pos)[0]
                pos += 4
                t["size"] = size_or_type
                t["signed"] = bool(enc & _BTF_INT_SIGNED)
                t["is_char"] = bool(enc & _BTF_INT_CHAR)

            elif kind in (_KIND_STRUCT, _KIND_UNION):
                t["size"] = size_or_type
                members: list[dict] = []
                for _ in range(vlen):
                    if pos + 12 > n:
                        break
                    m_name_off, m_type, m_offset_raw = struct.unpack_from("<III", d, pos)
                    pos += 12
                    bit_off = (m_offset_raw & 0xFFFFFF) if kind_flag else m_offset_raw
                    members.append(
                        {
                            "name": self._str(m_name_off),
                            "type_id": m_type,
                            "bit_offset": bit_off,
                        }
                    )
                t["members"] = members

            elif kind == _KIND_ARRAY:
                if pos + 12 > n:
                    break
                elem_type, _idx_type, nelems = struct.unpack_from("<III", d, pos)
                pos += 12
                t["elem_type"] = elem_type
                t["nelems"] = nelems

            elif kind in (_KIND_ENUM, _KIND_ENUM64):
                t["size"] = size_or_type
                entry_size = 12 if kind == _KIND_ENUM64 else 8
                enumerators: list[tuple[str, int]] = []
                for _ in range(vlen):
                    if pos + entry_size > n:
                        break
                    if kind == _KIND_ENUM64:
                        e_name_off, e_lo, e_hi = struct.unpack_from("<III", d, pos)
                        e_val: int = e_lo | (e_hi << 32)
                    else:
                        e_name_off, e_val = struct.unpack_from("<Ii", d, pos)
                    pos += entry_size
                    enumerators.append((self._str(e_name_off), e_val))
                t["enumerators"] = enumerators

            elif kind in _TRANSPARENT_KINDS:
                t["type"] = size_or_type

            elif kind in (_KIND_PTR, _KIND_FWD, _KIND_FUNC):
                t["type"] = size_or_type

            elif kind == _KIND_FUNC_PROTO:
                t["return_type"] = size_or_type
                pos += vlen * 8  # skip param (name_off + type_id) pairs

            elif kind == _KIND_VAR:
                if pos + 4 > n:
                    break
                pos += 4  # linkage u32

            elif kind == _KIND_DATASEC:
                pos += vlen * 12  # (type_id, offset, size) per var

            elif kind == _KIND_FLOAT:
                t["size"] = size_or_type

            elif kind == _KIND_DECL_TAG:
                if pos + 4 > n:
                    break
                pos += 4  # component_idx s32

            self.types[tid] = t
            tid += 1


# ─── ISF builder ──────────────────────────────────────────────────────────────


class _ISFBuilder:
    """Convert a parsed BTF type table + System.map into a Volatility 3 ISF dict."""

    _DEFAULT_BASE_TYPES: ClassVar[dict[str, dict]] = {
        "void": {"endian": "little", "kind": "int", "signed": False, "size": 0},
        "pointer": {"endian": "little", "kind": "int", "signed": False, "size": 8},
        "char": {"endian": "little", "kind": "char", "signed": True, "size": 1},
        "unsigned char": {"endian": "little", "kind": "char", "signed": False, "size": 1},
        "short int": {"endian": "little", "kind": "int", "signed": True, "size": 2},
        "unsigned short int": {"endian": "little", "kind": "int", "signed": False, "size": 2},
        "int": {"endian": "little", "kind": "int", "signed": True, "size": 4},
        "unsigned int": {"endian": "little", "kind": "int", "signed": False, "size": 4},
        "long int": {"endian": "little", "kind": "int", "signed": True, "size": 8},
        "unsigned long int": {"endian": "little", "kind": "int", "signed": False, "size": 8},
        "long long int": {"endian": "little", "kind": "int", "signed": True, "size": 8},
        "unsigned long long int": {"endian": "little", "kind": "int", "signed": False, "size": 8},
        "bool": {"endian": "little", "kind": "int", "signed": False, "size": 1},
        "_Bool": {"endian": "little", "kind": "int", "signed": False, "size": 1},
        "float": {"endian": "little", "kind": "float", "signed": True, "size": 4},
        "double": {"endian": "little", "kind": "float", "signed": True, "size": 8},
        "long double": {"endian": "little", "kind": "float", "signed": True, "size": 16},
    }

    def __init__(self, btf: _BTFParser) -> None:
        self._btf = btf

    def _resolve(self, type_id: int) -> int:
        """Follow typedef/volatile/const chains to the concrete type_id."""
        seen: set[int] = set()
        while type_id in self._btf.types:
            if type_id in seen:
                return 0
            seen.add(type_id)
            t = self._btf.types[type_id]
            if t["kind"] in _TRANSPARENT_KINDS:
                type_id = t.get("type", 0)
            else:
                return type_id
        return type_id

    def _flatten_struct_fields(
        self,
        members: list[dict],
        parent_bit_offset: int,
        depth: int = 0,
    ) -> dict[str, dict]:
        """Recursively flatten anonymous embedded struct/union members.

        Linux kernel structs built with CONFIG_RANDSTRUCT (e.g. mm_struct) wrap
        all their real fields inside an anonymous struct.  In BTF this shows up
        as a single member with an empty name ('') pointing to the inner struct.
        Without flattening, the ISF only sees '__pad_0' instead of arg_start,
        arg_end, mmap, pgd, etc., which breaks linux.psaux / linux.sockstat /
        linux.library_list / linux.malware.malfind.
        """
        if depth > 8:  # guard against pathological nesting
            return {}
        fields: dict[str, dict] = {}
        for m in members:
            m_name = m["name"]
            abs_bit_off = parent_bit_offset + m["bit_offset"]
            byte_off = abs_bit_off // 8
            if not m_name:
                # Anonymous embedded struct/union — inline its fields
                concrete = self._resolve(m["type_id"])
                anon_t = self._btf.types.get(concrete, {})
                if anon_t.get("kind") in (_KIND_STRUCT, _KIND_UNION):
                    nested = self._flatten_struct_fields(
                        anon_t.get("members", []), abs_bit_off, depth + 1
                    )
                    fields.update(nested)
                    continue
                # Anonymous non-struct (rare): emit as padding
                m_name = f"__pad_{abs_bit_off}"
            fields[m_name] = {
                "offset": byte_off,
                "type": self._type_ref(m["type_id"]),
            }
        return fields

    def _type_ref(self, type_id: int) -> dict:
        """Return a Volatility 3 ISF type reference dict for BTF type_id."""
        if type_id == 0:
            return {"kind": "base", "name": "void"}

        concrete = self._resolve(type_id)
        if concrete == 0 or concrete not in self._btf.types:
            return {"kind": "base", "name": "void"}

        t = self._btf.types[concrete]
        kind = t["kind"]
        name = t["name"]

        if kind == _KIND_INT:
            return {"kind": "base", "name": name or f"__int{t['size'] * 8}"}
        if kind == _KIND_FLOAT:
            return {"kind": "base", "name": name or f"float{t['size'] * 8}"}
        if kind == _KIND_PTR:
            return {"kind": "pointer", "subtype": self._type_ref(t.get("type", 0))}
        if kind == _KIND_ARRAY:
            return {
                "kind": "array",
                "count": t["nelems"],
                "subtype": self._type_ref(t.get("elem_type", 0)),
            }
        if kind == _KIND_STRUCT:
            return {"kind": "struct", "name": name or f"__anon_struct_{concrete}"}
        if kind == _KIND_UNION:
            return {"kind": "union", "name": name or f"__anon_union_{concrete}"}
        if kind in (_KIND_ENUM, _KIND_ENUM64):
            return {"kind": "enum", "name": name} if name else {"kind": "base", "name": "int"}
        if kind == _KIND_FWD:
            return {"kind": "struct", "name": name or "void"}
        if kind in (_KIND_FUNC, _KIND_FUNC_PROTO):
            return {"kind": "pointer", "subtype": {"kind": "base", "name": "void"}}
        return {"kind": "base", "name": "void"}

    def _parse_system_map(self, path: Path) -> dict[str, dict]:
        symbols: dict[str, dict] = {}
        try:
            for line in path.read_text(errors="replace").splitlines():
                parts = line.split()
                if len(parts) >= 3:
                    try:
                        symbols[parts[2]] = {"address": int(parts[0], 16)}
                    except ValueError:
                        pass
        except OSError:
            pass
        return symbols

    def build(self, system_map: Path | None, release: str) -> dict:
        base_types: dict[str, dict] = dict(self._DEFAULT_BASE_TYPES)
        user_types: dict[str, dict] = {}
        enums: dict[str, dict] = {}

        for tid, t in self._btf.types.items():
            kind = t["kind"]
            name = t["name"]

            if kind == _KIND_INT and name:
                is_char = t["is_char"] or name in ("char", "unsigned char")
                base_types[name] = {
                    "endian": "little",
                    "kind": "char" if is_char else "int",
                    "signed": t["signed"],
                    "size": t["size"],
                }

            elif kind == _KIND_FLOAT and name:
                base_types[name] = {
                    "endian": "little",
                    "kind": "float",
                    "signed": True,
                    "size": t["size"],
                }

            elif kind in (_KIND_STRUCT, _KIND_UNION):
                isf_name = name or (
                    f"__anon_struct_{tid}" if kind == _KIND_STRUCT else f"__anon_union_{tid}"
                )
                # Use recursive flattening so anonymous embedded structs
                # (e.g. the RANDSTRUCT wrapper inside mm_struct) expose all
                # their real fields rather than appearing as __pad_0.
                fields = self._flatten_struct_fields(t.get("members", []), 0)
                user_types[isf_name] = {
                    "fields": fields,
                    "kind": "struct" if kind == _KIND_STRUCT else "union",
                    "size": t["size"],
                }

            elif kind in (_KIND_ENUM, _KIND_ENUM64) and name:
                size = t["size"]
                base = (
                    "unsigned char"
                    if size == 1
                    else "unsigned short int"
                    if size == 2
                    else "unsigned long long int"
                    if size == 8
                    else "unsigned int"
                )
                enums[name] = {
                    "base": base,
                    "constants": dict(t["enumerators"]),
                    "size": size,
                }

        symbols = self._parse_system_map(system_map) if system_map else {}

        # Volatility 3 symbol cache (LinuxIdentifier) requires linux_banner to have
        # a "constant_data" field (base64-encoded banner bytes) so LinuxIntelStacker
        # can match ISF files against the banner string found in physical memory.
        if "linux_banner" in symbols:
            try:
                banner_bytes = Path("/proc/version").read_bytes()
                # /proc/version ends with \n — that matches the kernel's linux_banner
                symbols["linux_banner"]["constant_data"] = base64.b64encode(banner_bytes).decode(
                    "ascii"
                )
            except OSError:
                pass

        # Add type annotations for symbols accessed via object_from_symbol().
        # BTF VAR kinds only cover per-CPU/BPF variables, not these kernel globals.
        for sym_name, sym_type in _SYMBOL_TYPES.items():
            if sym_name in symbols:
                symbols[sym_name]["type"] = sym_type

        return {
            "metadata": {
                "producer": {
                    "name": "forensiq-btf2isf",
                    "version": "1.1.0",  # 1.1.0: anonymous struct flattening
                    "datetime": datetime.now(UTC).isoformat(),
                },
                "format": "6.1.0",
                "linux": {"release": release},
            },
            "base_types": base_types,
            "user_types": user_types,
            "enums": enums,
            "symbols": symbols,
        }


# ─── Discovery helpers ────────────────────────────────────────────────────────


def find_system_map(release: str | None = None) -> Path | None:
    """Return the System.map path for the given kernel release, or None."""
    if release is None:
        release = platform.release()
    candidates = [
        Path(f"/usr/lib/modules/{release}/build/System.map"),
        Path(f"/boot/System.map-{release}"),
        Path("/boot/System.map"),
    ]
    for p in candidates:
        if p.is_file():
            return p
    return None


def find_linux_isf(release: str | None = None) -> Path | None:
    """Return path to a valid cached ISF for *release*, or None.

    An ISF is considered valid only if it contains linux_banner.constant_data,
    which Volatility 3's LinuxIntelStacker requires to populate its symbol cache
    and match the banner string found in physical memory.  ISF files built by
    older ForensIQ versions that lack this field are treated as absent so that
    the menu prompts the user to rebuild them.
    """
    if release is None:
        release = platform.release()
    safe = release.replace("/", "-")
    for d in (_VOL3_CACHE_SYMBOLS_DIR, _FORENSIQ_SYMBOLS_DIR):
        for name in (f"linux-{safe}.json.gz", f"linux-{safe}.json"):
            p = d / name
            if p.is_file() and p.stat().st_size > 0 and _isf_has_banner_data(p):
                return p
    return None


# ─── Requirements check ───────────────────────────────────────────────────────


def check_linux_isf_requirements(
    release: str | None = None,
) -> dict[str, bool | str]:
    """Return a dict describing the ISF build environment.

    Keys
    ----
    btf_available     bool         /sys/kernel/btf/vmlinux is readable
    system_map_found  bool | str   path if found, False otherwise
    isf_cached        bool | str   path if found, False otherwise
    can_build         bool         BTF + System.map both present
    """
    if release is None:
        release = platform.release()

    btf_ok = _BTF_PATH.exists() and os.access(_BTF_PATH, os.R_OK)
    sysmap = find_system_map(release)
    cached = find_linux_isf(release)

    return {
        "btf_available": btf_ok,
        "system_map_found": str(sysmap) if sysmap else False,
        "isf_cached": str(cached) if cached else False,
        "can_build": btf_ok and sysmap is not None,
    }


# ─── ISF generation ───────────────────────────────────────────────────────────


def _isf_has_banner_data(path: Path) -> bool:
    """Return True if the ISF at *path* is valid and up-to-date.

    Checks:
      1. linux_banner.constant_data is present (Volatility 3 banner matching)
      2. Producer version is 1.1.0+ (anonymous struct flattening applied)

    Uses a fast bytes-level search (no full JSON parse) so calling this during
    menu display does not add noticeable latency.  ISFs built by older ForensIQ
    versions (v1.0.0, which lacked mm_struct field flattening) are treated as
    absent so they are automatically rebuilt.
    """
    try:
        opener = gzip.open if path.suffix == ".gz" else open
        with opener(path, "rb") as fh:
            content = fh.read()
        return b'"constant_data"' in content and b'"1.1.0"' in content
    except Exception:
        return False


def build_linux_isf(
    release: str | None = None,
    *,
    progress_cb: Callable[[str], None] | None = None,
) -> Path:
    """Generate a Volatility 3 Linux ISF for *release* from BTF + System.map.

    Reads the raw BTF binary from /sys/kernel/btf/vmlinux (no external tools
    required) and combines it with symbol addresses from System.map.

    The compressed JSON is written to:
      ~/.cache/volatility3/symbols/linux/   (auto-discovered by Volatility 3)
      ~/.forensiq/symbols/linux/             (forensiq cache)

    Returns the path of the primary (vol3 cache) copy.
    Raises RuntimeError on any failure.
    """
    if release is None:
        release = platform.release()

    existing = find_linux_isf(release)
    if existing:
        # find_linux_isf() already validated constant_data — safe to return.
        if progress_cb:
            progress_cb(f"ISF already cached → {existing}")
        return existing

    if not _BTF_PATH.exists():
        raise RuntimeError(
            f"BTF data not found at {_BTF_PATH}.\n"
            "Kernel must be built with CONFIG_DEBUG_INFO_BTF=y."
        )
    if not os.access(_BTF_PATH, os.R_OK):
        raise RuntimeError(f"{_BTF_PATH} exists but is not readable — run as root.")

    sysmap = find_system_map(release)
    if sysmap is None:
        raise RuntimeError(
            f"System.map not found for kernel {release}.\n"
            f"Expected: /usr/lib/modules/{release}/build/System.map"
        )

    if progress_cb:
        progress_cb(f"Generating ISF for kernel {release}…")
        progress_cb(f"  BTF:        {_BTF_PATH}  ({_BTF_PATH.stat().st_size // 1024} KB)")
        progress_cb(f"  System.map: {sysmap}")
        progress_cb("  Parsing BTF types (this may take 30-90 seconds)…")

    log.info("Reading BTF", path=str(_BTF_PATH))
    btf_data = _BTF_PATH.read_bytes()

    try:
        btf = _BTFParser(btf_data)
    except (ValueError, struct.error) as exc:
        raise RuntimeError(f"BTF parse error: {exc}") from exc

    if progress_cb:
        progress_cb(f"  Parsed {len(btf.types):,} BTF types")
        progress_cb("  Building ISF JSON…")

    isf_dict = _ISFBuilder(btf).build(sysmap, release)

    if progress_cb:
        n_syms = len(isf_dict["symbols"])
        n_types = len(isf_dict["user_types"])
        progress_cb(f"  ISF: {n_types:,} types, {n_syms:,} symbols")
        progress_cb("  Compressing and saving…")

    isf_bytes = json.dumps(isf_dict, separators=(",", ":")).encode()

    safe_release = release.replace("/", "-")
    isf_name = f"linux-{safe_release}.json.gz"

    saved: Path | None = None
    for dest_dir in (_VOL3_CACHE_SYMBOLS_DIR, _FORENSIQ_SYMBOLS_DIR):
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / isf_name
        with gzip.open(dest, "wb", compresslevel=6) as fh:
            fh.write(isf_bytes)
        log.info("ISF saved", path=str(dest), size_kb=len(isf_bytes) // 1024)
        if saved is None:
            saved = dest
        if progress_cb:
            progress_cb(f"  Saved → {dest}")

    assert saved is not None

    # Invalidate the Volatility 3 identifier cache (SQLite DB).
    # SymbolCacheMagic only re-processes ISF files it hasn't seen before or
    # files whose cache entry has expired.  Deleting the DB ensures the next
    # vol invocation picks up the new ISF with linux_banner.constant_data.
    _identifier_cache = _VOL3_CACHE_SYMBOLS_DIR.parent.parent / "identifier.cache"
    try:
        _identifier_cache.unlink(missing_ok=True)
    except OSError:
        pass

    if progress_cb:
        progress_cb(f"ISF generation complete ({len(isf_bytes) // 1024 // 1024} MB uncompressed)")
    return saved
