#!/usr/bin/env python3
"""
Address Library v5 + PE inspector for Starfield 1.16.x derivation work.

Why this exists
---------------
The original Parapets mod captured 9 hook targets as Address Library IDs against
Starfield 1.8.86. Bethesda has refactored most of those functions across 1.10
through 1.16.236, so several IDs either:

  * still resolve to the same logical function but the documented byte offset
    inside the function (where the E8 call lives) has shifted, or
  * resolve to a function that has been re-purposed entirely (for example
    BSInputDeviceManager::IsUsingGamepad's slot 178879 now points at a
    spdlog-style logging stub, not a predicate), or
  * were inlined into all callers and no longer exist as a callable function.

This module is the parser + analyzer used to re-derive 1.16.236 IDs and
offsets from a local copy of Starfield.exe and the matching versionlib bin.

Format-5 layout (matches CommonLibSF/lib/commonlib-shared/src/REL/IDDB.cpp):

    u32  fileVersion (== 5)
    u32  gameVersion[4]            # for example 1, 16, 236, 0
    char name[64]                  # "Starfield.exe"
    i32  pointerSize
    i32  dataFormat
    i32  offsetCount
    u32  offsets[offsetCount]      # offsets[id] = RVA, 0 = unmapped

Use
---

    from tools.al_db_parser import AlDb, PE
    db = AlDb("/path/to/versionlib-1-16-236-0.bin")
    pe = PE("/path/to/Starfield.exe")
    rva = db.rva(433589)           # forward lookup
    aid = db.id_for_rva(rva)       # reverse lookup
    bytes_at = pe.read(rva, 16)

Run as a script with --probe to dump diagnostics for the 9 stale hook targets.
"""
import argparse
import bisect
import struct
import sys
from pathlib import Path

try:
    import lief  # type: ignore
except ImportError:
    print("This tool needs lief: pip install --break-system-packages lief", file=sys.stderr)
    raise


class AlDb:
    """Format-5 Address Library database (Starfield)."""

    def __init__(self, path):
        path = Path(path)
        blob = path.read_bytes()
        fv, = struct.unpack_from("<I", blob, 0)
        if fv != 5:
            raise ValueError(f"{path}: expected fileVersion 5, got {fv}")
        self.path = path
        self.file_version = fv
        self.game_version = struct.unpack_from("<IIII", blob, 4)
        self.name = blob[20:84].split(b"\x00", 1)[0].decode("ascii", "replace")
        self.pointer_size, self.data_format, self.offset_count = struct.unpack_from("<iii", blob, 84)
        self.offsets = struct.unpack_from(f"<{self.offset_count}I", blob, 96)
        self._reverse = None

    def rva(self, alid):
        if alid < 0 or alid >= self.offset_count:
            return 0
        return self.offsets[alid]

    def reverse(self):
        if self._reverse is None:
            r = {}
            for i, off in enumerate(self.offsets):
                if off and off not in r:
                    r[off] = i
            self._reverse = r
        return self._reverse

    def id_for_rva(self, rva):
        return self.reverse().get(rva)


class PE:
    """Lightweight PE inspector for reading bytes by RVA."""

    def __init__(self, path):
        self.path = Path(path)
        self.bin = lief.PE.parse(str(self.path))
        self.image_base = self.bin.optional_header.imagebase
        self.text = next(s for s in self.bin.sections if s.name.startswith(".text"))
        self.text_va = self.text.virtual_address
        self.text_size = self.text.virtual_size
        self._sections = []
        for s in self.bin.sections:
            self._sections.append((s.virtual_address, s.virtual_size, bytes(s.content)))

    def read(self, rva, length):
        for sva, ssz, sb in self._sections:
            if sva <= rva < sva + ssz:
                off = rva - sva
                if off + length > len(sb):
                    return sb[off:off + max(0, len(sb) - off)].ljust(length, b"\x00")
                return sb[off:off + length]
        return None

    def read_u64(self, rva):
        b = self.read(rva, 8)
        return struct.unpack("<Q", b)[0] if b else None

    def va_to_rva(self, va):
        return va - self.image_base


def function_end(db, pe, start, cap=0x4000):
    """Function end heuristic: next AL-DB-mapped RVA in .text after start, capped."""
    text_va = pe.text_va
    text_end = text_va + pe.text_size
    rvas = sorted(set(o for o in db.offsets if text_va <= o < text_end))
    i = bisect.bisect_right(rvas, start)
    cap_end = start + cap
    if i < len(rvas):
        return min(rvas[i], cap_end, text_end)
    return min(cap_end, text_end)


def follow_thunk(db, pe, rva, max_hops=4):
    """Follow trivial register-mov + jmp-rel32 thunks until the real body."""
    cur = rva
    for _ in range(max_hops):
        end = function_end(db, pe, cur, 0x40)
        body = pe.read(cur, min(end - cur, 0x40))
        if not body:
            return cur
        i = 0
        while i < min(len(body), 0x18):
            b = body[i]
            if b == 0xE9:
                rel = struct.unpack("<i", body[i + 1:i + 5])[0]
                tgt = cur + i + 5 + rel
                if tgt == cur:
                    return cur
                cur = tgt
                break
            if i + 2 < len(body) and b in (0x48, 0x4C) and body[i + 1] == 0x8B and (body[i + 2] & 0xC0) == 0xC0:
                i += 3
                continue
            if i + 3 < len(body) and b in (0x48, 0x4C) and body[i + 1] == 0x8B and (body[i + 2] & 0xC0) == 0x40:
                i += 4
                continue
            return cur
        else:
            return cur
    return cur


def scan_e8(pe, start, end):
    """Return (offset_within_start, target_rva) for every E8 call in [start, end)."""
    body = pe.read(start, end - start)
    if not body:
        return []
    out = []
    i = 0
    while i < len(body) - 5:
        if body[i] == 0xE8:
            rel = struct.unpack("<i", body[i + 1:i + 5])[0]
            tgt = start + i + 5 + rel
            out.append((i, tgt))
        i += 1
    return out


HOOKS_1_8_86 = [
    ("LookHandler::Vtbl",                   433589, 0,     None,                   "vfunc_slot_1"),
    ("BSPCGamepadDevice::Poll",             179249, 0x2A0, b"\xC6\x43\x08\x01",    "byte_patch_nop4"),
    ("LookHandler::Func10",                 129152, 0x0E,  b"\xE8",                "rewrite_call5"),
    ("Manager::ProcessLookInput",           129407, 0x68,  b"\xE8",                "rewrite_call5"),
    ("Main::Run_WindowsMessageLoop",        149028, 0x39,  b"\xE8",                "rewrite_call5"),
    ("ShipHudDataModel::PerformInputProcessing+0x7AF", 137087, 0x7AF, b"\xE8",     "rewrite_call5"),
    ("ShipHudDataModel::PerformInputProcessing+0x82A", 137087, 0x82A, b"\xE8",     "rewrite_call5"),
    ("IMenu::ShowCursor",                   187256, 0x14,  b"\xE8",                "rewrite_call5"),
    ("UI::SetCursorStyle",                  187051, 0x98,  b"\xE8",                "rewrite_call5"),
    ("BSInputDeviceManager::IsUsingGamepad", 178879, 0,    None,                   "predicate_target"),
]


def probe(db_path, exe_path):
    db = AlDb(db_path)
    pe = PE(exe_path)
    print(f"AL DB game_version={db.game_version} offset_count={db.offset_count}")
    print(f"PE image_base=0x{pe.image_base:X} .text 0x{pe.text_va:X}+0x{pe.text_size:X}")
    print()
    for label, alid, off, want, mech in HOOKS_1_8_86:
        rva = db.rva(alid)
        real = follow_thunk(db, pe, rva)
        end = function_end(db, pe, real)
        size = end - real
        head = pe.read(real, 16) if real else None
        print(f"[{label}] alid={alid} mech={mech}")
        print(f"  rva=0x{rva:X} -> real=0x{real:X} size=0x{size:X}")
        if head:
            print(f"  prologue: {head.hex(' ')}")
        if mech == "rewrite_call5":
            calls = scan_e8(pe, real, end)
            print(f"  E8 call sites in body: {len(calls)}")
            for o, t in calls[:8]:
                ta = db.id_for_rva(t)
                print(f"    +0x{o:X} -> 0x{t:X} (alid {ta})")
        elif mech == "byte_patch_nop4" and want is not None:
            body = pe.read(real, size)
            hits = []
            if body:
                i = 0
                while i < len(body) - len(want):
                    if body[i:i + len(want)] == want:
                        hits.append(i)
                    i += 1
            print(f"  pattern {want.hex(' ')} hits: {[hex(h) for h in hits]}")
        print()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True, help="Path to versionlib-1-16-236-0.bin")
    ap.add_argument("--exe", required=True, help="Path to Starfield.exe")
    ap.add_argument("--probe", action="store_true", help="Dump per-hook diagnostic")
    args = ap.parse_args()
    if args.probe:
        probe(args.db, args.exe)


if __name__ == "__main__":
    main()
