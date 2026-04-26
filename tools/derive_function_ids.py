#!/usr/bin/env python3
"""Re-derive Starfield 1.16.236 hook offsets and host function RVAs.

Inputs (defaults match a typical local sandbox layout):
  --exe   Starfield.exe (any patch version; we read its PE structure)
  --db    versionlib-{ver}-0.bin (format-5 AL database)
  --log   SimultaneousInput.log (optional; if provided, the runtime-resolved
          host RVAs in skip messages are extracted and used as ground truth)

Output: JSON to stdout describing each hook's host RVA, candidate predicate
destinations, and recommended in-function offsets.

Why this script exists:

The original Parapets plugin (1.8.86) records 9 hooks at specific in-function
offsets keyed off Address Library IDs. Two facts about Starfield 1.16.236:

1. Bethesda refactored the byte layout INSIDE the host functions, so the
   Parapets in-function offsets (e.g. +0x7AF, +0x14, +0x2A0) no longer point
   at the documented anchors.

2. The "predicate" the original mod replaces (BSInputDeviceManager::IsUsingGamepad,
   AL 178879 in 1.8.86) is now spread across multiple distinct call targets in
   the runtime. The destination called by the most input-related host functions
   in 1.16.236 is 0x3660ab0 (called by Func10, ProcessLookInput,
   ShipHudDataModel::PerformInputProcessing, UI::SetCursorStyle).

3. There is an unresolved discrepancy between this script's parse of the AL DB
   and the runtime resolution observed in SimultaneousInput.log. With the same
   versionlib-1-16-236-0.bin file (sha256 verified identical), the deployed
   plugin's runtime resolution of e.g. AL 137087 yields RVA 0x27DA8E0, but a
   straight m_v5[id] lookup of the same file yields 0x27DAF60. The discrepancy
   is not a fixed delta. The most likely cause is a stale named memory map
   (libxse uses OpenFileMappingA before falling back to file mapping; if a
   prior process created COMMONLIB_IDDB_OFFSETS_1_16_236_0 with different
   data, libxse attaches to that). Until this is reproduced cleanly, the
   --log path is the only reliable source of ground-truth RVAs in 1.16.236.

This script therefore prefers --log values when available and falls back to
direct DB parsing otherwise. The output is structured to be auditable: every
derivation records which path was used.
"""
import argparse
import json
import re
import struct
import sys
from collections import defaultdict


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--exe", default="/tmp/sf/sf.exe")
    p.add_argument("--db",  default="/tmp/sf/aldb.bin")
    p.add_argument("--log", default="/tmp/sf/si.log",
                   help="SimultaneousInput.log to extract runtime-resolved host RVAs")
    return p.parse_args()


def load_db(path):
    with open(path, "rb") as f:
        db = f.read()
    fv = struct.unpack_from("<I", db, 0)[0]
    if fv != 5:
        raise SystemExit(f"only format 5 supported, got {fv}")
    game_ver = struct.unpack_from("<IIII", db, 4)
    name = db[20:84].rstrip(b"\x00").decode("ascii", "replace")
    ptr_size, data_format, oc = struct.unpack_from("<iii", db, 84)
    offsets = struct.unpack_from(f"<{oc}I", db, 96)
    return dict(game_version=".".join(str(x) for x in game_ver),
                name=name, pointer_size=ptr_size, data_format=data_format,
                offset_count=oc, offsets=offsets, raw=db)


def load_pe(path):
    with open(path, "rb") as f:
        pe = f.read()
    dos = struct.unpack_from("<I", pe, 0x3C)[0]
    coff = dos + 4
    size_opt = struct.unpack_from("<H", pe, coff + 16)[0]
    opt = coff + 20
    image_base = struct.unpack_from("<Q", pe, opt + 24)[0]
    nsec = struct.unpack_from("<H", pe, coff + 2)[0]
    sec_table = opt + size_opt
    sections = []
    for s in range(nsec):
        o = sec_table + s * 40
        name = pe[o:o + 8].rstrip(b"\x00").decode("ascii", "replace")
        vsize, vaddr, rsize, raw = struct.unpack_from("<IIII", pe, o + 8)
        sections.append((name, vaddr, vaddr + vsize, raw))

    def rva_to_file(rva):
        for n, vs, ve, fo in sections:
            if vs <= rva < ve:
                return fo + (rva - vs)
        return None

    def read(rva, n):
        o = rva_to_file(rva)
        if o is None or o + n > len(pe):
            return None
        return pe[o:o + n]

    return dict(raw=pe, image_base=image_base, sections=sections,
                rva_to_file=rva_to_file, read=read)


def parse_log_runtime_rvas(path):
    """Extract 'AL id <decimal> +<hex>' pairs from a SimultaneousInput.log
    and return a list of (host_rva, in_func_offset) tuples per skip line.
    """
    out = {}
    if not path:
        return out
    try:
        with open(path) as f:
            text = f.read()
    except FileNotFoundError:
        return out
    # The log line format is e.g.:
    #   hook 'IMenu::ShowCursor (menu cursor visibility)' skipped: AL id 58536432 +0x14 ...
    pat = re.compile(r"hook '([^']+)' skipped: AL id (\d+) \+0x([0-9a-fA-F]+)")
    for m in pat.finditer(text):
        label, rva_dec, off_hex = m.groups()
        out[label] = (int(rva_dec), int(off_hex, 16))
    # also catch byte patch line:
    #   byte patch skipped: BSPCGamepadDevice::Poll +0x2A0 pattern mismatch
    bp = re.search(r"byte patch skipped: ([^\s]+)\s+\+0x([0-9a-fA-F]+)", text)
    if bp:
        out[bp.group(1)] = (None, int(bp.group(2), 16))
    return out


def scan_e8(pe_read, host_rva, body_size=0x1500):
    body = pe_read(host_rva, body_size)
    if body is None:
        return []
    out, j = [], 0
    while j < len(body) - 5:
        if body[j] == 0xE8:
            rel = struct.unpack_from("<i", body, j + 1)[0]
            tgt = host_rva + j + 5 + rel
            out.append((j, tgt))
            j += 5
        else:
            j += 1
    return out


def find_byte_pattern(pe_read, host_rva, pattern_bytes, body_size=0x1500):
    body = pe_read(host_rva, body_size)
    if body is None:
        return []
    hits, i = [], 0
    while i < len(body) - len(pattern_bytes):
        if body[i:i + len(pattern_bytes)] == pattern_bytes:
            hits.append(i)
            i += len(pattern_bytes)
        else:
            i += 1
    return hits


# Original Parapets hook table (1.8.86 AL IDs + in-function offsets)
PARAPETS_HOOKS = [
    # name,                                     old_al_id,  old_offset,  mechanism
    ("BSPCGamepadDevice::Poll",                 179249,     0x2A0,       "byte_patch_nop4"),
    ("PlayerControls::LookHandler::Func10",     129152,     0xE,         "rewrite_call5"),
    ("PlayerControls::Manager::ProcessLookInput", 129407,   0x68,        "rewrite_call5"),
    ("Main::Run_WindowsMessageLoop",            149028,     0x39,        "rewrite_call5"),
    ("ShipHudDataModel::PerformInputProcessing@1st", 137087, 0x7AF,      "rewrite_call5"),
    ("ShipHudDataModel::PerformInputProcessing@2nd", 137087, 0x82A,      "rewrite_call5"),
    ("IMenu::ShowCursor",                       187256,     0x14,        "rewrite_call5"),
    ("UI::SetCursorStyle",                      187051,     0x98,        "rewrite_call5"),
]


def main():
    a = parse_args()
    db = load_db(a.db)
    pe = load_pe(a.exe)
    log_rvas = parse_log_runtime_rvas(a.log)

    sys.stderr.write(f"AL DB game_version={db['game_version']} count={db['offset_count']}\n")
    sys.stderr.write(f"PE image_base=0x{pe['image_base']:x}\n")
    sys.stderr.write(f"log entries parsed: {len(log_rvas)}\n")

    # For each hook, determine host RVA. Prefer log (runtime ground truth),
    # else fall back to direct DB parse.
    results = {}
    for name, al_id, old_off, mech in PARAPETS_HOOKS:
        # Match log label (substring match since labels include parenthetical desc)
        log_match = None
        for label, (rva, off) in log_rvas.items():
            if name.split("@")[0] in label:
                log_match = (rva, off)
                break

        if log_match and log_match[0] is not None:
            host_rva = log_match[0]
            host_source = "log"
        else:
            host_rva = db["offsets"][al_id]
            host_source = "db_parse"

        sys.stderr.write(f"\n[{name}] al={al_id} host_rva=0x{host_rva:x} ({host_source})\n")

        if mech == "byte_patch_nop4":
            hits = find_byte_pattern(pe["read"], host_rva, b"\xC6\x43\x08\x01")
            results[name] = dict(
                host_al=al_id, host_rva_hex=f"0x{host_rva:x}",
                host_source=host_source,
                old_offset_hex=f"0x{old_off:x}",
                mechanism=mech,
                new_offset_candidates_hex=[f"0x{h:x}" for h in hits],
            )
        else:
            calls = scan_e8(pe["read"], host_rva)
            results[name] = dict(
                host_al=al_id, host_rva_hex=f"0x{host_rva:x}",
                host_source=host_source,
                old_offset_hex=f"0x{old_off:x}",
                mechanism=mech,
                e8_destinations=[
                    dict(offset_hex=f"0x{o:x}", target_rva_hex=f"0x{t:x}")
                    for o, t in calls[:50]
                ],
            )

    # Cross-reference: find E8 destinations called by multiple host functions.
    # The destination called by the most input-related host functions is the
    # candidate predicate for that group of hooks. We only count destinations
    # that fall inside the executable (positive RVAs); rel32 sign-extension
    # produces sentinel values for jumps to imports/thunks which we skip.
    dest_to_hosts = defaultdict(set)
    for name, info in results.items():
        for c in info.get("e8_destinations", []):
            txt = c["target_rva_hex"]
            if txt.startswith("0x-"):
                continue   # skip negative (likely import-thunk) targets
            t = int(txt, 16)
            if t < 0x1000 or t > pe["sections"][-1][2]:
                continue
            dest_to_hosts[t].add(name)
    shared = sorted(dest_to_hosts.items(), key=lambda kv: -len(kv[1]))
    predicate_candidates = []
    for d, h in shared[:50]:
        if len(h) >= 2:
            alid = None
            for i, v in enumerate(db["offsets"]):
                if v == d:
                    alid = i
                    break
            predicate_candidates.append(dict(
                rva_hex=f"0x{d:x}", new_al_id=alid,
                host_count=len(h), hosts=sorted(h)))
        if len(predicate_candidates) >= 10:
            break

    out = dict(
        starfield_version=db["game_version"],
        image_base_hex=f"0x{pe['image_base']:x}",
        results=results,
        predicate_candidates=predicate_candidates,
        derivation_notes=[
            "host_source='log' means RVA was extracted from a SimultaneousInput.log "
            "skip message; that's the runtime-truth resolution.",
            "host_source='db_parse' means we used m_v5[al_id] from the AL DB file "
            "directly. This may diverge from runtime resolution if a prior process "
            "created the COMMONLIB_IDDB_OFFSETS_<ver> named map with different data.",
            "predicate_candidates is the set of E8 destinations shared across "
            "host bodies; the most-shared destination (typically 0x3660ab0 in "
            "1.16.236) is the runtime equivalent of the original IsUsingGamepad.",
        ],
    )
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
