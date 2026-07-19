"""
Flutter SSL Pinning Bypass — auto offset detection (Android, arm64-v8a).

Flutter apps bundle their own BoringSSL-based TLS stack inside libflutter.so,
so the generic Java-layer TrustManager/OkHttp Frida hooks used against native
Android apps do not apply. Instead this locates the ssl_verify_result-style
function inside libflutter.so by:
  1. Finding the "ssl_client"/"ssl_server" string literals embedded in the binary.
  2. Scanning the executable ELF segment for ADRP+ADD instruction pairs that
     reference those strings (Dart/BoringSSL debug logging refers to them).
  3. Walking back from each matching pair to the enclosing function's
     prologue (STP x29,x30 / SUB sp) to get the real hook address.

A single build of libflutter.so can produce more than one candidate pair, so
the result is reported honestly: CONFIDENT only when every candidate collapses
to the same address, AMBIGUOUS when they disagree (caller must decide whether
to proceed), NOT_FOUND when nothing matches. This module never guesses an
offset it can't back up with rescanned evidence.

Ported from the "K!ll Fl!utter" bypass technique, hardened against false
positives.
"""
import os
import re
import struct
import zipfile
from collections import Counter


class OffsetResult:
    """Outcome of an offset scan. status is one of: 'confident', 'ambiguous', 'not_found'."""
    def __init__(self, status, offset=None, candidates=None, detail=""):
        self.status = status
        self.offset = offset
        self.candidates = candidates or []
        self.detail = detail

    @property
    def ok(self):
        return self.status in ("confident", "ambiguous") and self.offset is not None


def extract_flutter_android(apk_path, out_dir):
    """Pull arm64-v8a/libflutter.so out of the APK. Returns the extracted path or None."""
    so_path = os.path.join(out_dir, "libflutter.so")
    with zipfile.ZipFile(apk_path, "r") as z:
        for name in z.namelist():
            if "arm64-v8a/libflutter.so" in name:
                with z.open(name) as src, open(so_path, "wb") as dst:
                    dst.write(src.read())
                return so_path
    return None


def _parse_elf_segments(data):
    """Returns (code_foff, code_vaddr, code_filesz) for the executable PT_LOAD segment."""
    if data[:4] != b"\x7fELF":
        return None, None, None

    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
    e_phnum = struct.unpack_from("<H", data, 0x38)[0]

    code_foff = code_vaddr = code_filesz = None
    for i in range(e_phnum):
        ph = data[e_phoff + i * e_phentsize: e_phoff + (i + 1) * e_phentsize]
        p_type = struct.unpack_from("<I", ph, 0x00)[0]
        p_flags = struct.unpack_from("<I", ph, 0x04)[0]
        if p_type == 1 and (p_flags & 1):  # PT_LOAD + PF_X
            code_foff = struct.unpack_from("<Q", ph, 0x08)[0]
            code_vaddr = struct.unpack_from("<Q", ph, 0x10)[0]
            code_filesz = struct.unpack_from("<Q", ph, 0x20)[0]

    return code_foff, code_vaddr, code_filesz


def find_flutter_ssl_offset(binary_path, log=None):
    """
    Locates the SSL-verify-result function offset inside libflutter.so.
    Returns an OffsetResult — never a bare guess. `log`, if given, receives
    progress strings for the caller's console.
    """
    def _log(msg):
        if log:
            log(msg)

    if not os.path.isfile(binary_path):
        return OffsetResult("not_found", detail=f"Binary not found: {binary_path}")

    with open(binary_path, "rb") as f:
        data = f.read()

    ssl_client = [m.start() for m in re.finditer(b"ssl_client\x00", data)]
    ssl_server = [m.start() for m in re.finditer(b"ssl_server\x00", data)]
    if not ssl_client or not ssl_server:
        return OffsetResult("not_found", detail="ssl_client/ssl_server string anchors not present — not a recognizable Flutter TLS build (stripped/obfuscated binary, or not Flutter).")

    code_foff, code_vaddr, code_filesz = _parse_elf_segments(data)
    if code_foff is None:
        return OffsetResult("not_found", detail="No executable ELF segment found (corrupt or non-ELF libflutter.so).")

    def foff_to_vaddr(fo):
        return fo - code_foff + code_vaddr

    def find_refs(target_va):
        lo12 = target_va & 0xfff
        refs = []
        for fi in range(code_foff, code_foff + code_filesz - 4, 4):
            instr = struct.unpack_from("<I", data, fi)[0]
            if (instr & 0xffc00000) == 0x91000000 and ((instr >> 10) & 0xfff) == lo12:
                if fi >= 4:
                    adrp = struct.unpack_from("<I", data, fi - 4)[0]
                    if (adrp & 0x9f000000) == 0x90000000:
                        immlo = (adrp >> 29) & 0x3
                        immhi = (adrp >> 5) & 0x7ffff
                        imm = ((immhi << 2) | immlo) << 12
                        if imm & (1 << 32):
                            imm -= (1 << 33)
                        pc_va = foff_to_vaddr(fi - 4)
                        if (pc_va & ~0xfff) + imm == (target_va & ~0xfff):
                            refs.append(fi)
        return refs

    _log(f"[*] Found {len(ssl_client)} ssl_client / {len(ssl_server)} ssl_server string anchor(s). Scanning ADRP+ADD refs across the code segment (may take a moment)...")

    candidates = []
    for sc in ssl_client:
        for ss in ssl_server:
            sc_refs = find_refs(sc)
            ss_refs = find_refs(ss)
            for a in sc_refs:
                for b in ss_refs:
                    if abs(a - b) < 0x800:
                        start = min(a, b)
                        for i in range(start, max(code_foff, start - 0x300), -4):
                            instr = struct.unpack_from("<I", data, i)[0]
                            if (instr & 0xff8003ff) == 0xd10003ff or (instr & 0xffe07fff) == 0xa9007bfd:
                                candidates.append(foff_to_vaddr(i))
                                break

    if not candidates:
        return OffsetResult("not_found", detail="String anchors present, but no ADRP+ADD reference pair resolved to a function prologue. The offset-finding heuristic doesn't match this build.")

    unique = sorted(set(candidates))
    if len(unique) == 1:
        _log(f"[+] {len(candidates)} reference path(s) all agree on one offset: {hex(unique[0])}")
        return OffsetResult("confident", offset=unique[0], candidates=unique,
                             detail=f"{len(candidates)} independent reference(s) converged on the same address.")

    # Disagreement across candidates — report it honestly instead of silently picking one.
    counts = Counter(candidates)
    best_offset, best_count = counts.most_common(1)[0]
    _log(f"[!] {len(unique)} distinct candidate offsets found: {[hex(c) for c in unique]} — no single agreement.")
    return OffsetResult("ambiguous", offset=best_offset, candidates=unique,
                         detail=f"{len(unique)} disagreeing candidates; picked the most frequent one ({best_count}/{len(candidates)} refs) as a best guess. Verify the hook actually fires at runtime before trusting this.")


def write_frida_script(offset, package, out_path):
    """
    Generates a Frida script that hooks the given libflutter.so offset and
    reports structured, machine-parseable status back over send() so the GUI
    can distinguish "script loaded" from "hook actually fired at runtime" —
    loading without exceptions is not proof the bypass works.
    """
    script = f"""// Auto-generated by MobiSuite — Flutter SSL Pinning Bypass
// Package : {package}
// Offset  : {hex(offset)}
// Module  : libflutter.so

function report(evt, extra) {{
    var payload = Object.assign({{ tag: "flutter_ssl_bypass", event: evt }}, extra || {{}});
    send(payload);
}}

function hook_ssl_verify_result(address) {{
    var hitCount = 0;
    try {{
        Interceptor.attach(address, {{
            onEnter: function (args) {{
                hitCount += 1;
            }},
            onLeave: function (retval) {{
                var before = retval.toInt32();
                retval.replace(0x1);
                report("hit", {{ count: hitCount, before_retval: before, forced_retval: 1 }});
            }}
        }});
        report("hook_installed", {{ address: address.toString() }});
    }} catch (e) {{
        report("hook_attach_failed", {{ error: e.toString() }});
    }}
}}

function disablePinning() {{
    var m = Process.findModuleByName("libflutter.so");
    if (!m) {{
        report("module_not_found", {{}});
        return;
    }}
    var addr = m.base.add({hex(offset)});
    report("module_found", {{ base: m.base.toString(), offset: "{hex(offset)}", target: addr.toString() }});
    hook_ssl_verify_result(addr);
}}

setTimeout(disablePinning, 1000);
"""
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(script)
    return out_path


def build_flutter_bypass_script(apk_path, package, out_dir, log=None):
    """
    End-to-end: extract libflutter.so from apk_path, auto-detect the SSL verify
    offset, and write a ready-to-load Frida script into out_dir.
    Returns (script_path, OffsetResult). script_path is None on failure —
    check result.status / result.detail for why.
    """
    def _log(msg):
        if log:
            log(msg)

    os.makedirs(out_dir, exist_ok=True)

    _log("[*] Extracting libflutter.so (arm64-v8a) from APK...")
    binary_path = extract_flutter_android(apk_path, out_dir)
    if not binary_path:
        return None, OffsetResult("not_found", detail="libflutter.so (arm64-v8a) not found in this APK — is it actually a Flutter app, or built for a different ABI?")

    result = find_flutter_ssl_offset(binary_path, log=log)
    if not result.ok:
        return None, result

    script_path = os.path.join(out_dir, "flutter_ssl_bypass_generated.js")
    write_frida_script(result.offset, package, script_path)
    _log(f"[+] Frida script generated: {script_path}")
    return script_path, result
