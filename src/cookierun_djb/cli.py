from __future__ import annotations
import argparse, json, os, sys, tempfile
from pathlib import Path
from . import __version__
from .core import DjbError, parse_header, decrypt_djb, verify, parse_records, VerificationResult
from .forge import forge_file

def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as f: f.write(data)
        os.replace(temp_name, path)
    except Exception:
        try: os.unlink(temp_name)
        except OSError: pass
        raise

def _info(path: Path) -> int:
    h = parse_header(path.read_bytes())
    modes = [x for x, yes in (("AES-ECB", h.uses_ecb), ("AES-CBC", h.uses_cbc), ("FastLZ", h.uses_fastlz)) if yes]
    print(f"file        : {path.name}\nversion     : 0x{h.version:04x} (generation {h.generation})\nheader size : 0x{h.profile.header_size:02x}\nflags       : 0x{h.flags:02x} ({'+'.join(modes) or 'raw'})\nplain size  : {h.size}\ncrc32       : 0x{h.crc:08x}\nblake3      : {h.blake3.hex() if h.blake3 else '(none)'}\nsuffix size : {h.suffix_size}")
    return 0

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="cookierun-djb", description="Inspect, decrypt, verify and rebuild DJBF files")
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="command", required=True)
    p = sub.add_parser("info"); p.add_argument("input", type=Path)
    p = sub.add_parser("decrypt"); p.add_argument("input", type=Path); p.add_argument("-o", "--output", type=Path); p.add_argument("--build", choices=["kakao", "qq"], default="kakao"); p.add_argument("--verify", action="store_true"); p.add_argument("--json", action="store_true")
    p = sub.add_parser("batch"); p.add_argument("input_dir", type=Path); p.add_argument("output_dir", type=Path); p.add_argument("--build", choices=["kakao", "qq"], default="kakao"); p.add_argument("--verify", action="store_true"); p.add_argument("--json", action="store_true")
    p = sub.add_parser("forge"); p.add_argument("input", type=Path); p.add_argument("output", type=Path); p.add_argument("--generation", type=int, choices=[1, 2], default=2); p.add_argument("--build", choices=["kakao", "qq"], default="kakao"); p.add_argument("--mode", choices=["cbc", "ecb"], default="cbc")
    a = ap.parse_args(argv)
    try:
        if a.command == "info": return _info(a.input)
        if a.command == "forge":
            forge_file(a.input, a.output, generation=a.generation, build=a.build, mode=a.mode)
            print(f"built {a.output}"); return 0
        if a.command == "decrypt":
            data = a.input.read_bytes(); plain = decrypt_djb(data, a.build)
            if a.verify:
                verdict = verify(data, plain, a.build)
                if verdict in (VerificationResult.FAILED, VerificationResult.PARTIAL):
                    print(f"verification: {verdict.value}", file=sys.stderr)
                    if verdict == VerificationResult.FAILED: return 2
            dst = a.output or Path(str(a.input) + (".json" if a.json else ".bin"))
            payload = json.dumps(parse_records(plain), ensure_ascii=False, indent=2).encode() if a.json else plain
            _atomic_write(dst, payload); print(f"{a.input} -> {dst} ({len(plain)} bytes)"); return 0
        failures = 0; successes = 0
        for src in sorted(a.input_dir.rglob("*.djb")):
            try:
                data = src.read_bytes(); plain = decrypt_djb(data, a.build)
                if a.verify:
                    verdict = verify(data, plain, a.build)
                    if verdict == VerificationResult.FAILED: raise DjbError("integrity verification failed")
                    if verdict == VerificationResult.PARTIAL: print(f"PARTIAL VERIFY: {src}")
                rel = src.relative_to(a.input_dir)
                dst = a.output_dir / (str(rel) + (".json" if a.json else ".bin"))
                payload = json.dumps(parse_records(plain), ensure_ascii=False, indent=2).encode() if a.json else plain
                _atomic_write(dst, payload); successes += 1
            except (DjbError, OSError, ValueError) as exc:
                print(f"ERROR {src}: {exc}", file=sys.stderr); failures += 1
        print(f"{successes} decrypted, {failures} failed")
        return 0 if failures == 0 else 2
    except (DjbError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr); return 1

if __name__ == "__main__": raise SystemExit(main())
