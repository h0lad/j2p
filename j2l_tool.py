#!/usr/bin/env python3
"""
j2l_tool - Jazz Jackrabbit 2 .j2l password tool.

  j2l_tool.py info   <file>              password status
  j2l_tool.py strip  <file> [out]        remove password (use - for stdout)
  j2l_tool.py set    <pw> <file> [out]   set password
  j2l_tool.py hash   <pw>                compute hash
  j2l_tool.py coll   <file>              find colliding password
  j2l_tool.py pass   <file>              show stored hash hex
"""

import struct, sys, zlib, os, random, string

HEADER_SIZE = 262
PW_OFF = 0xB8
SENTINEL = 0x00BABE

def hash_pw(pw: str) -> int:
    return zlib.crc32(pw.encode(), 0) & 0x00FFFFFF

def read_hash(data: bytearray) -> int:
    return (data[PW_OFF] << 16) | (data[PW_OFF+1] << 8) | data[PW_OFF+2]

def write_hash(data: bytearray, h: int):
    data[PW_OFF]   = (h >> 16) & 0xFF
    data[PW_OFF+1] = (h >> 8) & 0xFF
    data[PW_OFF+2] = h & 0xFF

def is_protected(data: bytearray) -> bool:
    return read_hash(data) != SENTINEL

def read_level(path: str) -> bytearray | None:
    if path == "-":
        try:
            return bytearray(sys.stdin.buffer.read())
        except:
            return None
    try:
        with open(path, "rb") as f:
            d = bytearray(f.read())
        if len(d) < HEADER_SIZE or d[0xB4:0xB8] != b"LEVL":
            return None
        return d
    except:
        return None

def write_level(path: str, data: bytes):
    if path == "-":
        sys.stdout.buffer.write(data)
    else:
        with open(path, "wb") as f:
            f.write(data)

def get_blocks(data: bytearray):
    hd = data[:HEADER_SIZE]
    offs = [0xE6, 0xEE, 0xF6, 0xFE]
    blocks, p = [], HEADER_SIZE
    for o in offs:
        cs = struct.unpack_from("<I", hd, o)[0]
        blocks.append(bytes(data[p:p+cs]))
        p += cs
    try:
        return zlib.decompress(blocks[0]), blocks
    except:
        return None, None

def get_fields(data: bytearray) -> dict:
    d1, _ = get_blocks(data)
    if d1 is None or len(d1) < 9:
        return {}
    return {
        "hash": read_hash(data),
        "prot": is_protected(data),
        "s1": struct.unpack_from("<H", d1, 2)[0],
        "s2": struct.unpack_from("<H", d1, 6)[0],
        "sl": d1[8],
        "layer": d1[8] & 0x0F,
        "env_ok": (struct.unpack_from("<H", d1, 2)[0] == 0xBA00 and
                    struct.unpack_from("<H", d1, 6)[0] == 0xBE00 and
                    (d1[8] & 0xF0) != 0),
    }

def rebuild(data: bytearray, blocks: list) -> bytes:
    for i, o in enumerate([0xE6, 0xEE, 0xF6, 0xFE]):
        struct.pack_into("<I", data, o, len(blocks[i]))
    crc = 0
    for bl in blocks:
        crc = zlib.crc32(bl, crc)
    struct.pack_into("<I", data, 0xE2, crc & 0xFFFFFFFF)
    out = bytes(data[:HEADER_SIZE]) + b"".join(blocks)
    struct.pack_into("<I", data, 0xDE, len(out))
    return bytes(data[:HEADER_SIZE]) + b"".join(blocks)

def collision(target: int) -> str | None:
    a = string.ascii_lowercase + string.digits
    for _ in range(50_000_000):
        pw = ''.join(random.choice(a) for _ in range(random.randint(4, 10)))
        if hash_pw(pw) == target:
            return pw
    return None

def cmd_info(path):
    d = read_level(path)
    if d is None: print("not a .j2l"); return 1
    f = get_fields(d)
    print(f"file:     {os.path.basename(path) if path != '-' else 'stdin'}")
    print(f"hash:     0x{f['hash']:06X}  (sentinel=0x{SENTINEL:06X})")
    print(f"password: {'YES' if f['prot'] else 'no'}")
    if f['prot']:
        print(f"sec1:     0x{f['s1']:04X} {'(ok)' if f['s1']==0xBA00 else '(BAD)'}")
        print(f"sec2:     0x{f['s2']:04X} {'(ok)' if f['s2']==0xBE00 else '(BAD)'}")
        print(f"seclayer: 0x{f['sl']:02X} layer={f['layer']} pw_nibble={'SET' if f['sl']&0xF0 else 'clear'}")
        print(f"envelope: {'INTACT' if f['env_ok'] else 'DAMAGED'}")
    return 0

def cmd_strip(path, out=None):
    d = read_level(path)
    if d is None: print("not a .j2l"); return 1
    if not is_protected(d): print("not protected"); return 0
    d1, blocks = get_blocks(d)
    if d1 is None: print("decompress failed"); return 1
    d1 = bytearray(d1)
    old = read_hash(d)
    write_hash(d, SENTINEL)
    d1[2:4] = b"\x00\x00"
    d1[6:8] = b"\x00\x00"
    d1[8] &= 0x0F
    blocks[0] = zlib.compress(bytes(d1))
    out_data = rebuild(d, blocks)
    out_path = out or path
    write_level(out_path, out_data)
    if out_path != "-":
        print(f"stripped 0x{old:06X} -> {out_path}")
    return 0

def cmd_set(pw, path, out=None):
    d = read_level(path)
    if d is None: print("not a .j2l"); return 1
    d1, blocks = get_blocks(d)
    if d1 is None: print("decompress failed"); return 1
    d1 = bytearray(d1)
    hsh = hash_pw(pw)
    write_hash(d, hsh)
    d1[2:4] = b"\x00\xBA"
    d1[6:8] = b"\x00\xBE"
    d1[8] |= 0x80
    blocks[0] = zlib.compress(bytes(d1))
    out_data = rebuild(d, blocks)
    out_path = out or path
    write_level(out_path, out_data)
    if out_path != "-":
        print(f"set '{pw}' hash=0x{hsh:06X} -> {out_path}")
    return 0

def cmd_hash(pw):
    v = hash_pw(pw)
    print(f"'{pw}' -> 0x{v:06X}  ({v>>16&0xFF:02X} {v>>8&0xFF:02X} {v&0xFF:02X})")
    return 0

def cmd_coll(path):
    d = read_level(path)
    if d is None: print("not a .j2l"); return 1
    if not is_protected(d): print("not protected"); return 0
    target = read_hash(d)
    print(f"hash=0x{target:06X} searching")
    pw = collision(target)
    if pw: print(pw)
    else: print("not found")
    return 0 if pw else 1

def cmd_pass(path):
    d = read_level(path)
    if d is None: print("not a .j2l"); return 1
    print(f"0x{read_hash(d):06X}")
    return 0

def main():
    if len(sys.argv) < 2:
        print(__doc__); return 1
    c, *a = sys.argv[1:]
    cmds = {"info": cmd_info, "strip": cmd_strip, "set": cmd_set,
            "hash": cmd_hash, "coll": cmd_coll, "pass": cmd_pass}
    if c not in cmds:
        print(f"unknown: {c}\n{__doc__}"); return 1
    try:
        return cmds[c](*a)
    except TypeError:
        print(f"usage: {cmds[c].__name__} needs more args")
        return 1

if __name__ == "__main__":
    sys.exit(main())
