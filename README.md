# Jazz Jackrabbit 2 .j2l Map Password Protection Remover

## j2l_tool.py

```
j2l_tool - Jazz Jackrabbit 2 .j2l password tool.

  j2l_tool.py info   <file>              password status
  j2l_tool.py strip  <file> [out]        remove password (use - for stdout)
  j2l_tool.py set    <pw> <file> [out]   set password
  j2l_tool.py hash   <pw>                compute hash
  j2l_tool.py coll   <file>              find colliding password
  j2l_tool.py pass   <file>              show stored hash hex
```

## Description

### File format

262-byte header followed by 4 zlib-compressed blocks (Data1-4).

```
offset  size  field
0x000   180   copyright (ignored)
0x0B4   4     magic "LEVL"
0x0B8   3     password hash (big-endian)
0x0BB   1     hide level (bool)
0x0BC   32    level name (null-terminated)
0x0DC   2     version (0x0202 = 1.23, 0x0203 = TSF)
0x0DE   4     file size
0x0E2   4     crc32 of compressed blocks
0x0E6   4     CData1
0x0EA   4     UData1
0x0EE   4     CData2
0x0F2   4     UData2
0x0F6   4     CData3
0x0FA   4     UData3
0x0FE   4     CData4
0x102   4     UData4
0x106   var   Data1 (zlib)
```

### Data1 security markers

```
offset  size  field            passworded
0x00    2     JCSHorizOffset   (unchanged)
0x02    2     Security1        0xBA00
0x04    2     JCSVertOffset    (unchanged)
0x06    2     Security2        0xBE00
0x08    1     SecAndLayer      upper nibble != 0
0x09    1     MinLight
0x0A    1     StartLight
```

### Password hash

Thanks to the nature of CRC-32 is very easy to find collisions.. so no need to bruteforce the original password.

The table is build (RVA 0x4AF9C0) using polynomial `0xEDB88320`.


```
hash = crc32(password, seed=0) & 0x00FFFFFF
```

Stored big-endian at header 0xB8:

```
byte[0xB8] = (hash >> 16) & 0xFF
byte[0xB9] = (hash >> 8) & 0xFF
byte[0xBA] = hash & 0xFF
```

Pattern `0x00BABE` (bytes `BE BA 00`) = no password.

### References

```
RVA        description
0x40C57C   cmp [ebx+0x1387a8], 0xBABE
0x40CE79   and eax,0xff; shl eax,8; or eax,edx; shl eax,8; or eax,ecx
0x40CED2   cmp edx, eax
0x429090   crc32(seed, *data, len)
0x4290A8   crc table init
0x474010   case-insensitive strncmp
0x46375E   EM_SETPASSWORDCHAR
```

### Password check flow

1. Read 3 bytes header[0xB8..0xBA] as big-endian 24-bit integer.
2. If == 0x00BABE: no password -> load level.
3. Decompress Data1, check Security1==0xBA00, Security2==0xBE00, SecAndLayer[7:4]!=0.
4. If markers missing: "security envelope damaged".
5. Hash entered password: `crc32(pw_bytes, 0) & 0xFFFFFF`.
6. Compare: mismatch -> "password incorrect".

### Removing protection

1. Header[0xB8..0xBA] = `BE BA 00`.
2. Data1[2:4] = `00 00`.
3. Data1[6:8] = `00 00`.
4. Data1[8] &= 0x0F.
5. Recompress Data1, update CData1, recompute CRC32 at 0xE2, update FileSize at 0xDE.
