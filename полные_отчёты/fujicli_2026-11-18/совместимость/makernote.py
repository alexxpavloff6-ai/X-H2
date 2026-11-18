"""Минимальное чтение MakerNote Fujifilm из JPEG (только чтение файла)."""
import struct, sys
NAMES = {0x1001:'Sharpness',0x1002:'WhiteBalance',0x1003:'Saturation(Color)',0x100A:'WBFineTune',0x100E:'NoiseReduction',
         0x1040:'ShadowTone',0x1041:'HighlightTone',0x1045:'LensModOpt',0x1047:'GrainEffectRoughness',0x1048:'ColorChromeEffect',
         0x104E:'ColorChromeFXBlue',0x1401:'FilmMode',0x1402:'DynamicRangeSetting',0x140B:'AutoDynamicRange',0x104F:'Clarity'}
def mn(path):
    b = open(path, 'rb').read(); i = b.find(b'FUJIFILM' + bytes([12, 0, 0, 0])); assert i > 0
    off = struct.unpack_from('<I', b, i + 8)[0]; n = struct.unpack_from('<H', b, i + off)[0]; out = {}
    for k in range(n):
        tag, typ, cnt, val = struct.unpack_from('<HHII', b, i + off + 2 + 12 * k)
        if tag not in NAMES: continue
        if typ == 3 and cnt == 1: v = val & 0xFFFF
        elif typ == 8 and cnt == 1: v = struct.unpack('<h', struct.pack('<H', val & 0xFFFF))[0]
        elif typ == 9 and cnt == 1: v = struct.unpack('<i', struct.pack('<I', val))[0]
        elif typ in (8, 9) and cnt == 2: v = struct.unpack_from('<2i', b, i + val)
        else: v = (typ, cnt, val)
        out[NAMES[tag]] = v
    return out
files = sys.argv[1:]; res = {f: mn(f) for f in files}
keys = sorted({k for r in res.values() for k in r})
print('tag'.ljust(22) + ''.join(f[:24].ljust(26) for f in files))
for k in keys: print(k.ljust(22) + ''.join(str(res[f].get(k, '-')).ljust(26) for f in files))
