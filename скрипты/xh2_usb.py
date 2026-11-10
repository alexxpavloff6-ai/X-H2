# -*- coding: utf-8 -*-
"""
xh2_usb.py - Fujifilm X-H2 over USB on Windows (WPD / MTP extension commands).

Commands:
  info                         device info and current values of all exposed properties (read-only)
  profile RAF                  upload RAF to the camera conversion buffer, print the 29-field D185 profile
  convert RAF OUT.jpg [opts]   in-camera RAW conversion with an optional recipe (JSON file or CLI flags)

Camera: PC Connection Mode = "USB RAW CONV./BACKUP RESTORE" for profile/convert. RAF must come from the same body.
Requires: Windows, Python 3.9+, comtypes (pip install comtypes). Uses the stock Microsoft MTP driver.

Safety: only these camera writes are possible -
  0x900C/0x900D (RAF -> conversion buffer), SetDevicePropValue 0xD185 (profile) and 0xD183 (start),
  DeleteObject only for result objects created by this run. Custom-setting slots (0xD18C..0xD1A5) are refused.

D185 profile (X-H2 fw 5.30): u16 count (29) at offset 0, then 29 x int32 LE at the end of the 625-byte buffer.
Index = rawji index + 1. Tones/color/sharpness/clarity x10, exposure in 1/1000 EV, WB applied only if field 11 = 2.
License: MIT
"""
import argparse, ctypes, json, os, struct, sys, time
from ctypes import POINTER, byref, c_ubyte, c_ulong, c_wchar_p, cast
import comtypes.client as cc
from comtypes import GUID

api = cc.GetModule('portabledeviceapi.dll')
typ = cc.GetModule('portabledevicetypes.dll')

# ---------------------------------------------------------------- WPD plumbing
def PK(fmt, pid):
    k = api._tagpropertykey(); k.fmtid = GUID(fmt); k.pid = pid
    return ctypes.pointer(k)

MTPX = '{4d545058-1a2e-4106-a357-771e0819fc56}'
CMN = '{F0422A9C-5DC8-4440-B5BD-5DF28835658A}'
K_CAT, K_ID, K_HR = PK(CMN, 1001), PK(CMN, 1002), PK(CMN, 1003)
K_OPCODE, K_PARAMS, K_RESP = PK(MTPX, 1001), PK(MTPX, 1002), PK(MTPX, 1003)
K_CTX, K_TOTAL, K_TOREAD, K_READ = PK(MTPX, 1006), PK(MTPX, 1007), PK(MTPX, 1008), PK(MTPX, 1009)
K_TOWRITE, K_DATA, K_OPTIMAL = PK(MTPX, 1010), PK(MTPX, 1012), PK(MTPX, 1013)
EXEC_NODATA, EXEC_READ, EXEC_WRITE, READ_DATA, WRITE_DATA, END_TRANSFER = 12, 13, 14, 15, 16, 17

READ_OPS = {0x1001, 0x1007, 0x1008, 0x1009, 0x1014, 0x1015}
WRITE_PROPS = {0xD185, 0xD183}
OK = 0x2001

def values():
    return cc.CreateObject(typ.PortableDeviceValues, interface=api.IPortableDeviceValues)

def params_coll(params):
    c = cc.CreateObject(typ.PortableDevicePropVariantCollection, interface=api.IPortableDevicePropVariantCollection)
    for p in params:
        tmp = values(); key = PK(MTPX, 9999); tmp.SetUnsignedIntegerValue(key, p)
        pv = tmp.GetValue(key); c.Add(byref(pv))
    return c

def command(cmd_id):
    v = values(); v.SetGuidValue(K_CAT, GUID(MTPX)); v.SetUnsignedIntegerValue(K_ID, cmd_id)
    return v

class Camera:
    def __init__(self):
        mgr = cc.CreateObject(api.PortableDeviceManager, interface=api.IPortableDeviceManager)
        n = c_ulong(0); mgr._IPortableDeviceManager__com_GetDevices(POINTER(c_wchar_p)(), byref(n))
        ids = (c_wchar_p * n.value)(); mgr._IPortableDeviceManager__com_GetDevices(cast(ids, POINTER(c_wchar_p)), byref(n))
        found = [ids[i] for i in range(n.value) if 'vid_04cb' in ids[i].lower()]
        if not found: sys.exit('No Fujifilm camera (VID 04CB) found among WPD devices')
        ci = values(); ci.SetStringValue(PK('{204D9F0C-2292-4080-9F42-40664E70F859}', 2), 'xh2_usb')
        self.dev = cc.CreateObject(api.PortableDevice, interface=api.IPortableDevice)
        self.dev.Open(found[0], ci)
        self.created = set()

    def close(self): self.dev.Close()

    def _send(self, v, what):
        r = self.dev.SendCommand(0, v)
        hr = r.GetErrorValue(K_HR)
        if hr: raise OSError('%s: HRESULT 0x%08X' % (what, hr & 0xFFFFFFFF))
        return r

    def _end(self, ctx):
        e = command(END_TRANSFER); e.SetStringValue(K_CTX, ctx)
        return self._send(e, 'END_DATA_TRANSFER').GetUnsignedIntegerValue(K_RESP)

    def read(self, op, params=()):
        """PTP operation with a device->host data phase. Returns (response code, bytes)."""
        if op not in READ_OPS: raise PermissionError('read op 0x%04X not allowed' % op)
        v = command(EXEC_READ); v.SetUnsignedIntegerValue(K_OPCODE, op)
        v.SetIPortableDevicePropVariantCollectionValue(K_PARAMS, params_coll(params))
        r = self._send(v, 'EXEC_READ 0x%04X' % op)
        ctx, total = r.GetStringValue(K_CTX), r.GetUnsignedLargeIntegerValue(K_TOTAL)
        try: chunk = r.GetUnsignedIntegerValue(K_OPTIMAL)
        except Exception: chunk = 262144
        data = b''
        try:
            while len(data) < total:
                n = min(chunk, total - len(data))
                rv = command(READ_DATA); rv.SetStringValue(K_CTX, ctx); rv.SetUnsignedIntegerValue(K_TOREAD, n)
                rv.SetBufferValue(K_DATA, (c_ubyte * n)(), n)
                rr = self._send(rv, 'READ_DATA')
                p, size = rr.GetBufferValue(K_DATA)
                got = ctypes.string_at(p, size); ctypes.windll.ole32.CoTaskMemFree(p)
                k = rr.GetUnsignedIntegerValue(K_READ); data += got[:k]
                if k == 0: break
        finally:
            resp = self._end(ctx)
        return resp, data

    def write(self, op, params, payload):
        """PTP operation with a host->device data phase (whitelisted)."""
        if op == 0x1016:
            if params[0] not in WRITE_PROPS: raise PermissionError('writing property 0x%04X is refused' % params[0])
        elif op not in (0x900C, 0x900D):
            raise PermissionError('write op 0x%04X not allowed' % op)
        v = command(EXEC_WRITE); v.SetUnsignedIntegerValue(K_OPCODE, op)
        v.SetIPortableDevicePropVariantCollectionValue(K_PARAMS, params_coll(params))
        v.SetUnsignedLargeIntegerValue(K_TOTAL, len(payload))
        r = self._send(v, 'EXEC_WRITE 0x%04X' % op)
        ctx = r.GetStringValue(K_CTX)
        try: chunk = min(max(r.GetUnsignedIntegerValue(K_OPTIMAL), 65536), 1 << 20)
        except Exception: chunk = 262144
        try:
            for o in range(0, len(payload), chunk):
                part = payload[o:o + chunk]
                w = command(WRITE_DATA); w.SetStringValue(K_CTX, ctx); w.SetUnsignedIntegerValue(K_TOWRITE, len(part))
                w.SetBufferValue(K_DATA, (c_ubyte * len(part)).from_buffer_copy(part), len(part))
                self._send(w, 'WRITE_DATA')
        finally:
            resp = self._end(ctx)
        if resp != OK: raise RuntimeError('op 0x%04X -> response 0x%04X' % (op, resp))

    def delete_own(self, handle):
        if handle not in self.created: raise PermissionError('refusing to delete an object this run did not create')
        v = command(EXEC_NODATA); v.SetUnsignedIntegerValue(K_OPCODE, 0x100B)
        v.SetIPortableDevicePropVariantCollectionValue(K_PARAMS, params_coll((handle, 0)))
        return self._send(v, 'DeleteObject').GetUnsignedIntegerValue(K_RESP)

    def handles(self):
        resp, d = self.read(0x1007, (0xFFFFFFFF, 0, 0))
        if resp != OK: raise RuntimeError('GetObjectHandles -> 0x%04X' % resp)
        n = struct.unpack_from('<I', d)[0] if len(d) >= 4 else 0
        return [struct.unpack_from('<I', d, 4 + 4 * i)[0] for i in range(n)]

# ---------------------------------------------------------------- PTP datasets
class Reader:
    def __init__(self, b): self.b, self.o = b, 0
    def u8(self): v = self.b[self.o]; self.o += 1; return v
    def u16(self): v = struct.unpack_from('<H', self.b, self.o)[0]; self.o += 2; return v
    def u32(self): v = struct.unpack_from('<I', self.b, self.o)[0]; self.o += 4; return v
    def arr16(self): return [self.u16() for _ in range(self.u32())]
    def string(self):
        n = self.u8(); s = self.b[self.o:self.o + 2 * n].decode('utf-16-le', 'replace').rstrip('\0'); self.o += 2 * n; return s

def device_info(cam):
    resp, d = cam.read(0x1001)
    r = Reader(d); r.u16(); r.u32(); r.u16(); vext = r.string(); r.u16()
    ops, events, props = r.arr16(), r.arr16(), r.arr16(); r.arr16(); r.arr16()
    return {'vendor_ext': vext, 'manufacturer': r.string(), 'model': r.string(), 'firmware': r.string(), 'ops': ops, 'props': props}

def objectinfo(size):
    name = 'FUP_FILE.dat\0'.encode('utf-16-le')
    return (struct.pack('<IHHI', 0, 0xF802, 0, size) + struct.pack('<HIII', 0, 0, 0, 0) + struct.pack('<III', 0, 0, 0)
            + struct.pack('<IHII', 0, 0, 0, 0) + bytes([len(name) // 2]) + name + b'\0\0\0')

# ---------------------------------------------------------------- D185 profile
FIELD = {'exposure': 5, 'dr': 6, 'dr_priority': 7, 'film': 8, 'grain': 9, 'cce': 10, 'wb_mode': 11, 'wb': 12,
         'wb_r': 13, 'wb_b': 14, 'kelvin': 15, 'highlight': 16, 'shadow': 17, 'color': 18, 'sharpness': 19, 'nr': 20,
         'lmo': 21, 'color_space': 22, 'mono_warm_cool': 23, 'smooth_skin': 24, 'fx_blue': 25, 'mono_magenta_green': 26,
         'clarity': 27}
FILMS = {'provia': 1, 'velvia': 2, 'astia': 3, 'monochrome': 6, 'classic_chrome': 11, 'acros': 12, 'classic_neg': 17, 'reala_ace': 20}
GRAIN = {'off': 1, 'weak_small': 2, 'strong_small': 3, 'weak_large': 4, 'strong_large': 5}
LEVEL = {'off': 1, 'weak': 2, 'strong': 3}
WB = {'auto': 2, 'daylight': 4, 'incandescent': 6, 'kelvin': 0x8007}
NR = {0: 0x2000, -4: 0x8000}          # verified steps only
X10 = {'highlight', 'shadow', 'color', 'sharpness', 'clarity', 'mono_warm_cool', 'mono_magenta_green'}

def fields(profile):
    n = struct.unpack_from('<H', profile)[0]; off = len(profile) - 4 * n
    return [struct.unpack_from('<i', profile, off + 4 * i)[0] for i in range(n)]

def apply_recipe(profile, recipe):
    """Return (patched profile, {index: value}). Unspecified fields keep the as-shot values."""
    ch = {}
    for key, val in recipe.items():
        if key not in FIELD: raise KeyError('unknown recipe key: %s' % key)
        if key == 'film': val = FILMS[val]
        elif key == 'grain': val = GRAIN[val]
        elif key in ('cce', 'fx_blue', 'smooth_skin'): val = LEVEL[val]
        elif key == 'wb': ch[FIELD['wb_mode']] = 2; val = WB[val]
        elif key == 'nr': val = NR[int(val)]
        elif key == 'exposure': val = round(float(val) * 1000)
        elif key == 'color_space': val = {'srgb': 1, 'adobe_rgb': 2}[val]
        elif key == 'lmo': val = 1 if val else 2
        elif key in X10: val = round(float(val) * 10)
        ch[FIELD[key]] = int(val)
    if ch.get(12) == 0x8007 and 15 not in ch: raise ValueError('wb "kelvin" needs "kelvin": <K>')
    b = bytearray(profile); n = struct.unpack_from('<H', b)[0]; off = len(b) - 4 * n
    for i, v in ch.items(): struct.pack_into('<i', b, off + 4 * i, v)
    return bytes(b), ch

# ---------------------------------------------------------------- operations
def upload(cam, raf_path):
    info = device_info(cam)
    if 0xD185 not in info['props'] or 0xD183 not in info['props']:
        sys.exit('Camera is not in "USB RAW CONV./BACKUP RESTORE" mode')
    raf = open(raf_path, 'rb').read()
    cam.write(0x900C, [0, 0, 0], objectinfo(len(raf)))
    cam.write(0x900D, [], raf)
    resp, profile = cam.read(0x1015, (0xD185,))
    if resp != OK or not profile: raise RuntimeError('D185 not readable after upload (0x%04X)' % resp)
    return profile

def convert(cam, profile, full, timeout=90):
    before = set(cam.handles())
    cam.write(0x1016, [0xD185], profile)
    cam.write(0x1016, [0xD183], struct.pack('<H', 1 if full else 0))
    t0 = time.time()
    while time.time() - t0 < timeout:
        new = [h for h in cam.handles() if h not in before]
        if new: break
        time.sleep(1)
    else:
        raise TimeoutError('conversion timeout')
    h = new[0]; cam.created.add(h)
    resp, jpg = cam.read(0x1009, (h,))
    if resp != OK: raise RuntimeError('GetObject -> 0x%04X' % resp)
    cam.delete_own(h)
    return jpg

def cmd_info(a):
    cam = Camera()
    try:
        info = device_info(cam)
        print('%s %s, firmware %s, %s' % (info['manufacturer'], info['model'], info['firmware'], info['vendor_ext']))
        print('operations:', ' '.join('%04X' % o for o in info['ops']))
        for p in info['props']:
            resp, d = cam.read(0x1015, (p,))
            print('%04X  resp %04X  %s' % (p, resp, d.hex()[:64]))
    finally:
        cam.close()

def cmd_profile(a):
    cam = Camera()
    try:
        f = fields(upload(cam, a.raf))
        names = {v: k for k, v in FIELD.items()}
        for i, v in enumerate(f): print('%2d %-20s %d' % (i, names.get(i, '?'), v))
    finally:
        cam.close()

def cmd_convert(a):
    recipe = json.load(open(a.recipe, encoding='utf-8-sig')) if a.recipe else {}
    for key in FIELD:
        v = getattr(a, key, None)
        if v is not None: recipe[key] = v
    if os.path.exists(a.out): sys.exit('output exists: %s' % a.out)
    cam = Camera()
    try:
        base = upload(cam, a.raf)
        prof, ch = apply_recipe(base, recipe)
        jpg = convert(cam, prof, a.full)
    finally:
        cam.close()
    open(a.out, 'wb').write(jpg)
    print('saved %s (%d bytes), changed fields %s' % (a.out, len(jpg), dict(sorted(ch.items()))))

def main():
    ap = argparse.ArgumentParser(description='Fujifilm X-H2 USB tool (Windows WPD)')
    sub = ap.add_subparsers(dest='cmd', required=True)
    sub.add_parser('info').set_defaults(fn=cmd_info)
    p = sub.add_parser('profile'); p.add_argument('raf'); p.set_defaults(fn=cmd_profile)
    c = sub.add_parser('convert'); c.add_argument('raf'); c.add_argument('out')
    c.add_argument('--recipe', help='JSON file, keys as in FIELD'); c.add_argument('--full', action='store_true')
    c.add_argument('--film', choices=FILMS); c.add_argument('--grain', choices=GRAIN)
    c.add_argument('--cce', choices=LEVEL); c.add_argument('--fx_blue', choices=LEVEL); c.add_argument('--wb', choices=WB)
    c.add_argument('--color_space', choices=('srgb', 'adobe_rgb')); c.add_argument('--nr', type=int, choices=sorted(NR))
    for k in ('kelvin', 'wb_r', 'wb_b', 'dr'): c.add_argument('--' + k, type=int)
    for k in ('exposure',) + tuple(sorted(X10)): c.add_argument('--' + k, type=float)
    c.set_defaults(fn=cmd_convert)
    a = ap.parse_args(); a.fn(a)

if __name__ == '__main__':
    main()
