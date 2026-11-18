# -*- coding: utf-8 -*-
"""
Проверка, принимает ли X-H2 записи в формате fujicli (27d3a6b). Разрешено владельцем 18.11.2026.
Транспорт, чтения и загрузка RAF — из проверенного PTP_чтение_2026-11-10/xh2_convert_usb.py (он исполняется до блока main).

render : загрузить RAF; проявить с родным профилем D185 (625 байт) и с профилем в раскладке fujicli
         (счётчик 29 + область кода 0x1FF + 29 полей = 629 байт); третья проявка — fujicli-профиль
         с exposure_offset (позиция fujicli 4) = +1000, чтобы проверить нумерацию полей без сдвига.
         Записи: 0x900C/0x900D (RAF), 0xD185, 0xD183; удаляются только наши временные JPEG.
recipe : выбрать слот C7 (0xD18C), прочитать 0xD18D..0xD1A5, записать ТЕ ЖЕ байты в свойства, которые
         записал бы fujicli (правила присутствия и порядок из fml/trait.cue), прочитать обратно,
         вернуть исходный 0xD18C. Значения не меняются.
grain  : (отдельно разрешено владельцем) в C7 записать Grain Effect = 0x01 — канонический код Off, который пишет fujicli.
set    : (разрешено владельцем 18.11) в слот SLOT записать одно свойство PROP = VALUE (u16), прочитать обратно.
usage: python fujicli_compat.py render|recipe|grain <outdir> | set <outdir> <slot> <prop_hex> <value>
"""
import sys, os, struct, json

HERE = os.path.dirname(os.path.abspath(__file__))
PTP = os.path.normpath(os.path.join(HERE, '..', '..', 'PTP_чтение_2026-11-10'))
RAF = os.path.join(PTP, 'кадры_слотов', 'DSCF0324.RAF')
MODE, OUT = sys.argv[1], sys.argv[2]
assert MODE in ('render', 'recipe', 'grain', 'set')
if MODE == 'set':
    SET_SLOT, SET_PROP = int(sys.argv[3]), int(sys.argv[4], 16)
    SET_VAL = bytes.fromhex(sys.argv[5][4:]) if sys.argv[5].startswith('hex:') else struct.pack('<H', int(sys.argv[5], 0) & 0xFFFF)

src = open(os.path.join(PTP, 'xh2_convert_usb.py'), encoding='utf-8').read().split('# ---- main ----')[0]
sys.argv = [sys.argv[0], os.path.join(PTP, 'xh2_read.py'), RAF, OUT]
exec(compile(src, 'xh2_convert_usb', 'exec'))

SLOT = 7
RECIPE_PROPS = list(range(0xD18D, 0xD1A5))          # D18D..D1A4 — то, что знает fujicli
if MODE == 'recipe':
    WRITE_PROPS.clear(); WRITE_PROPS.update({0xD18C, *RECIPE_PROPS})
elif MODE == 'grain':
    WRITE_PROPS.clear(); WRITE_PROPS.update({0xD18C, 0xD195})
elif MODE == 'set':
    assert SET_PROP in (0xD195, 0xD1A5, 0xD1A1, 0xD1A2, 0xD18E, 0xD199, 0xD18D) and 1 <= SET_SLOT <= 7
    WRITE_PROPS.clear(); WRITE_PROPS.update({0xD18C, SET_PROP})
else:
    WRITE_PROPS.clear(); WRITE_PROPS.update({0xD185, 0xD183})

MONO = {6, 7, 8, 9, 0xC, 0xD, 0xE, 0xF}              # monochrome*/acros*
SEPIA = 0xA

def u16(b): return struct.unpack('<H', b[:2])[0]

def fujicli_writes(v):
    """Порядок записи: обязательные поля, затем зависимые после тех, от кого зависят (как DAG в fujicodegen)."""
    q, film, wb, drp = u16(v[0xD18F]), u16(v[0xD192]), u16(v[0xD199]), u16(v[0xD191])
    order = [0xD18D, 0xD18F]
    if q != 0x01: order.append(0xD18E)                        # image_size только не для RAW
    order += [0xD192]
    if film in MONO: order += [0xD193, 0xD194]                # монохромная тонировка только для ч/б
    if film not in MONO and film != SEPIA: order.append(0xD19F)  # color не для ч/б и сепии
    order += [0xD195, 0xD196, 0xD197, 0xD198, 0xD199, 0xD19A, 0xD19B]
    if wb == 0x8007: order.append(0xD19C)                     # кельвины только при WB = temperature
    order += [0xD1A0, 0xD1A1, 0xD1A2, 0xD1A3, 0xD1A4, 0xD191]
    if drp == 0x00: order += [0xD190, 0xD19D, 0xD19E]          # DR и тона только при DR priority = off
    return order

def read_props(tag):
    vals = {}
    for p in RECIPE_PROPS + [0xD1A5]:
        resp, d = rd(0x1015, (p,))
        log('%s 0x%04X resp 0x%04X data %s' % (tag, p, resp, d.hex()))
        if resp == 0x2001: vals[p] = d
    return vals

def wr_soft(op, params, payload):
    """Как wr, но отказ камеры записывается, а не обрывает прогон."""
    try:
        wr(op, params, payload); return 0x2001
    except Stop as e:
        log('REJECTED:', e); return str(e)

result = {'mode': MODE}
mgr = cc.CreateObject(api.PortableDeviceManager, interface=api.IPortableDeviceManager)
cnt = c_ulong(0); mgr._IPortableDeviceManager__com_GetDevices(POINTER(c_wchar_p)(), byref(cnt))
ids = (c_wchar_p * cnt.value)(); mgr._IPortableDeviceManager__com_GetDevices(cast(ids, POINTER(c_wchar_p)), byref(cnt))
devid = [ids[i] for i in range(cnt.value) if 'vid_04cb' in ids[i].lower()][0]
ci = new_values(); ci.SetStringValue(PK(CLI, 2), 'XH2 fujicli compat')
dev = cc.CreateObject(api.PortableDevice, interface=api.IPortableDevice); dev.Open(devid, ci)
our_handles = set()
orig_slot = None
try:
    resp, info = rd(0x1001)
    if b'\x85\xd1' not in info or b'\x83\xd1' not in info: raise Stop('камера не в режиме USB RAW CONV./BACKUP RESTORE')
    resp, d = rd(0x1015, (0xD18C,)); orig_slot = d; log('D18C before = %s' % d.hex())

    if MODE == 'render':
        pre_handles = set(handles())
        raf = open(RAF, 'rb').read(); log('RAF %s %d bytes' % (os.path.basename(RAF), len(raf)))
        wr(0x900C, [0, 0, 0], objectinfo(len(raf))); wr(0x900D, [], raf)
        resp, base = rd(0x1015, (0xD185,))
        if resp != 0x2001 or len(base) != 625: raise Stop('D185: resp 0x%04X len %d, ожидалось 625' % (resp, len(base)))
        vals = [struct.unpack_from('<i', base, 513 + 4 * i)[0] for i in range(28)]
        log('D185 native: count %d, fields from 513:' % u16(base), vals)
        fj = struct.pack('<h', 29) + base[2:513] + b''.join(struct.pack('<i', x) for x in vals + [0])
        assert len(fj) == 629
        fj_ev = bytearray(fj); struct.pack_into('<i', fj_ev, 513 + 4 * 4, 1000); fj_ev = bytes(fj_ev)
        result['native'] = len(convert(base, 'native_625'))
        for tag, prof in (('fujicli_629', fj), ('fujicli_629_ev+1', fj_ev)):
            with open(os.path.join(OUT, 'profile_%s.bin' % tag), 'wb') as f: f.write(prof)
            r = wr_soft(0x1016, [0xD185], prof)
            rb_resp, rb = rd(0x1015, (0xD185,))
            log('%s: write -> %s; readback 0x%04X len %d count %d' % (tag, r, rb_resp, len(rb), u16(rb) if rb else -1))
            result[tag] = {'write': r, 'readback_len': len(rb),
                           'readback_fields': [struct.unpack_from('<i', rb, 513 + 4 * i)[0] for i in range((len(rb) - 513) // 4)]}
            if r != 0x2001: continue
            # convert() пишет D185 ещё раз, запускает D183, скачивает и удаляет временный JPEG
            result[tag]['jpeg'] = len(convert(prof, tag))
    elif MODE == 'set':
        if wr_soft(0x1016, [0xD18C], struct.pack('<H', SET_SLOT)) != 0x2001: raise Stop('слот не выбран')
        resp, d = rd(0x1015, (0xD18C,)); log('D18C now = %s' % d.hex())
        if u16(d) != SET_SLOT: raise Stop('слот не подтвердился')
        resp, v0 = rd(0x1015, (SET_PROP,)); log('0x%04X before = %s' % (SET_PROP, v0.hex()))
        r = wr_soft(0x1016, [SET_PROP], SET_VAL)
        resp, v1 = rd(0x1015, (SET_PROP,)); log('0x%04X after = %s' % (SET_PROP, v1.hex()))
        result.update(slot=SET_SLOT, prop='0x%04X' % SET_PROP, value=SET_VAL.hex(), before=v0.hex(), write=r, after=v1.hex())
    elif MODE == 'grain':
        if wr_soft(0x1016, [0xD18C], struct.pack('<H', SLOT)) != 0x2001: raise Stop('слот не выбран')
        resp, d = rd(0x1015, (0xD18C,)); log('D18C now = %s' % d.hex())
        if u16(d) != SLOT: raise Stop('слот не подтвердился')
        resp, g0 = rd(0x1015, (0xD195,)); log('D195 before = %s' % g0.hex())
        r = wr_soft(0x1016, [0xD195], struct.pack('<H', 0x01))
        resp, g1 = rd(0x1015, (0xD195,)); log('D195 after = %s' % g1.hex())
        result.update(before=g0.hex(), write=r, after=g1.hex())
    else:
        if wr_soft(0x1016, [0xD18C], struct.pack('<H', SLOT)) != 0x2001: raise Stop('слот не выбран')
        resp, d = rd(0x1015, (0xD18C,)); log('D18C now = %s' % d.hex())
        if u16(d) != SLOT: raise Stop('слот не подтвердился')
        before = read_props('before')
        order = fujicli_writes(before)
        log('fujicli write order:', ['0x%04X' % p for p in order])
        writes = {}
        for p in order:
            writes['0x%04X' % p] = wr_soft(0x1016, [p], before[p])
        after = read_props('after')
        diff = {'0x%04X' % p: [before[p].hex(), after.get(p, b'').hex()] for p in before if after.get(p) != before[p]}
        result.update(order=['0x%04X' % p for p in order], writes=writes, changed=diff)
        log('writes:', writes); log('changed after:', diff or 'нет')
except Stop as e:
    log('STOPPED:', e); result['stopped'] = str(e)
except Exception as e:
    log('ERROR:', repr(e)); result['error'] = repr(e)
finally:
    try:
        if MODE in ('recipe', 'grain', 'set') and orig_slot is not None:
            WRITE_PROPS.add(0xD18C)
            wr_soft(0x1016, [0xD18C], orig_slot[:2])
        resp, d = rd(0x1015, (0xD18C,)); log('D18C after = %s' % d.hex()); result['slot_after'] = d.hex()
    except Exception as e: log('final D18C failed', e)
    dev.Close(); log('closed')
    with open(os.path.join(OUT, 'result_%s.json' % MODE), 'w', encoding='utf-8') as f:
        json.dump(result, f, ensure_ascii=False, indent=1, default=str)
