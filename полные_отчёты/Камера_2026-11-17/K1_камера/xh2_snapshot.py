# Read-only Fujifilm X-H2 snapshots through WPD/COM.
# Default PTP allowlist: 0x1001, 0x1014, 0x1015 only.
# --backup additionally permits only 0x1008(handle=0) and 0x1009(handle=0),
# after separate coordinator approval. No write/data-to-camera operation exists here.
import argparse
import ctypes
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import sys
from ctypes import POINTER, byref, c_ubyte, c_ulong, c_wchar_p, cast

import comtypes
import comtypes.client as cc
from comtypes import GUID

api = cc.GetModule('portabledeviceapi.dll')
typ = cc.GetModule('portabledevicetypes.dll')

BASE_OPS = frozenset({0x1001, 0x1014, 0x1015})
BACKUP_OPS = frozenset({0x1008, 0x1009})
OP_NAMES = {
    0x1001: 'GetDeviceInfo',
    0x1008: 'GetObjectInfo',
    0x1009: 'GetObject',
    0x1014: 'GetDevicePropDesc',
    0x1015: 'GetDevicePropValue',
}
RESPONSE_NAMES = {
    0x2001: 'OK',
    0x2002: 'GeneralError',
    0x2005: 'OperationNotSupported',
    0x2009: 'InvalidObjectHandle',
    0x200A: 'DevicePropNotSupported',
    0x2015: 'NoValidObjectInfo',
    0x2019: 'DeviceBusy',
    0xA001: 'VendorResponse_0xA001',
}
MAX_PROPERTY_BYTES = 16 * 1024 * 1024
MAX_BACKUP_BYTES = 256 * 1024 * 1024

MTPX = '{4d545058-1a2e-4106-a357-771e0819fc56}'
CMN = '{F0422A9C-5DC8-4440-B5BD-5DF28835658A}'
DEV = '{26D4979A-E643-4626-9E2B-736DC0C92FDC}'
CLI = '{204D9F0C-2292-4080-9F42-40664E70F859}'
CMD_EXEC_READ = 13
CMD_READ_DATA = 15
CMD_END = 17
CMD_NAMES = {CMD_EXEC_READ: 'EXEC_READ', CMD_READ_DATA: 'READ_DATA', CMD_END: 'END_DATA_TRANSFER'}


def PK(fmt, pid):
    k = api._tagpropertykey()
    k.fmtid = GUID(fmt)
    k.pid = pid
    return ctypes.pointer(k)


K_CAT, K_ID, K_HR = PK(CMN, 1001), PK(CMN, 1002), PK(CMN, 1003)
K_OPCODE, K_PARAMS, K_RESP, K_RESPPARAMS = PK(MTPX, 1001), PK(MTPX, 1002), PK(MTPX, 1003), PK(MTPX, 1004)
K_CTX, K_TOTAL, K_TOREAD, K_READ = PK(MTPX, 1006), PK(MTPX, 1007), PK(MTPX, 1008), PK(MTPX, 1009)
K_DATA, K_OPTIMAL = PK(MTPX, 1012), PK(MTPX, 1013)


def new_values():
    return cc.CreateObject(typ.PortableDeviceValues, interface=api.IPortableDeviceValues)


def new_coll():
    return cc.CreateObject(typ.PortableDevicePropVariantCollection, interface=api.IPortableDevicePropVariantCollection)


def cmd_params(cmd_id):
    v = new_values()
    v.SetGuidValue(K_CAT, GUID(MTPX))
    v.SetUnsignedIntegerValue(K_ID, cmd_id)
    return v


def pv_raw(pv):
    b = ctypes.string_at(ctypes.addressof(pv), ctypes.sizeof(pv))
    vt = struct.unpack_from('<H', b, 0)[0]
    return vt, b[8:16]


def pv_uint(pv):
    vt, v = pv_raw(pv)
    if vt in (18, 2):
        return struct.unpack_from('<H', v)[0]
    if vt in (19, 3, 23, 22):
        return struct.unpack_from('<I', v)[0]
    if vt in (21, 20):
        return struct.unpack_from('<Q', v)[0]
    if vt in (17, 16):
        return v[0]
    return {'vt': vt, 'raw': v.hex()}


def coll_uints(c):
    nn = c_ulong(0)
    try:
        n = c.GetCount()
    except TypeError:
        c.GetCount(byref(nn))
        n = nn.value
    out = []
    for i in range(n):
        pv = api.tag_inner_PROPVARIANT()
        c.GetAt(i, byref(pv))
        out.append(pv_uint(pv))
        try:
            ctypes.oledll.ole32.PropVariantClear(byref(pv))
        except Exception:
            pass
    return out


def uint_pv(value):
    tmp = new_values()
    key = PK(MTPX, 9999)
    tmp.SetUnsignedIntegerValue(key, value)
    return tmp.GetValue(key)


def get_buffer(vals, key):
    p, n = vals.GetBufferValue(key)
    data = ctypes.string_at(p, n) if n else b''
    ctypes.windll.ole32.CoTaskMemFree(p)
    return data


def check_hr(res, what):
    hr = res.GetErrorValue(K_HR)
    if hr != 0:
        raise OSError('%s: driver HRESULT 0x%08X' % (what, hr & 0xFFFFFFFF))


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def mask(s):
    return ('*' * max(0, len(s) - 2)) + s[-2:] if s else s


def json_safe(value):
    if isinstance(value, dict):
        return {str(k): json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe(v) for v in value]
    if isinstance(value, bytes):
        return {'hex': value.hex()}
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def write_new_bytes(path, data):
    with open(path, 'xb') as f:
        f.write(data)


def write_new_json(path, value):
    with open(path, 'x', encoding='utf-8') as f:
        json.dump(json_safe(value), f, ensure_ascii=False, indent=2)
        f.write('\n')


class Logger:
    def __init__(self, directory):
        self.text = open(directory / 'run.log', 'x', encoding='utf-8')
        self.events = open(directory / 'operations.jsonl', 'x', encoding='utf-8')
        self.sequence = 0

    def line(self, message):
        print(message, flush=True)
        self.text.write(message + '\n')
        self.text.flush()

    def event(self, kind, **fields):
        self.sequence += 1
        record = {'sequence': self.sequence, 'timestamp': now(), 'event': kind, **fields}
        self.events.write(json.dumps(json_safe(record), ensure_ascii=False) + '\n')
        self.events.flush()
        return record

    def close(self):
        self.text.close()
        self.events.close()


class Reader:
    def __init__(self, data):
        self.data = data
        self.offset = 0

    def take(self, n):
        if n < 0 or self.offset + n > len(self.data):
            raise ValueError('truncated PTP data at 0x%X, need %d bytes' % (self.offset, n))
        out = self.data[self.offset:self.offset + n]
        self.offset += n
        return out

    def u8(self):
        return self.take(1)[0]

    def u16(self):
        return struct.unpack('<H', self.take(2))[0]

    def u32(self):
        return struct.unpack('<I', self.take(4))[0]

    def arr16(self):
        return [self.u16() for _ in range(self.u32())]

    def string(self):
        n = self.u8()
        if n == 0:
            return ''
        return self.take(2 * n).decode('utf-16-le', 'replace').rstrip('\x00')

    def remaining(self):
        return len(self.data) - self.offset


SIZES = {
    1: ('<b', 1), 2: ('<B', 1), 3: ('<h', 2), 4: ('<H', 2),
    5: ('<i', 4), 6: ('<I', 4), 7: ('<q', 8), 8: ('<Q', 8),
}


def read_value(reader, datatype):
    if datatype in SIZES:
        fmt, n = SIZES[datatype]
        return struct.unpack(fmt, reader.take(n))[0]
    if datatype == 9:
        return {'int128_le': reader.take(16).hex()}
    if datatype == 10:
        return {'uint128_le': reader.take(16).hex()}
    if datatype == 0xFFFF:
        return reader.string()
    if datatype & 0x4000:
        element_type = datatype & 0x3FFF
        count = reader.u32()
        if count > reader.remaining() + 1:
            raise ValueError('implausible array count %d' % count)
        return [read_value(reader, element_type) for _ in range(count)]
    raise ValueError('unknown datatype 0x%04X' % datatype)


def parse_propdesc(data):
    reader = Reader(data)
    result = {
        'code': '0x%04X' % reader.u16(),
        'datatype': '0x%04X' % reader.u16(),
    }
    datatype = int(result['datatype'], 16)
    result['getset'] = reader.u8()
    result['default'] = read_value(reader, datatype)
    result['current'] = read_value(reader, datatype)
    form = reader.u8()
    result['form'] = form
    if form == 1:
        result['range'] = [read_value(reader, datatype) for _ in range(3)]
    elif form == 2:
        result['enum'] = [read_value(reader, datatype) for _ in range(reader.u16())]
    result['trailing_bytes'] = reader.remaining()
    return result


def parse_device_info(data):
    reader = Reader(data)
    result = {
        'standard_version': reader.u16(),
        'vendor_extension_id': '0x%08X' % reader.u32(),
        'vendor_extension_version': reader.u16(),
        'vendor_extension_description': reader.string(),
        'functional_mode': '0x%04X' % reader.u16(),
        'operations': ['0x%04X' % x for x in reader.arr16()],
        'events': ['0x%04X' % x for x in reader.arr16()],
        'device_properties': ['0x%04X' % x for x in reader.arr16()],
        'capture_formats': ['0x%04X' % x for x in reader.arr16()],
        'image_formats': ['0x%04X' % x for x in reader.arr16()],
        'manufacturer': reader.string(),
        'model': reader.string(),
        'device_version': reader.string(),
        'serial_number_masked': mask(reader.string()),
        'trailing_bytes': reader.remaining(),
    }
    return result


def parse_object_info(data):
    reader = Reader(data)
    result = {
        'storage_id': '0x%08X' % reader.u32(),
        'object_format': '0x%04X' % reader.u16(),
        'protection_status': reader.u16(),
        'compressed_size': reader.u32(),
        'thumb_format': '0x%04X' % reader.u16(),
        'thumb_compressed_size': reader.u32(),
        'thumb_width': reader.u32(),
        'thumb_height': reader.u32(),
        'image_width': reader.u32(),
        'image_height': reader.u32(),
        'image_bit_depth': reader.u32(),
        'parent_object': '0x%08X' % reader.u32(),
        'association_type': reader.u16(),
        'association_desc': '0x%08X' % reader.u32(),
        'sequence_number': reader.u32(),
        'filename': reader.string(),
        'date_created': reader.string(),
        'date_modified': reader.string(),
        'keywords': reader.string(),
        'trailing_bytes': reader.remaining(),
    }
    return result


def scalar_candidates(data):
    result = {}
    if len(data) == 1:
        result = {'u8': data[0], 's8': struct.unpack('<b', data)[0]}
    elif len(data) == 2:
        result = {'u16_le': struct.unpack('<H', data)[0], 's16_le': struct.unpack('<h', data)[0]}
    elif len(data) == 4:
        result = {'u32_le': struct.unpack('<I', data)[0], 's32_le': struct.unpack('<i', data)[0]}
    elif len(data) == 8:
        result = {'u64_le': struct.unpack('<Q', data)[0], 's64_le': struct.unpack('<q', data)[0]}
    if data:
        try:
            reader = Reader(data)
            text = reader.string()
            if reader.remaining() == 0:
                result['ptp_string'] = text
        except Exception:
            pass
    return result


class WpdReadOnly:
    def __init__(self, device, logger, backup_approved=False):
        self.device = device
        self.logger = logger
        self.allowed_ops = BASE_OPS | BACKUP_OPS if backup_approved else BASE_OPS
        self.backup_approved = backup_approved

    def _check_operation(self, opcode, params):
        if opcode not in self.allowed_ops:
            raise PermissionError('PTP opcode 0x%04X is not in the active read-only allowlist' % opcode)
        if opcode == 0x1001 and params:
            raise PermissionError('GetDeviceInfo takes no parameters')
        if opcode in (0x1014, 0x1015):
            if len(params) != 1 or not isinstance(params[0], int) or not 0 <= params[0] <= 0xFFFF:
                raise PermissionError('property read requires exactly one uint16 property code')
        if opcode in BACKUP_OPS:
            if not self.backup_approved or params != (0,):
                raise PermissionError('BACKUP reads are restricted to approved handle 0')

    def _send(self, values, command_id, opcode=None, params=()):
        self.logger.event(
            'wpd_send', command=CMD_NAMES[command_id], command_id=command_id,
            ptp_opcode=('0x%04X' % opcode) if opcode is not None else None,
            ptp_params=list(params), direction='device_to_host',
        )
        try:
            result = self.device.SendCommand(0, values)
            hr = result.GetErrorValue(K_HR) & 0xFFFFFFFF
            self.logger.event('wpd_receive', command=CMD_NAMES[command_id], hresult='0x%08X' % hr)
            check_hr(result, CMD_NAMES[command_id])
            return result
        except Exception as exc:
            self.logger.event('wpd_exception', command=CMD_NAMES[command_id], error=repr(exc))
            raise

    def read(self, opcode, params=()):
        params = tuple(params)
        self._check_operation(opcode, params)
        name = OP_NAMES[opcode]
        self.logger.line('PTP SEND 0x%04X %s params=%s data=device->host' % (
            opcode, name, ['0x%X' % p for p in params]))
        self.logger.event('ptp_send', opcode='0x%04X' % opcode, name=name,
                          params=list(params), direction='device_to_host')
        values = cmd_params(CMD_EXEC_READ)
        values.SetUnsignedIntegerValue(K_OPCODE, opcode)
        collection = new_coll()
        for param in params:
            pv = uint_pv(param)
            collection.Add(byref(pv))
        values.SetIPortableDevicePropVariantCollectionValue(K_PARAMS, collection)
        try:
            result = self._send(values, CMD_EXEC_READ, opcode, params)
            context = result.GetStringValue(K_CTX)
            total = result.GetUnsignedLargeIntegerValue(K_TOTAL)
            try:
                optimal = result.GetUnsignedIntegerValue(K_OPTIMAL)
            except Exception:
                optimal = 0x40000
            if optimal <= 0:
                optimal = 0x40000
            limit = MAX_BACKUP_BYTES if opcode == 0x1009 else MAX_PROPERTY_BYTES
            data = bytearray()
            try:
                if total > limit:
                    raise IOError('refusing oversized read: %d bytes (limit %d)' % (total, limit))
                while len(data) < total:
                    chunk = min(optimal, total - len(data))
                    request = cmd_params(CMD_READ_DATA)
                    request.SetStringValue(K_CTX, context)
                    request.SetUnsignedIntegerValue(K_TOREAD, chunk)
                    buf = (c_ubyte * chunk)()
                    request.SetBufferValue(K_DATA, buf, chunk)
                    response = self._send(request, CMD_READ_DATA, opcode, params)
                    got = get_buffer(response, K_DATA)
                    nread = response.GetUnsignedIntegerValue(K_READ)
                    if nread <= 0 or nread > chunk:
                        raise IOError('invalid READ_DATA length %d (requested %d)' % (nread, chunk))
                    data.extend(got[:nread])
                if len(data) != total:
                    raise IOError('short read: %d of %d bytes' % (len(data), total))
            finally:
                end = cmd_params(CMD_END)
                end.SetStringValue(K_CTX, context)
                ended = self._send(end, CMD_END, opcode, params)
                response_code = ended.GetUnsignedIntegerValue(K_RESP)
                try:
                    response_params = coll_uints(ended.GetIPortableDevicePropVariantCollectionValue(K_RESPPARAMS))
                except Exception:
                    response_params = []
            payload = bytes(data)
            self.logger.line('PTP RECV 0x%04X %s response=0x%04X bytes=%d' % (
                opcode, name, response_code, len(payload)))
            self.logger.event('ptp_response', opcode='0x%04X' % opcode,
                              response='0x%04X' % response_code,
                              response_name=RESPONSE_NAMES.get(response_code, ''),
                              response_params=response_params, bytes=len(payload),
                              sha256=hashlib.sha256(payload).hexdigest())
            return response_code, response_params, payload
        except Exception as exc:
            self.logger.event('ptp_exception', opcode='0x%04X' % opcode, error=repr(exc))
            raise


def operation_record(opcode, params, function):
    try:
        response, response_params, data = function()
        return {
            'opcode': '0x%04X' % opcode,
            'params': list(params),
            'response': '0x%04X' % response,
            'response_name': RESPONSE_NAMES.get(response, ''),
            'response_params': response_params,
            'bytes': len(data),
            'data_hex': data.hex(),
            'sha256': hashlib.sha256(data).hexdigest(),
        }, data
    except Exception as exc:
        return {
            'opcode': '0x%04X' % opcode,
            'params': list(params),
            'transport_error': repr(exc),
        }, None


def read_wpd_properties(device, logger):
    logger.event('wpd_get_values', object_id='DEVICE', direction='device_to_host')
    values = device.Content().Properties().GetValues('DEVICE', None)
    names = {
        2: 'SYNC_PARTNER', 3: 'FIRMWARE_VERSION', 4: 'POWER_LEVEL',
        5: 'POWER_SOURCE', 6: 'PROTOCOL', 7: 'MANUFACTURER', 8: 'MODEL',
        9: 'SERIAL_NUMBER', 12: 'FRIENDLY_NAME', 15: 'TYPE',
    }
    result = {}
    for pid, name in names.items():
        key = PK(DEV, pid)
        try:
            try:
                value = values.GetStringValue(key)
            except Exception:
                value = values.GetUnsignedIntegerValue(key)
            if name == 'SERIAL_NUMBER' and isinstance(value, str):
                value = mask(value)
            result[name] = value
        except Exception as exc:
            result[name] = {'error': type(exc).__name__}
        logger.line('WPD_DEVICE_%s = %s' % (name, result[name]))
    return result


def find_camera(logger):
    manager = cc.CreateObject(api.PortableDeviceManager, interface=api.IPortableDeviceManager)
    count = c_ulong(0)
    manager._IPortableDeviceManager__com_GetDevices(POINTER(c_wchar_p)(), byref(count))
    ids = (c_wchar_p * count.value)()
    manager._IPortableDeviceManager__com_GetDevices(cast(ids, POINTER(c_wchar_p)), byref(count))
    matches = [device_id for device_id in ids if 'vid_04cb&pid_02f2' in device_id.lower()]
    logger.event('wpd_device_list', fujifilm_xh2_matches=len(matches))
    if len(matches) != 1:
        raise RuntimeError('expected exactly one X-H2 VID_04CB&PID_02F2, found %d' % len(matches))
    return matches[0]


def capture(label, output_root, backup_approved):
    if not re.fullmatch(r'[\w-]+', label, re.UNICODE) or label in ('.', '..'):
        raise ValueError('snapshot label may contain only letters, digits, underscore and hyphen')
    output_root.mkdir(parents=True, exist_ok=True)
    directory = output_root / label
    directory.mkdir(exist_ok=False)
    logger = Logger(directory)
    logger.line('X-H2 READ-ONLY snapshot %s started %s' % (label, now()))
    logger.line('Active PTP allowlist: %s' % ' '.join('0x%04X' % x for x in sorted(BASE_OPS | (BACKUP_OPS if backup_approved else frozenset()))))
    logger.event('snapshot_start', label=label, backup_approved=bool(backup_approved),
                 allowed_ops=['0x%04X' % x for x in sorted(BASE_OPS | (BACKUP_OPS if backup_approved else frozenset()))])
    snapshot = {
        'schema_version': 1,
        'label': label,
        'started': now(),
        'status': 'running',
        'backup_requested': bool(backup_approved),
        'properties': [],
    }
    device = None
    opened = False
    try:
        device_id = find_camera(logger)
        client_info = new_values()
        client_info.SetStringValue(PK(CLI, 2), 'XH2 read-only snapshot')
        client_info.SetUnsignedIntegerValue(PK(CLI, 3), 1)
        client_info.SetUnsignedIntegerValue(PK(CLI, 4), 0)
        client_info.SetUnsignedIntegerValue(PK(CLI, 5), 0)
        device = cc.CreateObject(api.PortableDevice, interface=api.IPortableDevice)
        logger.event('wpd_open', purpose='read-only snapshot')
        device.Open(device_id, client_info)
        opened = True
        logger.event('wpd_opened')
        snapshot['wpd_device'] = read_wpd_properties(device, logger)
        ptp = WpdReadOnly(device, logger, backup_approved=backup_approved)

        info_record, info_data = operation_record(0x1001, (), lambda: ptp.read(0x1001))
        snapshot['device_info_operation'] = info_record
        if info_data is None or info_record.get('response') != '0x2001':
            raise RuntimeError('GetDeviceInfo failed; no further operation sent')
        write_new_bytes(directory / 'device_info.bin', info_data)
        info = parse_device_info(info_data)
        snapshot['device_info'] = info
        logger.line('Model=%s Firmware=%s Props=%d Operations=%d' % (
            info['model'], info['device_version'], len(info['device_properties']), len(info['operations'])))
        logger.event('device_info', model=info['model'], firmware=info['device_version'],
                     functional_mode=info['functional_mode'], properties=len(info['device_properties']))
        if info['model'] != 'X-H2' or info['device_version'] != '5.30':
            raise RuntimeError('camera identity/firmware mismatch; refusing further operations')
        property_codes = [int(x, 16) for x in info['device_properties']]
        raw_conv_mode = 0xD183 in property_codes and 0xD185 in property_codes and len(property_codes) == 61
        snapshot['connection_mode_observed'] = 'USB_RAW_CONV_BACKUP_RESTORE' if raw_conv_mode else 'MTP_OR_OTHER'

        for index, code in enumerate(property_codes, 1):
            logger.line('Property %d/%d 0x%04X' % (index, len(property_codes), code))
            desc_record, desc_data = operation_record(0x1014, (code,), lambda c=code: ptp.read(0x1014, (c,)))
            value_record, value_data = operation_record(0x1015, (code,), lambda c=code: ptp.read(0x1015, (c,)))
            prop = {
                'code': '0x%04X' % code,
                'description': desc_record,
                'value': value_record,
            }
            if desc_data is not None and desc_record.get('response') == '0x2001':
                try:
                    prop['description_decoded'] = parse_propdesc(desc_data)
                except Exception as exc:
                    prop['description_parse_error'] = repr(exc)
            if value_data is not None and value_record.get('response') == '0x2001':
                prop['value_candidates'] = scalar_candidates(value_data)
                datatype = prop.get('description_decoded', {}).get('datatype')
                if datatype:
                    try:
                        reader = Reader(value_data)
                        prop['value_decoded'] = read_value(reader, int(datatype, 16))
                        prop['value_trailing_bytes'] = reader.remaining()
                    except Exception as exc:
                        prop['value_parse_error'] = repr(exc)
            snapshot['properties'].append(prop)

        backup = {'requested': bool(backup_approved), 'status': 'not_requested'}
        if backup_approved:
            if not raw_conv_mode or '0x1008' not in info['operations'] or '0x1009' not in info['operations']:
                backup['status'] = 'refused_mode_or_operations'
                logger.line('BACKUP refused: camera is not in the expected RAW CONV mode or lacks 0x1008/0x1009')
            else:
                logger.line('BACKUP export approved: GetObjectInfo(0), then GetObject(0), data=device->host')
                info_op, object_info_data = operation_record(0x1008, (0,), lambda: ptp.read(0x1008, (0,)))
                backup['object_info_operation'] = info_op
                if object_info_data is not None:
                    write_new_bytes(directory / 'backup_object_info.bin', object_info_data)
                if info_op.get('response') != '0x2001' or object_info_data is None:
                    backup['status'] = 'object_info_unavailable'
                else:
                    try:
                        object_info = parse_object_info(object_info_data)
                        backup['object_info'] = object_info
                        if object_info['object_format'] != '0x5000':
                            backup['status'] = 'refused_unexpected_object_format'
                        elif not 0 < object_info['compressed_size'] <= MAX_BACKUP_BYTES:
                            backup['status'] = 'refused_invalid_declared_size'
                        else:
                            object_op, blob = operation_record(0x1009, (0,), lambda: ptp.read(0x1009, (0,)))
                            backup['object_operation'] = object_op
                            if object_op.get('response') == '0x2001' and blob is not None:
                                write_new_bytes(directory / 'backup.bin', blob)
                                backup.update({
                                    'status': 'saved', 'file': 'backup.bin', 'size': len(blob),
                                    'sha256': hashlib.sha256(blob).hexdigest(),
                                    'declared_size_matches': len(blob) == object_info['compressed_size'],
                                    'format_note': 'opaque bytes; ObjectInfo format 0x5000',
                                })
                                logger.line('BACKUP saved: %d bytes sha256=%s' % (len(blob), backup['sha256']))
                            else:
                                backup['status'] = 'object_unavailable'
                    except Exception as exc:
                        backup['status'] = 'object_info_parse_error'
                        backup['error'] = repr(exc)
                logger.event('backup_result', **backup)
        snapshot['backup'] = backup
        snapshot['status'] = 'complete' if not backup_approved or backup['status'] == 'saved' else 'complete_backup_unavailable'
    except Exception as exc:
        snapshot['status'] = 'failed'
        snapshot['fatal_error'] = repr(exc)
        logger.line('FATAL: %r' % exc)
        logger.event('snapshot_exception', error=repr(exc))
    finally:
        if device is not None and opened:
            try:
                logger.event('wpd_close')
                device.Close()
                logger.event('wpd_closed')
            except Exception as exc:
                logger.event('wpd_close_exception', error=repr(exc))
        snapshot['finished'] = now()
        write_new_json(directory / 'snapshot.json', snapshot)
        logger.event('snapshot_finished', status=snapshot['status'])
        logger.line('Snapshot finished: %s' % snapshot['status'])
        logger.close()
    return directory, snapshot


def main():
    parser = argparse.ArgumentParser(description='Read-only X-H2 DeviceInfo/property snapshot; optional approved BACKUP export')
    parser.add_argument('label', help='new snapshot label, e.g. 00_MTP or 01_база')
    parser.add_argument('output_root', type=Path, help='parent directory; LABEL must not already exist below it')
    parser.add_argument('--backup', action='store_true',
                        help='after separate coordinator approval only: GetObjectInfo(0) + GetObject(0), camera->PC')
    args = parser.parse_args()
    directory, snapshot = capture(args.label, args.output_root, args.backup)
    print('Output: %s' % directory)
    return 0 if snapshot['status'] in ('complete', 'complete_backup_unavailable') else 1


if __name__ == '__main__':
    sys.exit(main())
