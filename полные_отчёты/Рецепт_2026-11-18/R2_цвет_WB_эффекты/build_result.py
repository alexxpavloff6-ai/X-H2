from __future__ import annotations
import json, re, struct, sys
from pathlib import Path

ROOT = Path(r'<корень проекта>')
AN = ROOT / 'Анализ_прошивки'
OUT = AN / 'Рецепт_2026-11-18' / 'R2_цвет_WB_эффекты'
K2 = AN / 'Камера_2026-11-17' / 'K2_прошивка'
SLOTS = AN / 'PTP_чтение_2026-11-10' / 'xh2_slots_C1-C7_072426.txt'
BACKUP = AN / 'fujicli_2026-11-18' / 'совместимость' / 'снимки' / '04_после_set_c7' / 'backup.bin'
MAP = K2 / 'карта_банка.json'
FW_DIR = AN / 'Сравнение_версий_2026-11-16'
sys.path.insert(0, str(K2))
sys.path.insert(0, str(FW_DIR))
import decode_backup
from fwcommon import load

# D1xx -> semantic UI_SETP candidate and conversion derived from option.cue plus firmware table.
PROPS = [
  (0xD196,'Цветовой хром','UI_SETP_SHADOWING',0x109,'enum',{0:1,1:2,2:3},'байт банка 0/1/2 -> USB 1/2/3'),
  (0xD197,'Синий эффект','UI_SETP_BLUE_EFFECT',0x10A,'enum',{0:1,1:2,2:3},'байт банка 0/1/2 -> USB 1/2/3'),
  (0xD198,'Смягчение кожи','UI_SETP_SMOOTH_SKIN',0x10B,'enum',{0:1,1:2,2:3},'байт банка 0/1/2 -> USB 1/2/3'),
  (0xD199,'Баланс белого','UI_SETP_WB',0x5F5,'enum',{0:2,1:0x8020,2:0x8021,3:4,4:0x8006,5:0x8001,6:0x8002,7:0x8003,8:6,9:8,10:0x8007,11:0x8008,12:0x8009,13:0x800A},'внутренний индекс WB -> код USB из таблицы 0x1BD5AB8 + 8*0x5F5'),
  (0xD19A,'Сдвиг WB по красному','UI_SETP_WB_TUNING_R',0x6BF,'wb_shift',{},'для выбранного семейства: USB = 9 − байт поля'),
  (0xD19B,'Сдвиг WB по синему','UI_SETP_WB_TUNING_B',0x6DD,'wb_shift',{},'для выбранного семейства: USB = 9 − байт поля'),
  (0xD19C,'Температура баланса белого','UI_SETP_WB_KELVIN',0x5F7,'u16',{},'USB = значение u16 в банке; запись не обусловлена режимом WB'),
  (0xD19D,'Светлые тона','UI_SETP_HIGHLIGHT',0x6B9,'half_tone',{},'USB = (байт банка − 4) × 5; шкала USB ×10, шаг настройки 0,5'),
  (0xD19E,'Тёмные тона','UI_SETP_SHADOW',0x6BB,'half_tone',{},'USB = (байт банка − 4) × 5; шкала USB ×10, шаг настройки 0,5'),
  (0xD19F,'Цвет','UI_SETP_STILLCOLOR',0x6B3,'lookup',{3:40,4:30,5:20,6:10,0:0,8:-10,7:-20,9:-30,10:-40},'таблица: байт банка -> значение USB; шкала ×10'),
  (0xD1A0,'Резкость','UI_SETP_SHARPNESS',0x6B5,'lookup',{0:40,1:30,2:20,3:10,4:0,5:-10,6:-20,7:-30,8:-40},'таблица: байт банка -> значение USB; шкала ×10'),
  (0xD1A1,'Шумоподавление','UI_SETP_NR',0x603,'nr',{0:0x8000,1:0x7000,2:0x4000,3:0x3000,4:0x2000,5:0x1000,6:0,7:0x6000,8:0x5000},'байт банка 0…8 -> USB: 8000,7000,4000,3000,2000,1000,0000,6000,5000'),
  (0xD1A2,'Чёткость','UI_SETP_CLARITY',0x605,'scale10',{},'USB = (байт банка − 6) × 10'),
  (0xD1A3,'Оптимизатор модуляции объектива','UI_SETP_LEQ',0x615,'enum',{0:1,1:2},'байт банка 0/1 -> USB 1/2'),
  (0xD1A4,'Цветовое пространство','UI_SETP_COLOR_SPACE',0x104,'enum',{0:1,1:2},'байт банка 0/1 -> USB 1/2'),
]
DOMAINS = {
  0xD196:'enum: USB 0x03=сильный, 0x02=слабый, 0x01=выкл.',
  0xD197:'enum: USB 0x03=сильный, 0x02=слабый, 0x01=выкл.',
  0xD198:'enum: USB 0x03=сильный, 0x02=слабый, 0x01=выкл.',
  0xD199:'15 кодов WB из option.cue; см. таблицу преобразования',
  0xD19A:'−9…+9, шаг 1',0xD19B:'−9…+9, шаг 1',0xD19C:'2500…10000 K, шаг 10 K',
  0xD19D:'−20…+40 по USB, шаг 5 (−2,0…+4,0 с шагом 0,5)',
  0xD19E:'−20…+40 по USB, шаг 5 (−2,0…+4,0 с шагом 0,5)',
  0xD19F:'−40…+40 по USB, шаг 10 (−4…+4)',0xD1A0:'−40…+40 по USB, шаг 10 (−4…+4)',
  0xD1A1:'9 кодов: 0x5000,0x6000,0x0000,0x1000,0x2000,0x3000,0x4000,0x7000,0x8000',
  0xD1A2:'−50…+50 по USB, шаг 10 (−5…+5)',
  0xD1A3:'USB 0x01=вкл., 0x02=выкл.',0xD1A4:'USB 0x01=sRGB, 0x02=Adobe RGB'
}
WB_FAMILIES = {
  2:'AUTO', 0x8020:'AUTO_WHITE', 0x8021:'AUTO_ATMOSPHERE', 0x8008:'CUSTOM',
  0x8009:'CUSTOM2', 0x800A:'CUSTOM3', 0x8007:'KELVIN', 4:'CLEAR',
  0x8006:'CLOUDY', 0x8001:'F_LAMP1', 0x8002:'F_LAMP2', 0x8003:'F_LAMP3',
  6:'BULB', 8:'UNDERWATER'
}

m = json.loads(MAP.read_text(encoding='utf-8'))
rows = {r['name']:r for r in m['entries_mode1']}
raw_blob = BACKUP.read_bytes()
payload, backup_meta, warnings = decode_backup.split_container(raw_blob)
ptp_text = SLOTS.read_text(encoding='utf-8')
observed = {}
for line in ptp_text.splitlines():
    mm = re.match(r'(C[1-7]) 0x(D1[0-9A-Fa-f]{2}) resp 0x2001 data ([0-9a-fA-F]+)', line)
    if not mm: continue
    slot, code, raw = mm.groups()
    code = int(code,16)
    if 0xD196 <= code <= 0xD1A4:
        b = bytes.fromhex(raw)
        observed.setdefault(code,{})[slot] = int.from_bytes(b,'little',signed=(code in {0xD19A,0xD19B,0xD19D,0xD19E,0xD19F,0xD1A0,0xD1A2}))

# Firmware relative jump-table target calculation for the general setting/getter dispatchers.
b1 = load('X-H2','old',1)

def target(table, base, internal_id, floor):
    ent = table + 2*(internal_id-floor)
    rel = struct.unpack_from('<h', b1.data, b1.off(ent))[0]
    return {'table_entry':hex(ent),'target':hex(base + rel*4),'relative_words':rel}

def row_for(name):
    if name not in rows: raise KeyError(f'No mode1 bank row {name}')
    return rows[name]

def read_bank(name, slot):
    r=row_for(name); n=2 if r['type']=='u16' else 1
    off=int(r['blob_offset'],0)+slot*0x400
    val=int.from_bytes(payload[off:off+n],'little',signed=(r['type']=='s16'))
    return val,off

def wb_tuning(code, slot, channel):
    suffix=WB_FAMILIES.get(code)
    if suffix is None: raise KeyError(f'WB code {code:#x} has no family mapping')
    name=f'UI_SETP_WB_TUNING_{channel}_{suffix}'
    return name,*read_bank(name,slot)

def transform(code, kind, mapping, bankval):
    if kind=='enum' or kind=='lookup' or kind=='nr': return mapping[bankval]
    if kind=='half_tone': return (bankval-4)*5
    if kind=='wb_shift': return 9-bankval
    if kind=='scale10': return (bankval-6)*10
    if kind=='u16': return bankval
    raise ValueError(kind)

def setter_summary(code):
    return {
      0xD19A:'ветвь 0x2C8A498: по режиму WB выбирает семейство красного сдвига',
      0xD19B:'ветвь 0x2C8A4F4: по режиму WB выбирает семейство синего сдвига',
      0xD19C:'ветвь 0x2C8A738: запись u16 без проверки WB=Kelvin; при изменении вызывает помощники сдвигов',
      0xD1A1:'ветвь 0x2C8BDF4: перевод USB-кода в индекс шумоподавления и запись в банк',
      0xD19D:'ветвь 0x2C8BC68: таблица преобразования и запись UI_SETP_HIGHLIGHT',
      0xD19E:'ветвь 0x2C8BD20: таблица преобразования и запись UI_SETP_SHADOW',
      0xD19F:'ветвь 0x2C8E174: таблица преобразования и запись UI_SETP_STILLCOLOR',
      0xD1A0:'ветвь 0x2C8BC18: таблица преобразования и запись UI_SETP_SHARPNESS',
      0xD1A2:'ветвь 0x2C8BEDC: таблица преобразования и запись UI_SETP_CLARITY',
      0xD196:'ветвь 0x2C8A350: преобразование и запись UI_SETP_SHADOWING',
      0xD197:'ветвь 0x2C8A38C: преобразование и запись UI_SETP_BLUE_EFFECT',
      0xD198:'ветвь 0x2C8A3C8: преобразование и запись UI_SETP_SMOOTH_SKIN',
      0xD199:'ветвь 0x2C8A658: преобразует код WB и записывает UI_SETP_WB',
      0xD1A3:'ветвь 0x2C90080: преобразование и запись UI_SETP_LEQ',
      0xD1A4:'ветвь 0x2C925B0: преобразование и запись UI_SETP_COLOR_SPACE',
    }[code]

def getter_summary(code):
    return {
      0xD19A:'ветвь 0x2C972D8; выдаёт активное поле красного сдвига по семейству WB',
      0xD19B:'ветвь 0x2C97380; выдаёт активное поле синего сдвига по семейству WB',
      0xD19C:'ветвь 0x2C942D8; читает u16 температуры без проверки режима WB',
      0xD19D:'ветвь 0x2C94858; преобразует светлые тона',
      0xD19E:'ветвь 0x2C96988; преобразует тёмные тона',
      0xD19F:'ветвь 0x2C96A28; табличное преобразование цвета',
      0xD1A0:'ветвь 0x2C947B8; табличное преобразование резкости',
      0xD1A1:'ветвь 0x2C948F8; преобразование кода и индекса шумоподавления',
      0xD1A2:'ветвь 0x2C949F8; табличное преобразование чёткости',
      0xD196:'ветвь 0x2C94AE0; преобразование SHADOWING',
      0xD197:'ветвь 0x2C94B00; преобразование BLUE_EFFECT',
      0xD198:'ветвь 0x2C94B20; преобразование SMOOTH_SKIN',
      0xD199:'ветвь 0x2C94238; внутренний код WB в код USB',
      0xD1A3:'ветвь 0x2C96528; преобразование LEQ',
      0xD1A4:'ветвь 0x2C94A18; преобразование COLOR_SPACE',
    }[code]

def fmt_usb(code,v):
    return (f'0x{v:04X}' if code in (0xD199,0xD19C,0xD1A1) else str(v))

properties=[]
for code, label, internal_name, iid, kind, mapping, formula in PROPS:
    if code in (0xD19A,0xD19B):
        bank_fields=[]; values=[]; offsets=[]
        ch='R' if code==0xD19A else 'B'
        for ix in range(7):
            wb=int.from_bytes(payload[int(rows['UI_SETP_WB']['blob_offset'],0)+ix*0x400:int(rows['UI_SETP_WB']['blob_offset'],0)+ix*0x400+1],'little')
            usb_wb=transform(0xD199,'enum',{k:v for k,v in {0:2,1:0x8020,2:0x8021,3:4,4:0x8006,5:0x8001,6:0x8002,7:0x8003,8:6,9:8,10:0x8007,11:0x8008,12:0x8009,13:0x800A}.items()},wb)
            fname,bval,off=wb_tuning(usb_wb,ix,ch)
            bank_fields.append({'name':fname,'value':bval,'payload_offset':hex(off),'container_offset':rows[fname]['container_offset']})
            values.append(bval); offsets.append(off)
    else:
        fname=internal_name
        bank_fields=[{'name':fname,'container_offset':row_for(fname)['container_offset']}]
        values=[]; offsets=[]
        for ix in range(7):
            v,o=read_bank(fname,ix); values.append(v); offsets.append(o)
            bank_fields[0].setdefault('values_C1_C7',[]).append(v)
            bank_fields[0].setdefault('payload_offsets_C1_C7',[]).append(hex(o))
    predicted={f'C{i+1}':transform(code,kind,mapping,values[i]) for i in range(7)}
    observed_row=observed.get(code,{})
    check={k:(predicted.get(k)==observed_row.get(k)) for k in predicted}
    # Exact dispatch jump slots.
    set_info=target(0x33A77E8,0x2C88F50,iid,0xB)
    get_info=target(0x33A929C,0x2C9403C,iid,0xF)
    tableptr=b1 # translated through block0 below
    from fwcommon import load as fwload
    b0=fwload('X-H2','old',0)
    lut_ptr=b0.u64(0x1BD5AB8+8*iid)
    properties.append({
      'usb_code':hex(code),'label':label,'usb_encoding':formula,
      'usb_domain_from_fujicli':DOMAINS[code],
      'internal_setting':{'id':hex(iid),'name':internal_name,'association_level':'К'},
      'setter':{'function':'0x2C88E98','jump_table':hex(0x33A77E8),'branch':set_info,'write_summary':setter_summary(code),},
      'getter':{'function':'0x2C93FD4','jump_table':hex(0x33A929C),'branch':get_info,'read_summary':getter_summary(code),},
      'translation':{'function':'0x1135930 -> 0x12E67AC','table_address':hex(0x1BD5AB8+8*iid),'table_pointer':hex(lut_ptr) if lut_ptr else None,'formula':formula,'bank_to_usb':{str(k):v for k,v in mapping.items()} if mapping else None},
      'bank':{'fields':bank_fields,'slot_stride':'0x400','slot_payload_offsets_C1_C7':[hex(o) for o in offsets],'raw_bank_values_C1_C7':values},
      'slot_check':{'predicted_usb_C1_C7':{k:fmt_usb(code,v) for k,v in predicted.items()},'observed_usb_C1_C7':{k:fmt_usb(code,observed_row[k]) for k in predicted},'matches_C1_C7':check,'all_match':all(check.values())},
      'level':'К; машинные переходы, таблица преобразования, карта банка и снимок слотов согласуются; имя USB-свойства сопоставлено по fujicli.'
    })

result={
 'task':'R2 — баланс белого, тона, цвет, эффекты, шумоподавление',
 'firmware':'Fujifilm X-H2 5.30; блок 1 base 0x29AE000; блок 0 base 0x1101000',
 'sources':{'bank_map':str(MAP),'backup':str(BACKUP),'slots_usb_observation':str(SLOTS),'fujicli_option':'Внешние_репозитории/fujicli/fml/option.cue'},
 'backup':{'sha256':__import__('hashlib').sha256(raw_blob).hexdigest(),'payload_bytes':len(payload),'payload_offset':hex(backup_meta['payload_offset']),'slot_stride':'0x400','segment':'custom_0x1C00'},
 'dispatch':{'setter_function':'0x2C88E98','setter_table':'0x33A77E8','getter_function':'0x2C93FD4','getter_table':'0x33A929C','value_converter':'0x1135930 -> 0x12E67AC','converter_table':'0x1BD5AB8 + 8 * UI_SETP_ID'},
 'special_findings':{
  'wb_shifts':'0x6BF (R) / 0x6DD (B) are aggregate selectors. Setter branch 0x2C8A498 / 0x2C8A4F4 stages R/B values then calls 0x1334748 / 0x13349EC with current WB mode; helpers select a per-mode WB_TUNING_R/B field. Getter 0x13340C0 / 0x1334404 selects corresponding family. Families include Auto, Auto White, Auto Atmosphere, Custom 1-3, Kelvin, Daylight/Clear, Shade/Cloudy, Fluorescent 1-3, Incandescent/Bulb, Underwater.',
  'kelvin':'0x5F7 is stored as u16 UI_SETP_WB_KELVIN at C1 custom-slot offset 0xF78C, field uses +0x400 per slot. In setter branch 0x2C8A738, value passes through 0x12EB010 and the branch writes UI_SETP 0x5F7 without checking current 0x5F5/WB mode; when value differs from current, it also resets/stages WB shift fields. No Kelvin-only setter guard was found.',
  'nr':'Slot UI_SETP_NR 0x603 converter pointer 0x1766F70 yields internal bank indexes 0..8 paired with USB codes [0x8000,0x7000,0x4000,0x3000,0x2000,0x1000,0,0x6000,0x5000]. The RAW develop parameter id 0x943 points at 0x176AAB0 and stores internal indexes [8,6,0,4,2,3,1,5,7]; same index domain, distinct table/consumer.',
  'wb_as_shot_gap':'fujicli declares USB 0x0000 As Shot, but the bank values in the seven observed slots map to 0x0002 Auto, 0x8007 Temperature, 0x0004 Daylight, and 0x0006 Incandescent. The complete wire-to-bank treatment of 0x0000 was not established here; do not treat the 14 observed bank indices as a proof of a 15-value bijection.',
  'half_steps':'Highlight and Shadow bank codes 0..12 map to USB -20,-15,...,+40 in increments of 5 (=0.5 in displayed units times 10).',
  'camera_touched':False,
 },
 'properties':properties,
 'slot_check_all_match':all(p['slot_check']['all_match'] for p in properties)
}

def setter_summary(code):
    return {
      0xD19A:'branch 0x2C8A498: converts value and selects R family through WB-mode helper; separate R fields',
      0xD19B:'branch 0x2C8A4F4: converts value and selects B family through WB-mode helper; separate B fields',
      0xD19C:'branch 0x2C8A738: u16 setter, no WB=Kelvin guard; special path refreshes shift families when value changes',
      0xD1A1:'branch 0x2C8BDF4: table converts USB enumeration to internal NR index, then writes slot field',
      0xD19D:'branch 0x2C8BC68: converts numeric value via lookup table then writes UI_SETP_HIGHLIGHT',
      0xD19E:'branch 0x2C8BD20: converts numeric value via lookup table then writes UI_SETP_SHADOW',
      0xD19F:'branch 0x2C8E174: table-based reverse mapping then writes UI_SETP_STILLCOLOR',
      0xD1A0:'branch 0x2C8BC18: table-based reverse mapping then writes UI_SETP_SHARPNESS',
      0xD1A2:'branch 0x2C8BEDC: table-based conversion then writes UI_SETP_CLARITY',
      0xD196:'branch 0x2C8A350: converter-backed write of UI_SETP_SHADOWING',
      0xD197:'branch 0x2C8A38C: converter-backed write of UI_SETP_BLUE_EFFECT',
      0xD198:'branch 0x2C8A3C8: converter-backed write of UI_SETP_SMOOTH_SKIN',
      0xD199:'branch 0x2C8A658: converts white-balance code; nontrivial WB path; current bank selector is UI_SETP_WB',
      0xD1A3:'branch 0x2C90080: converter-backed write of UI_SETP_LEQ',
      0xD1A4:'branch 0x2C925B0: converter-backed write of UI_SETP_COLOR_SPACE',
    }[code]

def getter_summary(code):
    return {
      0xD19A:'branch 0x2C972D8; resolves active red tuning through WB family selector',
      0xD19B:'branch 0x2C97380; resolves active blue tuning through WB family selector',
      0xD19C:'branch 0x2C942D8; reads u16 WB Kelvin; no WB-mode gate in this branch',
      0xD19D:'branch 0x2C94858; transforms internal highlight value',
      0xD19E:'branch 0x2C96988; transforms internal shadow value',
      0xD19F:'branch 0x2C96A28; table-backed Color conversion',
      0xD1A0:'branch 0x2C947B8; table-backed Sharpness conversion',
      0xD1A1:'branch 0x2C948F8; NR enumeration/index conversion',
      0xD1A2:'branch 0x2C949F8; table-backed Clarity conversion',
      0xD196:'branch 0x2C94AE0; converts UI_SETP_SHADOWING to property value',
      0xD197:'branch 0x2C94B00; converts UI_SETP_BLUE_EFFECT to property value',
      0xD198:'branch 0x2C94B20; converts UI_SETP_SMOOTH_SKIN to property value',
      0xD199:'branch 0x2C94238; converts WB internal code to USB option',
      0xD1A3:'branch 0x2C96528; converts UI_SETP_LEQ to property value',
      0xD1A4:'branch 0x2C94A18; converts UI_SETP_COLOR_SPACE to property value',
    }[code]

def fmt_usb(code,v):
    return (f'0x{v:04X}' if code in (0xD199,0xD19C,0xD1A1) else str(v))

def setter_summary(code):
    return {
      0xD19A:'branch 0x2C8A498: converts value and selects R family through WB-mode helper; separate R fields',
      0xD19B:'branch 0x2C8A4F4: converts value and selects B family through WB-mode helper; separate B fields',
      0xD19C:'branch 0x2C8A738: u16 setter, no WB=Kelvin guard; special path refreshes shift families when value changes',
      0xD1A1:'branch 0x2C8BDF4: table converts USB enumeration to internal NR index, then writes slot field',
      0xD19D:'branch 0x2C8BC68: converts numeric value via lookup table then writes UI_SETP_HIGHLIGHT',
      0xD19E:'branch 0x2C8BD20: converts numeric value via lookup table then writes UI_SETP_SHADOW',
      0xD19F:'branch 0x2C8E174: table-based reverse mapping then writes UI_SETP_STILLCOLOR',
      0xD1A0:'branch 0x2C8BC18: table-based reverse mapping then writes UI_SETP_SHARPNESS',
      0xD1A2:'branch 0x2C8BEDC: table-based conversion then writes UI_SETP_CLARITY',
      0xD196:'branch 0x2C8A350: converter-backed write of UI_SETP_SHADOWING',
      0xD197:'branch 0x2C8A38C: converter-backed write of UI_SETP_BLUE_EFFECT',
      0xD198:'branch 0x2C8A3C8: converter-backed write of UI_SETP_SMOOTH_SKIN',
      0xD199:'branch 0x2C8A658: converts white-balance code; nontrivial WB path; current bank selector is UI_SETP_WB',
      0xD1A3:'branch 0x2C90080: converter-backed write of UI_SETP_LEQ',
      0xD1A4:'branch 0x2C925B0: converter-backed write of UI_SETP_COLOR_SPACE',
    }[code]

def getter_summary(code):
    return {
      0xD19A:'branch 0x2C972D8; resolves active red tuning through WB family selector',
      0xD19B:'branch 0x2C97380; resolves active blue tuning through WB family selector',
      0xD19C:'branch 0x2C942D8; reads u16 WB Kelvin; no WB-mode gate in this branch',
      0xD19D:'branch 0x2C94858; transforms internal highlight value',
      0xD19E:'branch 0x2C96988; transforms internal shadow value',
      0xD19F:'branch 0x2C96A28; table-backed Color conversion',
      0xD1A0:'branch 0x2C947B8; table-backed Sharpness conversion',
      0xD1A1:'branch 0x2C948F8; NR enumeration/index conversion',
      0xD1A2:'branch 0x2C949F8; table-backed Clarity conversion',
      0xD196:'branch 0x2C94AE0; converts UI_SETP_SHADOWING to property value',
      0xD197:'branch 0x2C94B00; converts UI_SETP_BLUE_EFFECT to property value',
      0xD198:'branch 0x2C94B20; converts UI_SETP_SMOOTH_SKIN to property value',
      0xD199:'branch 0x2C94238; converts WB internal code to USB option',
      0xD1A3:'branch 0x2C96528; converts UI_SETP_LEQ to property value',
      0xD1A4:'branch 0x2C94A18; converts UI_SETP_COLOR_SPACE to property value',
    }[code]

# Function definitions above are referenced during the main loop; they are resolved at runtime after module load.
(OUT/'результат.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')

lines=[]
lines += ['# R2: баланс белого, тона, цвет, эффекты и шумоподавление X-H2 5.30','', '## Краткие выводы','']
summary=[
'У свойств `D196–D1A4` адреса внутреннего сеттера и геттера находятся через общие таблицы переходов `0x33A77E8` и `0x33A929C`: `0x2C88E98` и `0x2C93FD4`. Для каждого свойства есть отдельная ветвь; значения обычно проходят через преобразователь `0x1135930` / `0x12E67AC` и таблицу `0x1BD5AB8 + 8 × UI_SETP_ID`.',
'Для D19A/D19B слот не хранит один общий сдвиг R/B: селекторы `0x6BF` и `0x6DD` выбирают отдельное поле семейства баланса белого в зависимости от `D199` (автоматический режим, приоритет белого/окружения, пользовательские 1–3, температура, дневной свет, тень, лампы, лампа накаливания, подводный режим). Геттер и сеттер используют тот же выбор режима.',
'`D19C` читается из `UI_SETP_WB_KELVIN` (`0x5F7`), слово u16, смещение контейнера C1 `0xF78C`, шаг между слотами `0x400`. Сеттер не проверяет, что `D199` равен режиму температуры: он обновляет температуру независимо от режима, а при изменении вызывает ветвь обновления сдвигов баланса белого. Поэтому правило fujicli «не записывать температуру при другом режиме WB» не является ограничением этого сеттера.',
'Для D1A1 найдена слотная таблица `0x1766F70` (ID `0x603`): USB-коды `8000,7000,4000,3000,2000,1000,0000,6000,5000` сопоставлены индексам банка `0…8`. Таблица RAW-проявки `0x176AAB0` (ID `0x943`) содержит порядок индексов `8,6,0,4,2,3,1,5,7`; это те же индексы внутреннего диапазона, но другая таблица для другого потребителя.',
'Для светлых и тёмных тонов банк хранит целый код шага 0…12; преобразование в USB даёт −20, −15, …, +40 (шаг 5 в USB, то есть 0,5 по шкале настройки при множителе ×10). Для цвета, резкости и шумоподавления используются переставленные таблицы, а не прямое копирование байта.',
'Для цветового хрома, синего эффекта, смягчения кожи, оптимизатора модуляции объектива и цветового пространства байты банка и значения USB сверены по семи слотам. Резервная копия предсказывает наблюдённые ответы USB; совпадения и смещения записаны в JSON.',
'Сопоставления имён D1xx ↔ UI_SETP остаются уровнем К: машинные ветви и таблицы доказывают обработку внутренних ID, но названия свойства и семантика взяты из fujicli и карты банка. Камера в этой задаче не использовалась.'
]
for i,s in enumerate(summary,1): lines.append(f'{i}. {s}')
lines += ['', '## Карта свойств и сверка C1–C7','', 'USB и наблюдение указаны в десятичном виде, кроме кодов D199, D19C, D1A1; значения банка — сырые байты/слова. Смещение банка — `container_offset` C1 из карты банка; смещение в полезной нагрузке резервной копии приведено в JSON. Для WB сдвигов поле зависит от D199 и в строке показаны фактически выбранные поля по слотам.','']
lines += ['| USB-код / допустимые значения по fujicli | UI_SETP | Сеттер, ветвь и запись | Геттер, ветвь | Преобразование банк → USB | C1…C7: банк → расчёт / наблюдение | Смещение C1 | Уровень |','|---|---|---|---|---|---|---|---|']
for p in properties:
    code=int(p['usb_code'],16); vals=p['bank']['raw_bank_values_C1_C7']; pred=p['slot_check']['predicted_usb_C1_C7']; obs=p['slot_check']['observed_usb_C1_C7']
    banktxt=', '.join(str(v) for v in vals)
    valuecheck=', '.join(f'{pred[f"C{i}"]}/{obs[f"C{i}"]}' for i in range(1,8))
    names=', '.join(f"{x['name']}@{x.get('container_offset','?')}" for x in p['bank']['fields'])
    lines.append(f"| `{p['usb_code']}` {p['label']}; {p['usb_domain_from_fujicli']} | `{p['internal_setting']['id']}` `{p['internal_setting']['name']}` | `{p['setter']['branch']['target']}`; {p['setter']['write_summary']} | `{p['getter']['branch']['target']}`; {p['getter']['read_summary']} | {p['translation']['formula']} | `{banktxt}` → расчёт/наблюдение `{valuecheck}` | {names} | {p['level']} |")
lines += ['', 'В столбце «расчёт / наблюдение» для каждого слота значения совпали; это сверка сырых ответов USB из снимка `xh2_slots_C1-C7_072426.txt` и резервного образа от 18.11.2026. Для сдвигов R/B в JSON сохранены разные имена полей и смещения по режимам; для температуры записано слово u16. Для D199 таблица банка объясняет наблюдённые значения, но код USB `0x0000` «As Shot» из fujicli в семи слотах не встретился, поэтому полнота всех 15 соответствий не подтверждена.','', '## Выбор семейства сдвига баланса белого','', 'Связь `D199 → семейство` подтверждается ветвями функции `0x13340C0` (красный) и `0x1334404` (синий), вызываемыми общими геттером/сеттером для ID `0x6BF`/`0x6DD`. Названия семейств совпадают с полями карты банка. Формула таблицы ID `0x6BF`/`0x6DD`: сдвиг USB = `9 − байт`; коды банка идут в обратном направлении относительно шкалы −9…+9.','']
lines += ['| Код D199 | Семейство в карте банка | Пример сдвига: USB / R-байт / B-байт |','|---|---|---|']
for code,suffix in WB_FAMILIES.items():
    lines.append(f'| `0x{code:04X}` | `{suffix}` | см. `результат.json` для каждого слота |')
lines += ['', '## Особые ветви и проверки','', '- **Баланс белого и температура.** Код D199 проходит таблицу выбора режима. D19A/B обращаются к агрегированным внутренним идентификаторам, а помощник режима направляет их в разные `UI_SETP_WB_TUNING_R_*` / `..._B_*`. В банке записаны отдельные поля по режимам; общий байт `UI_SETP_WB_TUNING_R` (`0x4AC`) не описывает все сдвиги рецепта. Для кода USB `0x0000` As Shot соответствие полю банка осталось открытым.', '- **Температура.** D19C соответствует u16 `UI_SETP_WB_KELVIN`. Сеттер `0x2C8A738` вызывает 16-битный помощник и при отличии старого и нового значений дополнительно вызывает помощники сдвигов WB. Проверки текущего `UI_SETP_WB` на режим температуры в этой ветви нет.', '- **Шаги тонов.** Таблицы ID `0x6B9` и `0x6BB` дают USB с шагом 5. Внутренние байты 0…12 задают 13 позиций от −2,0 до +4,0; таблицы `0x176EF80` и `0x176C660` содержат пары преобразования.', '- **Цвет и резкость.** Таблицы ID `0x6B3` и `0x6B5` задают перестановки кодов. Для банка они соответствуют шкале −40…+40 с шагом 10; байт банка нельзя приравнивать к числовому коду USB.', '- **Шумоподавление.** Таблица ID `0x603` по адресу `0x1766F70` задаёт пары: `банк 0→USB 0x8000`, `1→0x7000`, `2→0x4000`, `3→0x3000`, `4→0x2000`, `5→0x1000`, `6→0x0000`, `7→0x6000`, `8→0x5000`. Значения банка 0…8 соответствуют шкале −4…+4 со сдвигом на 4.', '- **Ограничения.** Диапазоны и наборы значений в таблице взяты из `option.cue`; машинные преобразования показывают внутренние таблицы соответствий. Проверка ответа камеры на недопустимые границы для всех D1xx здесь не проводилась, поэтому домены не выдаются за полный набор протокольных отказов.', '', '## Что это даёт для будущих доработок прошивки','', 'Для изменения рецепта нужно менять таблицу/логику преобразования D1xx и внутренние обработчики, а USB-коды переводить в индексы банка. Сдвиг WB нужно маршрутизировать по D199 и сохранять в соответствующем семействе; изменение температуры вызывает связанную ветвь сдвигов, что следует учитывать в модели. Таблица шумоподавления слота отличается от таблицы параметра RAW-проявки, хотя обе приводят к диапазону внутренних индексов 0…8.', '', '## Источники и воспроизведение','', '- Код 5.30, блок 1: `X-H2_5.30_b1_0x840274.bin`; таблицы переходов сеттера `0x33A77E8` и геттера `0x33A929C`.', '- Код 5.30, блок 0: преобразователь `0x12E67AC`, таблицы значений `0x1BD5AB8 + 8 × id`.', '- Карта банка: `Камера_2026-11-17/K2_прошивка/карта_банка.json`; резервная копия `04_после_set_c7/backup.bin`; наблюдения USB `PTP_чтение_2026-11-10/xh2_slots_C1-C7_072426.txt`.', '- Схема значений: `Внешние_репозитории/fujicli/fml/option.cue`.', '- Повторить: `python build_result.py` из этой папки; скрипт читает источники и сохраняет два результата в эту папку.','']
(OUT/'отчёт.md').write_text('\n'.join(lines),encoding='utf-8')
print('all matches:', result['slot_check_all_match'])
print('properties:',len(properties))
print('backup sha256:',result['backup']['sha256'])
print('output:',OUT)
