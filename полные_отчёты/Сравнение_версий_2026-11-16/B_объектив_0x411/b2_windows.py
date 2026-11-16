"""Сборка доказательств: окна дизассемблера old/new по всем трём моделям.

Пишет b2_windows.txt — фрагменты кода, на которые ссылается отчёт.md.
Запуск: python b2_windows.py
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from fwcommon import load, dis, MODELS  # noqa: E402

# (метка, модель, состояние, адрес, сколько инструкций)
WINDOWS = [
    # --- X-H2: конструктор запроса и новый флаг -------------------------
    ('H2 main old', 'X-H2', 'old', 0x2df08f0, 34),
    ('H2 main new', 'X-H2', 'new', 0x2dec980, 34),
    ('H2 sibling old', 'X-H2', 'old', 0x2de9e5c, 8),
    ('H2 sibling new', 'X-H2', 'new', 0x2de5edc, 12),
    ('H2 sibling flag store', 'X-H2', 'new', 0x2de6008, 8),
    # --- X-H2: диспетчер, ветка MF-операций ------------------------------
    ('H2 disp old branch', 'X-H2', 'old', 0x2cecb34, 12),
    ('H2 disp old props MF', 'X-H2', 'old', 0x2cecd80, 8),
    ('H2 disp old tail', 'X-H2', 'old', 0x2cecca0, 4),
    ('H2 disp new branch', 'X-H2', 'new', 0x2ce8b34, 12),
    ('H2 disp new const', 'X-H2', 'new', 0x2ce8b48, 8),
    ('H2 disp new fallback', 'X-H2', 'new', 0x2ce8d80, 4),
    ('H2 disp new tail', 'X-H2', 'new', 0x2ce8ca0, 4),
    # --- X-H2: helper и потребители -------------------------------------
    ('H2 helper old A', 'X-H2', 'old', 0x2f39820, 14),
    ('H2 helper old B', 'X-H2', 'old', 0x2f39878, 14),
    ('H2 helper new', 'X-H2', 'new', 0x2f3458c, 22),
    ('H2 status caller new', 'X-H2', 'new', 0x2ce3d24, 12),
    ('H2 sibling dest new', 'X-H2', 'new', 0x2de6138, 6),
    ('H2 1db8->global', 'X-H2', 'new', 0x2f3bf7c, 6),
    ('H2 global reader', 'X-H2', 'new', 0x2f462b0, 14),
    # --- X-H2S ------------------------------------------------------------
    ('H2S main old', 'X-H2S', 'old', 0x3107f60, 10),
    ('H2S main new', 'X-H2S', 'new', 0x3107fd4, 10),
    ('H2S sibling old', 'X-H2S', 'old', 0x310141c, 8),
    ('H2S sibling new', 'X-H2S', 'new', 0x310149c, 8),
    ('H2S disp old', 'X-H2S', 'old', 0x3004458, 22),
    ('H2S disp new', 'X-H2S', 'new', 0x3004458, 32),
    ('H2S disp new fallback', 'X-H2S', 'new', 0x30046b0, 8),
    ('H2S helper old', 'X-H2S', 'old', 0x32505b4, 12),
    ('H2S helper new', 'X-H2S', 'new', 0x324f340, 22),
    # --- X-T5 -------------------------------------------------------------
    ('T5 main old', 'X-T5', 'old', 0x2d2dfb0, 10),
    ('T5 main new', 'X-T5', 'new', 0x2d2e034, 10),
    ('T5 sibling old', 'X-T5', 'old', 0x2d274e8, 8),
    ('T5 sibling new', 'X-T5', 'new', 0x2d27578, 8),
    ('T5 disp old', 'X-T5', 'old', 0x2c2b7f8, 14),
    ('T5 disp old props MF', 'X-T5', 'old', 0x2c2ba44, 8),
    ('T5 disp new branch', 'X-T5', 'new', 0x2c2b7f8, 14),
    ('T5 disp new props 205x', 'X-T5', 'new', 0x2c2b818, 8),
    ('T5 disp new fallback', 'X-T5', 'new', 0x2c2ba50, 8),
    ('T5 disp new tail', 'X-T5', 'new', 0x2c2b970, 4),
    ('T5 helper old', 'X-T5', 'old', 0x2e74b38, 12),
    ('T5 helper new', 'X-T5', 'new', 0x2e738e4, 22),
]

if __name__ == '__main__':
    out = []
    for label, model, state, addr, n in WINDOWS:
        b = load(model, state, 1)
        out.append('### %s   [%s %s, base=%#x]' % (label, model, b.version, b.base))
        out.append(dis(b, addr, n))
        out.append('')
    txt = '\n'.join(out)
    (HERE / 'b2_windows.txt').write_text(txt, encoding='utf8')
    print(txt[:2000])
    print('... всего строк:', txt.count('\n'))
    print('saved b2_windows.txt')
