"""03: поиск таблиц векторов Cortex-M по всему DAT 5.33 и в распакованных блоках.

Два независимых детектора:
  A) SP-детектор: word0 — правдоподобный указатель стека, далее >= min_vec подряд
     нечётных адресов в окне cluster (классическая таблица векторов ARMv7-M);
  B) odd-run: >= 10 подряд нечётных слов в окне 1 МиБ без требования к SP
     (ловит таблицы, чей SP лежит в неизвестной нам SRAM).

Для каждого кандидата считается близость кодовых адресов и, если вектор указывает
внутрь того же буфера, плотность Thumb-кода в точке reset. Только чтение.
"""
import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import m4lib

MIN_VEC = 6
CLUSTER = 0x200000


def odd_runs(words, base_va=0, min_run=10, cluster=0x100000, max_report=80):
    out = []
    n = len(words)
    i = 0
    while i < n:
        if not (words[i] & 1):
            i += 1
            continue
        j = i
        lo, hi = 1 << 32, 0
        while j < n and (words[j] & 1):
            v = words[j]
            if max(hi, v) - min(lo, v) > cluster:
                break
            lo, hi = min(lo, v), max(hi, v)
            j += 1
            if j - i >= 64:
                break
        if j - i >= min_run:
            out.append({'off': base_va + 4 * i, 'n': j - i, 'lo': lo, 'hi': hi,
                        'prev': words[i - 1] if i else None, 'next': words[j] if j < n else None,
                        'vecs': list(words[i:i + 20])})
            i = j
        else:
            i += 1
    out.sort(key=lambda r: -r['n'])
    return out[:max_report]


def scan_buffer(name, buf, base_va):
    words, _ = m4lib.words_of(buf)
    vc = m4lib.vector_candidates(words, base_va, min_vec=MIN_VEC, cluster=CLUSTER, max_report=40)
    orun = odd_runs(words, base_va)
    return {'name': name, 'len': len(buf), 'base': base_va, 'sp_vectors': vc, 'odd_runs': orun}


def main():
    fw = m4lib.load(m4lib.DAT_NEW)
    dec = fw['dec']
    blocks = m4lib.find_fflz(dec)
    regions = m4lib.regions(len(dec), blocks)
    report = {'file': fw['path'], 'buffers': []}

    # 1. сырые области DAT (включая префикс-загрузчик)
    for s, e, rname in regions:
        if rname == 'ecdsa_signature':
            continue
        buf = dec[s:e]
        if e - s < 0x4000:
            continue
        r = scan_buffer(f'{rname}@{s:#x}', buf, s)
        r['region'] = [s, e]
        report['buffers'].append(r)
        print(f"== {r['name']} len={r['len']:#x} SP-кандидатов={len(r['sp_vectors'])} odd-runs={len(r['odd_runs'])}")
        for c in r['sp_vectors'][:12]:
            print(f"   SP {c['sp']:#010x} nvec={c['nvec']} uniq={c['uniq']} off={c['off']:#x} "
                  f"код={c['lo']:#x}..{c['hi']:#x} vecs={[hex(v) for v in c['vecs'][:8]]}")
        for c in r['odd_runs'][:8]:
            prev = f"{c['prev']:#x}" if c['prev'] is not None else '-'
            print(f"   odd n={c['n']} off={c['off']:#x} {c['lo']:#x}..{c['hi']:#x} "
                  f"prev={prev} vecs={[hex(v) for v in c['vecs'][:8]]}")

    # 2. распакованные блоки 0-2 (в них ARM64-код, но может лежать блоб M4)
    for idx in (0, 1, 2, 3):
        b = m4lib.load('X-H2', 'new', idx)
        r = scan_buffer(f'block{idx}', b.data, b.base)
        r['base'] = b.base
        report['buffers'].append(r)
        print(f"== block{idx} base={b.base:#x} len={len(b.data):#x} "
              f"SP-кандидатов={len(r['sp_vectors'])} odd-runs={len(r['odd_runs'])}")
        for c in r['sp_vectors'][:10]:
            print(f"   SP {c['sp']:#010x} nvec={c['nvec']} uniq={c['uniq']} va={c['off']:#x} "
                  f"код={c['lo']:#x}..{c['hi']:#x} vecs={[hex(v) for v in c['vecs'][:8]]}")
        for c in r['odd_runs'][:6]:
            print(f"   odd n={c['n']} va={c['off']:#x} {c['lo']:#x}..{c['hi']:#x} "
                  f"vecs={[hex(v) for v in c['vecs'][:8]]}")

    (HERE / 'вектора.json').write_text(json.dumps(report, ensure_ascii=False, indent=1), encoding='utf8')
    print('saved вектора.json')


if __name__ == '__main__':
    main()
