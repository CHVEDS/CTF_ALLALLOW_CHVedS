#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
h3r3s engine — «мозг» помощника. Интерфейс и эффекты — в h3r3s.ps1.
Автор: Heres

Использование (результат — JSON в stdout, только ASCII):
  engine.py decode <файл_с_вводом>
  engine.py hunt   <путь>
  engine.py file   <путь>
  engine.py template <имя> <папка>
  engine.py templates
"""
import sys, os, io, re, json, math, zlib, gzip, base64, binascii, codecs, string

FLAG_PREFIXES = ["SOLARCTF{", "4rays{", "flag{", "CTF{"]
# тело флага: печатные символы без пробелов и управляющих — чтобы не принимать мусор
FLAG_RE = re.compile(r'(?:SOLARCTF|4rays|flag|CTF)\{[!-\|~]{1,160}\}')


# ═══════════════════════ ДВИЖОК ДЕКОДЕРА ══════════════════════════════
PRINTABLE = set(bytes(string.printable, "ascii")) - {0x0b, 0x0c}

def looks_text(b, thr=0.90):
    if not b: return False
    ok = sum(1 for x in b if x in PRINTABLE)
    return ok / len(b) >= thr

def flag_in(b):
    try: s = b.decode("latin1")
    except Exception: return None
    m = FLAG_RE.search(s)
    return m.group(0) if m else None

def flag_exact(b):
    """флаг занимает почти весь буфер (для принятия результата XOR — там данные это сам флаг)"""
    core = b.strip(b"\x00\r\n\t ")
    try: s = core.decode("latin1")
    except Exception: return None
    m = FLAG_RE.fullmatch(s)
    return m.group(0) if m else None

# префиксы, по которым безопасно ВЫЧИСЛЯТЬ XOR-ключ (достаточно длинные)
XOR_PREFIXES = [p for p in FLAG_PREFIXES if len(p) >= 6]

def entropy(b):
    if not b: return 0.0
    from collections import Counter
    n = len(b); e = 0.0
    for c in Counter(b).values():
        p = c / n; e -= p * math.log2(p)
    return e

# ---- отдельные преобразования: (имя) -> bytes | None ----
def t_b64(b):
    s = re.sub(rb"\s", b"", b)
    if len(s) < 4 or not re.fullmatch(rb"[A-Za-z0-9+/=]+", s): return None
    try: return base64.b64decode(s + b"=" * (-len(s) % 4), validate=False)
    except Exception: return None

def t_b64url(b):
    s = re.sub(rb"\s", b"", b)
    if len(s) < 4 or not re.fullmatch(rb"[A-Za-z0-9\-_=]+", s) or (b"-" not in s and b"_" not in s): return None
    try: return base64.urlsafe_b64decode(s + b"=" * (-len(s) % 4))
    except Exception: return None

def t_b32(b):
    s = re.sub(rb"\s", b"", b).upper()
    if len(s) < 8 or not re.fullmatch(rb"[A-Z2-7=]+", s): return None
    try: return base64.b32decode(s + b"=" * (-len(s) % 8))
    except Exception: return None

def t_b85(b):
    s = re.sub(rb"\s", b"", b)
    if len(s) < 4: return None
    try: return base64.b85decode(s)
    except Exception:
        try: return base64.a85decode(s)
        except Exception: return None

def t_hex(b):
    s = re.sub(rb"[\s:]", b"", b)
    if len(s) < 4 or len(s) % 2 or not re.fullmatch(rb"[0-9a-fA-F]+", s): return None
    try: return binascii.unhexlify(s)
    except Exception: return None

def t_url(b):
    if b"%" not in b: return None
    try:
        from urllib.parse import unquote_to_bytes
        out = unquote_to_bytes(b)
        return out if out != b else None
    except Exception: return None

def t_rot13(b):
    try: return codecs.encode(b.decode("latin1"), "rot13").encode("latin1")
    except Exception: return None

def t_reverse(b):
    return b[::-1]

def t_utf16(b):
    # снять нулевые байты: UTF-16 строки из Windows
    if b.count(0) < max(1, len(b) // 4): return None
    out = b.replace(b"\x00", b"")
    return out if out != b else None

def t_zlib(b):
    for fn in (zlib.decompress, lambda x: zlib.decompress(x, -15), lambda x: gzip.decompress(x)):
        try:
            out = fn(b)
            if out: return out
        except Exception: pass
    return None

def t_dec(b):
    # десятичные коды символов через пробел/запятую: "72 101 108"
    s = b.decode("latin1").strip()
    parts = re.split(r"[\s,]+", s)
    if len(parts) < 3 or not all(p.isdigit() for p in parts): return None
    try:
        vals = [int(p) for p in parts]
        if all(0 <= v < 256 for v in vals): return bytes(vals)
    except Exception: pass
    return None

SINGLE = [
    ("base64", t_b64), ("base64url", t_b64url), ("base32", t_b32), ("base85", t_b85),
    ("hex", t_hex), ("url", t_url), ("utf16-strip", t_utf16),
    ("rot13", t_rot13), ("reverse", t_reverse), ("dec", t_dec), ("zlib/gzip", t_zlib),
]

def xor_single(b):
    """вернуть (key, out) если XOR одним байтом даёт ровно флаг"""
    for k in range(256):
        out = bytes(x ^ k for x in b)
        if flag_exact(out): return ("xor-1b(0x%02x)" % k, out)
    return None

def xor_known(b):
    """вычислить повторяющийся XOR-ключ по известному началу флага.
       Принимаем только если вся расшифровка — это флаг (данные = сам флаг)."""
    for pre in XOR_PREFIXES:
        p = pre.encode()
        if len(b) < len(p): continue
        raw = bytes(b[i] ^ p[i] for i in range(len(p)))
        for klen in range(1, len(p) + 1):          # самый короткий период ключа
            kk = raw[:klen]
            if raw != bytes(kk[i % klen] for i in range(len(p))): continue
            out = bytes(b[i] ^ kk[i % klen] for i in range(len(b)))
            if flag_exact(out):
                disp = kk.decode("latin1") if looks_text(kk) else kk.hex()
                return ("xor(key=%s)" % disp, out)
            break
    return None

INVERSE_SELF = {"rot13", "reverse"}   # применить дважды подряд = ничего не сделать

def _magic_once(data, depth):
    best, seen, found = [], set(), []

    def rec(b, recipe, d):
        if len(found) >= 6 or d < 0: return
        h = (bytes(b[:64]), len(b), d)
        if h in seen: return
        seen.add(h)
        fl = flag_in(b)
        if fl:
            found.append((" > ".join(recipe) if recipe else "как есть", fl, b))
            return
        hit_here = False
        for name, res in filter(None, [xor_known(b), xor_single(b)]):
            fl2 = flag_exact(res)
            if fl2:
                found.append((" > ".join(recipe + [name]), fl2, res)); hit_here = True
        if hit_here or d == 0: return
        for name, fn in SINGLE:
            if recipe and name == recipe[-1] and name in INVERSE_SELF: continue
            try: out = fn(b)
            except Exception: out = None
            if not out or out == b: continue
            if looks_text(out): best.append((" > ".join(recipe + [name]), out))
            rec(out, recipe + [name], d - 1)

    rec(data, [], depth)
    return found, best

def magic(data, depth=4):
    """ищет флаг с постепенным углублением — так рецепт получается самым коротким"""
    best_all = []
    for d in range(depth + 1):
        found, best = _magic_once(data, d)
        if found:
            return found, best
        best_all = best
    return [], best_all


def iter_strings(b, minlen=4):
    """ASCII и UTF-16LE строки из бинарных данных"""
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % minlen, b):
        yield m.group()
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % minlen, b):
        yield m.group().replace(b"\x00", b"")

CHUNK_RES = [
    re.compile(rb"[A-Za-z0-9+/=_\-]{12,}"),            # base64/url-safe/hex общий
    re.compile(rb"[A-Za-z0-9+/]{16,}={0,2}"),          # чистый base64-токен без ведущего key=
    re.compile(rb"[0-9a-fA-F]{16,}"),                  # hex
    re.compile(rb"[A-Za-z0-9!#$%&()*+;<=>?@^_`{|}~.,/\-]{20,}"),  # base85 плотный кусок
    re.compile(rb"(?:%[0-9A-Fa-f]{2}|[A-Za-z0-9+/=_~.\-]){16,}"), # url-encoded блоб (с %XX)
]

# архивы, в которые заходим и сканируем каждый файл
def iter_archive(b):
    """вернуть [(имя_внутри, данные)] для zip/tar; пусто если не архив"""
    out = []
    try:
        import zipfile
        if b[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
            with zipfile.ZipFile(io.BytesIO(b)) as z:
                for n in z.namelist()[:200]:
                    try: out.append((n, z.read(n)))
                    except Exception: pass
            return out
    except Exception: pass
    try:
        import tarfile
        with tarfile.open(fileobj=io.BytesIO(b)) as t:
            for m in t.getmembers()[:200]:
                if m.isfile():
                    try: out.append((m.name, t.extractfile(m).read()))
                    except Exception: pass
        return out
    except Exception: pass
    return out

def hunt_bytes(b, src, hits, _depth=0):
    if _depth > 4: return
    # 1) прямой флаг (в т.ч. UTF-16)
    for s in iter_strings(b, 5):
        fl = flag_in(s)
        if fl: hits.append((src, "строка", "", fl))
    # 2) закодированные блобы — несколько видов нарезки
    seen = set()
    for rx in CHUNK_RES:
        for m in rx.finditer(b):
            chunk = m.group()
            if len(chunk) < 12 or len(chunk) > 8000: continue
            # кандидаты: весь кусок и часть после ведущего "key=" (param=VALUE)
            cands = [chunk]
            if b"=" in chunk[:10]:
                tail = chunk.split(b"=", 1)[1]
                if len(tail) >= 12: cands.append(tail)
            for c in cands:
                if c in seen: continue
                seen.add(c)
                found, _ = _magic_once(c, 4)          # быстрый проход
                if found: found, _ = magic(c, depth=4)  # для находки — кратчайший рецепт
                for recipe, fl, _ in found[:1]:
                    hits.append((src, "блоб", recipe, fl))
    # 3) распаковка: gzip/zlib целиком и заход внутрь архивов (zip/tar)
    if _depth < 3:
        z = t_zlib(b) or t_gzip_safe(b)
        if z and z != b: hunt_bytes(z, src + " ▸ unzip", hits, _depth + 1)
        for name, data in iter_archive(b):
            if data and data != b:
                hunt_bytes(data, src + " ▸ " + name, hits, _depth + 1)


def t_gzip_safe(b):
    try: return gzip.decompress(b)
    except Exception: return None


SIGS = [
    (b"\x89PNG\r\n\x1a\n", "PNG изображение"), (b"\xff\xd8\xff", "JPEG изображение"),
    (b"GIF8", "GIF изображение"), (b"PK\x03\x04", "ZIP/Office/APK архив"),
    (b"Rar!\x1a\x07", "RAR архив"), (b"7z\xbc\xaf\x27\x1c", "7z архив"),
    (b"\x1f\x8b", "GZIP архив"), (b"BZh", "BZIP2 архив"), (b"\xfd7zXZ\x00", "XZ архив"),
    (b"%PDF", "PDF документ"), (b"MZ", "Windows EXE/DLL"), (b"\x7fELF", "Linux ELF"),
    (b"\xca\xfe\xba\xbe", "Java class / Mach-O"), (b"OggS", "OGG аудио/видео"),
    (b"ID3", "MP3 аудио"), (b"RIFF", "WAV/AVI (RIFF)"), (b"regf", "Windows Registry hive"),
    (b"FILE", "NTFS MFT запись"), (b"\xfe\xed\xfa", "Mach-O"), (b"SQLite format 3", "SQLite БД"),
]
EMBED = [(b"PK\x03\x04", "ZIP"), (b"\x89PNG\r\n", "PNG"), (b"\xff\xd8\xff", "JPEG"),
         (b"%PDF", "PDF"), (b"7z\xbc\xaf\x27\x1c", "7z"), (b"Rar!\x1a\x07", "RAR")]


TEMPLATES = {
"ppc": ("ppc_spam.py", r'''# PPC: массовая отправка запросов (как Homyak Tap).
# Подставь URL, куки и тело запроса из DevTools -> Network.
import requests, json, random, time

URL = "https://TARGET/api/tap"
COOKIES = {"homyak": "ВСТАВЬ_КУКУ"}

def tap():
    payload = {"x": random.randint(600, 900), "y": random.randint(600, 900)}
    r = requests.post(URL, data=json.dumps(payload), cookies=COOKIES,
                      headers={"Content-Type": "application/json"})
    return r

for i in range(10000):
    tap()
    if i % 500 == 0: print("sent", i)
    # time.sleep(0.01)  # если сервер злится на частоту
'''),
"z3": ("solve_z3.py", r'''# REVERSE: восстановить флаг по проверке через SMT-солвер (как Rusty love).
# Опиши в решателе те же ограничения и формулу, что в бинарнике.
from z3 import *

N = 10                       # длина искомой части
chars = [BitVec(f"c{i}", 8) for i in range(N)]
s = Solver()
for c in chars:              # алфавит: цифры и заглавные
    s.add(Or(And(c >= ord('0'), c <= ord('9')),
             And(c >= ord('A'), c <= ord('Z'))))

# --- сюда перенеси вычисление контрольной суммы из дизассемблера ---
val = BitVecVal(0, 64)
for i, c in enumerate(chars):
    val = (val * 36 + ZeroExt(56, c)) & 0xFFFFFFFFFFFFFFFF
s.add(val == 0xDEADBEEF)     # <- целевое значение из бинарника

print("sat" if s.check() == sat else "unsat")
if s.check() == sat:
    m = s.model()
    print("".join(chr(m[c].as_long()) for c in chars))
'''),
"xor": ("xor_crack.py", r'''# CRYPTO: XOR с ключом, вычисленным по известному началу флага.
PREFIX = b"SOLARCTF{"
data = bytes.fromhex("ВСТАВЬ_HEX")   # или open("file","rb").read()

key = bytes(data[i] ^ PREFIX[i] for i in range(len(PREFIX)))  # период <= len(PREFIX)
for klen in range(1, len(PREFIX) + 1):
    k = key[:klen]
    out = bytes(data[i] ^ k[i % klen] for i in range(len(data)))
    if b"}" in out and all(32 <= x < 127 for x in out[:40]):
        print(klen, k, out[:80]); break
'''),
"req": ("http_probe.py", r'''# WEB: быстрый перебор/прощупывание эндпоинтов.
import requests
BASE = "https://TARGET"
for p in ["/admin", "/api", "/.git/config", "/robots.txt", "/flag", "/debug"]:
    try:
        r = requests.get(BASE + p, timeout=5)
        print(r.status_code, len(r.content), p)
    except Exception as e:
        print("err", p, e)
'''),
}



# ═══════════════════════ CLI ═════════════════════════════════════════
def out(obj):
    sys.stdout.write(json.dumps(obj, ensure_ascii=True))
    sys.stdout.flush()

def txt(b):
    return b.decode("latin1") if isinstance(b, (bytes, bytearray)) else str(b)

def cmd_decode(path):
    with open(path, "rb") as f:
        raw = f.read()
    try:
        data = raw.decode("utf-8-sig").strip().encode("latin1", "ignore")
    except Exception:
        data = raw.strip()
    found, best = magic(data, depth=5)
    if not found and len(data) > 24:
        hits = []
        hunt_bytes(data, "ввод", hits)
        for _, kind, recipe, fl in hits:
            found.append((recipe if recipe else "как есть", fl, b""))
    res = {"found": [], "readable": []}
    seen = set()
    for recipe, fl, _ in found:
        if fl in seen: continue
        seen.add(fl)
        res["found"].append({"recipe": recipe.split(" > ") if recipe != "как есть" else [], "flag": fl})
    rs = set()
    for recipe, o in best:
        t = txt(o)
        if t in rs: continue
        rs.add(t)
        res["readable"].append({"recipe": recipe.split(" > "), "text": t[:300]})
        if len(res["readable"]) >= 3: break
    out(res)

def cmd_hunt(path):
    files = []
    if os.path.isfile(path):
        files = [path]; base = os.path.dirname(path) or "."
    else:
        base = path
        for root, _, fs in os.walk(path):
            for f in fs: files.append(os.path.join(root, f))
    hits = []
    for f in files:
        try:
            if os.path.getsize(f) > 60 * 1024 * 1024: continue
            with open(f, "rb") as fh: b = fh.read()
        except Exception:
            continue
        rel = os.path.relpath(f, base)
        hunt_bytes(b, rel, hits)   # распаковка архивов/gzip — внутри hunt_bytes
    _seen = set(); uniq = []
    for h in hits:
        if (h[0], h[3]) in _seen: continue
        _seen.add((h[0], h[3])); uniq.append(h)
    out({"files": len(files), "hits": [
        {"src": s, "kind": k, "recipe": r.split(" > ") if r and r != "как есть" else [], "flag": fl}
        for s, k, r, fl in uniq[:60]]})

def cmd_file(path):
    with open(path, "rb") as fh: b = fh.read()
    ext = os.path.splitext(path)[1].lower()
    kind = "неизвестно (текст)" if looks_text(b[:512]) else "неизвестно (бинарные данные)"
    for sig, name in SIGS:
        if b.startswith(sig): kind = name; break
    mism = ""
    guessed = {".png": b"\x89PNG", ".jpg": b"\xff\xd8\xff", ".jpeg": b"\xff\xd8\xff", ".pdf": b"%PDF",
               ".zip": b"PK\x03\x04", ".gif": b"GIF8", ".exe": b"MZ", ".dll": b"MZ"}
    if ext in guessed and not b.startswith(guessed[ext]): mism = ext
    emb = []
    for sig, name in EMBED:
        st = 1
        while len(emb) < 20:
            i = b.find(sig, st)
            if i < 0: break
            emb.append({"offset": i, "name": name}); st = i + 1
    emb.sort(key=lambda x: x["offset"])
    flags = sorted({fl for s in iter_strings(b, 5) for fl in [flag_in(s)] if fl})
    strs = [txt(s)[:100] for s in iter_strings(b, 6)][:12]
    out({"size": len(b), "type": kind, "entropy": round(entropy(b[:200000]), 2), "ext_mismatch": mism,
         "embedded": emb, "flags": flags, "strings": strs})

def cmd_templates():
    out({"templates": [{"key": k, "file": v[0], "about": v[1].splitlines()[0].lstrip("# ")} for k, v in TEMPLATES.items()]})

def cmd_template(key, folder):
    fn, body = TEMPLATES[key]
    os.makedirs(folder, exist_ok=True)
    p = os.path.join(folder, fn)
    with open(p, "w", encoding="utf-8") as f: f.write(body)
    out({"saved": p})

if __name__ == "__main__":
    a = sys.argv[1:]
    try:
        if not a: raise SystemExit("нет команды")
        if a[0] == "decode": cmd_decode(a[1])
        elif a[0] == "hunt": cmd_hunt(a[1])
        elif a[0] == "file": cmd_file(a[1])
        elif a[0] == "templates": cmd_templates()
        elif a[0] == "template": cmd_template(a[1], a[2])
        else: raise SystemExit("неизвестная команда")
    except Exception as e:
        out({"error": str(e)})
