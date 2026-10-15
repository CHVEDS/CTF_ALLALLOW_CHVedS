#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
h3r3s — консольный помощник команды на CTF.
Автор: Heres

Запуск:  h3r3s.cmd   (двойной клик)
   или:  python h3r3s.py

Модули:
  1. Магический декодер   — разворачивает цепочки base64/32/85, hex, url, rot, XOR
  2. Охотник за флагом    — ищет флаг в файлах и папках (в т.ч. UTF-16, внутри блобов)
  3. Что это за файл      — тип по сигнатуре, энтропия, строки, вложенные файлы
  4. Шаблоны скриптов     — готовые заготовки (PPC-спам, z3, XOR) в буфер/файл
"""

import sys, os, io, time, random, string, base64, binascii, codecs, re, math, zlib, gzip, struct

# ───────────────────────── формат флага ──────────────────────────────
# Под SolarCTF 2026. Можно переопределить переменной окружения H3R3S_FLAG.
FLAG_PREFIXES = ["SOLARCTF{", "4rays{", "flag{", "CTF{"]
# тело флага: печатные символы без пробелов и управляющих — чтобы не принимать мусор
FLAG_RE = re.compile(r'(?:SOLARCTF|4rays|flag|CTF)\{[!-\|~]{1,160}\}')

# ───────────────────────── цвет и вывод ──────────────────────────────
WIN = os.name == "nt"
if WIN:
    os.system("")  # включить ANSI в Windows-консоли

class C:
    g  = "\033[92m"; dg = "\033[32m"; w = "\033[97m"; gray = "\033[90m"
    r  = "\033[91m"; y = "\033[93m"; cy = "\033[96m"; dim = "\033[2m"
    rs = "\033[0m";  b = "\033[1m"

NOSOUND = "-NoSound" in sys.argv or "--nosound" in sys.argv
NOTYPE  = "-NoType"  in sys.argv or "--notype"  in sys.argv

def beep(f, ms):
    if NOSOUND: return
    try:
        import winsound; winsound.Beep(int(f), int(ms))
    except Exception:
        pass

def tw(text, color=C.g, delay=0.008, nl=True):
    """печать по буквам"""
    if NOTYPE: delay = 0
    for ch in text:
        sys.stdout.write(color + ch + C.rs); sys.stdout.flush()
        if delay and not ch.isspace(): time.sleep(delay)
    if nl: sys.stdout.write("\n")
    sys.stdout.flush()

def say(text):
    sys.stdout.write("\n" + C.g + "  ※ " + C.dg + "Heres ▸ " + C.rs)
    tw(text, C.w, 0.01)

def rule(ch="─", color=C.dg):
    print(color + "  " + ch * 60 + C.rs)

def hdr(t):
    print(); print(C.g + "  == " + t + C.rs)

# ───────────────────────── баннер ────────────────────────────────────
BANNER = [
    "  ▄█    █▄      ▄████▄     █████▄   ▄████▄   ▄████▄",
    "  ███▄  ██    ██▀    ▀    ██   ██  ██▀  ▀█  ██▀    ",
    "  ██ ██ ██   ▆█▆▆▆▆    ██████▀  ████▆▆▆  ▀████▆ ",
    "  ██  ████   ██▄    ▄    ██  ██▄   ██▄  ▄█      ██",
    "  ██   ▀██    ▀████▀     ██   ██▄   ▀████▀   ▀████▀",
]
def banner():
    os.system("cls" if WIN else "clear")
    print()
    # глитч
    noise = "▓▒░#@%<>/\\|"
    for _ in range(2):
        for line in BANNER:
            out = "".join(random.choice(noise) if (c not in " " and random.random() < .5) else c for c in line)
            col = random.choice([C.r, C.dg, C.g])
            sys.stdout.write("  " + col + out + C.rs + "\n")
        time.sleep(.05)
        sys.stdout.write("\033[%dA" % (len(BANNER)))
    for line in BANNER:
        print("  " + C.g + line + C.rs)
    print("  " + C.dg + "─" * 52 + C.rs)
    print("  " + C.dg + "  h3r3s" + C.rs + C.gray + "  ::  помощник команды  ::  by Heres" + C.rs)
    print()

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

def magic(data, depth=4):
    """рекурсивно разворачивает слои; возвращает список (recipe, result) с найденным флагом,
       иначе лучший «читаемый» результат."""
    best = []
    seen = set()
    found = []

    def rec(b, recipe, d):
        if len(found) >= 6 or d < 0: return
        h = (bytes(b[:64]), len(b))
        if h in seen: return
        seen.add(h)
        fl = flag_in(b)
        if fl:
            found.append((" > ".join(recipe) if recipe else "как есть", fl, b))
            return
        # XOR-попытки на каждом слое
        hit_here = False
        for name, res in filter(None, [xor_known(b), xor_single(b)]):
            fl2 = flag_exact(res)
            if fl2:
                found.append((" > ".join(recipe + [name]), fl2, res)); hit_here = True
        if hit_here: return          # слой раскрылся в флаг — глубже не копаем
        if d == 0: return
        for name, fn in SINGLE:
            try: out = fn(b)
            except Exception: out = None
            if not out or out == b: continue
            # запоминаем читаемые ветки на случай, если флаг не найдём
            if looks_text(out): best.append((" > ".join(recipe + [name]), out))
            rec(out, recipe + [name], d - 1)

    rec(data, [], depth)
    return found, best

# ═══════════════════════ МОДУЛЬ 1: ДЕКОДЕР ════════════════════════════
def module_decode():
    hdr("МАГИЧЕСКИЙ ДЕКОДЕР")
    say("вставь строку — разберу слои сам. Enter на пустой строке — назад.")
    while True:
        print(C.dg + "\n  декодер" + C.rs + C.gray + " ▸ " + C.rs, end="")
        try: raw = input()
        except EOFError: return
        raw = raw.strip()
        if not raw: return
        data = raw.encode("latin1", "ignore")
        beep(900, 20)
        tw("  [*] разворачиваю слои...", C.g, 0.006)
        found, best = magic(data)
        if found:
            beep(1200, 40); beep(1500, 60)
            for recipe, flag, _ in found[:5]:
                print("  " + C.dg + recipe + C.rs)
                print("    " + C.r + C.b + flag + C.rs)
            say("готово. флаг подсвечен красным.")
        elif best:
            # показать до 3 самых читаемых результатов
            uniq = []
            for recipe, out in best:
                s = out.decode("latin1")
                if s not in [u[1] for u in uniq]:
                    uniq.append((recipe, s))
            for recipe, s in uniq[:3]:
                print("  " + C.dg + recipe + C.rs)
                print("    " + C.w + (s[:200] + ("..." if len(s) > 200 else "")) + C.rs)
            say("флага не видно, но вот что получилось раскодировать. глянь — вдруг нужен ещё слой.")
        else:
            say("не поддалось. проверь строку или добавь XOR-ключ вручную в CyberChef.")

# ═══════════════════════ МОДУЛЬ 2: ОХОТНИК ════════════════════════════
def iter_strings(b, minlen=4):
    """ASCII и UTF-16LE строки из бинарных данных"""
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % minlen, b):
        yield m.group()
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % minlen, b):
        yield m.group().replace(b"\x00", b"")

CHUNK_RES = [
    re.compile(rb"[A-Za-z0-9+/=_\-]{12,}"),        # base64/url-safe/hex общий
    re.compile(rb"[A-Za-z0-9+/]{16,}={0,2}"),      # чистый base64-токен без ведущего key=
    re.compile(rb"[0-9a-fA-F]{16,}"),              # hex
    re.compile(rb"[!-~]{20,}"),                     # url/base85 плотный печатный кусок
]

def hunt_bytes(b, src, hits):
    # 1) прямой флаг (в т.ч. UTF-16)
    for s in iter_strings(b, 5):
        fl = flag_in(s)
        if fl: hits.append((src, "строка", "", fl))
    # 2) закодированные блобы — несколько видов нарезки
    seen = set()
    for rx in CHUNK_RES:
        for m in rx.finditer(b):
            chunk = m.group()
            if len(chunk) > 6000 or chunk in seen: continue
            seen.add(chunk)
            found, _ = magic(chunk, depth=3)
            for recipe, fl, _ in found[:1]:
                hits.append((src, "блоб", recipe, fl))

def module_hunt():
    hdr("ОХОТНИК ЗА ФЛАГОМ")
    say("дай путь к файлу или папке — прочешу всё, включая UTF-16 и закодированные куски.")
    print(C.dg + "\n  путь" + C.rs + C.gray + " ▸ " + C.rs, end="")
    try: path = input().strip().strip('"')
    except EOFError: return
    if not path: return
    if not os.path.exists(path):
        say("не нашёл такой путь."); return
    files = []
    if os.path.isfile(path): files = [path]
    else:
        for root, _, fs in os.walk(path):
            for f in fs: files.append(os.path.join(root, f))
    say("файлов к осмотру: %d. поехали." % len(files))
    hits = []
    for i, f in enumerate(files):
        try:
            if os.path.getsize(f) > 60 * 1024 * 1024: continue
            with open(f, "rb") as fh: b = fh.read()
        except Exception: continue
        rel = os.path.relpath(f, path if os.path.isdir(path) else os.path.dirname(path) or ".")
        hunt_bytes(b, rel, hits)
        # внутрь gzip/zlib
        z = t_zlib(b) or t_gzip_safe(b)
        if z: hunt_bytes(z, rel + " (unzip)", hits)
        if (i + 1) % 25 == 0:
            sys.stdout.write("\r  " + C.gray + "просмотрено %d/%d, найдено %d" % (i + 1, len(files), len(hits)) + C.rs)
            sys.stdout.flush()
    print()
    # убрать дубли
    uniq = list(dict.fromkeys(hits))
    if uniq:
        beep(1200, 40); beep(1600, 70)
        rule()
        for src, kind, recipe, fl in uniq[:40]:
            print("  " + C.r + C.b + fl + C.rs)
            print("    " + C.gray + src + ("  [" + recipe + "]" if recipe else "") + C.rs)
        say("нашёл %d штук. проверь каждый — не всё обязательно настоящий флаг." % len(uniq))
    else:
        say("флага в открытом и закодированном виде не нашёл. возможно, он глубже — тащи подозрительный файл в модуль 3.")

def t_gzip_safe(b):
    try: return gzip.decompress(b)
    except Exception: return None

# ═══════════════════════ МОДУЛЬ 3: ФАЙЛ ═══════════════════════════════
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

def module_file():
    hdr("ЧТО ЭТО ЗА ФАЙЛ")
    print(C.dg + "\n  путь к файлу" + C.rs + C.gray + " ▸ " + C.rs, end="")
    try: path = input().strip().strip('"')
    except EOFError: return
    if not path or not os.path.isfile(path):
        say("это не файл."); return
    with open(path, "rb") as fh: b = fh.read()
    ext = os.path.splitext(path)[1].lower()
    # тип по сигнатуре
    kind = "неизвестно (похоже на текст)" if looks_text(b[:512]) else "неизвестно (бинарные данные)"
    for sig, name in SIGS:
        if b.startswith(sig): kind = name; break
    print("  размер   : " + C.w + str(len(b)) + " байт" + C.rs)
    print("  тип      : " + C.w + kind + C.rs)
    ent = entropy(b[:200000])
    ehint = "  (высокая — зашифровано/упаковано)" if ent > 7.2 else ""
    print("  энтропия : " + C.w + "%.2f / 8.0" % ent + C.rs + C.gray + ehint + C.rs)
    # расширение врёт?
    guessed_ext = {".png": b"\x89PNG", ".jpg": b"\xff\xd8\xff", ".pdf": b"%PDF", ".zip": b"PK\x03\x04"}
    if ext in guessed_ext and not b.startswith(guessed_ext[ext]):
        print("  " + C.y + "! расширение %s не совпадает с содержимым — файл замаскирован" % ext + C.rs)
    # вложенные файлы (как binwalk)
    found_embed = []
    for sig, name in EMBED:
        start = 1
        while True:
            idx = b.find(sig, start)
            if idx < 0: break
            found_embed.append((idx, name)); start = idx + 1
            if len(found_embed) > 20: break
    if found_embed:
        print("  " + C.y + "вложенные файлы (как binwalk):" + C.rs)
        for off, name in found_embed[:20]:
            print("    offset %d (0x%x): %s" % (off, off, name))
        say("внутри что-то спрятано. вырезать: в консоли  dd  или python: open(out,'wb').write(data[offset:])")
    # флаг прямо в строках
    flags = set()
    for s in iter_strings(b, 5):
        fl = flag_in(s)
        if fl: flags.add(fl)
    if flags:
        beep(1300, 50)
        for fl in flags: print("  " + C.r + C.b + "FLAG: " + fl + C.rs)
    # немного строк
    strs = [s.decode("latin1") for s in iter_strings(b, 6)]
    if strs:
        print("  " + C.gray + "первые строки:" + C.rs)
        for s in strs[:12]: print("    " + C.dim + s[:100] + C.rs)
    say("если энтропия высокая и флага нет — тащи блобы в декодер (модуль 1).")

# ═══════════════════════ МОДУЛЬ 4: ШАБЛОНЫ ════════════════════════════
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

def module_templates():
    hdr("ШАБЛОНЫ СКРИПТОВ")
    items = list(TEMPLATES.items())
    for i, (k, (fn, _)) in enumerate(items, 1):
        print("  " + C.g + "[%d] " % i + C.rs + C.w + fn + C.rs + C.gray + "  (" + k + ")" + C.rs)
    say("введи номер — сохраню шаблон рядом в файл. Enter — назад.")
    print(C.dg + "\n  шаблон" + C.rs + C.gray + " ▸ " + C.rs, end="")
    try: sel = input().strip()
    except EOFError: return
    if not sel.isdigit() or not (1 <= int(sel) <= len(items)): return
    k, (fn, body) = items[int(sel) - 1]
    try:
        with open(fn, "w", encoding="utf-8") as f: f.write(body)
        beep(1100, 40)
        say("сохранил %s рядом. открой и подставь свои значения." % fn)
    except Exception as e:
        say("не смог сохранить: %s" % e)

# ═══════════════════════ ГЛАВНОЕ МЕНЮ ═════════════════════════════════
MENU = [
    ("Магический декодер", "base64/hex/url/rot/xor — разворачивает слои сам", module_decode),
    ("Охотник за флагом", "ищет SOLARCTF{...} в файлах и папках", module_hunt),
    ("Что это за файл", "тип, энтропия, вложения, строки", module_file),
    ("Шаблоны скриптов", "PPC / z3 / XOR / HTTP — готовые заготовки", module_templates),
]

def main():
    banner()
    beep(600, 30); beep(800, 30)
    say(random.choice([
        "на связи. что разбираем?",
        "готов к работе. неси задачу.",
        "флаги сами себя не найдут. поехали.",
    ]))
    while True:
        print()
        print("  " + C.dg + "┌─[ МОДУЛИ ]" + "─" * 42 + C.rs)
        for i, (name, desc, _) in enumerate(MENU, 1):
            print("  " + C.dg + "│  " + C.g + "[%d] " % i + C.w + ("%-22s" % name) + C.rs + C.gray + desc + C.rs)
        print("  " + C.dg + "│  " + C.gray + "[Q] выход" + C.rs)
        print("  " + C.dg + "└─" + C.g + "team@h3r3s" + C.gray + ":~# " + C.rs, end="")
        try: sel = input().strip().lower()
        except (EOFError, KeyboardInterrupt):
            print(); break
        if sel in ("q", "quit", "exit", ""): break
        if sel.isdigit() and 1 <= int(sel) <= len(MENU):
            try:
                MENU[int(sel) - 1][2]()
            except KeyboardInterrupt:
                say("прервал. возвращаю в меню.")
    print()
    tw("  ※ Heres ▸ удачи на SolarCTF. принеси флагов.", C.g, 0.01)
    print()

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(C.r + "\n  сбой: %s" % e + C.rs)
        if WIN:
            input("  Enter для выхода...")
