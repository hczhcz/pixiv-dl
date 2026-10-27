#!/usr/bin/env python3

import argparse
import hashlib
import json
import random
import re
import sqlite3
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

import requests

LOG_NAME = "pixiv-dl.log"
TYPES = {"illust": 0, "manga": 1}
GROUP_DEFAULTS = {
    "s_mode": ["s_tag", "s_tc"],
    "mode": "all",
    "order": "date_d",
    "max_pages": 0,
    "types": ["illust", "manga"],
    "exclude_ai": False,
}


def log(msg):
    print(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {msg}", flush=True)


def now_iso():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def keyring_password(app):
    try:
        import gi
        gi.require_version("Secret", "1")
        from gi.repository import Secret
    except (ImportError, ValueError):
        return None
    for schema_name in ["chrome_libsecret_os_crypt_password_v2", "chrome_libsecret_os_crypt_password_v1"]:
        schema = Secret.Schema.new(schema_name, Secret.SchemaFlags.DONT_MATCH_NAME, {"application": Secret.SchemaAttributeType.STRING})
        password = Secret.password_lookup_sync(schema, {"application": app}, None)
        if password is not None:
            return password
    return None


def derive_key(password):
    return hashlib.pbkdf2_hmac("sha1", password.encode(), b"saltysalt", 1, 16)


def decrypt_cookie(value, keys, strip_hash):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    key = keys.get(value[:3])
    if key is None:
        return None
    decryptor = Cipher(algorithms.AES(key), modes.CBC(b" " * 16)).decryptor()
    data = decryptor.update(value[3:]) + decryptor.finalize()
    data = data[:-data[-1]]
    if strip_hash:
        data = data[32:]
    try:
        return data.decode()
    except UnicodeDecodeError:
        return None


def chromium_cookies(profile, app):
    profile = Path(profile).expanduser()
    db = next((p for p in [profile / "Cookies", profile / "Network" / "Cookies"] if p.exists()), None)
    if db is None:
        sys.exit(f"cookie database not found in {profile}")
    password = keyring_password(app)
    if password is None:
        log(f"keyring password for '{app}' not found, trying fallback keys")
    keys = {b"v10": derive_key("peanuts"), b"v11": derive_key(password or "")}
    conn = sqlite3.connect(f"file:{db}?mode=ro&immutable=1", uri=True)
    version = int(conn.execute("SELECT value FROM meta WHERE key = 'version'").fetchone()[0])
    rows = conn.execute("SELECT name, value, encrypted_value FROM cookies WHERE host_key LIKE '%pixiv.net'").fetchall()
    conn.close()
    cookies = {}
    for name, value, encrypted in rows:
        if not value and encrypted:
            value = decrypt_cookie(encrypted, keys, version >= 24)
        if value:
            cookies[name] = value
    if "PHPSESSID" not in cookies:
        sys.exit("PHPSESSID not found, please log in to pixiv in the browser first")
    return cookies


def parse_cookie_string(text):
    cookies = {}
    for part in text.split(";"):
        if "=" in part:
            name, value = part.split("=", 1)
            cookies[name.strip()] = value.strip()
    return cookies


def browser_user_agent(profile):
    version_file = Path(profile).expanduser().parent / "Last Version"
    version = "137.0.0.0"
    if version_file.exists():
        major = version_file.read_text().strip().split(".")[0]
        if major.isdigit():
            version = f"{major}.0.0.0"
    return f"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version} Safari/537.36"


class Client:
    def __init__(self, cfg, cookies, user_agent):
        self.session = requests.Session()
        self.session.cookies.update(cookies)
        self.session.headers.update({
            "User-Agent": user_agent,
            "Referer": "https://www.pixiv.net/",
            "Accept-Language": cfg.get("language", "en-US,en;q=0.9"),
        })
        if cfg.get("proxy"):
            self.session.proxies = {"http": cfg["proxy"], "https": cfg["proxy"]}
        self.delay = cfg.get("delay", 3)
        self.retries = cfg.get("retries", 5)
        self.retry_wait = cfg.get("retry_wait", 30)
        self.timeout = cfg.get("timeout", 60)
        self.last = 0
        self.login_checked = False

    def wait(self):
        pause = self.delay * random.uniform(1, 1.5) - (time.time() - self.last)
        if pause > 0:
            time.sleep(pause)

    def get(self, url, params=None):
        for attempt in range(self.retries + 1):
            self.wait()
            try:
                r = self.session.get(url, params=params, timeout=self.timeout)
                self.last = time.time()
                if r.status_code == 200:
                    return r
                if r.status_code in (400, 404):
                    raise FileNotFoundError(f"HTTP {r.status_code} {url}")
                error = f"HTTP {r.status_code}"
            except requests.RequestException as e:
                self.last = time.time()
                error = str(e)
            if attempt < self.retries:
                wait = self.retry_wait * (attempt + 1)
                log(f"request failed ({error}), retry in {wait}s: {url}")
                time.sleep(wait)
        raise RuntimeError(f"giving up after {self.retries + 1} attempts: {url}")

    def api(self, url, params=None):
        params = dict(params or {}, lang="en")
        r = self.get(url, params)
        if not self.login_checked:
            if not r.headers.get("x-userid"):
                sys.exit("not logged in, please check the browser cookies")
            log(f"logged in as user {r.headers['x-userid']}")
            self.login_checked = True
        data = r.json()
        if data.get("error"):
            raise RuntimeError(f"API error: {data.get('message')} {url}")
        return data["body"]


def clean_name(name):
    return "".join(c for c in name if c.isalnum())[:50]


class Library:
    def __init__(self, root):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self.dirs = {}
        for p in self.root.iterdir():
            m = re.match(r"(\d+)(_|$)", p.name)
            if p.is_dir() and m:
                self.dirs.setdefault(m.group(1), p)
        self.states = {}

    def state(self, uid):
        if uid not in self.states:
            state = {"done": {}, "skip": set(), "skip_user": False}
            if uid in self.dirs:
                log_path = self.dirs[uid] / LOG_NAME
                if log_path.exists():
                    for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
                        parse_line(line, state)
            self.states[uid] = state
        return self.states[uid]

    def user_dir(self, uid, name):
        if uid not in self.dirs:
            cleaned = clean_name(name)
            path = self.root / (f"{uid}_{cleaned}" if cleaned else uid)
            path.mkdir(parents=True, exist_ok=True)
            self.dirs[uid] = path
        return self.dirs[uid]

    def record(self, uid, line):
        with open(self.dirs[uid] / LOG_NAME, "a", encoding="utf-8") as f:
            f.write(line + "\n")


def parse_line(line, state):
    parts = line.split()
    if not parts or parts[0].startswith("#"):
        return
    cmd, args = parts[0], parts[1:]
    if cmd == "done" and len(args) >= 3 and args[0].isdigit():
        state["done"][args[0]] = args[2]
    elif cmd == "skip":
        state["skip"].update(a for a in args if a.isdigit())
    elif cmd == "skip_user":
        state["skip_user"] = True


def search_pages(client, word, s_mode, opts):
    page = 1
    while True:
        params = {
            "word": word,
            "order": opts["order"],
            "mode": opts["mode"],
            "s_mode": s_mode,
            "type": "all",
            "p": page,
        }
        body = client.api(f"https://www.pixiv.net/ajax/search/artworks/{quote(word, safe='')}", params)
        result = body["illustManga"]
        items = [d for d in result["data"] if isinstance(d, dict) and d.get("id")]
        last = result.get("lastPage", page)
        total = result.get("total", 0)
        log(f"search '{word}' ({s_mode}) page {page}/{last}, total {total}")
        if page == 1 and total > last * 60:
            log(f"warning: search '{word}' ({s_mode}) is capped at {last} pages, only about {last * 60} of {total} works are reachable")
        if not items:
            return
        yield items
        if page >= last or (opts["max_pages"] and page >= opts["max_pages"]):
            return
        page += 1


def download_work(client, lib, item):
    wid, uid = str(item["id"]), str(item["userId"])
    pages = client.api(f"https://www.pixiv.net/ajax/illust/{wid}/pages")
    user_dir = lib.user_dir(uid, item.get("userName", ""))
    for i, page in enumerate(pages):
        url = page["urls"]["original"]
        if not url:
            raise RuntimeError(f"no original url for {wid} page {i}")
        path = user_dir / f"{wid}_{i}.{url.rsplit('.', 1)[-1]}"
        if path.exists():
            continue
        data = client.get(url).content
        tmp = path.with_name(path.name + ".part")
        tmp.write_bytes(data)
        tmp.replace(path)
    update = item.get("updateDate") or item.get("createDate") or "-"
    lib.record(uid, f"done {wid} {len(pages)} {update} {now_iso()}")
    lib.state(uid)["done"][wid] = update
    log(f"downloaded {wid} ({len(pages)} pages) by {uid} {item.get('userName', '')}")


def run_group(client, cfg, group, base):
    opts = {k: group.get(k, cfg.get(k, v)) for k, v in GROUP_DEFAULTS.items()}
    types = {TYPES[t] for t in opts["types"]}
    root = (base / Path(group["dir"]).expanduser()).resolve()
    lib = Library(root)
    seen = set()
    stats = {"new": 0, "known": 0, "skipped": 0, "failed": 0}
    log(f"group '{group.get('name', group['dir'])}' -> {root}")
    for word, s_mode in [(w, m) for w in group["keywords"] for m in opts["s_mode"]]:
        for items in search_pages(client, word, s_mode, opts):
            for item in items:
                wid, uid = str(item["id"]), str(item["userId"])
                if wid in seen:
                    continue
                seen.add(wid)
                if item.get("illustType") not in types or (opts["exclude_ai"] and item.get("aiType") == 2):
                    stats["skipped"] += 1
                    continue
                state = lib.state(uid)
                if state["skip_user"] or wid in state["skip"]:
                    stats["skipped"] += 1
                    continue
                if wid in state["done"]:
                    stats["known"] += 1
                    continue
                try:
                    download_work(client, lib, item)
                    stats["new"] += 1
                except (RuntimeError, FileNotFoundError, KeyError, TypeError, ValueError) as e:
                    stats["failed"] += 1
                    log(f"failed {wid}: {e}")
    log(f"group done: {stats}")


def main():
    parser = argparse.ArgumentParser(description="Batch download pixiv illustrations by keywords")
    parser.add_argument("-c", "--config", default="config.json")
    parser.add_argument("groups", nargs="*", help="only run groups with these names")
    args = parser.parse_args()
    config_path = Path(args.config).expanduser().resolve()
    cfg = json.loads(config_path.read_text(encoding="utf-8"))
    profile = cfg.get("chromium_profile", "~/.config/chromium/Default")
    if cfg.get("cookie"):
        cookies = parse_cookie_string(cfg["cookie"])
    else:
        cookies = chromium_cookies(profile, cfg.get("keyring_app", "chromium"))
    client = Client(cfg, cookies, cfg.get("user_agent") or browser_user_agent(profile))
    groups = [g for g in cfg["groups"] if not args.groups or g.get("name") in args.groups]
    for group in groups:
        run_group(client, cfg, group, config_path.parent)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("interrupted")
        sys.exit(130)
