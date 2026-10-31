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
WORK_TYPES = {"illust": 0, "manga": 1}
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


def keyring_password(app):
    try:
        import gi
        gi.require_version("Secret", "1")
        from gi.repository import Secret
    except (ImportError, ValueError):
        return None
    for name in ["chrome_libsecret_os_crypt_password_v2", "chrome_libsecret_os_crypt_password_v1"]:
        schema = Secret.Schema.new(name, Secret.SchemaFlags.DONT_MATCH_NAME, {"application": Secret.SchemaAttributeType.STRING})
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
    major = version_file.read_text().split(".")[0] if version_file.exists() else ""
    if not major.isdigit():
        sys.exit(f"cannot read the browser version from {version_file}, please set user_agent in the config")
    return f"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36"


def response_error(r, image):
    if r.status_code != 200:
        return f"HTTP {r.status_code}"
    if image and not r.headers.get("Content-Type", "").startswith("image/"):
        return "not an image"
    if image and len(r.content) != int(r.headers.get("Content-Length", len(r.content))):
        return "incomplete image"
    return None


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
        self.user_id = None

    def get(self, url, params=None, image=False):
        for attempt in range(self.retries + 1):
            time.sleep(max(0, self.last + self.delay * random.uniform(1, 1.5) - time.time()))
            r = None
            try:
                r = self.session.get(url, params=params, timeout=self.timeout)
                error = response_error(r, image)
            except requests.RequestException as e:
                error = str(e)
            self.last = time.time()
            if error is None:
                return r
            if r is not None and r.status_code in (400, 404):
                raise RuntimeError(f"{error} {url}")
            if attempt < self.retries:
                wait = self.retry_wait * (attempt + 1)
                log(f"request failed ({error}), retry in {wait}s: {url}")
                time.sleep(wait)
        raise RuntimeError(f"giving up after {self.retries + 1} attempts: {url}")

    def api(self, path, params=None):
        r = self.get(f"https://www.pixiv.net/ajax/{path}", dict(params or {}, lang="en"))
        user_id = r.headers.get("x-userid")
        if not user_id:
            sys.exit("not logged in, please log in to pixiv in the browser first")
        if user_id != self.user_id:
            log(f"logged in as user {user_id}")
            self.user_id = user_id
        data = r.json()
        if data.get("error"):
            raise RuntimeError(f"API error: {data.get('message')} {path}")
        return data["body"]


def clean_name(name):
    return "".join(c for c in name if c.isalnum())[:50]


def new_user(path):
    return {"dir": path, "done": {}, "skip": set(), "skip_user": False}


def parse_line(line, user):
    parts = line.split()
    if len(parts) >= 4 and parts[0] == "done" and parts[1].isdigit():
        user["done"][parts[1]] = parts[3]
    elif parts and parts[0] == "skip":
        user["skip"].update(p for p in parts[1:] if p.isdigit())
    elif parts and parts[0] == "skip_user":
        user["skip_user"] = True


def load_users(root):
    users = {}
    for path in sorted(root.iterdir()):
        m = re.match(r"(\d+)(_|$)", path.name)
        if not (path.is_dir() and m):
            continue
        if m.group(1) in users:
            log(f"warning: {path.name} and {users[m.group(1)]['dir'].name} belong to the same user, logs are merged")
        user = users.setdefault(m.group(1), new_user(path))
        log_path = path / LOG_NAME
        if log_path.exists():
            for line in log_path.read_text(encoding="utf-8-sig", errors="replace").splitlines():
                parse_line(line, user)
    return users


def append_log(user, line):
    path = user["dir"] / LOG_NAME
    tail = path.read_bytes()[-1:] if path.exists() else b""
    if tail not in (b"", b"\n"):
        line = "\n" + line
    with open(path, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def newer(a, b):
    try:
        return datetime.fromisoformat(a) > datetime.fromisoformat(b)
    except (TypeError, ValueError):
        return False


def search(client, word, s_mode, opts):
    page = 1
    while True:
        params = {"word": word, "order": opts["order"], "mode": opts["mode"], "s_mode": s_mode, "type": "all", "p": page}
        result = client.api(f"search/artworks/{quote(word, safe='')}", params)["illustManga"]
        last, total = result["lastPage"], result["total"]
        log(f"search '{word}' ({s_mode}) page {page}/{last}, total {total}")
        if page == 1 and total > last * 60:
            log(f"warning: search '{word}' ({s_mode}) is capped at {last} pages, only about {last * 60} of {total} works are reachable")
        items = [d for d in result["data"] if isinstance(d, dict) and d.get("id")]
        yield from items
        if not items or page >= last or page == opts["max_pages"]:
            return
        page += 1


def download_work(client, root, user, item):
    wid, uid, name = str(item["id"]), str(item["userId"]), clean_name(item.get("userName", ""))
    update = item["updateDate"]
    images = []
    for i, page in enumerate(client.api(f"illust/{wid}/pages")):
        url = page["urls"]["original"]
        if not url:
            raise RuntimeError(f"no original url for page {i}")
        images.append((f"{wid}_{i}", url.rsplit(".", 1)[-1], client.get(url, image=True).content))
    pages = len(images)
    if user["dir"] is None:
        user["dir"] = root / (f"{uid}_{name}" if name else uid)
        user["dir"].mkdir(exist_ok=True)
    previous = user["done"].get(wid)
    if previous:
        old = {hashlib.sha256(p.read_bytes()).digest() for p in user["dir"].glob(f"{wid}_*") if p.suffix != ".part"}
        stamp = datetime.fromisoformat(update).strftime("%Y%m%dT%H%M%S")
        images = [(f"{stem}_{stamp}", ext, data) for stem, ext, data in images if hashlib.sha256(data).digest() not in old]
    for stem, ext, data in images:
        path = user["dir"] / f"{stem}.{ext}"
        tmp = path.with_name(path.name + ".part")
        tmp.write_bytes(data)
        tmp.replace(path)
    append_log(user, f"done {wid} {pages} {update} {datetime.now().astimezone().isoformat(timespec='seconds')}")
    user["done"][wid] = update
    if previous:
        log(f"updated {wid} ({len(images)} new of {pages} pages) by {uid} {name}")
    else:
        log(f"downloaded {wid} ({pages} pages) by {uid} {name}")


def run_group(client, cfg, group, base):
    opts = {k: group.get(k, cfg.get(k, v)) for k, v in GROUP_DEFAULTS.items()}
    types = {WORK_TYPES[t] for t in opts["types"]}
    root = (base / Path(group["dir"]).expanduser()).resolve()
    root.mkdir(parents=True, exist_ok=True)
    users = load_users(root)
    seen = set()
    stats = {"new": 0, "updated": 0, "known": 0, "skipped": 0, "failed": 0}
    log(f"group '{group.get('name', group['dir'])}' -> {root}")
    for word, s_mode in [(w, m) for w in group["keywords"] for m in opts["s_mode"]]:
        for item in search(client, word, s_mode, opts):
            wid, uid = str(item["id"]), str(item["userId"])
            if wid in seen:
                continue
            seen.add(wid)
            user = users.setdefault(uid, new_user(None))
            done = user["done"].get(wid)
            if item.get("illustType") not in types or (opts["exclude_ai"] and item.get("aiType") == 2):
                stats["skipped"] += 1
            elif user["skip_user"] or wid in user["skip"]:
                stats["skipped"] += 1
            elif done and not newer(item.get("updateDate"), done):
                stats["known"] += 1
            else:
                try:
                    download_work(client, root, user, item)
                    stats["updated" if done else "new"] += 1
                except (RuntimeError, KeyError, TypeError, ValueError) as e:
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
    for group in cfg["groups"]:
        if not args.groups or group.get("name") in args.groups:
            run_group(client, cfg, group, config_path.parent)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("interrupted")
        sys.exit(130)
